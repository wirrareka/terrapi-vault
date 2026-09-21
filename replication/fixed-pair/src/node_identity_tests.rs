use super::*;

fn identity() -> Identity {
    Identity {
        cluster: "pair".into(),
        tenant: "one".into(),
        epoch: 1,
        schema: 1,
    }
}

fn catalog(c: &Connection) -> rusqlite::Result<Vec<(String, Option<String>)>> {
    c.prepare("SELECT name,sql FROM sqlite_schema ORDER BY name")?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect()
}

#[test]
fn damaged_identity_is_not_repaired_or_reassigned_before_schema_ddl() -> Result<()> {
    for damage in [
        "DELETE FROM node_identity",
        "DROP TABLE node_identity",
        "INSERT INTO node_identity SELECT value FROM node_identity",
        "UPDATE node_identity SET value='invalid'",
    ] {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("node.db");
        drop(Node::open(&path, Role::Primary, identity(), "fixture")?);
        let db = Vesta::open(&path, "fixture")?;
        db.with_connection(|c| {
            c.execute_batch(damage)?;
            // Detect whether rejected open reached application schema initialization.
            c.execute_batch("DROP TABLE features")?;
            Ok(())
        })?;
        drop(db);
        for role in [Role::Primary, Role::Secondary] {
            assert!(
                Node::open(&path, role, identity(), "fixture").is_err(),
                "{damage}"
            );
        }
        let db = Vesta::open(&path, "fixture")?;
        db.with_connection(|c| {
            let exists: bool = c.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='features')",
                [],
                |r| r.get(0),
            )?;
            assert!(
                !exists,
                "rejected open initialized application schema: {damage}"
            );
            Ok(())
        })?;
    }
    Ok(())
}

#[test]
fn existing_non_node_database_is_not_implicitly_adopted() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("unbound.db");
    let db = Vesta::create(&path, "fixture", KdfParams::default())?;
    db.with_connection(|c| {
        c.execute_batch(
            "CREATE TABLE user_data(value TEXT); INSERT INTO user_data VALUES('keep')",
        )?;
        Ok(())
    })?;
    let before = db.with_connection(catalog)?;
    drop(db);
    assert!(Node::open(&path, Role::Primary, identity(), "fixture").is_err());
    let db = Vesta::open(&path, "fixture")?;
    db.with_connection(|c| {
        assert_eq!(catalog(c)?, before);
        let value: String = c.query_row("SELECT value FROM user_data", [], |r| r.get(0))?;
        assert_eq!(value, "keep");
        Ok(())
    })?;
    Ok(())
}

#[test]
fn exact_identity_reopens_but_other_scope_or_role_does_not() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("node.db");
    drop(Node::open(&path, Role::Primary, identity(), "fixture")?);
    for field in 0..4 {
        let mut other = identity();
        match field {
            0 => other.cluster.push('x'),
            1 => other.tenant.push('x'),
            2 => other.epoch += 1,
            _ => other.schema += 1,
        }
        assert!(Node::open(&path, Role::Primary, other, "fixture").is_err());
    }
    assert!(Node::open(&path, Role::Secondary, identity(), "fixture").is_err());
    let node = Node::open(&path, Role::Primary, identity(), "fixture")?;
    assert_eq!(node.view()?, View::default());
    Ok(())
}

#[test]
fn legacy_schema_upgrade_is_explicit_and_preserves_data_receipts_and_checkpoint() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("legacy.db");
    let mut node = Node::open(&path, Role::Primary, identity(), "fixture")?;
    let secondary_path = dir.path().join("secondary.db");
    let mut secondary = Node::open(&secondary_path, Role::Secondary, identity(), "fixture")?;
    let batch = Batch {
        identity: identity(),
        operation_id: "one".into(),
        changes: vec![Change::PutPlace {
            id: "p".into(),
            name: "kept".into(),
        }],
    };
    let result = commit(&mut node, &mut secondary, batch.clone())?;
    let view = node.view()?;
    let receipt = node.receipt("one")?;
    let checkpoint = node.checkpoint()?;
    let contract = node.schema_contract()?;
    node.connection(|c| {
        c.execute_batch("DROP TABLE node_schema_contract")?;
        Ok(())
    })?;
    secondary.connection(|c| {
        c.execute_batch("DROP TABLE node_schema_contract")?;
        Ok(())
    })?;
    drop(secondary);
    drop(node);
    assert!(Node::open(&path, Role::Primary, identity(), "fixture").is_err());
    let upgraded =
        Node::upgrade_legacy_schema_contract(&path, Role::Primary, identity(), "fixture")?;
    assert_eq!(upgraded.view()?, view);
    assert_eq!(upgraded.receipt("one")?, receipt);
    assert_eq!(upgraded.checkpoint()?, checkpoint);
    assert_eq!(upgraded.schema_contract()?, contract);
    drop(upgraded);
    drop(Node::open(&path, Role::Primary, identity(), "fixture")?);
    // An exact retry verifies the existing binding instead of overwriting it.
    drop(Node::upgrade_legacy_schema_contract(
        &path,
        Role::Primary,
        identity(),
        "fixture",
    )?);
    let mut secondary = Node::upgrade_legacy_schema_contract(
        &secondary_path,
        Role::Secondary,
        identity(),
        "fixture",
    )?;
    assert_eq!(secondary.view()?, view);
    assert_eq!(secondary.receipt("one")?, receipt);
    assert_eq!(secondary.checkpoint()?, checkpoint);
    assert_eq!(secondary.schema_contract()?, contract);
    let mut primary = Node::open(&path, Role::Primary, identity(), "fixture")?;
    assert_eq!(commit(&mut primary, &mut secondary, batch)?, result);
    let next = commit(
        &mut primary,
        &mut secondary,
        Batch {
            identity: identity(),
            operation_id: "two".into(),
            changes: vec![Change::PutPlace {
                id: "p".into(),
                name: "after upgrade".into(),
            }],
        },
    )?;
    assert_eq!(next.sequence, 2);
    assert_eq!(primary.view()?, secondary.view()?);
    assert_eq!(primary.receipt("two")?, secondary.receipt("two")?);
    Ok(())
}

#[test]
fn schema_contract_corruption_and_catalog_drift_are_not_repaired() -> Result<()> {
    for damage in [
        "DELETE FROM node_schema_contract",
        "UPDATE node_schema_contract SET contract=json_set(contract,'$.fingerprint_version',99)",
        "UPDATE node_schema_contract SET contract=json_set(contract,'$.schema.name','other')",
        "CREATE INDEX unexpected_index ON places(name)",
        "DROP TABLE features",
        "DROP TABLE node_schema_contract; CREATE INDEX legacy_drift ON places(name)",
    ] {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("node.db");
        let node = Node::open(&path, Role::Primary, identity(), "fixture")?;
        node.connection(|c| {
            c.execute_batch(damage)?;
            Ok(())
        })?;
        let before = node.connection(|c| Ok(catalog(c)?))?;
        assert!(node.schema_contract().is_err(), "{damage}");
        drop(node);
        assert!(
            Node::open(&path, Role::Primary, identity(), "fixture").is_err(),
            "{damage}"
        );
        assert!(
            Node::upgrade_legacy_schema_contract(&path, Role::Primary, identity(), "fixture")
                .is_err(),
            "{damage}"
        );
        let db = Vesta::open(&path, "fixture")?;
        assert_eq!(db.with_connection(catalog)?, before);
    }
    Ok(())
}

#[test]
fn legacy_upgrade_rejects_corrupt_history_without_installing_contract() -> Result<()> {
    for damage in [
        "DELETE FROM operation_receipts",
        "DROP TABLE operation_receipts",
        "DROP TABLE replication_log",
    ] {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("legacy.db");
        let mut node = Node::open(&path, Role::Primary, identity(), "fixture")?;
        node.prepare(Batch {
            identity: identity(),
            operation_id: "one".into(),
            changes: vec![],
        })?;
        let decision = node.decide("one")?;
        node.apply(decision)?;
        node.connection(|c| {
            c.execute_batch("DROP TABLE node_schema_contract")?;
            c.execute_batch(damage)?;
            Ok(())
        })?;
        let before = node.connection(|c| Ok(catalog(c)?))?;
        drop(node);
        assert!(
            Node::upgrade_legacy_schema_contract(&path, Role::Primary, identity(), "fixture")
                .is_err()
        );
        let db = Vesta::open(&path, "fixture")?;
        assert!(!db.with_connection(|c| Ok(schema_contract::exists(c)))??);
        assert_eq!(db.with_connection(catalog)?, before, "{damage}");
    }
    Ok(())
}

#[test]
fn legacy_upgrade_cannot_create_a_node_or_adopt_unowned_file() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("absent.db");
    assert!(
        Node::upgrade_legacy_schema_contract(&path, Role::Primary, identity(), "fixture").is_err()
    );
    assert!(!path.exists());
    drop(Vesta::create(&path, "fixture", KdfParams::default())?);
    assert!(
        Node::upgrade_legacy_schema_contract(&path, Role::Primary, identity(), "fixture").is_err()
    );
    Ok(())
}
