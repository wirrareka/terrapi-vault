use rusqlite::{params, Connection};
use serde::Serialize;
use terrapi_vesta_replication::{
    schema::{self, Schema, SchemaId},
    sql_snapshot as snap, Result,
};

struct Inventory;
#[derive(Clone, Debug, Serialize, PartialEq)]
struct Item {
    id: String,
    payload: Option<Vec<u8>>,
    quantity: i64,
}
impl Schema for Inventory {
    type Change = Item;
    type View = Vec<Item>;
    fn identity(&self) -> SchemaId {
        SchemaId {
            name: "example.snapshot-inventory".into(),
            version: 1,
        }
    }
    fn tables(&self) -> &'static [&'static str] {
        &["items"]
    }
    fn initialize(&self, c: &Connection) -> Result<()> {
        c.execute_batch("CREATE TABLE IF NOT EXISTS items(id TEXT PRIMARY KEY NOT NULL,payload BLOB,quantity INTEGER NOT NULL CHECK(quantity>=0));")?;
        Ok(())
    }
    fn execute(&self, c: &Connection, changes: &[Item]) -> Result<()> {
        for r in changes {
            c.execute(
                "INSERT INTO items VALUES(?1,?2,?3)",
                params![r.id, r.payload, r.quantity],
            )?;
        }
        Ok(())
    }
    fn view(&self, c: &Connection) -> Result<Vec<Item>> {
        Ok(
            c.prepare("SELECT id,payload,quantity FROM items ORDER BY id")?
                .query_map([], |r| {
                    Ok(Item {
                        id: r.get(0)?,
                        payload: r.get(1)?,
                        quantity: r.get(2)?,
                    })
                })?
                .collect::<rusqlite::Result<_>>()?,
        )
    }
}
fn scope() -> snap::Scope {
    snap::Scope {
        cluster: "eu".into(),
        tenant: "tenant-a".into(),
        epoch: 1,
        schema: Inventory.identity(),
    }
}

#[test]
fn exact_row_quota_exports_but_one_more_row_is_rejected() -> Result<()> {
    let c = Connection::open_in_memory()?;
    initialize(&c)?;
    c.execute(
        "WITH RECURSIVE ids(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM ids WHERE n<?1)
         INSERT INTO items SELECT CAST(n AS TEXT),NULL,0 FROM ids",
        [snap::MAX_ROWS],
    )?;
    let export = snap::export(&c, &Inventory, &scope())?;
    assert_eq!(export.manifest.rows, snap::MAX_ROWS);
    drop(export);
    c.execute("INSERT INTO items VALUES('overflow',NULL,0)", [])?;
    assert_eq!(
        snap::export(&c, &Inventory, &scope())
            .err()
            .unwrap()
            .to_string(),
        "SQL snapshot quota exceeded"
    );
    // An export refusal is observational, never a deletion of excess data.
    assert_eq!(
        c.query_row("SELECT count(*) FROM items", [], |r| r.get::<_, u64>(0))?,
        snap::MAX_ROWS + 1
    );
    Ok(())
}

#[test]
fn exact_encoded_row_size_exports_but_one_more_byte_is_rejected() -> Result<()> {
    let c = Connection::open_in_memory()?;
    initialize(&c)?;
    let row = snap::Row {
        table: 0,
        values: vec![
            snap::SqlValue::Text(String::new()),
            snap::SqlValue::Null,
            snap::SqlValue::Integer(0),
        ],
    };
    let overhead = serde_json::to_vec(&row)?.len();
    let id = "x".repeat(snap::MAX_ROW_BYTES - overhead);
    c.execute("INSERT INTO items VALUES(?1,NULL,0)", [&id])?;
    let export = snap::export(&c, &Inventory, &scope())?;
    assert_eq!(export.manifest.bytes, snap::MAX_ROW_BYTES as u64);
    c.execute("UPDATE items SET id=id || 'x'", [])?;
    assert_eq!(
        snap::export(&c, &Inventory, &scope())
            .err()
            .unwrap()
            .to_string(),
        "snapshot row too large"
    );
    Ok(())
}

#[test]
fn damaged_empty_binding_cannot_be_recreated_or_reassigned() -> Result<()> {
    let source = populated()?;
    let export = snap::export(&source, &Inventory, &scope())?;
    let pages = export.pages(1)?;
    for damage in [
        "DELETE FROM snapshot_sql_binding",
        "DROP TABLE snapshot_sql_binding",
        "DROP TABLE snapshot_sql_progress",
        "DROP TABLE snapshot_sql_rows",
    ] {
        let c = Connection::open_in_memory()?;
        initialize(&c)?;
        c.execute_batch(damage)?;
        let tables_before: i64 = c.query_row(
            "SELECT count(*) FROM sqlite_schema WHERE name IN ('snapshot_sql_binding','snapshot_sql_progress','snapshot_sql_rows')",
            [], |r| r.get(0))?;
        assert!(snap::bind(&c, &Inventory, &scope()).is_err(), "{damage}");
        let mut other = scope();
        other.tenant = "tenant-b".into();
        assert!(snap::bind(&c, &Inventory, &other).is_err(), "{damage}");
        assert!(snap::export(&c, &Inventory, &scope()).is_err(), "{damage}");
        assert!(
            snap::begin(&c, &Inventory, &scope(), &export.manifest).is_err(),
            "{damage}"
        );
        assert!(
            snap::receive(&c, &Inventory, &scope(), &pages[0]).is_err(),
            "{damage}"
        );
        assert!(snap::finish(&c, &Inventory, &scope()).is_err(), "{damage}");
        let tables_after: i64 = c.query_row(
            "SELECT count(*) FROM sqlite_schema WHERE name IN ('snapshot_sql_binding','snapshot_sql_progress','snapshot_sql_rows')",
            [], |r| r.get(0))?;
        assert_eq!(tables_before, tables_after, "must not repair {damage}");
        assert!(Inventory.view(&c)?.is_empty());
    }
    Ok(())
}

#[test]
fn lost_binding_is_rejected_after_encrypted_reopen() -> Result<()> {
    use terrapi_vesta::{KdfParams, Vesta};
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("damaged-binding.db");
    let db = Vesta::create(&path, "test-only", KdfParams::default())?;
    db.with_connection(|c| Ok(initialize(c)))??;
    db.with_connection(|c| {
        c.execute("DELETE FROM snapshot_sql_binding", [])?;
        Ok(())
    })?;
    drop(db);
    let reopened = Vesta::open(&path, "test-only")?;
    reopened.with_connection(|c| {
        assert!(snap::bind(c, &Inventory, &scope()).is_err());
        let mut other = scope();
        other.tenant = "tenant-b".into();
        assert!(snap::bind(c, &Inventory, &other).is_err());
        let rows: u32 = c.query_row("SELECT count(*) FROM snapshot_sql_binding", [], |r| {
            r.get(0)
        })?;
        assert_eq!(rows, 0);
        Ok(())
    })?;
    Ok(())
}
fn initialize(c: &Connection) -> Result<()> {
    c.pragma_update(None, "foreign_keys", "ON")?;
    schema::initialize(c, &Inventory)?;
    snap::bind(c, &Inventory, &scope())
}
fn populated() -> Result<Connection> {
    let c = Connection::open_in_memory()?;
    initialize(&c)?;
    let change = schema::capture(
        &c,
        &Inventory,
        &[
            Item {
                id: "a".into(),
                payload: None,
                quantity: 1,
            },
            Item {
                id: "b".into(),
                payload: Some(vec![]),
                quantity: 2,
            },
            Item {
                id: "c".into(),
                payload: Some(vec![0, 255, 128]),
                quantity: 3,
            },
        ],
    )?;
    schema::replay(&c, &Inventory, &change)?;
    Ok(c)
}
#[test]
fn pages_roundtrip_resume_on_encrypted_target_and_finish_atomically() -> Result<()> {
    use terrapi_vesta::{KdfParams, Vesta};
    let source = populated()?;
    let export = snap::export(&source, &Inventory, &scope())?;
    let pages = export.pages(1)?;
    assert_eq!(pages.len(), 3);
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("target.vesta");
    {
        let db = Vesta::create(&path, "snapshot-test-only", KdfParams::default())?;
        db.with_connection(|c| Ok(initialize(c)))??;
        db.with_connection(|c| Ok(snap::begin(c, &Inventory, &scope(), &export.manifest)))??;
        let page = snap::Page::decode(&pages[0].encode()?)?;
        db.with_connection(|c| Ok(snap::receive(c, &Inventory, &scope(), &page)))??;
        assert!(db.with_connection(|c| Ok(Inventory.view(c)))??.is_empty());
    }
    let db = Vesta::open(&path, "snapshot-test-only")?;
    assert!(db
        .with_connection(|c| Ok(snap::begin(c, &Inventory, &scope(), &export.manifest)))?
        .is_err());
    db.with_connection(|c| Ok(snap::bind(c, &Inventory, &scope())))??;
    assert_eq!(
        db.with_connection(|c| c.query_row("PRAGMA synchronous", [], |r| r.get::<_, i64>(0)))?,
        2
    );
    assert_eq!(
        db.with_connection(|c| Ok(snap::begin(c, &Inventory, &scope(), &export.manifest)))??
            .received,
        1
    );
    for page in &pages {
        // exact duplicate first page is safe
        db.with_connection(|c| Ok(snap::receive(c, &Inventory, &scope(), page)))??;
    }
    assert!(db.with_connection(|c| Ok(Inventory.view(c)))??.is_empty());
    db.with_connection(|c| Ok(snap::finish(c, &Inventory, &scope())))??;
    db.with_connection(|c| Ok(snap::finish(c, &Inventory, &scope())))??;
    assert_eq!(
        db.with_connection(|c| Ok(Inventory.view(c)))??,
        Inventory.view(&source)?
    );
    Ok(())
}
#[test]
fn wrong_scope_reorder_conflicts_and_corrupt_finish_preserve_target() -> Result<()> {
    let source = populated()?;
    let export = snap::export(&source, &Inventory, &scope())?;
    let pages = export.pages(1)?;
    let target = Connection::open_in_memory()?;
    initialize(&target)?;
    let mut wrong = scope();
    wrong.tenant = "tenant-b".into();
    assert!(snap::bind(&target, &Inventory, &wrong).is_err());
    assert!(snap::begin(&target, &Inventory, &wrong, &export.manifest).is_err());
    snap::begin(&target, &Inventory, &scope(), &export.manifest)?;
    assert!(snap::receive(&target, &Inventory, &scope(), &pages[1]).is_err());
    assert!(snap::finish(&target, &Inventory, &scope()).is_err());
    snap::receive(&target, &Inventory, &scope(), &pages[0])?;
    let mut conflict = pages[0].clone();
    conflict.rows[0].values[2] = snap::SqlValue::Integer(999);
    assert!(snap::receive(&target, &Inventory, &scope(), &conflict).is_err());
    for p in &pages[1..] {
        snap::receive(&target, &Inventory, &scope(), p)?;
    }
    target.execute("UPDATE snapshot_sql_rows SET row='{}' WHERE position=1", [])?;
    assert!(snap::finish(&target, &Inventory, &scope()).is_err());
    assert!(Inventory.view(&target)?.is_empty());
    Ok(())
}
#[test]
fn wire_limits_and_nonempty_target_are_rejected() -> Result<()> {
    assert!(snap::Page::decode(&vec![b' '; snap::MAX_PAGE_BYTES + 1]).is_err());
    assert!(snap::Page::decode(b"{}").is_err());
    let source = populated()?;
    let export = snap::export(&source, &Inventory, &scope())?;
    assert!(export.pages(0).is_err());
    assert!(snap::begin(&source, &Inventory, &scope(), &export.manifest).is_err());
    Ok(())
}

#[test]
fn empty_snapshot_and_manifest_wire_contract() -> Result<()> {
    let source = Connection::open_in_memory()?;
    initialize(&source)?;
    let export = snap::export(&source, &Inventory, &scope())?;
    assert!(export.pages(1)?.is_empty());
    assert_eq!(
        snap::Manifest::decode(&export.manifest.encode()?)?,
        export.manifest
    );
    assert!(snap::Manifest::decode(&vec![b' '; snap::MAX_MANIFEST_BYTES + 1]).is_err());
    let mut json = serde_json::to_value(&export.manifest)?;
    json["unrecognized"] = true.into();
    assert!(snap::Manifest::decode(&serde_json::to_vec(&json)?).is_err());
    let target = Connection::open_in_memory()?;
    initialize(&target)?;
    snap::begin(&target, &Inventory, &scope(), &export.manifest)?;
    assert!(snap::finish(&target, &Inventory, &scope())?.complete);
    Ok(())
}

#[test]
fn every_scope_component_and_physical_schema_are_bound() -> Result<()> {
    let source = populated()?;
    let export = snap::export(&source, &Inventory, &scope())?;
    for i in 0..5 {
        let target = Connection::open_in_memory()?;
        initialize(&target)?;
        let mut wrong = scope();
        match i {
            0 => wrong.cluster = "other".into(),
            1 => wrong.tenant = "other".into(),
            2 => wrong.epoch = 2,
            3 => wrong.schema.name = "other".into(),
            _ => wrong.schema.version = 2,
        }
        assert!(snap::bind(&target, &Inventory, &wrong).is_err());
        assert!(snap::begin(&target, &Inventory, &wrong, &export.manifest).is_err());
        let mut manifest = export.manifest.clone();
        manifest.scope = wrong;
        assert!(snap::begin(&target, &Inventory, &scope(), &manifest).is_err());
        assert!(Inventory.view(&target)?.is_empty());
    }
    let target = Connection::open_in_memory()?;
    target.pragma_update(None, "foreign_keys", "ON")?;
    schema::initialize(&target, &Inventory)?;
    target.execute_batch("CREATE INDEX items_quantity ON items(quantity);")?;
    snap::bind(&target, &Inventory, &scope())?;
    assert!(snap::begin(&target, &Inventory, &scope(), &export.manifest).is_err());
    source.execute_batch("CREATE INDEX changed_schema ON items(quantity);")?;
    assert!(snap::export(&source, &Inventory, &scope()).is_err());
    Ok(())
}

#[test]
fn binding_cannot_adopt_populated_data_or_unsupported_schema_features() -> Result<()> {
    let c = Connection::open_in_memory()?;
    c.pragma_update(None, "foreign_keys", "ON")?;
    schema::initialize(&c, &Inventory)?;
    c.execute("INSERT INTO items VALUES('existing',NULL,1)", [])?;
    assert!(snap::bind(&c, &Inventory, &scope()).is_err());
    assert_eq!(Inventory.view(&c)?.len(), 1);
    for ddl in [
        "CREATE TRIGGER items_trigger AFTER INSERT ON items BEGIN SELECT 1; END;",
        "CREATE TEMP TRIGGER items_trigger AFTER INSERT ON items BEGIN SELECT 1; END;",
        "ALTER TABLE items ADD COLUMN doubled INTEGER GENERATED ALWAYS AS (quantity*2) VIRTUAL;",
    ] {
        let c = Connection::open_in_memory()?;
        c.pragma_update(None, "foreign_keys", "ON")?;
        schema::initialize(&c, &Inventory)?;
        c.execute_batch(ddl)?;
        assert!(snap::bind(&c, &Inventory, &scope()).is_err());
    }
    Ok(())
}

#[test]
fn invalid_pages_never_advance_progress() -> Result<()> {
    let source = populated()?;
    let export = snap::export(&source, &Inventory, &scope())?;
    let pages = export.pages(1)?;
    let target = Connection::open_in_memory()?;
    initialize(&target)?;
    snap::begin(&target, &Inventory, &scope(), &export.manifest)?;
    let mut invalid = Vec::new();
    let mut page = pages[0].clone();
    page.format = 2;
    invalid.push(page);
    let mut page = pages[0].clone();
    page.manifest_digest = "0".repeat(64);
    invalid.push(page);
    let mut page = pages[0].clone();
    page.rows[0].table = u32::MAX;
    invalid.push(page);
    let mut page = pages[0].clone();
    page.rows[0].values.pop();
    invalid.push(page);
    let mut page = pages[0].clone();
    page.rows[0].values[2] = snap::SqlValue::RealBits(f64::NAN.to_bits());
    invalid.push(page);
    let mut page = pages[0].clone();
    page.offset = u64::MAX;
    invalid.push(page);
    let mut page = pages[0].clone();
    page.rows.clear();
    invalid.push(page);
    let mut page = pages[0].clone();
    page.rows[0].values[0] = snap::SqlValue::Text("a".repeat(snap::MAX_ROW_BYTES + 1));
    invalid.push(page);
    for page in invalid {
        assert!(snap::receive(&target, &Inventory, &scope(), &page).is_err());
        assert_eq!(
            snap::begin(&target, &Inventory, &scope(), &export.manifest)?.received,
            0
        );
    }
    snap::receive(&target, &Inventory, &scope(), &pages[0])?;
    let overlap = export.pages(2)?.remove(0);
    assert!(snap::receive(&target, &Inventory, &scope(), &overlap).is_err());
    assert_eq!(
        snap::begin(&target, &Inventory, &scope(), &export.manifest)?.received,
        1
    );
    Ok(())
}

#[test]
fn final_content_and_application_hash_failures_roll_back_all_rows() -> Result<()> {
    for corrupt_state in [false, true] {
        let source = populated()?;
        let mut export = snap::export(&source, &Inventory, &scope())?;
        if corrupt_state {
            export.manifest.state_digest = "0".repeat(64);
        }
        let mut pages = export.pages(1)?;
        if !corrupt_state {
            pages[0].rows[0].values[2] = snap::SqlValue::Integer(9);
        }
        let target = Connection::open_in_memory()?;
        initialize(&target)?;
        snap::begin(&target, &Inventory, &scope(), &export.manifest)?;
        for p in pages {
            snap::receive(&target, &Inventory, &scope(), &p)?;
        }
        assert!(snap::finish(&target, &Inventory, &scope()).is_err());
        assert!(Inventory.view(&target)?.is_empty());
        assert!(!snap::begin(&target, &Inventory, &scope(), &export.manifest)?.complete);
    }
    Ok(())
}

struct ChildFirst;
impl Schema for ChildFirst {
    type Change = terrapi_vesta_replication::Change;
    type View = terrapi_vesta_replication::View;
    fn identity(&self) -> SchemaId {
        terrapi_vesta_replication::reference::Proximi.identity()
    }
    fn tables(&self) -> &'static [&'static str] {
        &["features", "places"]
    }
    fn initialize(&self, c: &Connection) -> Result<()> {
        terrapi_vesta_replication::reference::Proximi.initialize(c)
    }
    fn execute(&self, c: &Connection, changes: &[Self::Change]) -> Result<()> {
        terrapi_vesta_replication::reference::Proximi.execute(c, changes)
    }
    fn view(&self, c: &Connection) -> Result<Self::View> {
        terrapi_vesta_replication::reference::Proximi.view(c)
    }
}
#[test]
fn foreign_key_children_can_arrive_before_parents() -> Result<()> {
    use terrapi_vesta_replication::Change;
    let source = Connection::open_in_memory()?;
    let target = Connection::open_in_memory()?;
    let binding = snap::Scope {
        schema: ChildFirst.identity(),
        ..scope()
    };
    for c in [&source, &target] {
        c.pragma_update(None, "foreign_keys", "ON")?;
        schema::initialize(c, &ChildFirst)?;
        snap::bind(c, &ChildFirst, &binding)?;
    }
    let change = schema::capture(
        &source,
        &ChildFirst,
        &[
            Change::PutPlace {
                id: "p".into(),
                name: "place".into(),
            },
            Change::PutFeature {
                id: "f".into(),
                place_id: "p".into(),
                geojson: "{}".into(),
            },
        ],
    )?;
    schema::replay(&source, &ChildFirst, &change)?;
    let export = snap::export(&source, &ChildFirst, &binding)?;
    snap::begin(&target, &ChildFirst, &binding, &export.manifest)?;
    for p in export.pages(1)? {
        snap::receive(&target, &ChildFirst, &binding, &p)?;
    }
    snap::finish(&target, &ChildFirst, &binding)?;
    assert_eq!(ChildFirst.view(&source)?, ChildFirst.view(&target)?);
    assert_eq!(
        target.query_row("PRAGMA defer_foreign_keys", [], |r| r.get::<_, i64>(0))?,
        0
    );
    Ok(())
}

#[test]
fn operation_codec_pins_finish_and_completed_retries_recheck_live_data() -> Result<()> {
    use snap::transport::{self, Request};
    let source = populated()?;
    let export = snap::export(&source, &Inventory, &scope())?;
    let target = Connection::open_in_memory()?;
    initialize(&target)?;
    let call = |request: Request| -> Result<snap::Progress> {
        let decoded = Request::decode(&request.encode()?)?;
        transport::dispatch(&target, &Inventory, &scope(), &decoded)
    };
    call(Request::Begin {
        manifest: export.manifest.clone(),
    })?;
    let pages = export.pages(1)?;
    for page in &pages {
        call(Request::Page { page: page.clone() })?;
    }
    assert!(call(Request::Finish {
        manifest_digest: "0".repeat(64)
    })
    .is_err());
    assert!(Inventory.view(&target)?.is_empty());
    assert!(
        call(Request::Finish {
            manifest_digest: export.manifest.digest()?
        })?
        .complete
    );
    assert_eq!(Inventory.view(&source)?, Inventory.view(&target)?);
    target.execute("UPDATE items SET quantity=7 WHERE id='a'", [])?;
    assert!(call(Request::Begin {
        manifest: export.manifest.clone()
    })
    .is_err());
    assert!(call(Request::Page {
        page: pages[0].clone()
    })
    .is_err());
    assert!(call(Request::Finish {
        manifest_digest: export.manifest.digest()?
    })
    .is_err());
    assert!(Request::decode(&vec![b' '; transport::MAX_REQUEST_BYTES + 1]).is_err());
    assert!(
        Request::decode(br#"{"operation":"Finish","manifest_digest":"bad","extra":true}"#).is_err()
    );
    Ok(())
}

#[test]
fn large_rows_are_split_by_bytes_and_oversized_cells_refused() -> Result<()> {
    let source = Connection::open_in_memory()?;
    initialize(&source)?;
    for n in 0..8 {
        source.execute(
            "INSERT INTO items VALUES(?1,?2,1)",
            params![n.to_string(), vec![255u8; 60_000]],
        )?;
    }
    let export = snap::export(&source, &Inventory, &scope())?;
    let pages = export.pages(snap::MAX_PAGE_ROWS)?;
    assert!(pages.len() > 1);
    let target = Connection::open_in_memory()?;
    initialize(&target)?;
    snap::begin(&target, &Inventory, &scope(), &export.manifest)?;
    for p in &pages {
        assert!(p.encode()?.len() <= snap::MAX_PAGE_BYTES);
        snap::receive(&target, &Inventory, &scope(), p)?;
    }
    snap::finish(&target, &Inventory, &scope())?;
    assert_eq!(Inventory.view(&source)?, Inventory.view(&target)?);
    source.execute(
        "INSERT INTO items VALUES('oversized',zeroblob(?1),1)",
        [snap::MAX_ROW_BYTES + 1],
    )?;
    assert!(snap::export(&source, &Inventory, &scope()).is_err());
    Ok(())
}

struct Measurements;
impl Schema for Measurements {
    type Change = ();
    type View = Vec<(String, i64, u64)>;
    fn identity(&self) -> SchemaId {
        SchemaId {
            name: "example.measurements".into(),
            version: 1,
        }
    }
    fn tables(&self) -> &'static [&'static str] {
        &["measurements"]
    }
    fn initialize(&self, c: &Connection) -> Result<()> {
        c.execute_batch("CREATE TABLE IF NOT EXISTS measurements(sensor TEXT NOT NULL,sequence INTEGER NOT NULL,reading REAL NOT NULL,PRIMARY KEY(sensor,sequence)) WITHOUT ROWID;")?;
        Ok(())
    }
    fn execute(&self, _: &Connection, _: &[()]) -> Result<()> {
        Ok(())
    }
    fn view(&self, c: &Connection) -> Result<Self::View> {
        Ok(
            c.prepare("SELECT sensor,sequence,reading FROM measurements ORDER BY sensor,sequence")?
                .query_map([], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get::<_, f64>(2)?.to_bits()))
                })?
                .collect::<rusqlite::Result<_>>()?,
        )
    }
}
#[test]
fn composite_keys_and_real_bits_roundtrip_losslessly() -> Result<()> {
    let source = Connection::open_in_memory()?;
    let target = Connection::open_in_memory()?;
    let binding = snap::Scope {
        schema: Measurements.identity(),
        ..scope()
    };
    for c in [&source, &target] {
        c.pragma_update(None, "foreign_keys", "ON")?;
        schema::initialize(c, &Measurements)?;
        snap::bind(c, &Measurements, &binding)?;
    }
    for (sequence, value) in [
        (i64::MIN, -f64::INFINITY),
        (0, 0.25),
        (i64::MAX, f64::INFINITY),
    ] {
        source.execute(
            "INSERT INTO measurements VALUES('sensor',?1,?2)",
            params![sequence, value],
        )?;
    }
    let export = snap::export(&source, &Measurements, &binding)?;
    snap::begin(&target, &Measurements, &binding, &export.manifest)?;
    for page in export.pages(2)? {
        snap::receive(
            &target,
            &Measurements,
            &binding,
            &snap::Page::decode(&page.encode()?)?,
        )?;
    }
    snap::finish(&target, &Measurements, &binding)?;
    assert_eq!(Measurements.view(&source)?, Measurements.view(&target)?);
    Ok(())
}

#[test]
fn autoincrement_and_corrupt_completion_counters_are_rejected() -> Result<()> {
    let c = Connection::open_in_memory()?;
    c.pragma_update(None, "foreign_keys", "ON")?;
    c.execute_batch("CREATE TABLE items(id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,payload BLOB,quantity INTEGER NOT NULL);")?;
    let error = snap::bind(&c, &Inventory, &scope()).expect_err("AUTOINCREMENT must be rejected");
    assert!(error.to_string().contains("AUTOINCREMENT"));
    let source = populated()?;
    let export = snap::export(&source, &Inventory, &scope())?;
    let target = Connection::open_in_memory()?;
    initialize(&target)?;
    snap::begin(&target, &Inventory, &scope(), &export.manifest)?;
    for page in export.pages(1)? {
        snap::receive(&target, &Inventory, &scope(), &page)?;
    }
    snap::finish(&target, &Inventory, &scope())?;
    target.execute(
        "UPDATE snapshot_sql_progress SET progress=json_set(progress,'$.received',0)",
        [],
    )?;
    assert!(snap::begin(&target, &Inventory, &scope(), &export.manifest).is_err());
    assert!(snap::finish(&target, &Inventory, &scope()).is_err());
    assert_eq!(Inventory.view(&target)?, Inventory.view(&source)?);
    Ok(())
}

#[test]
fn temporary_objects_cannot_shadow_bound_application_tables() -> Result<()> {
    for ddl in [
        "CREATE TEMP TABLE items(id TEXT PRIMARY KEY NOT NULL,payload BLOB,quantity INTEGER NOT NULL); INSERT INTO temp.items VALUES('shadow',NULL,99);",
        "CREATE TEMP VIEW items AS SELECT 'shadow' AS id,NULL AS payload,99 AS quantity;",
    ] {
        let source=populated()?;
        source.execute_batch(ddl)?;
        assert!(snap::export(&source,&Inventory,&scope()).is_err());
        assert_eq!(source.query_row("SELECT count(*) FROM main.items",[],|r|r.get::<_,u64>(0))?,3);
    }
    Ok(())
}

#[test]
fn weakened_durability_profiles_are_rejected_without_erasing_temp_objects() -> Result<()> {
    let stronger = populated()?;
    stronger.pragma_update(None, "synchronous", "EXTRA")?;
    snap::bind(&stronger, &Inventory, &scope())?;
    assert_eq!(
        stronger.query_row("PRAGMA synchronous", [], |r| r.get::<_, i64>(0))?,
        3
    );
    snap::export(&stronger, &Inventory, &scope())?;
    for pragma in [
        "PRAGMA synchronous=NORMAL;",
        "PRAGMA synchronous=OFF;",
        "PRAGMA journal_mode=OFF;",
    ] {
        let source = populated()?;
        source.execute_batch(pragma)?;
        assert!(snap::export(&source, &Inventory, &scope()).is_err());
        assert_eq!(Inventory.view(&source)?.len(), 3);
    }
    let dir = tempfile::tempdir()?;
    let c = Connection::open(dir.path().join("profile.sqlite"))?;
    c.pragma_update(None, "foreign_keys", "ON")?;
    schema::initialize(&c, &Inventory)?;
    assert!(snap::bind(&c, &Inventory, &scope()).is_err()); // disk temp storage default is not accepted
    c.pragma_update(None, "temp_store", "MEMORY")?;
    c.pragma_update(None, "journal_mode", "MEMORY")?;
    assert!(snap::bind(&c, &Inventory, &scope()).is_err()); // disk DB cannot use a volatile journal
    c.pragma_update(None, "journal_mode", "WAL")?;
    snap::bind(&c, &Inventory, &scope())?;
    c.execute_batch("CREATE TEMP TABLE scratch(value TEXT); INSERT INTO scratch VALUES('keep');")?;
    assert!(snap::bind(&c, &Inventory, &scope()).is_err());
    assert_eq!(
        c.query_row("SELECT value FROM temp.scratch", [], |r| r
            .get::<_, String>(0))?,
        "keep"
    );
    Ok(())
}
