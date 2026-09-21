use super::*;
use journal::store;

const LOG_DDL: &str = "CREATE TABLE replication_log(sequence INTEGER PRIMARY KEY,operation_id TEXT UNIQUE NOT NULL,entry TEXT NOT NULL)";

#[test]
fn typed_capacity_rejects_unexportable_receipt_before_preparing() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let mut batch = stock_entry().batch;
    let mut p = typed::Node::open(
        dir.path().join("p.db"),
        Role::Primary,
        batch.identity.clone(),
        "test-only",
        StockSchema,
    )?;
    batch.operation_id = "x".repeat(sql_snapshot::MAX_ROW_BYTES);
    let result = p.prepare(batch);
    assert!(result.is_err(), "unexportable receipt must not be prepared");
    assert!(p.status()?.entries.is_empty());
    assert!(p.view()?.is_empty());
    Ok(())
}

#[test]
fn typed_capacity_rejects_unexportable_data_and_secondary_stage() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let mut batch = stock_entry().batch;
    let id = batch.identity.clone();
    batch.changes = vec![StockChange::Set {
        sku: "x".repeat(sql_snapshot::MAX_ROW_BYTES),
        quantity: 1,
    }];
    let mut p = typed::Node::open(
        dir.path().join("p.db"),
        Role::Primary,
        id.clone(),
        "test-only",
        StockSchema,
    )?;
    assert!(p.prepare(batch.clone()).is_err());
    assert!(p.view()?.is_empty());
    assert!(p.status()?.entries.is_empty());
    // Construct what a pre-capacity sender could have staged.
    let c = Connection::open_in_memory()?;
    schema::initialize(&c, &StockSchema)?;
    let captured = schema::capture(&c, &StockSchema, &batch.changes)?;
    let mut entry = Entry {
        batch,
        sequence: 1,
        before: captured.before,
        after: captured.after,
        changeset: captured.changeset,
        digest: String::new(),
        state: State::Prepared,
    };
    entry.digest = entry.checksum()?;
    journal::check_entry_size(&entry)?;
    let mut s = typed::Node::open(
        dir.path().join("s.db"),
        Role::Secondary,
        id,
        "test-only",
        StockSchema,
    )?;
    assert!(s.stage(entry).is_err());
    assert!(s.view()?.is_empty());
    assert!(s.status()?.entries.is_empty());
    Ok(())
}

#[test]
fn typed_capacity_matches_snapshot_and_survives_restore_and_retry() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let batch = stock_entry().batch;
    let id = batch.identity.clone();
    let path = dir.path().join("p.db");
    let mut p = typed::Node::open(&path, Role::Primary, id.clone(), "test-only", StockSchema)?;
    let mut s = typed::Node::open(
        dir.path().join("s.db"),
        Role::Secondary,
        id.clone(),
        "test-only",
        StockSchema,
    )?;
    assert_eq!(p.snapshot_capacity()?.receipts, 0);
    commit(&mut p, &mut s, batch.clone())?;
    let capacity = p.snapshot_capacity()?;
    let manifest = p.publish_snapshot()?;
    assert_eq!(capacity.data_rows, manifest.data.rows);
    assert_eq!(capacity.data_bytes, manifest.data.bytes);
    assert_eq!(capacity.receipts, manifest.checkpoint.sequence);
    assert_eq!(capacity.receipt_bytes, manifest.receipt_bytes);
    assert_eq!(capacity, s.snapshot_capacity()?);
    let mut t = typed::Node::open(
        dir.path().join("t.db"),
        Role::Secondary,
        id.clone(),
        "test-only",
        StockSchema,
    )?;
    t.begin_snapshot(&manifest)?;
    for n in 0..manifest.pages {
        t.receive_snapshot(&p.snapshot_page(&manifest, n)?)?;
    }
    t.finish_snapshot(&manifest)?;
    assert_eq!(t.snapshot_capacity()?, capacity);
    recover(&mut p, &mut t)?;
    assert_eq!(commit(&mut p, &mut t, batch)?.sequence, 1);
    assert_eq!(p.snapshot_capacity()?, capacity);
    drop(p);
    let p = typed::Node::open(&path, Role::Primary, id, "test-only", StockSchema)?;
    assert_eq!(p.snapshot_capacity()?, capacity);
    Ok(())
}

#[test]
fn typed_capacity_legacy_prepared_is_blocked_but_decided_can_finish() -> Result<()> {
    let dir = tempfile::tempdir()?;
    for state in [State::Prepared, State::Decided] {
        let path = dir.path().join(format!("legacy-{state:?}.db"));
        let mut entry = stock_entry();
        entry.batch.operation_id = "x".repeat(sql_snapshot::MAX_ROW_BYTES);
        let scratch = Connection::open_in_memory()?;
        schema::initialize(&scratch, &StockSchema)?;
        let captured = schema::capture(&scratch, &StockSchema, &entry.batch.changes)?;
        entry.sequence = 1;
        entry.before = captured.before;
        entry.after = captured.after;
        entry.changeset = captured.changeset;
        entry.digest = entry.checksum()?;
        entry.state = state;
        let id = entry.batch.identity.clone();
        drop(typed::Node::open(
            &path,
            Role::Primary,
            id.clone(),
            "test-only",
            StockSchema,
        )?);
        // Fixture for an on-disk record written by the previous implementation.
        let db = Vesta::open(&path, "test-only")?;
        db.with_connection(|c| Ok(store::write(c, &entry)))??;
        drop(db);
        let mut p = typed::Node::open(&path, Role::Primary, id, "test-only", StockSchema)?;
        if state == State::Prepared {
            assert!(p.prepare(entry.batch.clone()).is_err());
            assert!(p.decide(&entry.batch.operation_id).is_err());
            assert_eq!(p.status()?.entries[0].state, State::Prepared);
            assert!(p.view()?.is_empty());
            p.abort(&entry.batch.operation_id)?;
            assert!(p.status()?.entries.is_empty());
        } else {
            p.apply(entry.clone())?;
            assert_eq!(p.status()?.entries[0].state, State::Applied);
            assert!(p.completed_result(&entry.batch)?.is_some());
            assert!(p.snapshot_capacity().is_err());
        }
    }
    Ok(())
}

#[test]
fn typed_snapshot_restart_frozen_pages_receipts_and_tail() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let batch = stock_entry().batch;
    let id = batch.identity.clone();
    let ppath = dir.path().join("p.db");
    let spath = dir.path().join("s.db");
    let target = dir.path().join("bootstrap.db");
    let mut p = typed::Node::open(&ppath, Role::Primary, id.clone(), "test-only", StockSchema)?;
    let mut s = typed::Node::open(
        &spath,
        Role::Secondary,
        id.clone(),
        "test-only",
        StockSchema,
    )?;
    commit(&mut p, &mut s, batch.clone())?;
    let manifest = p.publish_snapshot()?;
    assert!(manifest.pages >= 2);
    let first = p.snapshot_page(&manifest, 0)?;
    let mut t = typed::Node::open(
        &target,
        Role::Secondary,
        id.clone(),
        "test-only",
        StockSchema,
    )?;
    assert_eq!(t.begin_snapshot(&manifest)?, 0);
    assert!(t.finish_snapshot(&manifest).is_err());
    assert_eq!(t.receive_snapshot(&first)?, 1);
    assert_eq!(t.receive_snapshot(&first)?, 1);
    assert!(t.checkpoint().is_err());
    assert!(t.verified_view().is_err());
    assert!(t.stage(p.status()?.entries[0].clone()).is_err());
    drop(t);
    drop(p);
    let mut p = typed::Node::open(&ppath, Role::Primary, id.clone(), "test-only", StockSchema)?;
    assert_eq!(p.publish_snapshot()?, manifest);
    assert_eq!(p.snapshot_page(&manifest, 0)?, first);
    let mut later = batch.clone();
    later.operation_id = "after-publication".into();
    later.changes = vec![StockChange::Set {
        sku: "b".into(),
        quantity: 8,
    }];
    commit(&mut p, &mut s, later.clone())?;
    assert_eq!(p.publish_snapshot()?, manifest);
    let mut t = typed::Node::open(
        &target,
        Role::Secondary,
        id.clone(),
        "test-only",
        StockSchema,
    )?;
    assert_eq!(t.begin_snapshot(&manifest)?, 1);
    let mut other = manifest.clone();
    other.contract.fingerprint_version += 1;
    assert!(t.begin_snapshot(&other).is_err());
    for n in 1..manifest.pages {
        t.receive_snapshot(&p.snapshot_page(&manifest, n)?)?;
    }
    assert_eq!(t.finish_snapshot(&manifest)?, manifest.checkpoint);
    assert_eq!(t.finish_snapshot(&manifest)?, manifest.checkpoint);
    assert_eq!(t.begin_snapshot(&manifest)?, manifest.pages);
    assert_eq!(
        t.receipt(&batch.operation_id)?,
        p.receipt(&batch.operation_id)?
    );
    assert!(t.verified_view()?.is_none());
    drop(t);
    let mut t = typed::Node::open(&target, Role::Secondary, id, "test-only", StockSchema)?;
    assert_eq!(recover(&mut p, &mut t)?, 1);
    assert_eq!(t.checkpoint()?, p.checkpoint()?);
    assert_eq!(t.verified_view()?, Some(p.view()?));
    assert_eq!(commit(&mut p, &mut t, batch)?.sequence, 1);
    assert_eq!(commit(&mut p, &mut t, later)?.sequence, 2);
    Ok(())
}

#[test]
fn typed_snapshot_bad_receipt_rolls_back_application_and_never_admits() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let batch = stock_entry().batch;
    let id = batch.identity.clone();
    let mut p = typed::Node::open(
        dir.path().join("p.db"),
        Role::Primary,
        id.clone(),
        "test-only",
        StockSchema,
    )?;
    let mut s = typed::Node::open(
        dir.path().join("s.db"),
        Role::Secondary,
        id.clone(),
        "test-only",
        StockSchema,
    )?;
    commit(&mut p, &mut s, batch)?;
    let manifest = p.publish_snapshot()?;
    let path = dir.path().join("t.db");
    let mut t = typed::Node::open(&path, Role::Secondary, id.clone(), "test-only", StockSchema)?;
    t.begin_snapshot(&manifest)?;
    for n in 0..manifest.pages {
        let mut page = p.snapshot_page(&manifest, n)?;
        if let typed::snapshot::Content::Receipts(receipts) = &mut page.content {
            receipts[0].request_digest = "0".repeat(64);
        }
        t.receive_snapshot(&page)?;
    }
    assert!(t.finish_snapshot(&manifest).is_err());
    assert!(t.view()?.is_empty());
    assert!(t.checkpoint().is_err());
    drop(t);
    let mut t = typed::Node::open(&path, Role::Secondary, id, "test-only", StockSchema)?;
    assert!(t.view()?.is_empty());
    assert!(t.finish_snapshot(&manifest).is_err());
    assert!(t.verified_view().is_err());
    // Staged content is immutable, even a corrected retry must not replace it.
    assert!(t
        .receive_snapshot(&p.snapshot_page(&manifest, manifest.pages - 1)?)
        .is_err());
    Ok(())
}
type StockEntry = Entry<StockChange, schema::SchemaId>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) enum StockChange {
    Set { sku: String, quantity: i64 },
}

pub(crate) struct StockSchema;
impl schema::Schema for StockSchema {
    type Change = StockChange;
    type View = Vec<(String, i64)>;
    fn identity(&self) -> schema::SchemaId {
        schema::SchemaId {
            name: "example.inventory".into(),
            version: 1,
        }
    }
    fn tables(&self) -> &'static [&'static str] {
        &["stock"]
    }
    fn initialize(&self, c: &Connection) -> Result<()> {
        c.execute_batch(
            "CREATE TABLE stock(sku TEXT PRIMARY KEY NOT NULL,quantity INTEGER NOT NULL)",
        )?;
        Ok(())
    }
    fn execute(&self, c: &Connection, changes: &[StockChange]) -> Result<()> {
        for StockChange::Set { sku, quantity } in changes {
            c.execute("INSERT INTO stock VALUES(?1,?2) ON CONFLICT(sku) DO UPDATE SET quantity=excluded.quantity", params![sku, quantity])?;
        }
        Ok(())
    }
    fn view(&self, c: &Connection) -> Result<Self::View> {
        Ok(c.prepare("SELECT sku,quantity FROM stock ORDER BY sku")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?)
    }
}
impl schema::RequestSchema for StockSchema {
    const FINGERPRINT_VERSION: u32 = 2;
    fn request_fingerprint(&self, changes: &[StockChange]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"example.inventory-request-v2\0");
        h.update((changes.len() as u64).to_be_bytes());
        for StockChange::Set { sku, quantity } in changes {
            h.update([1]);
            h.update((sku.len() as u64).to_be_bytes());
            h.update(sku.as_bytes());
            h.update(quantity.to_be_bytes());
        }
        h.finalize().into()
    }
}

#[test]
fn typed_receipt_checks_state_content_key_and_adapter_version() -> Result<()> {
    let mut e = stock_entry();
    for state in [State::Prepared, State::Decided] {
        e.state = state;
        assert!(OperationReceipt::from_applied(&StockSchema, &e).is_err());
    }
    e.state = State::Applied;
    let receipt = OperationReceipt::from_applied(&StockSchema, &e)?;
    assert_eq!(receipt.fingerprint_version, 2);
    receipt.matches_request(&StockSchema, &e.batch)?;
    for field in 0..5 {
        let mut invalid = receipt.clone();
        match field {
            0 => invalid.fingerprint_version = 1,
            1 => invalid.result_version = 99,
            2 => invalid.result.sequence = 0,
            3 => invalid.result.operation_id.push('x'),
            _ => invalid.request_digest.push('x'),
        }
        assert!(invalid.matches_request(&StockSchema, &e.batch).is_err());
    }
    let mut changed = e.batch.clone();
    changed.changes.push(StockChange::Set {
        sku: "other".into(),
        quantity: 1,
    });
    assert!(receipt.matches_request(&StockSchema, &changed).is_err());
    for case in 0..3 {
        let mut invalid = e.clone();
        match case {
            0 => invalid.sequence = 0,
            1 => invalid.sequence = u64::MAX,
            _ => invalid.batch.operation_id.clear(),
        }
        invalid.digest = invalid.checksum()?;
        assert!(OperationReceipt::from_applied(&StockSchema, &invalid).is_err());
    }
    e.after.push('x');
    assert!(OperationReceipt::from_applied(&StockSchema, &e).is_err());
    Ok(())
}

#[test]
fn typed_receipts_share_entity_journal_transaction_and_reopen_encrypted() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("stock-receipts.db");
    let db = Vesta::create(&path, "fixture", KdfParams::default())?;
    let result: Result<StockEntry> = db.with_connection(|c| Ok((|| {
        c.pragma_update(None, "synchronous", "FULL")?;
        schema::initialize(c, &StockSchema)?;
        let contract = schema_contract::expected(&StockSchema)?;
        schema_contract::install(c, &StockSchema, &contract)?;
        c.execute_batch(LOG_DDL)?;
        c.execute_batch("CREATE TABLE operation_receipts(operation_id TEXT PRIMARY KEY NOT NULL,sequence INTEGER UNIQUE NOT NULL,receipt TEXT NOT NULL)")?;
        let mut e = stock_entry();
        let captured = schema::capture(c, &StockSchema, &e.batch.changes)?;
        e.before = captured.before.clone();
        e.after = captured.after.clone();
        e.changeset = captured.changeset.clone();
        e.digest = e.checksum()?;
        store::write(c, &e)?;
        assert!(receipts::validate_entry_for(c, &StockSchema, &e)?.is_none());
        let mut applied = e.clone();
        applied.state = State::Applied;
        c.execute_batch("CREATE TRIGGER reject_receipt BEFORE INSERT ON operation_receipts BEGIN SELECT RAISE(ABORT,'fixture'); END")?;
        let tx = c.unchecked_transaction()?;
        schema::replay_in(&tx, &StockSchema, &captured)?;
        store::write(&tx, &applied)?;
        assert!(receipts::insert_for(&tx, &StockSchema, &applied).is_err());
        tx.rollback()?;
        assert!(StockSchema.view(c)?.is_empty());
        assert_eq!(store::by_sequence(c, 1)?, Some(e));
        assert!(receipts::get_for(c, &StockSchema, "restock")?.is_none());
        c.execute_batch("DROP TRIGGER reject_receipt")?;
        let tx = c.unchecked_transaction()?;
        schema::replay_in(&tx, &StockSchema, &captured)?;
        store::write(&tx, &applied)?;
        receipts::insert_for(&tx, &StockSchema, &applied)?;
        // Exact local insert retry is idempotent, not a second acknowledgement.
        receipts::insert_for(&tx, &StockSchema, &applied)?;
        tx.commit()?;
        let mut conflict = applied.clone();
        conflict.sequence = 2;
        conflict.digest = conflict.checksum()?;
        assert!(receipts::insert_for(c, &StockSchema, &conflict).is_err());
        let mut pending = applied.clone();
        pending.state = State::Decided;
        assert!(receipts::validate_entry_for(c, &StockSchema, &pending).is_err());
        let tx = c.unchecked_transaction()?;
        tx.execute("UPDATE operation_receipts SET sequence=2", [])?;
        assert!(receipts::get_for(&tx, &StockSchema, "restock").is_err());
        tx.rollback()?;
        assert!(receipts::validate_entry_for(c, &StockSchema, &applied)?.is_some());
        assert!(receipts::get(c, "restock").is_err(), "legacy V1 must reject V2 receipts");
        Ok(applied)
    })()))?;
    let applied = result?;
    drop(db);
    let reopened = Vesta::open(&path, "fixture")?;
    let checked: Result<()> = reopened.with_connection(|c| {
        Ok((|| {
            schema_contract::verify(c, &StockSchema, &schema_contract::expected(&StockSchema)?)?;
            assert_eq!(StockSchema.view(c)?, vec![("a".into(), 7)]);
            assert_eq!(store::by_sequence(c, 1)?, Some(applied.clone()));
            let receipt = receipts::validate_entry_for(c, &StockSchema, &applied)?
                .ok_or("missing receipt")?;
            receipt.matches_request(&StockSchema, &applied.batch)?;
            assert_eq!(receipt.result.sequence, 1);
            Ok(())
        })())
    })?;
    checked
}

fn stock_history_schema(c: &Connection) -> Result<()> {
    c.pragma_update(None, "foreign_keys", "ON")?;
    schema::initialize(c, &StockSchema)?;
    schema_contract::install(c, &StockSchema, &schema_contract::expected(&StockSchema)?)?;
    c.execute_batch(LOG_DDL)?;
    c.execute_batch("CREATE TABLE operation_receipts(operation_id TEXT PRIMARY KEY NOT NULL,sequence INTEGER UNIQUE NOT NULL,receipt TEXT NOT NULL);
        CREATE TABLE replication_base(id INTEGER PRIMARY KEY CHECK(id=1),checkpoint TEXT NOT NULL)")?;
    Ok(())
}

#[test]
fn typed_nodes_share_commit_recovery_and_preserve_exact_retry_after_restart() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let identity = stock_entry().batch.identity;
    let mut p = typed::Node::open(
        dir.path().join("p"),
        Role::Primary,
        identity.clone(),
        "fixture",
        StockSchema,
    )?;
    let mut s = typed::Node::open(
        dir.path().join("s"),
        Role::Secondary,
        identity.clone(),
        "fixture",
        StockSchema,
    )?;
    assert!(s.verified_view()?.is_none());
    let request = stock_entry().batch;
    let result = commit(&mut p, &mut s, request.clone())?;
    assert_eq!(result.sequence, 1);
    assert_eq!(p.view()?, vec![("a".into(), 7)]);
    assert_eq!(s.verified_view()?, Some(p.view()?));
    assert_eq!(p.receipt("restock")?, s.receipt("restock")?);
    drop(p);
    drop(s);
    let mut p = typed::Node::open(
        dir.path().join("p"),
        Role::Primary,
        identity.clone(),
        "fixture",
        StockSchema,
    )?;
    let mut s = typed::Node::open(
        dir.path().join("s"),
        Role::Secondary,
        identity.clone(),
        "fixture",
        StockSchema,
    )?;
    assert_eq!(commit(&mut p, &mut s, request.clone())?, result);
    let mut conflict = request.clone();
    conflict.changes = vec![StockChange::Set {
        sku: "a".into(),
        quantity: 99,
    }];
    assert!(commit(&mut p, &mut s, conflict).is_err());
    let mut next = request;
    next.operation_id = "second".into();
    next.changes = vec![StockChange::Set {
        sku: "b".into(),
        quantity: 8,
    }];
    s.stage(p.prepare(next.clone())?)?;
    let decision = p.decide("second")?;
    s.apply(decision)?; // Simulate lost apply ACK before primary applies.
    drop(p);
    drop(s);
    let mut p = typed::Node::open(
        dir.path().join("p"),
        Role::Primary,
        identity.clone(),
        "fixture",
        StockSchema,
    )?;
    let mut s = typed::Node::open(
        dir.path().join("s"),
        Role::Secondary,
        identity.clone(),
        "fixture",
        StockSchema,
    )?;
    assert_eq!(recover(&mut p, &mut s)?, 1);
    assert_eq!(commit(&mut p, &mut s, next)?.sequence, 2);
    assert_eq!(p.checkpoint()?, s.checkpoint()?);
    assert_eq!(p.view()?, vec![("a".into(), 7), ("b".into(), 8)]);
    Ok(())
}

#[test]
fn typed_nodes_reject_wrong_owner_and_abort_only_uncommitted_tail() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let identity = stock_entry().batch.identity;
    let path = dir.path().join("p");
    let mut p = typed::Node::open(
        &path,
        Role::Primary,
        identity.clone(),
        "fixture",
        StockSchema,
    )?;
    let mut s = typed::Node::open(
        dir.path().join("s"),
        Role::Secondary,
        identity.clone(),
        "fixture",
        StockSchema,
    )?;
    assert!(typed::Node::open(
        &path,
        Role::Primary,
        identity.clone(),
        "fixture",
        StockSchema
    )
    .is_err());
    s.stage(p.prepare(stock_entry().batch)?)?;
    assert_eq!(recover(&mut p, &mut s)?, 0);
    assert!(p.status()?.entries.is_empty());
    assert!(s.status()?.entries.is_empty());
    assert_eq!(commit(&mut p, &mut s, stock_entry().batch)?.sequence, 1);
    assert!(p.abort("restock").is_err());
    assert!(s.abort("restock").is_err());
    drop(p);
    let mut wrong = identity.clone();
    wrong.tenant.push('x');
    assert!(typed::Node::open(&path, Role::Primary, wrong, "fixture", StockSchema).is_err());
    assert!(typed::Node::open(&path, Role::Secondary, identity, "fixture", StockSchema).is_err());
    Ok(())
}

fn stock_history() -> Result<Vec<StockEntry>> {
    let c = Connection::open_in_memory()?;
    stock_history_schema(&c)?;
    let mut history = Vec::new();
    for sequence in 1..=2 {
        let mut e = stock_entry();
        e.sequence = sequence;
        e.batch.operation_id = format!("restock-{sequence}");
        e.batch.changes = vec![StockChange::Set {
            sku: "a".into(),
            quantity: sequence as i64 * 7,
        }];
        let captured = schema::capture(&c, &StockSchema, &e.batch.changes)?;
        e.before = captured.before.clone();
        e.after = captured.after.clone();
        e.changeset = captured.changeset.clone();
        e.state = State::Applied;
        e.digest = e.checksum()?;
        schema::replay(&c, &StockSchema, &captured)?;
        history.push(e);
    }
    Ok(history)
}

#[test]
fn typed_history_restore_commits_receipts_and_checkpoint_then_reopens() -> Result<()> {
    let history = stock_history()?;
    let identity = history[0].batch.identity.clone();
    let initial = hash(&Vec::<(String, i64)>::new())?;
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("typed-restore.db");
    let db = Vesta::create(&path, "fixture", KdfParams::default())?;
    let result: Result<Checkpoint<schema::SchemaId>> = db.with_connection(|c| Ok((|| {
        c.pragma_update(None, "synchronous", "FULL")?;
        stock_history_schema(c)?;
        // Failure at the last receipt must roll back the complete restored history.
        c.execute_batch("CREATE TRIGGER fail_last_receipt BEFORE INSERT ON operation_receipts WHEN NEW.sequence=2 BEGIN SELECT RAISE(ABORT,'fixture'); END")?;
        let tx = c.unchecked_transaction()?;
        assert!(journal::replay_history_in(&tx, &StockSchema, &identity, &history).is_err());
        tx.rollback()?;
        assert!(StockSchema.view(c)?.is_empty());
        assert!(store::all::<StockChange, schema::SchemaId>(c)?.is_empty());
        assert_eq!(receipts::count(c)?, 0);
        c.execute_batch("DROP TRIGGER fail_last_receipt")?;
        let tx = c.unchecked_transaction()?;
        journal::replay_history_in(&tx, &StockSchema, &identity, &history)?;
        let (checkpoint, view) = checkpoint::current_for(&tx, &StockSchema, &identity, &initial, true)?;
        assert_eq!(view, vec![("a".into(), 14)]);
        assert_eq!(checkpoint.sequence, 2);
        let expected_receipts = history.iter().map(|e| OperationReceipt::from_applied(&StockSchema, e)).collect::<Result<Vec<_>>>()?;
        assert_eq!(checkpoint.receipt_digest, hash(&expected_receipts)?);
        tx.execute_batch("CREATE TABLE published_receipts AS SELECT * FROM operation_receipts")?;
        assert_eq!(checkpoint::receipt_digest_from_for(&tx, &StockSchema, 2, true)?, checkpoint.receipt_digest);
        // Independent spelling of the retained format-1 chain encoding.
        let mut digest = hash(&("proximiio-journal-chain-v1", &identity))?;
        for e in &history { digest = hash(&("proximiio-journal-link-v1", digest, &e.digest))?; }
        assert_eq!(checkpoint.journal_digest, digest);
        tx.commit()?;
        assert!(checkpoint::receipt_digest_from(c, 2, false).is_err(), "reference V1 must reject V2 receipts");
        Ok(checkpoint)
    })()))?;
    let expected = result?;
    drop(db);
    let reopened = Vesta::open(&path, "fixture")?;
    let result: Result<()> = reopened.with_connection(|c| {
        Ok((|| {
            schema_contract::verify(c, &StockSchema, &schema_contract::expected(&StockSchema)?)?;
            assert_eq!(
                checkpoint::current_for(c, &StockSchema, &identity, &initial, true)?.0,
                expected
            );
            assert_eq!(store::all::<StockChange, schema::SchemaId>(c)?, history);
            // A typed base can anchor compacted history without discarding receipts.
            c.execute(
                "INSERT INTO replication_base VALUES(1,?1)",
                [serde_json::to_string(&expected)?],
            )?;
            c.execute("DELETE FROM replication_log", [])?;
            assert_eq!(
                checkpoint::current_for(c, &StockSchema, &identity, &initial, true)?.0,
                expected
            );
            assert!(
                checkpoint::calculate_for(c, &StockSchema, &identity, &initial, true, Some(1))
                    .is_err()
            );
            let mut wrong = identity.clone();
            wrong.tenant.push('x');
            assert!(checkpoint::current_for(c, &StockSchema, &wrong, &initial, true).is_err());
            c.execute("UPDATE stock SET quantity=99", [])?;
            assert!(checkpoint::current_for(c, &StockSchema, &identity, &initial, true).is_err());
            Ok(())
        })())
    })?;
    result
}

#[test]
fn typed_history_rejects_corruption_and_incomplete_receipt_chains() -> Result<()> {
    let history = stock_history()?;
    let identity = history[0].batch.identity.clone();
    let initial = hash(&Vec::<(String, i64)>::new())?;
    let c = Connection::open_in_memory()?;
    stock_history_schema(&c)?;
    for case in 0..7 {
        let mut bad = history.clone();
        match case {
            0 => bad[1].batch.identity.tenant.push('x'),
            1 => bad[1].sequence = 3,
            2 => bad[1].state = State::Decided,
            3 => bad[1].before.push('x'),
            4 => bad[1].after.push('x'),
            5 => bad[1].batch.operation_id = bad[0].batch.operation_id.clone(),
            _ => bad[1].changeset.clear(),
        }
        bad[1].digest = bad[1].checksum()?;
        let tx = c.unchecked_transaction()?;
        assert!(
            journal::replay_history_in(&tx, &StockSchema, &identity, &bad).is_err(),
            "case {case}"
        );
        tx.rollback()?;
        assert!(StockSchema.view(&c)?.is_empty());
        assert_eq!(receipts::count(&c)?, 0);
    }
    let tx = c.unchecked_transaction()?;
    journal::replay_history_in(&tx, &StockSchema, &identity, &history)?;
    tx.commit()?;
    for sql in [
        "DELETE FROM operation_receipts WHERE sequence=2",
        "UPDATE operation_receipts SET receipt=json_set(receipt,'$.fingerprint_version',1) WHERE sequence=2",
        "UPDATE operation_receipts SET operation_id='other' WHERE sequence=2",
        "UPDATE replication_log SET entry=json_set(entry,'$.state','Prepared') WHERE sequence=1",
        "INSERT INTO operation_receipts VALUES('orphan',3,'{}')",
    ] {
        let tx = c.unchecked_transaction()?;
        tx.execute_batch(sql)?;
        assert!(checkpoint::current_for(&tx, &StockSchema, &identity, &initial, true).is_err(), "{sql}");
        tx.rollback()?;
    }
    assert!(
        checkpoint::calculate_for(&c, &StockSchema, &identity, &initial, true, Some(3)).is_err()
    );
    assert!(checkpoint::receipt_digest_from_for(&c, &StockSchema, u64::MAX, false).is_err());
    Ok(())
}

#[test]
fn typed_checkpoint_distinguishes_pending_tail_from_applied_prefix() -> Result<()> {
    let history = stock_history()?;
    let identity = history[0].batch.identity.clone();
    let initial = hash(&Vec::<(String, i64)>::new())?;
    let c = Connection::open_in_memory()?;
    stock_history_schema(&c)?;
    let tx = c.unchecked_transaction()?;
    journal::replay_history_in(&tx, &StockSchema, &identity, &history)?;
    tx.commit()?;
    let expected = checkpoint::current_for(&c, &StockSchema, &identity, &initial, true)?.0;
    let mut pending = stock_entry();
    pending.sequence = 3;
    pending.batch.operation_id = "pending".into();
    pending.batch.changes = vec![StockChange::Set {
        sku: "a".into(),
        quantity: 21,
    }];
    let captured = schema::capture(&c, &StockSchema, &pending.batch.changes)?;
    pending.before = captured.before;
    pending.after = captured.after;
    pending.changeset = captured.changeset;
    pending.digest = pending.checksum()?;
    for state in [State::Prepared, State::Decided] {
        pending.state = state;
        store::write(&c, &pending)?;
        assert_eq!(
            checkpoint::current_for(&c, &StockSchema, &identity, &initial, false)?.0,
            expected
        );
        assert!(checkpoint::current_for(&c, &StockSchema, &identity, &initial, true).is_err());
        assert_eq!(
            checkpoint::calculate_for(&c, &StockSchema, &identity, &initial, true, Some(2))?,
            expected
        );
        assert!(
            checkpoint::calculate_for(&c, &StockSchema, &identity, &initial, true, Some(3))
                .is_err()
        );
    }
    let mut later = pending.clone();
    later.sequence = 4;
    later.batch.operation_id = "later".into();
    later.digest = later.checksum()?;
    store::write(&c, &later)?;
    assert!(checkpoint::current_for(&c, &StockSchema, &identity, &initial, false).is_err());
    Ok(())
}

pub(crate) fn stock_entry() -> Entry<StockChange, schema::SchemaId> {
    let mut e = Entry {
        batch: Batch {
            identity: Identity {
                cluster: "pair".into(),
                tenant: "inventory".into(),
                epoch: 3,
                schema: schema::SchemaId {
                    name: "example.inventory".into(),
                    version: 1,
                },
            },
            operation_id: "restock".into(),
            changes: vec![StockChange::Set {
                sku: "a".into(),
                quantity: 7,
            }],
        },
        sequence: 1,
        before: "before".into(),
        after: "after".into(),
        changeset: vec![0, 255],
        digest: String::new(),
        state: State::Prepared,
    };
    e.digest = e.checksum().unwrap();
    e
}

#[test]
fn legacy_envelope_bytes_and_digest_remain_exact() -> Result<()> {
    let checkpoint_json = r#"{"format":1,"identity":{"cluster":"pair","tenant":"tenant","epoch":1,"schema":1},"sequence":1,"view_digest":"view","journal_digest":"journal","receipt_digest":"receipt"}"#;
    let checkpoint: Checkpoint = serde_json::from_str(checkpoint_json)?;
    assert_eq!(serde_json::to_string(&checkpoint)?, checkpoint_json);
    let json = r#"{"batch":{"identity":{"cluster":"pair","tenant":"tenant","epoch":1,"schema":1},"operation_id":"op","changes":[{"PutPlace":{"id":"a","name":"A"}}]},"sequence":1,"before":"before","after":"after","changeset":[0,255],"digest":"59fb07e5d6323fa0b8fbc213096c1638f80b2d0dd9f56f46756960cbaea44102","state":"Prepared"}"#;
    let e: Entry = serde_json::from_str(json)?;
    assert_eq!(serde_json::to_string(&e)?, json);
    e.validate(&Identity {
        cluster: "pair".into(),
        tenant: "tenant".into(),
        epoch: 1,
        schema: 1,
    })?;
    assert_eq!(e.checksum()?, e.digest);
    let mut applied = e.clone();
    applied.state = State::Applied;
    let receipt = OperationReceipt::from_applied(&reference::Proximi, &applied)?;
    assert_eq!(
        serde_json::to_string(&receipt)?,
        r#"{"fingerprint_version":1,"request_digest":"10ab126b2c8ccfcc695cd1b7a6f5afc8c48c29ea17fd7b00ff68c6fb97ee0d30","result_version":1,"result":{"operation_id":"op","sequence":1}}"#
    );
    // The runtime, not the checksum, enforces legal transitions. This remains
    // unchanged: one content digest identifies Prepared/Decided/Applied states.
    for state in [State::Decided, State::Applied] {
        let mut transitioned = e.clone();
        transitioned.state = state;
        assert_eq!(transitioned.checksum()?, e.digest);
    }
    Ok(())
}

#[test]
fn typed_envelope_checks_scope_and_all_content_fields() -> Result<()> {
    let e = stock_entry();
    let identity = e.batch.identity.clone();
    e.validate(&identity)?;
    let json = serde_json::to_vec(&e)?;
    assert_eq!(
        serde_json::from_slice::<Entry<StockChange, schema::SchemaId>>(&json)?,
        e
    );
    assert!(serde_json::from_slice::<Entry>(&json).is_err());
    for field in 0..5 {
        let mut other = identity.clone();
        match field {
            0 => other.cluster.push('x'),
            1 => other.tenant.push('x'),
            2 => other.epoch += 1,
            3 => other.schema.name.push('x'),
            _ => other.schema.version += 1,
        }
        assert!(e.validate(&other).is_err());
    }
    for field in 0..7 {
        let mut changed = e.clone();
        match field {
            0 => changed.batch.operation_id.push('x'),
            1 => changed.batch.changes.push(StockChange::Set {
                sku: "b".into(),
                quantity: 2,
            }),
            2 => changed.sequence += 1,
            3 => changed.before.push('x'),
            4 => changed.after.push('x'),
            5 => changed.changeset.push(1),
            _ => changed.digest.push('x'),
        }
        assert!(changed.validate(&identity).is_err());
    }
    Ok(())
}

#[test]
fn typed_envelope_survives_encrypted_storage_reopen() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("inventory.db");
    let expected = stock_entry();
    let db = Vesta::create(&path, "test-only", KdfParams::default())?;
    db.with_connection(|c| {
        c.pragma_update(None, "synchronous", "FULL")?;
        c.execute_batch(LOG_DDL)?;
        Ok(store::write(c, &expected))
    })??;
    drop(db);
    let reopened = Vesta::open(&path, "test-only")?;
    let actual: StockEntry = reopened
        .with_connection(|c| Ok(store::by_sequence(c, 1)))??
        .ok_or("missing entry after reopen")?;
    actual.validate(&expected.batch.identity)?;
    assert_eq!(actual, expected);
    // This proves envelope storage compatibility, not a generic durable Node or
    // a valid changeset: the byte payload above is intentionally a wire fixture.
    Ok(())
}

#[test]
fn typed_journal_lookup_conflicts_and_transaction_rollback() -> Result<()> {
    let c = Connection::open_in_memory()?;
    c.execute_batch(LOG_DDL)?;
    let e = stock_entry();
    assert!(store::by_operation::<StockChange, schema::SchemaId>(&c, "absent")?.is_none());
    assert!(store::by_sequence::<StockChange, schema::SchemaId>(&c, 1)?.is_none());
    assert!(store::tail::<StockChange, schema::SchemaId>(&c)?.is_none());
    store::write(&c, &e)?;
    let mut later = e.clone();
    later.sequence = 2;
    later.batch.operation_id = "later".into();
    later.digest = later.checksum()?;
    let tx = c.unchecked_transaction()?;
    store::write(&tx, &later)?;
    let mut decided = e.clone();
    decided.state = State::Decided;
    store::write(&tx, &decided)?;
    assert_eq!(store::all(&tx)?, vec![decided, later.clone()]);
    tx.rollback()?;
    assert_eq!(store::all(&c)?, vec![e.clone()]);
    assert_eq!(store::tail(&c)?, Some(e.clone()));
    assert_eq!(store::by_operation(&c, "restock")?, Some(e.clone()));
    assert_eq!(store::by_sequence(&c, 1)?, Some(e.clone()));
    // Same sequence must never rewrite another operation's metadata.
    later.sequence = 1;
    later.digest = later.checksum()?;
    assert!(store::write(&c, &later).is_err());
    // Same operation ID cannot be inserted under a different sequence either.
    later.sequence = 2;
    later.batch.operation_id = e.batch.operation_id.clone();
    later.digest = later.checksum()?;
    assert!(store::write(&c, &later).is_err());
    assert_eq!(store::all(&c)?, vec![e]);
    Ok(())
}

#[test]
fn typed_journal_rejects_corrupt_keys_json_and_content() -> Result<()> {
    for sql in [
        "UPDATE replication_log SET sequence=2",
        "UPDATE replication_log SET sequence=0",
        "UPDATE replication_log SET operation_id='other'",
        "UPDATE replication_log SET entry='{'",
        "UPDATE replication_log SET entry=json_set(entry,'$.after','tampered')",
    ] {
        let c = Connection::open_in_memory()?;
        c.execute_batch(LOG_DDL)?;
        store::write(&c, &stock_entry())?;
        c.execute_batch(sql)?;
        let (sequence, id): (u64, String) = c.query_row(
            "SELECT sequence,operation_id FROM replication_log",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        assert!(
            store::by_operation::<StockChange, schema::SchemaId>(&c, &id).is_err(),
            "{sql}"
        );
        assert!(
            store::by_sequence::<StockChange, schema::SchemaId>(&c, sequence).is_err(),
            "{sql}"
        );
        assert!(
            store::tail::<StockChange, schema::SchemaId>(&c).is_err(),
            "{sql}"
        );
        assert!(
            store::all::<StockChange, schema::SchemaId>(&c).is_err(),
            "{sql}"
        );
    }
    Ok(())
}

#[test]
fn typed_journal_rejects_invalid_write_without_mutation() -> Result<()> {
    let c = Connection::open_in_memory()?;
    c.execute_batch(LOG_DDL)?;
    for case in 0..4 {
        let mut e = stock_entry();
        match case {
            0 => e.sequence = 0,
            1 => e.sequence = u64::MAX,
            2 => e.batch.operation_id.clear(),
            _ => e.after.push('x'),
        }
        if case < 3 {
            e.digest = e.checksum()?;
        }
        assert!(store::write(&c, &e).is_err());
    }
    assert!(store::all::<StockChange, schema::SchemaId>(&c)?.is_empty());
    // A matching checksum must not make an invalid persisted key acceptable.
    let mut invalid = stock_entry();
    invalid.batch.operation_id.clear();
    invalid.digest = invalid.checksum()?;
    c.execute(
        "INSERT INTO replication_log VALUES(1,'',?1)",
        [serde_json::to_string(&invalid)?],
    )?;
    assert!(store::by_operation::<StockChange, schema::SchemaId>(&c, "").is_err());
    assert!(store::all::<StockChange, schema::SchemaId>(&c).is_err());
    Ok(())
}
