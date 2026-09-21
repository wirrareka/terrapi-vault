use super::*;
use crate::envelope_tests::{stock_entry, StockChange, StockSchema};
use std::{cell::Cell, rc::Rc, time::Instant};

struct Counted(Rc<Cell<u64>>);
impl Schema for Counted {
    type Change = <StockSchema as Schema>::Change;
    type View = <StockSchema as Schema>::View;
    fn identity(&self) -> SchemaId {
        StockSchema.identity()
    }
    fn tables(&self) -> &'static [&'static str] {
        StockSchema.tables()
    }
    fn initialize(&self, c: &Connection) -> Result<()> {
        StockSchema.initialize(c)
    }
    fn execute(&self, c: &Connection, changes: &[Self::Change]) -> Result<()> {
        StockSchema.execute(c, changes)
    }
    fn view(&self, c: &Connection) -> Result<Self::View> {
        self.0.set(self.0.get() + 1);
        StockSchema.view(c)
    }
}
impl RequestSchema for Counted {
    const FINGERPRINT_VERSION: u32 = StockSchema::FINGERPRINT_VERSION;
    fn request_fingerprint(&self, changes: &[Self::Change]) -> [u8; 32] {
        StockSchema.request_fingerprint(changes)
    }
}

fn measure<T>(phase: &str, views: &Cell<u64>, f: impl FnOnce() -> Result<T>) -> Result<T> {
    views.set(0);
    let start = Instant::now();
    let result = f()?;
    println!(
        "phase={phase} elapsed_us={} view_calls={}",
        start.elapsed().as_micros(),
        views.get()
    );
    Ok(result)
}

fn scenario(rows: usize, history: usize) -> Result<()> {
    ensure(
        (1..=10_000).contains(&rows) && (1..=100).contains(&history),
        "profile fixture bounds",
    )?;
    let dir = tempfile::tempdir()?;
    let views = Rc::new(Cell::new(0));
    let mut batch = stock_entry().batch;
    let id = batch.identity.clone();
    let mut p = Node::open(
        dir.path().join("p"),
        Role::Primary,
        id.clone(),
        "fixture",
        Counted(views.clone()),
    )?;
    let mut s = Node::open(
        dir.path().join("s"),
        Role::Secondary,
        id.clone(),
        "fixture",
        Counted(views.clone()),
    )?;
    batch.changes = (0..rows)
        .map(|n| StockChange::Set {
            sku: format!("item-{n:05}"),
            quantity: 0,
        })
        .collect();
    commit(&mut p, &mut s, batch.clone())?;
    for n in 1..history {
        batch.operation_id = format!("history-{n}");
        batch.changes = vec![StockChange::Set {
            sku: "item-00000".into(),
            quantity: n as i64,
        }];
        commit(&mut p, &mut s, batch.clone())?;
    }
    println!(
        "profile rows={rows} receipts_before_write={history} transport=local build_debug={}",
        cfg!(debug_assertions)
    );
    let expected = p.checkpoint()?;
    // Diagnostic components only: neither measurement replaces live-state admission.
    let journal = measure("journal_validation", &views, || {
        p.connection(|c| {
            checkpoint::calculate_for(c, &p.adapter, &p.identity, &p.initial, true, None)
        })
    })?;
    assert_eq!(journal, expected);
    assert_eq!(views.get(), 0);
    let view_digest = measure("view_and_hash", &views, || hash(&p.view()?))?;
    assert_eq!(view_digest, expected.view_digest);
    assert_eq!(views.get(), 1);
    for _ in 0..3 {
        let actual = measure("checkpoint", &views, || p.checkpoint())?;
        assert_eq!(actual, expected);
        assert_eq!(views.get(), 1);
    }
    batch.operation_id = "measured-write".into();
    batch.changes = vec![StockChange::Set {
        sku: "item-00000".into(),
        quantity: 999,
    }];
    measure("two_copy_commit", &views, || {
        commit(&mut p, &mut s, batch.clone())
    })?;
    let checkpoint = p.checkpoint()?;
    assert_eq!(checkpoint.sequence, history as u64 + 1);
    assert_eq!(checkpoint, s.checkpoint()?);
    let manifest = measure("publish_snapshot", &views, || p.publish_snapshot())?;
    assert_eq!(manifest.checkpoint, checkpoint);
    assert_eq!(manifest.data.rows, rows as u64);
    let mut target = Node::open(
        dir.path().join("target"),
        Role::Secondary,
        id,
        "fixture",
        Counted(views.clone()),
    )?;
    measure("restore_snapshot", &views, || {
        target.begin_snapshot(&manifest)?;
        for n in 0..manifest.pages {
            target.receive_snapshot(&p.snapshot_page(&manifest, n)?)?;
        }
        target.finish_snapshot(&manifest)?;
        Ok(())
    })?;
    assert_eq!(target.checkpoint()?, checkpoint);
    assert_eq!(target.view()?, p.view()?);
    assert_eq!(
        target.receipt("measured-write")?,
        p.receipt("measured-write")?
    );
    Ok(())
}

#[test]
fn tenant_profile_scenario_preserves_checkpoint_and_restore() -> Result<()> {
    scenario(3, 2)
}

#[test]
#[ignore = "manual tenant profile; requires VESTA_PROFILE_ROWS and VESTA_PROFILE_HISTORY"]
fn profile_tenant_pair() -> Result<()> {
    scenario(
        std::env::var("VESTA_PROFILE_ROWS")?.parse()?,
        std::env::var("VESTA_PROFILE_HISTORY")?.parse()?,
    )
}
