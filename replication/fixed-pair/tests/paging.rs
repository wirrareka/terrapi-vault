use terrapi_vesta_replication::{journal::*, *};

fn identity() -> Identity {
    Identity {
        cluster: "test".into(),
        tenant: "one".into(),
        epoch: 1,
        schema: 1,
    }
}
fn batch(id: &str) -> Batch {
    Batch {
        identity: identity(),
        operation_id: id.into(),
        changes: vec![Change::PutPlace {
            id: "one".into(),
            name: id.into(),
        }],
    }
}

#[test]
fn pages_are_ordered_bounded_and_bound_to_durable_revision() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = Node::open(dir.path().join("p"), Role::Primary, identity(), "fixture").unwrap();
    let empty = p.journal_head().unwrap();
    assert!(p.journal_page(&empty, 0, 2).unwrap().entries.is_empty());
    p.prepare(batch("one")).unwrap();
    assert!(p.journal_page(&empty, 0, 2).is_err());
    let prepared = p.journal_head().unwrap();
    let page = p.journal_page(&prepared, 0, 1).unwrap();
    page.validate(&prepared, 0, 1).unwrap();
    assert_eq!(page.entries[0].sequence, 1);
    assert!(p.journal_page(&prepared, 0, 0).is_err());
    assert!(p.journal_page(&prepared, 0, MAX_PAGE_ENTRIES + 1).is_err());
    assert!(p.journal_page(&prepared, 2, 1).is_err());
    let e = p.decide("one").unwrap();
    assert!(p.journal_page(&prepared, 0, 1).is_err());
    p.apply(e).unwrap();
    let applied = p.journal_head().unwrap();
    drop(p);
    let p = Node::open(dir.path().join("p"), Role::Primary, identity(), "fixture").unwrap();
    assert_eq!(p.journal_head().unwrap(), applied);
    assert!(p.journal_page(&prepared, 0, 1).is_err());
}

#[test]
fn abort_recreate_and_quarantine_invalidate_old_cursors() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = Node::open(dir.path().join("p"), Role::Primary, identity(), "fixture").unwrap();
    let mut s = Node::open(dir.path().join("s"), Role::Secondary, identity(), "fixture").unwrap();
    let first = p.prepare(batch("one")).unwrap();
    let old = p.journal_head().unwrap();
    p.abort("one").unwrap();
    assert_eq!(p.prepare(batch("one")).unwrap(), first);
    assert!(p.journal_page(&old, 0, 1).is_err());
    let empty = s.journal_head().unwrap();
    s.quarantine().unwrap();
    assert!(s.journal_page(&empty, 0, 1).is_err());
}

#[test]
fn page_validation_rejects_substitution_gaps_and_early_end() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = Node::open(dir.path().join("p"), Role::Primary, identity(), "fixture").unwrap();
    p.prepare(batch("one")).unwrap();
    let head = p.journal_head().unwrap();
    let page = p.journal_page(&head, 0, 1).unwrap();
    for case in 0..6 {
        let mut bad = page.clone();
        match case {
            0 => bad.head.identity.tenant = "other".into(),
            1 => bad.head.revision[0] ^= 1,
            2 => bad.after = 1,
            3 => bad.entries.clear(),
            4 => bad.entries[0].sequence = 2,
            _ => bad.entries[0].digest = "bad".into(),
        }
        assert!(bad.validate(&head, 0, 1).is_err());
    }
}

struct PagedOnly {
    node: Node,
    poison: bool,
    calls: usize,
    contract_override: Option<schema_contract::Contract>,
}
impl Replica for PagedOnly {
    fn summary(&mut self) -> Result<Summary> {
        let mut summary = self.node.summary()?;
        if let Some(contract) = &self.contract_override {
            summary.schema_contract = contract.clone();
        }
        Ok(summary)
    }
    fn journal_page(&mut self, head: &JournalHead, after: u64, limit: u32) -> Result<JournalPage> {
        self.calls += 1;
        let mut page = self.node.journal_page(head, after, limit)?;
        if self.poison && after >= MAX_PAGE_ENTRIES as u64 {
            page.entries.clear();
        }
        Ok(page)
    }
    fn status(&mut self) -> Result<Status> {
        panic!("recovery must not load full status")
    }
    fn view(&mut self) -> Result<View> {
        panic!("recovery must not transfer full view")
    }
    fn confirm_checkpoint(&mut self, c: Checkpoint) -> Result<()> {
        self.node.confirm_checkpoint(c)
    }
    fn stage(&mut self, e: Entry) -> Result<()> {
        self.node.stage(e)
    }
    fn apply(&mut self, e: Entry) -> Result<()> {
        self.node.apply(e)
    }
    fn abort(&mut self, id: &str) -> Result<()> {
        self.node.abort(id)
    }
}

#[test]
fn malformed_later_page_fails_before_mutation_then_retry_recovers() {
    use sha2::{Digest, Sha256};
    let dir = tempfile::tempdir().unwrap();
    let mut p = Node::open(dir.path().join("p"), Role::Primary, identity(), "fixture").unwrap();
    let mut s = Node::open(dir.path().join("s"), Role::Secondary, identity(), "fixture").unwrap();
    for i in 0..40 {
        let b = batch(&format!("op-{i}"));
        s.stage(p.prepare(b.clone()).unwrap()).unwrap();
        let e = p.decide(&b.operation_id).unwrap();
        s.apply(e.clone()).unwrap();
        p.apply(e).unwrap();
    }
    let before = s.journal_head().unwrap();
    p.prepare(batch("decided-before-failure")).unwrap();
    p.decide("decided-before-failure").unwrap();
    let primary_before = p.journal_head().unwrap();
    let mut peer = PagedOnly {
        node: s,
        poison: true,
        calls: 0,
        contract_override: None,
    };
    assert!(recover(&mut p, &mut peer).is_err());
    assert_eq!(peer.calls, 2);
    assert_eq!(p.journal_head().unwrap(), primary_before);
    assert_eq!(peer.node.journal_head().unwrap(), before);
    assert!(peer.node.verified_view().unwrap().is_none());
    peer.poison = false;
    assert_eq!(recover(&mut p, &mut peer).unwrap(), 1);
    // Checkpoint format 1 is a resumable chain, independently recomputed here.
    let mut expected = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&("proximiio-journal-chain-v1", identity())).unwrap())
    );
    for e in p.status().unwrap().entries {
        expected = format!(
            "{:x}",
            Sha256::digest(
                serde_json::to_vec(&("proximiio-journal-link-v1", &expected, &e.digest)).unwrap()
            )
        );
    }
    assert_eq!(p.checkpoint().unwrap().format, 1);
    assert_eq!(p.checkpoint().unwrap().journal_digest, expected);
    assert_eq!(peer.node.verified_view().unwrap(), Some(p.view().unwrap()));
    p.prepare(batch("tail")).unwrap();
    p.decide("tail").unwrap();
    assert_eq!(recover(&mut p, &mut peer).unwrap(), 1);
}

#[test]
fn schema_mismatch_blocks_recovery_before_journal_or_mutation() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let mut p = Node::open(dir.path().join("p"), Role::Primary, identity(), "fixture")?;
    let s = Node::open(dir.path().join("s"), Role::Secondary, identity(), "fixture")?;
    p.prepare(batch("pending"))?;
    p.decide("pending")?;
    let primary_before = p.journal_head()?;
    let secondary_before = s.journal_head()?;
    let contract = p.schema_contract()?;
    let mut peer = PagedOnly {
        node: s,
        poison: false,
        calls: 0,
        contract_override: None,
    };
    for field in 0..5 {
        let mut wrong = contract.clone();
        match field {
            0 => wrong.format += 1,
            1 => wrong.schema.name.push('x'),
            2 => wrong.schema.version += 1,
            3 => wrong.fingerprint_version += 1,
            _ => wrong.catalog_digest.push('x'),
        }
        peer.contract_override = Some(wrong);
        assert_eq!(
            recover(&mut p, &mut peer).unwrap_err().to_string(),
            "replica schema contract mismatch"
        );
        assert_eq!(peer.calls, 0);
        assert_eq!(p.journal_head()?, primary_before);
        assert_eq!(peer.node.journal_head()?, secondary_before);
        assert!(peer.node.receipt("pending")?.is_none());
    }
    peer.contract_override = None;
    assert_eq!(recover(&mut p, &mut peer)?, 1);
    assert_eq!(p.view()?, peer.node.view()?);
    assert_eq!(p.receipt("pending")?, peer.node.receipt("pending")?);
    let mut legacy = serde_json::to_value(peer.node.summary()?)?;
    legacy.as_object_mut().unwrap().remove("schema_contract");
    assert!(serde_json::from_value::<Summary>(legacy).is_err());
    Ok(())
}

#[test]
fn oversized_entry_is_rejected_before_persisting_prepare() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = Node::open(dir.path().join("p"), Role::Primary, identity(), "fixture").unwrap();
    let head = p.journal_head().unwrap();
    let b = Batch {
        identity: identity(),
        operation_id: "x".repeat(MAX_PAGE_BYTES),
        changes: vec![],
    };
    assert!(p.prepare(b).is_err());
    assert_eq!(p.journal_head().unwrap(), head);
    assert!(p.view().unwrap().places.is_empty());
}
