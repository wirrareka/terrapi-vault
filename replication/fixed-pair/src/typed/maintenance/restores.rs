use super::*;

impl<A: ReplicatedSchema> Node<A> {
    /// Cancel only the exact unfinished bootstrap into an otherwise initial node.
    /// This is not a permanent ban on future authenticated begin_snapshot calls.
    /// Transfer ownership and cancellation of the sender are caller responsibilities.
    pub fn cancel_snapshot(&mut self, manifest: &snapshot::Manifest) -> Result<()> {
        self.validate_manifest(manifest)?;
        ensure(
            self.role == Role::Secondary,
            "snapshot cancellation requires secondary",
        )?;
        self.connection(|c| {
            super::loss::require_no_loss_recovery(c)?;
            self.verify_owner(c)?;
            self.recovery_admission(c)?;
            compaction::require_idle(c)?;
            let tx=c.unchecked_transaction()?;
            let occupied:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM node_restore_complete) OR EXISTS(SELECT 1 FROM replication_base) OR EXISTS(SELECT 1 FROM replication_log) OR EXISTS(SELECT 1 FROM operation_receipts)",[],|r|r.get(0))?;
            ensure(!occupied && hash(&self.adapter.view(&tx)?)?==self.initial,"cannot cancel installed or noninitial data")?;
            let restoring:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM node_restore)",[],|r|r.get(0))?;
            if !restoring {
                let orphan:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM node_restore_pages) OR EXISTS(SELECT 1 FROM snapshot_sql_rows) OR EXISTS(SELECT 1 FROM snapshot_sql_progress)",[],|r|r.get(0))?;
                return ensure(!orphan,"orphan snapshot staging");
            }
            ensure(self.restore_manifest_in(&tx)?.0==*manifest,"snapshot cancellation mismatch")?;
            tx.execute_batch("DELETE FROM snapshot_sql_rows; DELETE FROM snapshot_sql_progress;
                DELETE FROM node_restore_pages; DELETE FROM node_restore; DELETE FROM replication_readiness;")?;
            tx.execute("UPDATE replication_generation SET value=?1 WHERE id=1",[checkpoint::fresh_generation()?.as_slice()])?;
            tx.commit()?;
            Ok(())
        })
    }

    /// Remove completed transfer buffers, preserving completion metadata, binding,
    /// live application data, receipts and the installed base. Exact retry is safe.
    pub fn cleanup_snapshot_staging(&mut self, manifest: &snapshot::Manifest) -> Result<()> {
        self.validate_manifest(manifest)?;
        self.connection(|c| {
            self.admission(c)?;
            let tx = c.unchecked_transaction()?;
            let json: String = tx.query_row(
                "SELECT manifest FROM node_restore_complete WHERE id=1",
                [],
                |r| r.get(0),
            )?;
            ensure(
                snapshot::Manifest::decode(json.as_bytes())? == *manifest
                    && checkpoint::base_for::<SchemaId>(&tx)?.as_ref()
                        == Some(&manifest.checkpoint),
                "completed snapshot cleanup mismatch",
            )?;
            self.current(&tx, false)?;
            let progress = sql_snapshot::progress(&tx)?.ok_or("missing completed SQL snapshot")?;
            ensure(
                progress.complete && progress.manifest == manifest.data,
                "SQL snapshot not complete",
            )?;
            tx.execute_batch("DELETE FROM node_restore_pages; DELETE FROM snapshot_sql_rows;")?;
            tx.commit()?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope_tests::{stock_entry, StockSchema};

    #[test]
    fn cancellation_and_completed_cleanup_preserve_live_state() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let batch = stock_entry().batch;
        let id = batch.identity.clone();
        let mut p = Node::open(
            dir.path().join("p"),
            Role::Primary,
            id.clone(),
            "fixture",
            StockSchema,
        )?;
        let mut s = Node::open(
            dir.path().join("s"),
            Role::Secondary,
            id.clone(),
            "fixture",
            StockSchema,
        )?;
        commit(&mut p, &mut s, batch)?;
        let manifest = p.publish_snapshot()?;
        let path = dir.path().join("target");
        let mut target = Node::open(&path, Role::Secondary, id.clone(), "fixture", StockSchema)?;
        target.begin_snapshot(&manifest)?;
        target.receive_snapshot(&p.snapshot_page(&manifest, 0)?)?;
        let mut wrong = manifest.clone();
        wrong.receipt_bytes += 1;
        assert!(target.cancel_snapshot(&wrong).is_err());
        target.connection(|c| {c.execute_batch("CREATE TRIGGER fail_cancel BEFORE DELETE ON node_restore BEGIN SELECT RAISE(ABORT,'fixture'); END;")?;Ok(())})?;
        assert!(target.cancel_snapshot(&manifest).is_err());
        assert_eq!(target.begin_snapshot(&manifest)?, 1);
        target.connection(|c| {
            c.execute_batch("DROP TRIGGER fail_cancel")?;
            Ok(())
        })?;
        target.cancel_snapshot(&manifest)?;
        target.cancel_snapshot(&manifest)?;
        assert!(target.view()?.is_empty());
        drop(target);
        let mut target = Node::open(&path, Role::Secondary, id, "fixture", StockSchema)?;
        assert_eq!(target.begin_snapshot(&manifest)?, 0);
        for n in 0..manifest.pages {
            target.receive_snapshot(&p.snapshot_page(&manifest, n)?)?;
        }
        target.finish_snapshot(&manifest)?;
        assert!(target.cancel_snapshot(&manifest).is_err());
        assert!(target.cleanup_snapshot_staging(&wrong).is_err());
        target.cleanup_snapshot_staging(&manifest)?;
        target.cleanup_snapshot_staging(&manifest)?;
        assert_eq!(target.finish_snapshot(&manifest)?, manifest.checkpoint);
        assert_eq!(target.view()?, p.view()?);
        assert_eq!(target.checkpoint()?, p.checkpoint()?);
        target.connection(|c| {
            assert_eq!(
                c.query_row("SELECT count(*) FROM node_restore_pages", [], |r| r
                    .get::<_, u64>(0))?,
                0
            );
            assert_eq!(
                c.query_row("SELECT count(*) FROM snapshot_sql_rows", [], |r| r
                    .get::<_, u64>(0))?,
                0
            );
            Ok(())
        })?;
        Ok(())
    }
}
