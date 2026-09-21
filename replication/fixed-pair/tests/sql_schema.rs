use rusqlite::{params, Connection};
use serde::Serialize;
use terrapi_vesta_replication::{
    schema::{self, RequestSchema, Schema, SchemaId},
    schema_contract, Result,
};

struct Inventory;

struct FingerprintVersion<const N: u32>;
impl<const N: u32> Schema for FingerprintVersion<N> {
    type Change = Mutation;
    type View = InventoryView;
    fn identity(&self) -> SchemaId {
        Inventory.identity()
    }
    fn tables(&self) -> &'static [&'static str] {
        Inventory.tables()
    }
    fn initialize(&self, c: &Connection) -> Result<()> {
        Inventory.initialize(c)
    }
    fn execute(&self, c: &Connection, changes: &[Mutation]) -> Result<()> {
        Inventory.execute(c, changes)
    }
    fn view(&self, c: &Connection) -> Result<InventoryView> {
        Inventory.view(c)
    }
}
impl<const N: u32> RequestSchema for FingerprintVersion<N> {
    const FINGERPRINT_VERSION: u32 = N;
    fn request_fingerprint(&self, changes: &[Mutation]) -> [u8; 32] {
        Inventory.request_fingerprint(changes)
    }
}

#[test]
fn adapter_contract_binds_fingerprint_version_and_ddl_not_application_rows() -> Result<()> {
    let c = db()?;
    let expected = schema_contract::expected(&Inventory)?;
    assert_eq!(schema_contract::describe(&c, &Inventory)?, expected);
    let captured = schema::capture(&c, &Inventory, &[Mutation::Put("a", 2)])?;
    schema::replay(&c, &Inventory, &captured)?;
    assert_eq!(schema_contract::describe(&c, &Inventory)?, expected);
    let v2 = schema_contract::expected(&FingerprintVersion::<2>)?;
    assert_eq!(v2.catalog_digest, expected.catalog_digest);
    assert_ne!(v2, expected);
    assert!(schema_contract::expected(&FingerprintVersion::<0>).is_err());
    c.execute_batch("CREATE INDEX stock_quantity ON stock(quantity)")?;
    assert_ne!(schema_contract::describe(&c, &Inventory)?, expected);
    Ok(())
}

#[test]
fn adapter_contract_rejects_shadowing_and_disabled_integrity_checks() -> Result<()> {
    let c = db()?;
    c.execute_batch(
        "CREATE TEMP TABLE stock(sku TEXT PRIMARY KEY NOT NULL,quantity INTEGER NOT NULL)",
    )?;
    assert!(schema_contract::describe(&c, &Inventory).is_err());
    c.execute_batch("DROP TABLE temp.stock")?;
    c.pragma_update(None, "foreign_keys", "OFF")?;
    assert!(schema_contract::describe(&c, &Inventory).is_err());
    Ok(())
}
impl RequestSchema for Inventory {
    const FINGERPRINT_VERSION: u32 = 1;
    fn request_fingerprint(&self, changes: &[Mutation]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"example.inventory.request-v1\0");
        h.update((changes.len() as u64).to_be_bytes());
        for change in changes {
            match change {
                Mutation::Put(sku, quantity) => {
                    h.update([1]);
                    h.update((sku.len() as u64).to_be_bytes());
                    h.update(sku.as_bytes());
                    h.update(quantity.to_be_bytes());
                }
                Mutation::Delete(sku) => {
                    h.update([2]);
                    h.update((sku.len() as u64).to_be_bytes());
                    h.update(sku.as_bytes());
                }
                Mutation::Invalid => h.update([3]),
            }
        }
        h.finalize().into()
    }
}

#[test]
fn request_identity_is_not_the_resulting_state() -> Result<()> {
    let c = db()?;
    let a = [Mutation::Put("a", 1)];
    let b = [Mutation::Put("a", 2), Mutation::Put("a", 1)];
    assert_eq!(
        schema::capture(&c, &Inventory, &a)?.after,
        schema::capture(&c, &Inventory, &b)?.after
    );
    assert_ne!(
        Inventory.request_fingerprint(&a),
        Inventory.request_fingerprint(&b)
    );
    assert_eq!(
        Inventory.request_fingerprint(&a),
        Inventory.request_fingerprint(&a)
    );
    let mut reversed = b.clone();
    reversed.reverse();
    assert_ne!(
        Inventory.request_fingerprint(&b),
        Inventory.request_fingerprint(&reversed)
    );
    Ok(())
}

#[test]
fn reference_request_encoding_preserves_legacy_golden_vectors() {
    use terrapi_vesta_replication::{reference::Proximi, Change};
    fn hex(bytes: [u8; 32]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
    assert_eq!(Proximi::FINGERPRINT_VERSION, 1);
    assert_eq!(
        hex(Proximi.request_fingerprint(&[])),
        "5d8a5d392deb10183a0f79a156a22c658a90409447a1fac358bd3efd86240704"
    );
    let changes = [
        Change::PutPlace {
            id: "ž\0".into(),
            name: "".into(),
        },
        Change::PutFeature {
            id: "f".into(),
            place_id: "ž\0".into(),
            geojson: "{ }".into(),
        },
        Change::DeletePlace { id: "ž\0".into() },
    ];
    assert_eq!(
        hex(Proximi.request_fingerprint(&changes)),
        "216e77798cd49f6853ab02afab4f7496ad2eb7a738ba3ebe41f42512f5829e54"
    );
}
#[derive(Clone)]
enum Mutation {
    Put(&'static str, i64),
    Delete(&'static str),
    Invalid,
}
#[derive(Debug, Serialize, PartialEq, Eq)]
struct InventoryView(Vec<(String, i64)>);
impl Schema for Inventory {
    type Change = Mutation;
    type View = InventoryView;
    fn identity(&self) -> SchemaId {
        SchemaId {
            name: "example.inventory".into(),
            version: 1,
        }
    }
    fn tables(&self) -> &'static [&'static str] {
        &["stock"]
    }
    fn initialize(&self, c: &Connection) -> Result<()> {
        c.execute_batch("CREATE TABLE IF NOT EXISTS stock(sku TEXT PRIMARY KEY NOT NULL, quantity INTEGER NOT NULL CHECK(quantity>=0));")?;
        Ok(())
    }
    fn execute(&self, c: &Connection, changes: &[Mutation]) -> Result<()> {
        for m in changes {
            match m {
                Mutation::Put(sku, n) => {
                    c.execute("INSERT INTO stock VALUES(?1,?2) ON CONFLICT(sku) DO UPDATE SET quantity=excluded.quantity", params![sku,n])?;
                }
                Mutation::Delete(sku) => {
                    c.execute("DELETE FROM stock WHERE sku=?1", [sku])?;
                }
                Mutation::Invalid => {
                    c.execute("INSERT INTO stock VALUES('invalid',-1)", [])?;
                }
            }
        }
        Ok(())
    }
    fn view(&self, c: &Connection) -> Result<InventoryView> {
        Ok(InventoryView(
            c.prepare("SELECT sku,quantity FROM stock ORDER BY sku")?
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<rusqlite::Result<_>>()?,
        ))
    }
}
fn db() -> Result<Connection> {
    let c = Connection::open_in_memory()?;
    c.pragma_update(None, "foreign_keys", "ON")?;
    schema::initialize(&c, &Inventory)?;
    Ok(c)
}

#[test]
fn independent_sql_schema_captures_without_mutating_and_replays_exactly() -> Result<()> {
    let primary = db()?;
    let secondary = db()?;
    let captured = schema::capture(
        &primary,
        &Inventory,
        &[Mutation::Put("b", 2), Mutation::Put("a", 1)],
    )?;
    assert_eq!(Inventory.view(&primary)?.0.len(), 0);
    schema::replay(&primary, &Inventory, &captured)?;
    schema::replay(&secondary, &Inventory, &captured)?;
    assert_eq!(Inventory.view(&primary)?, Inventory.view(&secondary)?);
    assert_eq!(
        Inventory.view(&primary)?.0,
        vec![("a".into(), 1), ("b".into(), 2)]
    );
    let update = schema::capture(
        &primary,
        &Inventory,
        &[Mutation::Delete("a"), Mutation::Put("b", 5)],
    )?;
    schema::replay(&primary, &Inventory, &update)?;
    schema::replay(&secondary, &Inventory, &update)?;
    assert_eq!(Inventory.view(&primary)?, Inventory.view(&secondary)?);
    Ok(())
}

#[test]
fn invalid_request_and_wrong_replay_are_atomic() -> Result<()> {
    let c = db()?;
    assert!(schema::capture(&c, &Inventory, &[Mutation::Put("a", 1), Mutation::Invalid]).is_err());
    assert!(Inventory.view(&c)?.0.is_empty());
    let good = schema::capture(&c, &Inventory, &[Mutation::Put("a", 1)])?;
    let mut bad = good.clone();
    bad.after = "wrong".into();
    assert!(schema::replay(&c, &Inventory, &bad).is_err());
    assert!(Inventory.view(&c)?.0.is_empty());
    bad = good.clone();
    bad.schema.version += 1;
    assert!(schema::replay(&c, &Inventory, &bad).is_err());
    bad = good.clone();
    bad.schema.name = "another.product".into();
    assert!(schema::replay(&c, &Inventory, &bad).is_err());
    bad = good.clone();
    bad.before = "wrong".into();
    assert!(schema::replay(&c, &Inventory, &bad).is_err());
    bad = good.clone();
    bad.changeset = vec![255, 0, 255];
    assert!(schema::replay(&c, &Inventory, &bad).is_err());
    assert!(Inventory.view(&c)?.0.is_empty());
    schema::replay(&c, &Inventory, &good)?;
    assert!(schema::replay(&c, &Inventory, &good).is_err()); // receipts belong to the caller
    Ok(())
}

#[test]
fn foreign_table_changeset_is_rejected_not_silently_filtered() -> Result<()> {
    let c = db()?;
    c.execute_batch(
        "CREATE TABLE private_data(id TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL);",
    )?;
    let tx = c.unchecked_transaction()?;
    let mut session = rusqlite::session::Session::new(&tx)?;
    session.attach(Some("stock"))?;
    session.attach(Some("private_data"))?;
    tx.execute_batch(
        "INSERT INTO stock VALUES('a',1); INSERT INTO private_data VALUES('id','value');",
    )?;
    let mut data = Vec::new();
    session.changeset_strm(&mut data)?;
    drop(session);
    tx.rollback()?;
    let mut captured = schema::capture(&c, &Inventory, &[Mutation::Put("a", 1)])?;
    captured.changeset = data;
    assert!(schema::replay(&c, &Inventory, &captured).is_err());
    assert!(Inventory.view(&c)?.0.is_empty());
    assert_eq!(
        c.query_row("SELECT count(*) FROM private_data", [], |r| r
            .get::<_, i64>(0))?,
        0
    );
    Ok(())
}

#[test]
fn foreign_keys_must_be_enabled_and_outer_transactions_are_not_committed() -> Result<()> {
    let c = db()?;
    c.pragma_update(None, "foreign_keys", "OFF")?;
    assert!(schema::capture(&c, &Inventory, &[]).is_err());
    c.pragma_update(None, "foreign_keys", "ON")?;
    let tx = c.unchecked_transaction()?;
    assert!(schema::capture(&tx, &Inventory, &[]).is_err());
    tx.execute("INSERT INTO stock VALUES('outer',1)", [])?;
    tx.rollback()?;
    assert!(Inventory.view(&c)?.0.is_empty());
    Ok(())
}

struct Catalog {
    name: &'static str,
    version: u32,
    tables: &'static [&'static str],
    ddl: &'static str,
}
impl Schema for Catalog {
    type Change = ();
    type View = ();
    fn identity(&self) -> SchemaId {
        SchemaId {
            name: self.name.into(),
            version: self.version,
        }
    }
    fn tables(&self) -> &'static [&'static str] {
        self.tables
    }
    fn initialize(&self, c: &Connection) -> Result<()> {
        c.execute_batch(self.ddl)?;
        Ok(())
    }
    fn execute(&self, _: &Connection, _: &[()]) -> Result<()> {
        Ok(())
    }
    fn view(&self, _: &Connection) -> Result<()> {
        Ok(())
    }
}
#[test]
fn schema_descriptor_and_primary_keys_are_validated_before_adoption() -> Result<()> {
    let good = || Catalog {
        name: "example.valid",
        version: 1,
        tables: &["items"],
        ddl: "CREATE TABLE items(id TEXT PRIMARY KEY NOT NULL);",
    };
    let mut invalid = vec![
        Catalog { name: "", ..good() },
        Catalog {
            name: "has spaces",
            ..good()
        },
        Catalog {
            version: 0,
            ..good()
        },
        Catalog {
            tables: &[],
            ..good()
        },
        Catalog {
            tables: &["items", "items"],
            ..good()
        },
        Catalog {
            tables: &["Items"],
            ..good()
        },
        Catalog {
            tables: &["x;drop_table"],
            ..good()
        },
        Catalog {
            tables: &[""],
            ..good()
        },
        Catalog {
            tables: &["missing"],
            ..good()
        },
        Catalog {
            ddl: "CREATE TABLE items(id TEXT);",
            ..good()
        },
        Catalog {
            ddl: "CREATE TABLE items(id TEXT PRIMARY KEY);",
            ..good()
        },
        Catalog {
            ddl: "CREATE VIEW items AS SELECT 1 AS id;",
            ..good()
        },
        Catalog {
            tables: &["checkpoint_format"],
            ddl: "CREATE TABLE checkpoint_format(id TEXT PRIMARY KEY NOT NULL);",
            ..good()
        },
        Catalog {
            tables: &["receipt_format"],
            ddl: "CREATE TABLE receipt_format(id TEXT PRIMARY KEY NOT NULL);",
            ..good()
        },
    ];
    for tables in [
        &["node_identity"][..],
        &["replication_log"][..],
        &["operation_receipts"][..],
        &["published_places"][..],
        &["materialized_rows"][..],
        &["snapshot_staging"][..],
        &["recovery_state"][..],
        &["sqlite_master"][..],
    ] {
        invalid.push(Catalog { tables, ..good() });
    }
    for bad in invalid {
        let c = Connection::open_in_memory()?;
        c.pragma_update(None, "foreign_keys", "ON")?;
        assert!(
            schema::initialize(&c, &bad).is_err(),
            "accepted {:?}",
            bad.tables
        );
        assert_eq!(
            c.query_row("SELECT count(*) FROM sqlite_schema", [], |r| r
                .get::<_, i64>(0))?,
            0
        );
    }
    let c = Connection::open_in_memory()?;
    c.pragma_update(None, "foreign_keys", "ON")?;
    schema::initialize(&c, &good())?;
    Ok(())
}

#[test]
fn reference_encoding_and_cascades_remain_compatible() -> Result<()> {
    use terrapi_vesta_replication::{reference::Proximi, Change, View};
    let a = Connection::open_in_memory()?;
    let b = Connection::open_in_memory()?;
    for c in [&a, &b] {
        c.pragma_update(None, "foreign_keys", "ON")?;
        schema::initialize(c, &Proximi)?;
    }
    assert_eq!(
        serde_json::to_string(&View::default())?,
        r#"{"places":[],"features":[]}"#
    );
    let captured = schema::capture(
        &a,
        &Proximi,
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
    for c in [&a, &b] {
        schema::replay(c, &Proximi, &captured)?;
    }
    assert_eq!(
        serde_json::to_string(&Proximi.view(&a)?)?,
        r#"{"places":[{"id":"p","name":"place"}],"features":[{"id":"f","place_id":"p","geojson":"{}"}]}"#
    );
    let deleted = schema::capture(&a, &Proximi, &[Change::DeletePlace { id: "p".into() }])?;
    for c in [&a, &b] {
        schema::replay(c, &Proximi, &deleted)?;
        assert_eq!(Proximi.view(c)?, View::default());
    }
    Ok(())
}

struct BinaryLedger;
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct LedgerRow {
    account: String,
    revision: i64,
    payload: Option<Vec<u8>>,
}
impl Schema for BinaryLedger {
    type Change = LedgerRow;
    type View = Vec<LedgerRow>;
    fn identity(&self) -> SchemaId {
        SchemaId {
            name: "example.binary-ledger".into(),
            version: 1,
        }
    }
    fn tables(&self) -> &'static [&'static str] {
        &["ledger"]
    }
    fn initialize(&self, c: &Connection) -> Result<()> {
        c.execute_batch("CREATE TABLE IF NOT EXISTS ledger(account TEXT NOT NULL, revision INTEGER NOT NULL, payload BLOB, PRIMARY KEY(account,revision)) WITHOUT ROWID;")?;
        Ok(())
    }
    fn execute(&self, c: &Connection, changes: &[LedgerRow]) -> Result<()> {
        for r in changes {
            c.execute(
                "INSERT INTO ledger VALUES(?1,?2,?3)",
                params![r.account, r.revision, r.payload],
            )?;
        }
        Ok(())
    }
    fn view(&self, c: &Connection) -> Result<Vec<LedgerRow>> {
        Ok(
            c.prepare("SELECT account,revision,payload FROM ledger ORDER BY account,revision")?
                .query_map([], |r| {
                    Ok(LedgerRow {
                        account: r.get(0)?,
                        revision: r.get(1)?,
                        payload: r.get(2)?,
                    })
                })?
                .collect::<rusqlite::Result<_>>()?,
        )
    }
}

#[test]
fn composite_keys_preserve_null_empty_and_binary_values() -> Result<()> {
    let a = Connection::open_in_memory()?;
    let b = Connection::open_in_memory()?;
    for c in [&a, &b] {
        c.pragma_update(None, "foreign_keys", "ON")?;
        schema::initialize(c, &BinaryLedger)?;
    }
    let rows = vec![
        LedgerRow {
            account: "a".into(),
            revision: 1,
            payload: None,
        },
        LedgerRow {
            account: "a".into(),
            revision: 2,
            payload: Some(vec![]),
        },
        LedgerRow {
            account: "a".into(),
            revision: i64::MAX,
            payload: Some(vec![0, 255, 128, 42]),
        },
    ];
    let captured = schema::capture(&a, &BinaryLedger, &rows)?;
    for c in [&a, &b] {
        schema::replay(c, &BinaryLedger, &captured)?;
        assert_eq!(BinaryLedger.view(c)?, rows);
    }
    Ok(())
}

#[test]
fn custom_schema_reopens_on_two_encrypted_vesta_files() -> Result<()> {
    use terrapi_vesta::{KdfParams, Vesta};
    let dir = tempfile::tempdir()?;
    let pa = dir.path().join("a.vesta");
    let pb = dir.path().join("b.vesta");
    {
        let a = Vesta::create(&pa, "inventory-primary-test-only", KdfParams::default())?;
        let b = Vesta::create(&pb, "inventory-secondary-test-only", KdfParams::default())?;
        for db in [&a, &b] {
            db.with_connection(|c| Ok(schema::initialize(c, &Inventory)))??;
        }
        let captured = a.with_connection(|c| {
            Ok(schema::capture(
                c,
                &Inventory,
                &[Mutation::Put("persisted", 17)],
            ))
        })??;
        for db in [&a, &b] {
            db.with_connection(|c| Ok(schema::replay(c, &Inventory, &captured)))??;
        }
    }
    let a = Vesta::open(&pa, "inventory-primary-test-only")?;
    let b = Vesta::open(&pb, "inventory-secondary-test-only")?;
    let av = a.with_connection(|c| Ok(Inventory.view(c)))??;
    let bv = b.with_connection(|c| Ok(Inventory.view(c)))??;
    assert_eq!(av, bv);
    assert_eq!(av.0, vec![("persisted".into(), 17)]);
    assert!(Vesta::open(&pa, "wrong-test-password").is_err());
    Ok(())
}
