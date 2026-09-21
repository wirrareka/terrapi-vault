//! Legacy Proximi reference schema. Its data and request encodings are unchanged.
use crate::{
    schema::{RequestSchema, Schema, SchemaId},
    Result,
};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Change {
    PutPlace {
        id: String,
        name: String,
    },
    PutFeature {
        id: String,
        place_id: String,
        geojson: String,
    },
    DeletePlace {
        id: String,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Place {
    pub id: String,
    pub name: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Feature {
    pub id: String,
    pub place_id: String,
    pub geojson: String,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct View {
    pub places: Vec<Place>,
    pub features: Vec<Feature>,
}

pub struct Proximi;
impl RequestSchema for Proximi {
    const FINGERPRINT_VERSION: u32 = 1;

    fn request_fingerprint(&self, changes: &[Change]) -> [u8; 32] {
        fn string(h: &mut Sha256, value: &str) {
            h.update((value.len() as u64).to_be_bytes());
            h.update(value.as_bytes());
        }
        let mut h = Sha256::new();
        h.update(b"proximiio-core-request-v1\0");
        h.update((changes.len() as u64).to_be_bytes());
        for change in changes {
            match change {
                Change::PutPlace { id, name } => {
                    h.update([1]);
                    string(&mut h, id);
                    string(&mut h, name);
                }
                Change::PutFeature {
                    id,
                    place_id,
                    geojson,
                } => {
                    h.update([2]);
                    string(&mut h, id);
                    string(&mut h, place_id);
                    string(&mut h, geojson);
                }
                Change::DeletePlace { id } => {
                    h.update([3]);
                    string(&mut h, id);
                }
            }
        }
        h.finalize().into()
    }
}
impl Schema for Proximi {
    type Change = Change;
    type View = View;
    fn identity(&self) -> SchemaId {
        SchemaId {
            name: "proximiio.core-geo".into(),
            version: 1,
        }
    }
    fn tables(&self) -> &'static [&'static str] {
        &["places", "features"]
    }
    fn initialize(&self, c: &Connection) -> Result<()> {
        c.execute_batch("CREATE TABLE IF NOT EXISTS places(id TEXT PRIMARY KEY NOT NULL,name TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS features(id TEXT PRIMARY KEY NOT NULL,place_id TEXT NOT NULL REFERENCES places(id) ON DELETE CASCADE,geojson TEXT NOT NULL CHECK(json_valid(geojson)));")?;
        Ok(())
    }
    fn execute(&self, c: &Connection, changes: &[Change]) -> Result<()> {
        for change in changes {
            match change {
                Change::PutPlace { id, name } => {
                    c.execute("INSERT INTO places VALUES(?1,?2) ON CONFLICT(id) DO UPDATE SET name=excluded.name",params![id,name])?;
                }
                Change::PutFeature {
                    id,
                    place_id,
                    geojson,
                } => {
                    c.execute("INSERT INTO features VALUES(?1,?2,?3) ON CONFLICT(id) DO UPDATE SET place_id=excluded.place_id,geojson=excluded.geojson",params![id,place_id,geojson])?;
                }
                Change::DeletePlace { id } => {
                    c.execute("DELETE FROM places WHERE id=?1", [id])?;
                }
            }
        }
        Ok(())
    }
    fn view(&self, c: &Connection) -> Result<View> {
        let places = c
            .prepare("SELECT id,name FROM places ORDER BY id")?
            .query_map([], |r| {
                Ok(Place {
                    id: r.get(0)?,
                    name: r.get(1)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let features = c
            .prepare("SELECT id,place_id,geojson FROM features ORDER BY id")?
            .query_map([], |r| {
                Ok(Feature {
                    id: r.get(0)?,
                    place_id: r.get(1)?,
                    geojson: r.get(2)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(View { places, features })
    }
}
