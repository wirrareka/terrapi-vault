use serde::Deserialize;
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};
use terrapi_vesta_replication::*;

#[derive(Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
enum Request {
    ActivateBase { proposal: publication::Proposal },
    CaptureBase { proposal: publication::Proposal },
    ConfirmBase { proposal: publication::Proposal },
    MaterializedFinish { token: [u8; 32] },
    SnapshotFinish { token: [u8; 32] },
    Status,
    View,
    Prepare { batch: Batch },
    Stage { entry: Entry },
    Decide { operation_id: String },
    Apply { entry: Entry },
    Abort { operation_id: String },
    Snapshot,
    Install { snapshot: Snapshot },
}
fn execute(node: &mut Node, request: Request) -> Result<Value> {
    Ok(match request {
        Request::ActivateBase { proposal } => {
            node.activate_published_base(proposal)?;
            Value::Null
        }
        Request::CaptureBase { proposal } => serde_json::to_value(node.capture_base(proposal)?)?,
        Request::ConfirmBase { proposal } => serde_json::to_value(node.confirm_base(proposal)?)?,
        Request::MaterializedFinish { token } => {
            serde_json::to_value(node.materialized_finish(token)?)?
        }
        Request::SnapshotFinish { token } => serde_json::to_value(node.snapshot_finish(token)?)?,
        Request::Status => serde_json::to_value(node.status()?)?,
        Request::View => serde_json::to_value(node.view()?)?,
        Request::Prepare { batch } => serde_json::to_value(node.prepare(batch)?)?,
        Request::Stage { entry } => {
            node.stage(entry)?;
            Value::Null
        }
        Request::Decide { operation_id } => serde_json::to_value(node.decide(&operation_id)?)?,
        Request::Apply { entry } => {
            node.apply(entry)?;
            Value::Null
        }
        Request::Abort { operation_id } => {
            node.abort(&operation_id)?;
            Value::Null
        }
        Request::Snapshot => serde_json::to_value(node.snapshot()?)?,
        Request::Install { snapshot } => {
            node.install(snapshot)?;
            Value::Null
        }
    })
}
fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        return Err("usage: vesta-node <database-path> <primary|secondary>; passphrase in VESTA_PROTOTYPE_PASSPHRASE".into());
    }
    let role = match args[2].as_str() {
        "primary" => Role::Primary,
        "secondary" => Role::Secondary,
        _ => return Err("invalid role".into()),
    };
    let identity = Identity {
        cluster: "eu-pair".into(),
        tenant: "tenant-a".into(),
        epoch: 1,
        schema: 1,
    };
    let mut node = Node::open(
        &args[1],
        role,
        identity,
        &std::env::var("VESTA_PROTOTYPE_PASSPHRASE")?,
    )?;
    let mut stdout = io::stdout().lock();
    for line in io::stdin().lock().lines() {
        let result = serde_json::from_str::<Request>(&line?)
            .map_err(Into::into)
            .and_then(|r| execute(&mut node, r));
        let response = match result {
            Ok(value) => json!({"ok":value}),
            Err(e) => json!({"error":e.to_string()}),
        };
        writeln!(stdout, "{response}")?;
        stdout.flush()?;
    }
    Ok(())
}
