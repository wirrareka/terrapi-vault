#![cfg(not(feature = "test-support"))]
use terrapi_vesta_replication::{commit, Batch, Change, Identity, Node, Role};

#[test]
fn inherited_crash_environment_cannot_terminate_default_library() {
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "default_build_child", "--ignored"])
        .env("VESTA_PROTOTYPE_CRASH_APPLY", "1")
        .stdout(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(
        result.success(),
        "default library honored a fixture crash switch"
    );
}

#[test]
#[ignore = "parent-owned subprocess for default-feature isolation"]
fn default_build_child() {
    let dir = tempfile::tempdir().unwrap();
    let identity = Identity {
        cluster: "local-test".into(),
        tenant: "fixture".into(),
        epoch: 1,
        schema: 1,
    };
    let mut primary = Node::open(
        dir.path().join("primary"),
        Role::Primary,
        identity.clone(),
        "test-primary",
    )
    .unwrap();
    let mut secondary = Node::open(
        dir.path().join("secondary"),
        Role::Secondary,
        identity.clone(),
        "test-secondary",
    )
    .unwrap();
    let result = commit(
        &mut primary,
        &mut secondary,
        Batch {
            identity,
            operation_id: "survives-inherited-env".into(),
            changes: vec![Change::PutPlace {
                id: "fixture".into(),
                name: "test".into(),
            }],
        },
    )
    .unwrap();
    assert_eq!(result.sequence, 1);
    assert_eq!(primary.view().unwrap(), secondary.view().unwrap());
}
