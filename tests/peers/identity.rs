use super::*;

#[test]
fn database_identity_rejects_unrelated_files() {
    let dir = Temp::new();
    let database = dir.0.join("unrelated.db");
    let existing = rusqlite::Connection::open(&database).unwrap();
    existing
        .execute_batch("CREATE TABLE entries (label TEXT); INSERT INTO entries VALUES ('keep');")
        .unwrap();
    let original = fs::read(&database).unwrap();
    assert!(matches!(
        PeerStore::open(&database),
        Err(PeerError::Unsupported(_))
    ));
    assert_eq!(fs::read(database).unwrap(), original);
}

#[test]
fn stable_grant_survives_transport_certificate_replacement_and_respects_identity_revocation() {
    let dir = Temp::new();
    let path = &dir.0;
    certificates(path);
    let database = path.join("storage.db");
    let server_id = PeerIdentity::generate(path.join("identity.key")).unwrap();
    let caller_key = path.join("caller.key");
    let caller_id = PeerIdentity::generate(&caller_key).unwrap();
    let caller = PeerNetwork::new(
        PeerIdentity::load(caller_key).unwrap(),
        DiscoveryConfig {
            lan: false,
            ..Default::default()
        },
    )
    .unwrap();

    let mut store = PeerStore::open(&database).unwrap();
    let revision = store.create_ref("private", &Data::Int(7)).unwrap();
    let program = pack(
        &mut store,
        "export default state => state;",
        BTreeSet::new(),
    );
    store.publish(program).unwrap();
    let grant = store
        .issue("private", caller_id, Access::Read, Some(program))
        .unwrap();
    let launch = |certificate: &str, revoked: BTreeSet<Hash>| {
        fs::copy(
            path.join(format!("{certificate}.pem")),
            path.join("peer.pem"),
        )
        .unwrap();
        fs::copy(
            path.join(format!("{certificate}.key")),
            path.join("peer.key"),
        )
        .unwrap();
        let settings = DiscoveryConfig {
            lan: false,
            revoked,
            ..Default::default()
        };
        fs::write(
            path.join("discovery.json"),
            serde_json::to_vec(&settings).unwrap(),
        )
        .unwrap();
        Daemon::from_child(
            Command::new(env!("CARGO_BIN_EXE_pp2"))
                .args(["peer", "serve-network"])
                .arg(&database)
                .arg("127.0.0.1:0")
                .arg(path)
                .stdout(Stdio::piped())
                .spawn()
                .unwrap(),
        )
    };
    for certificate in ["server", "rogue"] {
        let daemon = launch(certificate, BTreeSet::new());
        let client = Client::for_peer(&caller, server_id, Some(daemon.1));
        assert_eq!(
            run(
                &client,
                grant,
                program,
                None,
                &Data::Nil,
                EvaluationMode::Read
            )
            .unwrap()
            .value,
            Data::Int(7),
        );
        assert!(
            matches!(client.fetch(revision.hash), Err(PeerError::Missing(hash)) if hash == revision.hash)
        );
        let wrong_peer = Client::for_peer(&caller, caller_id, Some(daemon.1));
        assert!(
            matches!(wrong_peer.fetch(program), Err(PeerError::PeerUnavailable(id)) if id == caller_id)
        );
    }

    let daemon = launch("rogue", BTreeSet::from([caller_id]));
    let client = Client::for_peer(&caller, server_id, Some(daemon.1));
    assert!(matches!(
        run(
            &client,
            grant,
            program,
            None,
            &Data::Nil,
            EvaluationMode::Read
        ),
        Err(PeerError::Denied),
    ));
}

#[test]
fn version_one_databases_keep_their_snapshot_references() {
    let dir = Temp::new();
    let database = dir.0.join("old.db");
    let mut store = PeerStore::open(&database).unwrap();
    let revision = store.create_ref("old", &Data::Int(71)).unwrap();
    drop(store);
    {
        let old = rusqlite::Connection::open(&database).unwrap();
        old.execute_batch(
            "DROP TABLE replica_private; DROP TABLE replica_pending; DROP TABLE replica_routes; DROP TABLE replica_parents;
             DROP TABLE replica_versions; DROP TABLE replicas; DROP INDEX edges_child;
             ALTER TABLE receipts DROP COLUMN view; ALTER TABLE jobs DROP COLUMN replica_grant;
             DROP TABLE native_bindings; DROP TABLE native_installations; DROP TABLE host_resources;
             DROP TABLE job_effects; DROP TABLE job_blocks; DROP TABLE jobs;
             DROP VIEW subscription_authority; DROP TABLE subscriptions;
             DROP TABLE applications; DROP TABLE change_events; DROP TABLE reaction_writers;
             DROP TABLE graph_forward_replays; DROP TABLE graph_grants;
             DROP TABLE entries; DROP TABLE collections; PRAGMA user_version = 1;",
        )
        .unwrap();
    }
    let mut store = PeerStore::open(&database).unwrap();
    assert_eq!(
        store.read_ref("old").unwrap(),
        Some((revision, Data::Int(71)))
    );
    store
        .create_collection("new", [Ok(("counter".into(), Data::Int(5)))])
        .unwrap();
    assert!(store.read_ref("new").is_err());
    assert_eq!(
        store.read_ref("old").unwrap(),
        Some((revision, Data::Int(71)))
    );
}

// Relay a TLS 1.3 handshake, then suppress the server's first reply. The client completes
// the handshake before sending its request. Receiving the withheld record proves it was handled.
