use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
};

struct Peer(PathBuf);
impl Peer {
    fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_pp2"));
        cmd.env("PP2_HOME", &self.0).args(args);
        cmd
    }
    fn run(&self, args: &[&str]) -> String {
        let out = self.command(args).output().unwrap();
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap().trim().into()
    }
    fn denied(&self, args: &[&str], reason: &str) {
        let out = self.command(args).output().unwrap();
        assert!(!out.status.success());
        assert!(
            String::from_utf8_lossy(&out.stderr).contains(reason),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    fn serve(&self) -> (Daemon, String) {
        let mut child = self
            .command(&["serve", "127.0.0.1:0"])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut addr = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut addr)
            .unwrap();
        assert!(addr.contains('@'));
        (Daemon(child), addr.trim().into())
    }
    fn pack(&self, file: &str) -> String {
        self.run(&[
            "pack",
            Path::new("examples/portable").join(file).to_str().unwrap(),
        ])
    }
}
struct Daemon(Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        self.0.wait().unwrap();
    }
}

#[test]
fn portable_programs_run_at_the_owner_and_released_results_work_offline() {
    let temp = tempfile::tempdir().unwrap();
    let owner = Peer(temp.path().join("owner"));
    let guest = Peer(temp.path().join("guest"));
    let owner_id = owner.run(&["init"]);
    let guest_id = guest.run(&["init"]);
    let (daemon, at) = owner.serve();
    let (_guest_daemon, guest_at) = guest.serve();
    owner.run(&[
        "create",
        "sensor",
        r#"{"readings":[2,4,8],"serial":"owner-private"}"#,
    ]);
    guest.run(&[
        "create",
        "sensor",
        r#"{"readings":[100],"serial":"guest-private"}"#,
    ]);
    let query = guest.pack("summary.ts");
    let append = guest.pack("append.ts");
    let average = guest.pack("average.ts");
    let read = owner.run(&["grant", "sensor", &guest_id, &query, "read"]);
    let write = owner.run(&["grant", "sensor", &guest_id, &append, "write"]);
    let options = json!({"at":at,"input":3,"capabilities":[{"grant":read}]}).to_string();
    // The owner knows only the approved digest. Neither the entry nor its import is preinstalled.
    let db = rusqlite::Connection::open(owner.0.join("peer.db")).unwrap();
    assert_eq!(
        db.query_row("SELECT count(*) FROM modules", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        guest.run(&["eval", &query, &options]),
        r#"{"count":2,"total":12}"#
    );
    assert_eq!(owner.pack("summary.ts"), query);
    let reverse = guest.run(&["grant", "sensor", &owner_id, &query, "read"]);
    let reverse_options =
        json!({"at":guest_at,"input":3,"capabilities":[{"grant":reverse}]}).to_string();
    assert_eq!(
        owner.run(&["eval", &query, &reverse_options]),
        r#"{"count":1,"total":100}"#
    );
    owner.denied(&["eval", &query, &options], "access denied");
    guest.denied(&["eval", &append, &options], "access denied");
    guest.denied(
        &["eval", &query, &json!({"at":at}).to_string()],
        "access denied",
    );

    let snapshot: Value = serde_json::from_str(&guest.run(&["pin", &query, &options])).unwrap();
    let mut update =
        json!({"at":at,"capabilities":[{"grant":write,"operation":"append-1"}],"input":10});
    let first = update.to_string();
    thread::scope(|scope| {
        let retry = scope.spawn(|| guest.run(&["eval", &append, &first]));
        assert_eq!(guest.run(&["eval", &append, &first]), "4");
        assert_eq!(retry.join().unwrap(), "4");
    });
    update["input"] = json!(11);
    guest.denied(
        &["eval", &append, &update.to_string()],
        "operation ID reused",
    );
    update["capabilities"][0]["operation"] = json!("append-2");
    update["input"] = Value::Null;
    guest.denied(&["eval", &append, &update.to_string()], "guest");
    assert_eq!(
        guest.run(&["eval", &query, &options]),
        r#"{"count":3,"total":22}"#
    );

    drop(daemon);
    let (daemon, new_at) = owner.serve();
    update["at"] = json!(new_at);
    update["capabilities"][0]["operation"] = json!("append-1");
    update["input"] = json!(10);
    assert_eq!(guest.run(&["eval", &append, &update.to_string()]), "4");
    owner.run(&["revoke", &write]);
    guest.denied(&["eval", &append, &update.to_string()], "access denied");
    owner.run(&["revoke", &read]);
    let revoked = json!({"at":new_at,"input":3,"capabilities":[{"grant":read}]}).to_string();
    guest.denied(&["pin", &query, &revoked], "access denied");
    drop(daemon);
    assert_eq!(guest.run(&["eval", &average, &snapshot.to_string()]), "6");
    guest.denied(
        &["eval", &average, &json!({"at":snapshot["at"]}).to_string()],
        "access denied",
    );
    let mut attempt = snapshot.clone();
    attempt["capabilities"][0]["operation"] = json!("replace");
    guest.denied(
        &["eval", &append, &attempt.to_string()],
        "immutable snapshot",
    );
    guest.run(&[
        "revoke",
        snapshot["capabilities"][0]["grant"].as_str().unwrap(),
    ]);
    guest.denied(&["eval", &average, &snapshot.to_string()], "access denied");
}

#[test]
fn evaluation_by_identity_over_the_existing_relay() {
    let dir = tempfile::tempdir().unwrap();
    let owner = Peer(dir.path().join("owner"));
    let guest = Peer(dir.path().join("guest"));
    let id = owner.run(&["init"]);
    let holder = guest.run(&["init"]);
    let mut relay = Daemon(
        owner
            .command(&["rendezvous", "127.0.0.1:0"])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut address = String::new();
    BufReader::new(relay.0.stdout.take().unwrap())
        .read_line(&mut address)
        .unwrap();
    for peer in [&owner, &guest] {
        let config = json!({"rendezvous":address.trim(),"lan":false,"relay":true});
        std::fs::write(peer.0.join("discovery.json"), config.to_string()).unwrap();
    }
    let (_daemon, _) = owner.serve();
    let program = guest.pack("summary.ts");
    owner.run(&["create", "readings", r#"{"readings":[3,7]}"#]);
    let grant = owner.run(&["grant", "readings", &holder, &program, "read"]);
    let options = json!({"at":id,"capabilities":[{"grant":grant}],"input":0}).to_string();
    // Relay registration and signed discovery publication run independently.
    let until = std::time::Instant::now() + std::time::Duration::from_secs(6);
    loop {
        let out = guest
            .command(&["eval", &program, &options])
            .output()
            .unwrap();
        if out.status.success() {
            assert_eq!(
                serde_json::from_slice::<Value>(&out.stdout).unwrap(),
                json!({"count":2,"total":10})
            );
            break;
        }
        assert!(
            std::time::Instant::now() < until
                && String::from_utf8_lossy(&out.stderr).contains("peer unavailable"),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        thread::sleep(std::time::Duration::from_millis(100));
    }
}

#[test]
fn local_javascript_is_content_checked_and_time_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let peer = Peer(dir.path().join("peer"));
    peer.run(&["init"]);
    let file = dir.path().join("example.mjs");
    std::fs::write(&file, "export default async (_, x) => x + 1").unwrap();
    let program = peer.run(&["pack", file.to_str().unwrap()]);
    assert_eq!(peer.run(&["eval", &program, r#"{"input":2}"#]), "3");

    std::fs::write(&file, "export default () => { while (true) {} }").unwrap();
    let loop_program = peer.run(&["pack", file.to_str().unwrap()]);
    peer.denied(&["eval", &loop_program], "interrupt");
    let db = rusqlite::Connection::open(peer.0.join("peer.db")).unwrap();
    db.execute(
        "UPDATE modules SET bytes=(SELECT bytes FROM modules WHERE hash=?1) WHERE hash=?2",
        [&program, &loop_program],
    )
    .unwrap();
    peer.denied(&["eval", &loop_program], "module hash mismatch");
}
