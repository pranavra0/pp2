#![cfg(target_os = "linux")]

use std::{
    fs,
    io::{BufRead, BufReader},
    net::TcpListener,
    os::unix::fs::symlink,
    path::Path,
    process::{Child, Command, Output, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    thread,
};

use pp2::peer::{
    Binding, Directory, GraphMetrics, HostProvider, PeerStore, data_from_json, data_to_json,
};
use serde_json::{Value, json};

fn command(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_pp2"))
        .args(args)
        .output()
        .unwrap()
}

fn success(args: &[&str]) -> String {
    let output = command(args);
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    String::from_utf8(output.stdout).unwrap().trim().into()
}

fn native(args: &[&str]) -> String {
    success(&[&["app", "native"], args].concat())
}

struct Daemon(Child, String);

impl Daemon {
    fn spawn(args: &[&str]) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_pp2"))
            .args(args)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        Self(
            child,
            line.trim().strip_prefix("listening on ").unwrap().into(),
        )
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn path(path: &Path) -> &str {
    path.to_str().unwrap()
}

#[test]
fn installs_updates_searches_and_revokes_over_discovery() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let laptop = root.join("laptop");
    let host = root.join("host");
    let publisher = root.join("publisher");
    let sources = root.join("documents");
    fs::create_dir_all(sources.join("projects")).unwrap();
    fs::write(
        sources.join("projects/plan.md"),
        "meeting budget ".repeat(900),
    )
    .unwrap();
    fs::write(sources.join("notes.txt"), "meeting".repeat(1200)).unwrap();
    fs::write(root.join("private.txt"), "meeting budget private").unwrap();
    symlink(root.join("private.txt"), sources.join("escape.txt")).unwrap();

    let laptop_id = native(&["identity", path(&laptop)]);
    native(&["identity", path(&host)]);
    let publisher_id = native(&["identity", path(&publisher)]);
    let rendezvous = Daemon::spawn(&["peer", "rendezvous", "127.0.0.1:0"]);
    let host_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let publisher_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let host_address = host_listener.local_addr().unwrap().to_string();
    let publisher_address = publisher_listener.local_addr().unwrap().to_string();
    drop((host_listener, publisher_listener));
    for (home, address) in [
        (&laptop, None),
        (&host, Some(&host_address)),
        (&publisher, Some(&publisher_address)),
    ] {
        let mut settings = json!({"lan": false, "rendezvous": rendezvous.1});
        if let Some(address) = address {
            settings["advertise"] = json!([address]);
        }
        fs::write(home.join("discovery.json"), settings.to_string()).unwrap();
    }

    let publish = |file: &Path| {
        success(&[
            "peer",
            "put",
            path(&publisher.join("peer.db")),
            path(file),
            "--publish",
        ])
    };
    let pack_program = |source: &str, name: &str| {
        let source_path = root.join(format!("{name}.mjs"));
        let block = root.join(format!("{name}.ppj"));
        fs::write(&source_path, source).unwrap();
        let hash = success(&["peer", "pack", path(&source_path), path(&block)]);
        assert_eq!(publish(&block), hash);
        hash
    };
    let app_source = include_str!("../examples/native-documents/app.mjs");
    let indexer = pack_program(
        include_str!("../examples/native-documents/index.mjs"),
        "index",
    );
    let first_app = pack_program(app_source, "app");
    let second_app = pack_program(
        &app_source.replace("Document search", "Document search v2"),
        "app-v2",
    );
    let document_request =
        json!({"description": "Search a shared directory", "program": indexer, "access": "Write"});
    let pack_app = |entry: &str, bindings: Value| {
        let manifest = root.join("application.json");
        let package = root.join("application.ppa");
        fs::write(
            &manifest,
            json!({
                "name": "Document search",
                "entry": entry,
                "budget": {"timeout_ms": 6000, "calls": 4, "depth": 1},
                "bindings": bindings,
            })
            .to_string(),
        )
        .unwrap();
        let hash = native(&["pack", path(&manifest), path(&package)]);
        assert_eq!(publish(&package), hash);
        hash
    };
    let first = pack_app(&first_app, json!({"documents": document_request}));
    let second = pack_app(
        &second_app,
        json!({
            "documents": document_request,
            "extra": {"description": "Extra directory", "program": indexer, "access": "Read"}
        }),
    );
    let third = pack_app(
        &second_app,
        json!({"documents": {
            "description": "Different directory request", "program": indexer, "access": "Write"
        }}),
    );
    let publisher = Daemon::spawn(&[
        "app",
        "native",
        "host",
        path(&publisher),
        &publisher_address,
    ]);

    let share = root.join("share.json");
    let binding = native(&[
        "share-directory",
        path(&host),
        "documents",
        path(&sources),
        &laptop_id,
        &indexer,
        "writer",
    ]);
    fs::write(&share, &binding).unwrap();
    let binding: Binding = serde_json::from_str(&binding).unwrap();
    let running_host = Daemon::spawn(&["app", "native", "host", path(&host), &host_address]);
    let rejected = command(&[
        "app",
        "native",
        "install",
        path(&laptop),
        &first,
        &publisher_id,
    ]);
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("approval declined"));
    assert!(native(&["list", path(&laptop)]).is_empty());
    let id = native(&["install", path(&laptop), &first, &publisher_id, "--yes"]);
    let run = |line| native(&["run", path(&laptop), &id, line]);
    assert!(run("index").contains("Connect the documents grant"));
    assert!(
        !command(&[
            "app",
            "native",
            "grant",
            path(&laptop),
            &id,
            "other",
            path(&share)
        ])
        .status
        .success()
    );
    native(&["grant", path(&laptop), &id, "documents", path(&share)]);

    // Only the publisher initially has the code. It reaches the host after the laptop goes to run it.
    assert!(
        PeerStore::open(host.join("peer.db"))
            .unwrap()
            .get(indexer.parse().unwrap())
            .unwrap()
            .is_none()
    );
    let refresh = command(&[
        "app",
        "native",
        "run",
        path(&laptop),
        &id,
        "index",
        "--metrics",
    ]);
    assert!(
        refresh.status.success(),
        "{}",
        String::from_utf8_lossy(&refresh.stderr)
    );
    assert!(String::from_utf8_lossy(&refresh.stdout).contains("Indexed 2 documents"));
    let metrics: GraphMetrics = serde_json::from_slice(&refresh.stderr).unwrap();
    eprintln!("Index refresh metrics {metrics:?}");
    assert_eq!(metrics.remote_calls, 2);
    assert!(metrics.remote_response_bytes < 1024, "{metrics:?}");
    let search = run("search meeting budget");
    assert!(
        search.contains("1 match") && search.contains("projects/plan.md"),
        "{search}"
    );
    assert!(!search.contains("escape.txt"));
    assert!(
        PeerStore::open(host.join("peer.db"))
            .unwrap()
            .get(indexer.parse().unwrap())
            .unwrap()
            .is_some()
    );

    drop(running_host);
    let offline = run("search meeting budget");
    assert!(
        offline.contains("Offline cache") && offline.contains("projects/plan.md"),
        "{offline}"
    );
    assert!(run("search uncached").contains("no cached result"));
    let rejected = command(&[
        "app",
        "native",
        "update",
        path(&laptop),
        &id,
        &second,
        &publisher_id,
    ]);
    assert!(!rejected.status.success());
    let summary = String::from_utf8(rejected.stderr).unwrap();
    assert!(summary.contains("extra  Read") && summary.contains("approval declined"));
    assert!(native(&["status", path(&laptop), &id]).contains(&first));
    let update = native(&[
        "update",
        path(&laptop),
        &id,
        &second,
        &publisher_id,
        "--yes",
    ]);
    assert_eq!(update, id);
    assert!(run("help").contains("Document search v2"));
    assert_eq!(run("search meeting budget"), offline);
    let status = native(&["status", path(&laptop), &id]);
    assert!(status.contains("extra  Read  awaiting grant"));
    assert!(status.contains(&format!("documents  Write  {}", binding.peer)));
    let mut laptop_store = PeerStore::open(laptop.join("peer.db")).unwrap();
    laptop_store.collect().unwrap();
    assert!(laptop_store.get(second.parse().unwrap()).unwrap().is_some());
    assert!(laptop_store.get(first.parse().unwrap()).unwrap().is_none());

    let _running_host = Daemon::spawn(&["app", "native", "host", path(&host), &host_address]);
    assert_eq!(run("search meeting budget"), search);
    assert!(
        PeerStore::open(host.join("peer.db"))
            .unwrap()
            .revoke(binding.grant)
            .unwrap()
    );
    assert!(run("search meeting budget").contains("capability denied"));
    native(&["update", path(&laptop), &id, &third, &publisher_id, "--yes"]);
    assert!(run("search meeting budget").contains("Connect the documents grant"));
    let local_grant = native(&[
        "share-directory",
        path(&laptop),
        "local-documents",
        path(&sources),
        &laptop_id,
        &indexer,
        "writer",
    ]);
    fs::write(&share, local_grant).unwrap();
    native(&["grant", path(&laptop), &id, "documents", path(&share)]);
    let local = command(&[
        "app",
        "native",
        "run",
        path(&laptop),
        &id,
        "index",
        "--metrics",
    ]);
    assert!(local.status.success());
    assert!(String::from_utf8_lossy(&local.stdout).contains("Indexed 2 documents"));
    assert_eq!(
        serde_json::from_slice::<GraphMetrics>(&local.stderr)
            .unwrap()
            .remote_calls,
        0
    );
    assert_eq!(run("search meeting budget"), search);

    drop(publisher);
    native(&["remove", path(&laptop), &id]);
    assert!(
        laptop_store
            .reference(&format!("native.{id}"))
            .unwrap()
            .is_none()
    );
    assert!(laptop_store.native_installations().unwrap().is_empty());
    assert!(
        !command(&["app", "native", "run", path(&laptop), &id, "help"])
            .status
            .success()
    );
}

#[test]
fn directory_reads_remain_scoped_during_replacement() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    fs::create_dir(&root).unwrap();
    let outside = dir.path().join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("secret.txt"), "outside").unwrap();
    fs::write(root.join("ok.txt"), "inside").unwrap();
    symlink(outside.join("secret.txt"), root.join("link")).unwrap();
    symlink(&outside, root.join("jump")).unwrap();
    fs::hard_link(outside.join("secret.txt"), root.join("hard")).unwrap();

    let selected_link = dir.path().join("root-link");
    symlink(&root, &selected_link).unwrap();
    assert!(Directory::resource(&selected_link).is_err());
    let grant = Directory::resource(&root).unwrap();
    let call = |op, input| {
        Directory.read(
            &grant.configuration,
            op,
            data_from_json(input).unwrap(),
            &|| Ok(()),
        )
    };
    for relative in [
        "../outside/secret.txt",
        path(&outside.join("secret.txt")),
        "jump/secret.txt",
        "link",
        "hard",
        "./ok.txt",
        "ok.txt\0",
    ] {
        assert!(
            call("readText", json!({"path": relative})).is_err(),
            "{relative}"
        );
    }
    let first = call("list", json!({"path": "", "limit": 1})).unwrap();
    assert_eq!(
        data_to_json(&first).unwrap(),
        json!({"entries":[["hard","file"]], "next":"hard"})
    );
    let next = call("list", json!({"path": "", "after": "hard", "limit": 1})).unwrap();
    assert_eq!(
        data_to_json(&next).unwrap(),
        json!({"entries":[["ok.txt","file"]], "next":null})
    );
    let bytes = call("read", json!({"path": "ok.txt", "limit": 2, "offset": 1})).unwrap();
    assert_eq!(
        data_to_json(&bytes).unwrap(),
        json!({"bytes": [110, 115], "next": 3})
    );
    assert!(call("list", json!({"path":"jump"})).is_err());

    let slot = root.join("secret.txt");
    let replace = root.join("swap");
    fs::write(&slot, "inside").unwrap();
    let stop = AtomicBool::new(false);
    thread::scope(|scope| {
        scope.spawn(|| {
            while !stop.load(Ordering::Relaxed) {
                symlink(outside.join("secret.txt"), &replace).unwrap();
                fs::rename(&replace, &slot).unwrap();
                fs::write(&replace, "inside").unwrap();
                fs::rename(&replace, &slot).unwrap();
            }
        });
        let escaped = (0..300).any(|_| {
            call("readText", json!({"path": "secret.txt"}))
                .is_ok_and(|value| data_to_json(&value).unwrap() != json!("inside"))
        });
        stop.store(true, Ordering::Relaxed);
        assert!(!escaped);
    });

    fs::rename(&root, dir.path().join("old")).unwrap();
    fs::create_dir(&root).unwrap();
    fs::write(root.join("ok.txt"), "replacement").unwrap();
    assert!(call("readText", json!({"path":"ok.txt"})).is_err());
}
