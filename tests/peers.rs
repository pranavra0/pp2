#![cfg(target_os = "linux")]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{BufRead, BufReader},
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Barrier,
    thread,
    time::{Duration, Instant},
};

use pp2::{
    Block, Data, Expr, Hash, Program,
    peer::{
        self, Access, Cancellation, Client, Credentials, DiscoveryConfig, Evaluation,
        EvaluationMode, JavaScript, PeerError, PeerIdentity, PeerNetwork, PeerStore, RemoteReport,
    },
};

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let mut id = [0; 32];
        getrandom::fill(&mut id).unwrap();
        let path = std::env::temp_dir().join(format!("pp2-test-{}", Hash(id)));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Daemon(Child, SocketAddr);
impl Daemon {
    fn launch(path: &Path, db: &Path) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_pp2"))
            .args(["peer", "serve"])
            .arg(db)
            .arg("127.0.0.1:0")
            .args(["ca.pem", "server.pem", "server.key"])
            .current_dir(path)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        Self::from_child(child)
    }

    fn from_child(mut child: Child) -> Self {
        let mut ready = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut ready)
            .unwrap();
        let address = ready
            .strip_prefix("listening on ")
            .unwrap_or_else(|| panic!("server did not start: {ready:?}"))
            .trim()
            .parse()
            .unwrap();
        Self(child, address)
    }
}
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn certificates(path: &Path) {
    let output = Command::new("sh").args(["-eu", "-c", r#"
        openssl req -new -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj /CN=pp2-test -keyout ca.key -out ca.pem
        for name in server writer reader stranger; do
            openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$name" -keyout "$name.key" -out "$name.csr"
            if [ "$name" = server ]; then
                printf '%s\n' 'subjectAltName=DNS:localhost' 'extendedKeyUsage=serverAuth' > extensions
            else
                printf '%s\n' 'extendedKeyUsage=clientAuth' > extensions
            fi
            openssl x509 -req -in "$name.csr" -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 -extfile extensions -out "$name.pem"
        done
        openssl req -new -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj /CN=rogue -keyout rogue.key -out rogue.pem
    "#]).current_dir(path).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn credentials(path: &Path, name: &str) -> Credentials {
    Credentials {
        ca: path.join("ca.pem"),
        certificate: path.join(format!("{name}.pem")),
        key: path.join(format!("{name}.key")),
    }
}
fn client(path: &Path, daemon: &Daemon, name: &str) -> Client {
    Client::new(daemon.1, "localhost", &credentials(path, name)).unwrap()
}
fn pack(store: &mut PeerStore, source: impl Into<String>, imports: BTreeSet<Hash>) -> Hash {
    store
        .put(
            &JavaScript {
                source: source.into(),
                imports,
            }
            .to_bytes()
            .unwrap(),
        )
        .unwrap()
}
fn run(
    client: &Client,
    grant: Hash,
    program: Hash,
    packages: Option<&PeerStore>,
    input: &Data,
    mode: EvaluationMode,
) -> Result<RemoteReport, PeerError> {
    client.evaluate(Evaluation {
        grant,
        program,
        packages,
        input,
        mode,
    })
}
fn json(value: serde_json::Value) -> Data {
    peer::data_from_json(value).unwrap()
}

#[path = "peers/collections.rs"]
mod collections;
#[path = "peers/delegation.rs"]
mod delegation;
#[path = "peers/execution.rs"]
mod execution;
#[path = "peers/identity.rs"]
mod identity;
#[path = "peers/jobs.rs"]
mod jobs;
