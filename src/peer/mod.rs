mod content;
mod discovery;
mod protocol;
mod transport;
mod typescript;
mod worker;

use crate::Hash;
use content::JavaScript;
pub use discovery::{PeerIdentity, serve_rendezvous};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};
pub use worker::main as worker_main;

pub type Result<T> = std::result::Result<T, PeerError>;
#[derive(Debug, thiserror::Error)]
pub enum PeerError {
    #[error("access denied")]
    Denied,
    #[error("{0}")]
    Invalid(&'static str),
    #[error("{0}")]
    Value(String),
    #[error("limit exceeded: {0}")]
    Limit(&'static str),
    #[error("protocol: {0}")]
    Protocol(String),
    #[error("guest: {0}")]
    Guest(String),
    #[error("peer unavailable: {0}")]
    PeerUnavailable(Hash),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Database(#[from] rusqlite::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Tls(#[from] rustls::Error),
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
fn token() -> Result<String> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(std::io::Error::other)?;
    Ok(Hash(bytes).to_string())
}

type Package = Vec<(Hash, Vec<u8>)>;

#[derive(Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Options {
    pub input: Value,
    pub capabilities: Vec<Capability>,
    pub at: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capability {
    pub grant: String,
    /// Required for a write grant. Reuse for every retry of that logical operation.
    pub operation: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct Invocation {
    program: Hash,
    code: Package,
    input: String,
    capability: Option<Capability>,
}

pub struct Peer {
    home: PathBuf,
    worker: PathBuf,
    network: discovery::PeerNetwork,
}

impl Peer {
    pub fn init(home: &Path) -> Result<Hash> {
        // Publish the whole identity at once. A failed setup leaves no half-created peer.
        let parent = home
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        use std::os::unix::fs::PermissionsExt;
        let staging = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(parent)?;
        let dir = staging.path();
        let id = PeerIdentity::generate(dir.join("identity.key"))?;
        let status = std::process::Command::new("openssl")
            .current_dir(dir)
            .args([
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-nodes",
                "-days",
                "3650",
                "-subj",
                "/CN=pp2",
                "-keyout",
                "tls.key",
                "-out",
                "tls.pem",
            ])
            .stderr(std::process::Stdio::null())
            .status()?;
        if !status.success() {
            return Err(PeerError::Invalid("could not generate TLS certificate"));
        }
        Connection::open(dir.join("peer.db"))?.execute_batch("
            PRAGMA journal_mode=WAL;
            CREATE TABLE modules(hash TEXT PRIMARY KEY, bytes BLOB NOT NULL);
            CREATE TABLE resources(name TEXT PRIMARY KEY, state TEXT NOT NULL);
            CREATE TABLE grants(token TEXT PRIMARY KEY, resource TEXT NOT NULL REFERENCES resources(name), holder TEXT NOT NULL, program TEXT NOT NULL, writable INTEGER NOT NULL);
            CREATE TABLE receipts(token TEXT, operation TEXT, request TEXT NOT NULL, result TEXT NOT NULL, PRIMARY KEY(token,operation), FOREIGN KEY(token) REFERENCES grants(token) ON DELETE CASCADE);
            CREATE TABLE snapshots(token TEXT PRIMARY KEY, hash TEXT NOT NULL, state TEXT NOT NULL);
        ")?;
        std::fs::rename(dir, home)?;
        Ok(id)
    }
    pub fn open(home: &Path, worker: &Path) -> Result<Self> {
        let identity = PeerIdentity::load(home.join("identity.key"))?;
        let settings = match std::fs::File::open(home.join("discovery.json")) {
            Ok(file) => serde_json::from_reader(file)?,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Default::default(),
            Err(err) => return Err(err.into()),
        };
        Ok(Self {
            home: home.into(),
            worker: worker.canonicalize()?,
            network: discovery::PeerNetwork::new(identity, settings)?,
        })
    }
    fn db(&self) -> Result<Connection> {
        let db = Connection::open_with_flags(
            self.home.join("peer.db"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
        )?;
        db.busy_timeout(Duration::from_secs(5))?;
        db.execute_batch("PRAGMA foreign_keys=ON")?;
        Ok(db)
    }
    pub fn id(&self) -> Hash {
        self.network.id()
    }
    pub fn create(&self, name: &str, state: Value) -> Result<()> {
        self.db()?.execute(
            "INSERT INTO resources VALUES(?1,?2)",
            params![name, json(&state)?],
        )?;
        Ok(())
    }
    pub fn grant(&self, name: &str, holder: Hash, program: Hash, writable: bool) -> Result<String> {
        let cap = token()?;
        self.db()?.execute(
            "INSERT INTO grants VALUES(?1,?2,?3,?4,?5)",
            params![cap, name, holder.to_string(), program.to_string(), writable],
        )?;
        Ok(cap)
    }
    pub fn revoke(&self, cap: &str) -> Result<()> {
        let mut db = self.db()?;
        let tx = db.transaction()?;
        let count = tx.execute("DELETE FROM grants WHERE token=?1", [cap])?
            + tx.execute("DELETE FROM snapshots WHERE token=?1", [cap])?;
        if count == 0 {
            return Err(PeerError::Denied);
        }
        tx.commit()?;
        Ok(())
    }
    pub fn pack(&self, source: &Path) -> Result<Hash> {
        let blocks = typescript::package_source(source)?;
        let program = blocks.last().unwrap().0;
        let mut db = self.db()?;
        let tx = db.transaction()?;
        for (hash, bytes) in blocks {
            tx.execute(
                "INSERT OR IGNORE INTO modules VALUES(?1,?2)",
                params![hash.to_string(), bytes],
            )?;
        }
        tx.commit()?;
        Ok(program)
    }
    fn package(&self, root: Hash) -> Result<Package> {
        let db = self.db()?;
        let mut pending = vec![root];
        let mut seen = BTreeSet::new();
        let mut code = Vec::new();
        let mut size = 0;
        while let Some(hash) = pending.pop() {
            if !seen.insert(hash) {
                continue;
            }
            let bytes: Vec<u8> = db.query_row(
                "SELECT bytes FROM modules WHERE hash=?1",
                [hash.to_string()],
                |r| r.get(0),
            )?;
            size += bytes.len();
            if seen.len() > content::MAX_MODULES || size > content::MAX_CODE {
                return Err(PeerError::Limit("module graph"));
            }
            pending.extend(JavaScript::from_bytes(&bytes)?.imports);
            code.push((hash, bytes));
        }
        Ok(code)
    }

    pub fn evaluate(&self, program: Hash, options: Options) -> Result<Value> {
        let capability = match options.capabilities.as_slice() {
            [] => None,
            [cap] => Some(cap.clone()),
            _ => {
                return Err(PeerError::Invalid(
                    "expected at most one resource capability",
                ));
            }
        };
        let call = Invocation {
            program,
            code: self.package(program)?,
            input: json(&options.input)?,
            capability,
        };
        let result = match options.at.as_deref().unwrap_or("local") {
            "local" => self.execute(self.id(), call, None)?,
            at if at.starts_with("snapshot:") => {
                self.execute(self.id(), call, Some(at[9..].parse()?))?
            }
            at => {
                let (id, addr) = at
                    .split_once('@')
                    .map_or((at, None), |(id, addr)| (id, Some(addr)));
                let addr: Option<SocketAddr> = addr
                    .map(str::parse)
                    .transpose()
                    .map_err(|_| PeerError::Invalid("invalid peer address"))?;
                self.remote(id.parse()?, addr, &call)?
            }
        };
        Ok(serde_json::from_str(&result)?)
    }
    /// Save only a value already released to this peer. The local grant permits offline reads.
    pub fn pin(&self, value: Value) -> Result<Options> {
        let state = json(&value)?;
        let hash = Hash::digest(state.as_bytes()).to_string();
        let cap = token()?;
        self.db()?.execute(
            "INSERT INTO snapshots VALUES(?1,?2,?3)",
            params![cap, hash, state],
        )?;
        Ok(Options {
            capabilities: vec![Capability {
                grant: cap,
                operation: None,
            }],
            at: Some(format!("snapshot:{hash}")),
            ..Default::default()
        })
    }
    fn execute(&self, holder: Hash, call: Invocation, snapshot: Option<Hash>) -> Result<String> {
        let Invocation {
            program,
            code,
            input,
            capability,
        } = call;
        if code.len() > content::MAX_MODULES
            || code.iter().map(|(_, b)| b.len()).sum::<usize>() > content::MAX_CODE
            || input.len() > content::MAX_BYTES
        {
            return Err(PeerError::Limit("invocation"));
        }
        let run = |state| {
            worker::run(
                &self.worker,
                worker::Work {
                    program,
                    code,
                    input: input.clone(),
                    state,
                },
            )
        };
        let Some(Capability {
            grant: cap,
            operation,
        }) = capability
        else {
            if snapshot.is_some() || holder != self.id() {
                return Err(PeerError::Denied);
            }
            return run("null".into());
        };
        let mut db = self.db()?;
        if let Some(hash) = snapshot {
            if operation.is_some() {
                return Err(PeerError::Invalid("immutable snapshot"));
            }
            let state: String = db
                .query_row(
                    "SELECT state FROM snapshots WHERE hash=?1 AND token=?2",
                    params![hash.to_string(), cap],
                    |r| r.get(0),
                )
                .optional()?
                .ok_or(PeerError::Denied)?;
            if Hash::digest(state.as_bytes()) != hash {
                return Err(PeerError::Invalid("snapshot hash mismatch"));
            }
            return run(state);
        }
        // A write locks the owner database before either the state or retry receipt is read.
        let tx = db.transaction_with_behavior(if operation.is_some() {
            TransactionBehavior::Immediate
        } else {
            TransactionBehavior::Deferred
        })?;
        let (resource, state, write): (String, String, bool) = tx
            .query_row(
                "SELECT name,state,writable FROM resources JOIN grants ON resource=name
             WHERE token=?1 AND holder=?2 AND program=?3",
                params![cap, holder.to_string(), program.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?
            .ok_or(PeerError::Denied)?;
        if write != operation.is_some() {
            return Err(PeerError::Invalid(
                "writes require an operation ID and a write grant",
            ));
        }
        let Some(key) = operation else {
            return run(state);
        };
        if key.is_empty() || key.len() > 128 {
            return Err(PeerError::Invalid("invalid operation ID"));
        }
        let digest = Hash::digest(input.as_bytes()).to_string();
        if let Some((saved, value)) = tx
            .query_row(
                "SELECT request,result FROM receipts WHERE token=?1 AND operation=?2",
                params![cap, key],
                |r| Ok((r.get::<_, String>(0)?, r.get(1)?)),
            )
            .optional()?
        {
            return if saved == digest {
                Ok(value)
            } else {
                Err(PeerError::Invalid(
                    "operation ID reused with different input",
                ))
            };
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Update {
            state: Value,
            value: Value,
        }
        let update: Update = serde_json::from_str(&run(state)?)?;
        let value = json(&update.value)?;
        tx.execute(
            "UPDATE resources SET state=?1 WHERE name=?2",
            params![json(&update.state)?, resource],
        )?;
        tx.execute(
            "INSERT INTO receipts VALUES(?1,?2,?3,?4)",
            params![cap, key, digest, value],
        )?;
        tx.commit()?;
        Ok(value)
    }
}
fn json(value: &Value) -> Result<String> {
    let text = serde_json::to_string(value)?;
    if text.len() > content::MAX_BYTES {
        return Err(PeerError::Limit("JSON bytes"));
    }
    Ok(text)
}
