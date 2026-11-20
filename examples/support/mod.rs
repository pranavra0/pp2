use std::{
    collections::BTreeMap,
    fs::{self, File},
    net::SocketAddr,
    path::{Path, PathBuf},
};

use pp2::{
    Data, Hash,
    peer::{
        Client, Credentials, Evaluation, EvaluationMode, JavaScript, PeerError, PeerStore,
        RemoteReport, compile_typescript, data_to_json,
    },
};
use serde::Deserialize;
use serde_json::{Value, json};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Deserialize)]
pub struct Profile {
    address: SocketAddr,
    name: String,
    ca: PathBuf,
    certificate: PathBuf,
    key: PathBuf,
    cache: PathBuf,
    read: Binding,
    write: Option<Binding>,
}

#[derive(Deserialize)]
struct Binding {
    grant: String,
    program: String,
}

impl Profile {
    pub fn load(path: &str) -> Result<Self> {
        Ok(serde_json::from_reader(File::open(path)?)?)
    }

    pub fn cache(&self) -> Result<PeerStore> {
        Ok(PeerStore::open(&self.cache)?)
    }

    pub fn evaluate(
        &self,
        cache: &PeerStore,
        input: &Data,
        mode: EvaluationMode,
    ) -> std::result::Result<RemoteReport, PeerError> {
        let binding = match mode {
            EvaluationMode::Read
            | EvaluationMode::ReadReplica
            | EvaluationMode::ReadRevision(_) => &self.read,
            EvaluationMode::Update { .. } | EvaluationMode::UpdateReplica { .. } => {
                self.write.as_ref().ok_or(PeerError::Denied)?
            }
        };
        let credentials = Credentials {
            ca: self.ca.clone(),
            certificate: self.certificate.clone(),
            key: self.key.clone(),
        };
        Client::new(self.address, self.name.clone(), &credentials)?.evaluate(Evaluation {
            grant: binding.grant.parse()?,
            program: binding.program.parse()?,
            mode,
            input,
            packages: Some(cache),
        })
    }

    pub fn scope(&self, write: bool) -> Result<Hash> {
        let binding = if write {
            self.write.as_ref().ok_or(PeerError::Denied)?
        } else {
            &self.read
        };
        let holder = Credentials::fingerprint(&self.certificate)?;
        Ok(Hash::digest(&serde_json::to_vec(&(
            &self.address,
            &self.name,
            holder,
            &binding.grant,
            &binding.program,
        ))?))
    }
}

pub fn sources(files: &[(&str, &str)]) -> Result<tempfile::TempDir> {
    let dir = tempfile::tempdir()?;
    for (name, contents) in files {
        fs::write(dir.path().join(name), contents)?;
    }
    Ok(dir)
}

pub fn install(
    store: &mut PeerStore,
    source: &Path,
    aliases: &BTreeMap<String, Hash>,
) -> Result<Hash> {
    let module = JavaScript {
        source: compile_typescript(source, aliases)?,
        imports: aliases.values().copied().collect(),
    };
    let hash = store.put(&module.to_bytes()?)?;
    store.publish(hash)?;
    Ok(hash)
}

pub fn report(report: &RemoteReport) -> Result<Value> {
    Ok(json!({
        "revision": report.revision, "value": data_to_json(&report.value)?,
        "request_bytes": report.request_bytes, "response_bytes": report.response_bytes,
        "elapsed_ms": report.elapsed_ms, "worker_ms": report.worker_ms,
    }))
}
