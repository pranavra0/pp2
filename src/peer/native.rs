use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{Block, Data, Hash};

use super::{
    Access, Binding, Client, GraphBudget, HostProvider, HostResource, PeerError, PeerStore, Result,
    content::{self, load_code},
    data_to_json, protocol, validate_binding_names,
};

pub(super) const MAGIC: &[u8; 4] = b"PPA1";
pub(super) const STATE: &str = "state";
const TERMINAL: &str = "terminal";
const MAX_LABEL: usize = 160;
const MAX_EVENT: usize = 4096;

/// An immutable terminal application package. Every installation owns a private collection.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativePackage {
    pub name: String,
    #[serde(with = "hash_text")]
    pub entry: Hash,
    pub budget: GraphBudget,
    pub bindings: BTreeMap<String, RequestedBinding>,
}

/// A named operation program and the collection access it needs at its issuing peer.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequestedBinding {
    pub description: String,
    #[serde(with = "hash_text")]
    pub program: Hash,
    pub access: Access,
}

/// An installation ID persists across updates and identifies its private collection.
#[derive(Debug)]
pub struct NativeInstallation {
    pub id: Hash,
    pub package: Hash,
    pub manifest: NativePackage,
    pub bindings: BTreeMap<String, Binding>,
}

impl NativePackage {
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = MAGIC.to_vec();
        bytes.extend(protocol::encode(self)?);
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > Block::MAX_BYTES || !bytes.starts_with(MAGIC) {
            return Err(PeerError::Value("expected a native package".into()));
        }
        let package: Self = protocol::decode(&bytes[MAGIC.len()..])?;
        if package.to_bytes()? != bytes {
            return Err(PeerError::Value("noncanonical native package".into()));
        }
        Ok(package)
    }

    /// Returns the distinct entry and binding programs referenced by this package.
    pub fn programs(&self) -> BTreeSet<Hash> {
        std::iter::once(self.entry)
            .chain(self.bindings.values().map(|binding| binding.program))
            .collect()
    }

    fn validate(&self) -> Result<()> {
        self.budget.validate()?;
        let mut names = vec![STATE.to_owned()];
        names.extend(self.bindings.keys().cloned());
        validate_binding_names(&names)?;
        if std::iter::once(&self.name)
            .chain(self.bindings.values().map(|binding| &binding.description))
            .any(|label| {
                label.trim().is_empty()
                    || label.len() > MAX_LABEL
                    || label.chars().any(char::is_control)
            })
        {
            return Err(PeerError::Value(
                "invalid package name or capability description".into(),
            ));
        }
        Ok(())
    }

    /// Fetches by hash through the local cache and explicitly selected authenticated peers.
    pub fn fetch(cache: &mut PeerStore, sources: &[Client], hash: Hash) -> Result<Self> {
        let package = Self::from_bytes(&Client::fetch_into(cache, sources, hash)?)?;
        for program in package.programs() {
            Self::load_program(program, |hash| {
                Client::fetch_into(cache, sources, hash).map(Some)
            })?;
        }
        Ok(package)
    }

    pub(super) fn load_program(
        program: Hash,
        get: impl FnMut(Hash) -> Result<Option<Vec<u8>>>,
    ) -> Result<Vec<(Hash, Vec<u8>)>> {
        let code = load_code(program, false, get)?;
        if !code[0].1.starts_with(content::MAGIC) {
            return Err(PeerError::Value(
                "native packages require JavaScript programs".into(),
            ));
        }
        Ok(code)
    }
}

/// A terminal invocation can return up to 64 lines, with at most 16 KiB of text.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalResult {
    pub lines: Vec<String>,
}

impl TerminalResult {
    pub fn from_data(data: &Data) -> Result<Self> {
        let result: Self = serde_json::from_value(data_to_json(data)?)
            .map_err(|_| PeerError::Value("expected a terminal result with text lines".into()))?;
        if result.lines.len() > 64
            || result.lines.iter().map(String::len).sum::<usize>() > 16 * 1024
            || result.lines.iter().any(|line| line.contains(['\r', '\n']))
        {
            return Err(PeerError::Limit("terminal result"));
        }
        Ok(result)
    }
}

pub(super) fn terminal_event(line: &str) -> Result<HostResource> {
    if line.len() > MAX_EVENT || line.contains(['\r', '\n']) {
        return Err(PeerError::Limit("terminal event"));
    }
    let id = super::random_id()?;
    Ok(HostResource {
        provider: TERMINAL.into(),
        configuration: Data::Record(BTreeMap::from([
            ("type".into(), Data::Text("line".into())),
            ("id".into(), Data::Text(id.to_string())),
            ("text".into(), Data::Text(line.into())),
        ])),
    })
}

pub(super) struct Terminal;

impl HostProvider for Terminal {
    fn read(
        &self,
        event: &Data,
        operation: &str,
        input: Data,
        check: &dyn Fn() -> Result<()>,
    ) -> Result<Data> {
        check()?;
        if operation != "event" || input != Data::Nil {
            return Err(PeerError::Denied);
        }
        Ok(event.clone())
    }
}

mod hash_text {
    use crate::Hash;
    use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error};

    pub fn serialize<S: Serializer>(hash: &Hash, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.collect_str(hash)
        } else {
            hash.serialize(serializer)
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Hash, D::Error> {
        if deserializer.is_human_readable() {
            String::deserialize(deserializer)?
                .parse()
                .map_err(D::Error::custom)
        } else {
            Hash::deserialize(deserializer)
        }
    }
}
