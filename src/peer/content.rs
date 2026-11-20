use super::{PeerError, Result};
use crate::Hash;
use std::collections::BTreeSet;
pub(super) const MAGIC: &[u8; 4] = b"PPJ1";
pub(super) const MAX_MODULES: usize = 32;
pub(super) const MAX_CODE: usize = 512 * 1024;
pub(super) const MAX_BYTES: usize = 256 * 1024;

/// An ECMAScript module and its explicitly declared content-addressed imports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JavaScript {
    pub source: String,
    pub imports: BTreeSet<Hash>,
}

impl JavaScript {
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        if self.imports.len() >= MAX_MODULES {
            return Err(PeerError::Limit("module imports"));
        }
        let header = 5 + 32 * self.imports.len();
        if self.source.len() > MAX_BYTES - header {
            return Err(PeerError::Limit("module bytes"));
        }
        let mut bytes = Vec::with_capacity(header + self.source.len());
        bytes.extend(MAGIC);
        bytes.push(self.imports.len() as u8);
        for hash in &self.imports {
            bytes.extend(hash.0);
        }
        bytes.extend(self.source.as_bytes());
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if !bytes.starts_with(MAGIC) || !(5..=MAX_BYTES).contains(&bytes.len()) {
            return Err(PeerError::Invalid("invalid JavaScript block"));
        }
        let count = usize::from(bytes[4]);
        let end = 5 + 32 * count;
        if count >= MAX_MODULES || bytes.len() < end {
            return Err(PeerError::Invalid("invalid JavaScript imports"));
        }
        let mut imports = BTreeSet::new();
        for chunk in bytes[5..end].chunks_exact(32) {
            let hash = Hash(chunk.try_into().expect("chunk length is fixed"));
            if imports.last().is_some_and(|last| *last >= hash) {
                return Err(PeerError::Invalid(
                    "JavaScript imports must be sorted and unique",
                ));
            }
            imports.insert(hash);
        }
        let source = std::str::from_utf8(&bytes[end..])
            .map_err(|_| PeerError::Invalid("invalid JavaScript UTF-8"))?;
        Ok(Self {
            source: source.to_owned(),
            imports,
        })
    }
}
