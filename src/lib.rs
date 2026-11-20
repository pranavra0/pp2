pub mod peer;
use peer::{PeerError, Result};
use sha2::{Digest, Sha256};
use std::{fmt, str::FromStr};
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    pub fn digest(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(out, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for Hash {
    type Err = PeerError;

    fn from_str(input: &str) -> Result<Self> {
        if input.len() != 64 || !input.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(PeerError::Invalid(
                "expected a 64-character hexadecimal hash",
            ));
        }
        let mut bytes = [0; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&input[index * 2..index * 2 + 2], 16)
                .map_err(|_| PeerError::Invalid("invalid hexadecimal hash"))?;
        }
        Ok(Self(bytes))
    }
}
