use super::{PeerError, Result};
use serde::{Serialize, de::DeserializeOwned};
use std::io::{Read, Write};
const MAGIC: &[u8; 4] = b"PPN2";
const MAX_FRAME: usize = 1028 * 1024;

pub(super) fn encode(value: &impl Serialize) -> Result<Vec<u8>> {
    postcard::to_allocvec(value).map_err(|err| PeerError::Protocol(err.to_string()))
}

pub(super) fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let (value, rest) =
        postcard::take_from_bytes(bytes).map_err(|err| PeerError::Protocol(err.to_string()))?;
    if !rest.is_empty() {
        return Err(PeerError::Protocol("trailing bytes".into()));
    }
    Ok(value)
}

pub(super) fn send(out: &mut impl Write, value: &impl Serialize) -> Result<()> {
    let payload = encode(value)?;
    if payload.len() > MAX_FRAME {
        return Err(PeerError::Limit("frame bytes"));
    }
    let mut header = [0; 8];
    header[..4].copy_from_slice(MAGIC);
    header[4..].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    out.write_all(&header)?;
    out.write_all(&payload)?;
    out.flush()?;
    Ok(())
}

pub(super) fn receive<T: DeserializeOwned>(input: &mut impl Read) -> Result<T> {
    let mut header = [0; 8];
    input.read_exact(&mut header)?;
    if &header[..4] != MAGIC {
        return Err(PeerError::Protocol("unknown protocol version".into()));
    }
    let len = u32::from_be_bytes(header[4..].try_into().expect("header length is fixed")) as usize;
    if len > MAX_FRAME {
        return Err(PeerError::Limit("frame bytes"));
    }
    let mut bytes = vec![0; len];
    input.read_exact(&mut bytes)?;
    decode(&bytes)
}
