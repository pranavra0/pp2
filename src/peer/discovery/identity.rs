use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::Path,
    sync::Arc,
};

use ring::{
    rand::SystemRandom,
    signature::{self, Ed25519KeyPair, KeyPair, UnparsedPublicKey},
};
use rustls::{
    ClientConfig,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{WebPkiSupportedAlgorithms, verify_tls13_signature},
    pki_types::{CertificateDer, ServerName},
};
use serde::{Deserialize, Serialize};

use crate::Hash;

use super::super::{PeerError, Result};

pub(in crate::peer) const IDENTITY_ALPN: &[u8] = b"pp2/identity/1";

const KEY_BYTES: u64 = 128;
const ID_DOMAIN: &[u8] = b"pp2 peer identity v1\0";

pub(super) const ADVERTISEMENT: &[u8] = b"pp2 advertisement v1\0";
pub(super) const RELAY: &[u8] = b"pp2 relay registration v1\0";

pub struct PeerIdentity(Ed25519KeyPair);

impl PeerIdentity {
    /// Creates a new identity key without replacing an existing file.
    pub fn generate(path: impl AsRef<Path>) -> Result<Hash> {
        let key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .map_err(|_| PeerError::Value("could not generate peer identity".into()))?;
        let mut file = OpenOptions::new();
        file.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            file.mode(0o600);
        }
        let mut file = file.open(path)?;
        file.write_all(key.as_ref())?;
        file.sync_all()?;
        Ok(Self::parse(key.as_ref())?.id())
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let mut bytes = Vec::new();
        File::open(path)?.take(KEY_BYTES).read_to_end(&mut bytes)?;
        Self::parse(&bytes)
    }

    fn parse(bytes: &[u8]) -> Result<Self> {
        Ed25519KeyPair::from_pkcs8(bytes)
            .map(Self)
            .map_err(|_| PeerError::Value("invalid Ed25519 identity key".into()))
    }

    pub fn id(&self) -> Hash {
        peer_id(self.public_key())
    }

    fn public_key(&self) -> &[u8] {
        self.0.public_key().as_ref()
    }

    pub(super) fn sign(&self, domain: &[u8], message: &[u8]) -> Proof {
        let signature = self.0.sign(&[domain, message].concat());
        Proof {
            key: self.public_key().try_into().expect("Ed25519 public key"),
            signature: [
                signature.as_ref()[..32].try_into().expect("signature half"),
                signature.as_ref()[32..].try_into().expect("signature half"),
            ],
        }
    }
}

fn peer_id(key: &[u8]) -> Hash {
    Hash::digest(&[ID_DOMAIN, key].concat())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct Proof {
    key: [u8; 32],
    signature: [[u8; 32]; 2],
}

impl Proof {
    pub(super) fn verify(&self, domain: &[u8], message: &[u8]) -> Result<Hash> {
        UnparsedPublicKey::new(&signature::ED25519, self.key)
            .verify(&[domain, message].concat(), self.signature.as_flattened())
            .map_err(|_| PeerError::Denied)?;
        Ok(peer_id(&self.key))
    }
}

pub(in crate::peer) fn prove_transport(
    identity: &PeerIdentity,
    stream: &mut impl Write,
    exporter: &[u8; 32],
) -> Result<()> {
    let proof = identity.sign(b"pp2 TLS identity v1\0", exporter);
    stream.write_all(&proof.key)?;
    stream.write_all(proof.signature.as_flattened())?;
    stream.flush()?;
    Ok(())
}

pub(in crate::peer) fn verify_transport(
    stream: &mut impl Read,
    exporter: &[u8; 32],
) -> Result<Hash> {
    let mut proof = Proof {
        key: [0; 32],
        signature: [[0; 32]; 2],
    };
    stream.read_exact(&mut proof.key)?;
    stream.read_exact(proof.signature.as_flattened_mut())?;
    proof.verify(b"pp2 TLS identity v1\0", exporter)
}

// The certificate establishes the encrypted channel. The signed TLS exporter
// binds the expected pp2 identity to that exact channel before a request is sent.
#[derive(Debug)]
struct TransportCertificate(WebPkiSupportedAlgorithms);

impl ServerCertVerifier for TransportCertificate {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("pp2 requires TLS 1.3".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, signature, &self.0)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.supported_schemes()
    }
}

pub(super) fn client_tls() -> ClientConfig {
    let provider = rustls::crypto::ring::default_provider();
    let verifier = TransportCertificate(provider.signature_verification_algorithms);
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("ring supports TLS 1.3")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    config.alpn_protocols = vec![IDENTITY_ALPN.to_vec()];
    config.resumption = rustls::client::Resumption::disabled();
    config
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_proof_is_bound_to_the_exporter() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("identity.key");
        let expected = PeerIdentity::generate(&key).unwrap();
        let identity = PeerIdentity::load(&key).unwrap();
        let mut proof = Vec::new();
        prove_transport(&identity, &mut proof, &[1; 32]).unwrap();
        assert_eq!(
            verify_transport(&mut proof.as_slice(), &[1; 32]).unwrap(),
            expected
        );
        assert!(verify_transport(&mut proof.as_slice(), &[2; 32]).is_err());
    }
}
