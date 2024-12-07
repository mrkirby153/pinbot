// Derived from https://github.com/serenity-rs/serenity/blob/d6b9b287d4f72aca511f22163c89ff70264ac3f0/src/interactions_endpoint.rs

use anyhow::{anyhow, Result};
use thiserror::Error;

fn parse_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 {
        return None;
    }

    let mut result = [0; N];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        result[i] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).ok()?;
    }

    Some(result)
}

#[derive(Debug)]
pub struct InvalidKey(ed25519_dalek::SignatureError);

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid signature")]
    InvalidSignature,
}

#[derive(Clone)]
pub struct Verifier {
    key: ed25519_dalek::VerifyingKey,
}

impl Verifier {
    pub fn new(public_key: &str) -> Self {
        Self::try_new(parse_hex(public_key).expect("cannot decode public key"))
            .expect("invalid public key")
    }

    pub fn try_new(public_key: [u8; 32]) -> Result<Self, InvalidKey> {
        Ok(Self {
            key: ed25519_dalek::VerifyingKey::from_bytes(&public_key).map_err(InvalidKey)?,
        })
    }

    pub fn verify(&self, signature: &str, timestamp: &str, body: &[u8]) -> Result<()> {
        use ed25519_dalek::Verifier as _;
        let signature_bytes = parse_hex(signature).ok_or(Error::InvalidSignature)?;
        let signature = ed25519_dalek::Signature::from_bytes(&signature_bytes);
        let to_verify = [timestamp.as_bytes(), body].concat();
        self.key
            .verify(&to_verify, &signature)
            .map_err(|_| anyhow!(Error::InvalidSignature))
    }
}
