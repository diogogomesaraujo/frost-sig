#![doc = include_str!("../README.md")]

use blake2::{digest::consts::U64, Blake2b, Digest};
use curve25519_dalek::{edwards::CompressedEdwardsY, EdwardsPoint, Scalar};
use message::Message;
use serde::{Deserialize, Serialize};
use std::error::Error;

pub mod keygen;
pub mod preprocess;
pub mod sign;

pub mod message;

pub mod client;
pub mod server;

pub mod nano;

#[cfg(test)]
mod test;

/// Constant context string for the hashing operations.

/// Struct that saves the constants needed for FROST. These values should be used by all participants throughout the signing session and discarted after.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FrostState {
    /// `participants` is the chosen number of participants that hold a secret share and can participate in signing operations.
    pub participants: u32,
    /// `threshold` is the minimum ammount of participants needed to sign a message.
    pub threshold: u32,
}

impl FrostState {
    /// Function that creates a new `FrostState`.
    pub fn new(participants: u32, threshold: u32) -> Self {
        Self {
            participants,
            threshold,
        }
    }

    /// Function that converts the `FrostState` to a frost state `Message`.
    pub fn to_message(self) -> Message {
        Message::FrostState {
            participants: self.participants,
            threshold: self.threshold,
        }
    }

    /// Function that converts the `FrostState` into a JSON formated `String`.
    pub fn to_json_string(&self) -> String {
        serde_json::to_string(&self).unwrap()
    }
}

/// Function that simplifies the decompresson of an ed25519 point.
pub fn decompress(
    compressed_point: &CompressedEdwardsY,
) -> Result<EdwardsPoint, Box<dyn Error + Send + Sync>> {
    match compressed_point.decompress() {
        Some(point) => Ok(point),
        None => return Err("Couldn't decompress the point.".into()),
    }
}

/// Function that hashes an array of u8 arrays using `Blake2b`.
pub fn hash_to_array(inputs: &[&[u8]]) -> [u8; 32] {
    let mut h: Blake2b<U64> = Blake2b::new();
    for i in inputs {
        h.update(i);
    }
    let hash = h.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&hash[..32]);
    output
}

/// Function that hashes a `Scalar` using `Blake2b`.
pub fn hash_to_scalar(inputs: &[&[u8]]) -> Scalar {
    let mut h: Blake2b<U64> = Blake2b::new();
    for i in inputs {
        h.update(i);
    }
    let hash = h.finalize();
    Scalar::from_bytes_mod_order_wide(&hash.into())
}
