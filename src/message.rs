//! Implementation of the messages that are sent and received.
//!
//! # Dependencies
//!
//! - `rug` is a arbitrary precision numbers crate and provides infrastructure for the 256bit numbers and calculations.
//! - `serde` is a crate to serialize and deserialize JSON.
//!
//! # Features
//!
//! - `Message` Enum.
//! - `MessageJSON` Enum.
//! - Conversions from `Message` into a JSON formated `String` and the other way arround.

use std::error::Error;

use curve25519_dalek::{edwards::CompressedEdwardsY, Scalar};
use serde::{Deserialize, Serialize};

/// Enum that represents all the messages that will be sent during the FROST protocol operations.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Message {
    /// Message utilized during the keygen round 1 phase.
    /// It represents the commitments and signature used to validate a user and create the aggregate public key.
    Broadcast {
        participant_id: u32,
        commitments: Vec<CompressedEdwardsY>,
        signature: (Scalar, Scalar),
    },

    /// Message that is sent during the keygen round 2 phase.
    /// It represents the secret sent from every participant to all others and it is used to calculate a participant's private key.
    SecretShare {
        sender_id: u32,
        receiver_id: u32,
        secret: Scalar,
    },

    /// Message that is sent during the signature phase.
    /// It is used by the main participant (SA) for others to verify the commitments chosen by the SA.
    PublicCommitment {
        participant_id: u32,
        di: CompressedEdwardsY,
        ei: CompressedEdwardsY,
        public_share: CompressedEdwardsY,
    },

    /// Message that is sent during the signature phase.
    /// It is used to compute the aggregate response and is sent by every participant to the SA.
    Response { sender_id: u32, value: Scalar },

    /// Message that is sent at the beginning of a FROST operation.
    /// It is used to do all the calculations needed for all the FROST operations.
    FrostState { participants: u32, threshold: u32 },

    /// Message that is sent at the begging of the Frost sign operation.
    /// It is used to atribute a temporary id to identify the participant as the operation is happening.
    Id(u32),
}

impl Message {
    /// Function that converts a `Message` into a JSON formated `String`.
    pub fn to_json_string(&self) -> Result<String, Box<dyn Error>> {
        Ok(serde_json::to_string(&self)?)
    }

    /// Function that convert a JSON formated `String` into a `Message`.
    pub fn from_json_string(message: &str) -> Option<Message> {
        match serde_json::from_str::<Message>(&message) {
            Ok(message) => Some(message),
            Err(_) => None,
        }
    }
}
