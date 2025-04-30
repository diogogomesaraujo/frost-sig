//! # frost-sig
//!
//! `frost-sig` is a threshold signature library that implements the FROST protocol.
//!
//! ## Features
//!
//! - Key Generation.
//! - Preprocessing.
//! - Signing Transactions.
//! - Servers/Clients to use the protocol in a pratical setting.
//!
//! ## Dependencies
//!
//! - `rug` is a arbitrary precision numbers crate and provides infrastructure for the 256bit numbers and calculations.
//! - `rand` is a random number generation crate and it is used to generate a random seed for the 256bit numbers generation.
//! - `sha-256` is an implementation of SHA-256 and it is the predefined hashing algorythm for the threshold signature system.
//! - `tokio` an async runtime for Rust.
//! - `serde` a crate to serialize and deserialize JSON.
//!
//! ## Requirements
//!
//! - Cargo installed
//!
//! ## Example
//! ```
//! use frost_sig::*;
//! use std::error::Error;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn Error>> {
//!     let mode = std::env::args()
//!         .nth(1)
//!         .expect("Failed to give enough arguments.");
//!     let operation = std::env::args()
//!         .nth(2)
//!         .expect("Failed to give enough arguments.");
//!
//!     match (mode.as_str(), operation.as_str()) {
//!         ("server", "keygen") => {
//!             server::keygen_server::run("localhost", 3333, 3, 2).await?;
//!         }
//!         ("client", "keygen") => {
//!             let path = std::env::args()
//!                 .nth(3)
//!                 .expect("Failed to give enough arguments.");
//!             client::keygen_client::run("localhost", 3333, &path).await?;
//!         }
//!         ("server", "sign") => {
//!             server::sign_server::run("localhost", 3333, 3, 2)
//!                 .await
//!                 .unwrap();
//!         }
//!         ("client", "sign") => {
//!             let path = std::env::args()
//!                 .nth(3)
//!                 .expect("Failed to give enough arguments.");
//!             client::sign_client::run("localhost", 3333, &path).await?;
//!         }
//!         _ => {
//!             eprintln!("Invalid arguments.");
//!         }
//!     }
//!
//!     Ok(())
//! }
//!```
//!
//! ## Support
//!
//! See the [resources](https://eprint.iacr.org/2020/852.pdf) here.

use message::Message;
use serde::{Deserialize, Serialize};

pub mod keygen;
pub mod preprocess;
pub mod sign;

// pub mod modular;

pub mod message;

#[cfg(test)]
pub mod test;

pub mod client;
pub mod server;

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
