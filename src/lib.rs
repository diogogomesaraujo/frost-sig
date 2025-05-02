//! # frost-sig
//!
//! `frost-sig` is a threshold signature library that implements the FROST protocol.
//!
//! It uses [Risttretto](https://ristretto.group/) elliptic curve cryptography and the [Blake2](https://www.blake2.net/) hashing algorythm for computations.
//!
//! ## Features
//!
//! - Key Generation.
//! - Preprocessing.
//! - Signing Transactions.
//! - Servers/Clients to use the protocol in a pratical setting.
//!
//! ## Usage Flow
//!
//! ![Activity Diagrams](./doc/assets/frost-server.jpg)
//!
//! ## Dependencies
//!
//! - `curve25519_dalek` is a crate for elliptic curve cryptography.
//! - `rand` is a random number generation crate and it is used to generate a random seed for the 256bit numbers generation.
//! - `serde` is a framework for serializing and deserializing Rust data structures efficiently and generically.
//! - `tokio` is a runtime for writting reliable async Rust code.
//!
//! ## Requirements
//!
//! - Cargo installed
//!
//! ## Example
//! ```rust
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
//!             let p = std::env::args()
//!                 .nth(3)
//!                 .expect("Failed to give enough arguments.")
//!                 .parse::<u32>()
//!                 .expect("Invalid arguments.");
//!             let t = std::env::args()
//!                 .nth(4)
//!                 .expect("Failed to give enough arguments.")
//!                 .parse::<u32>()
//!                 .expect("Invalid arguments.");
//!             server::keygen_server::run("localhost", 3333, p, t).await?;
//!         }
//!         ("client", "keygen") => {
//!             let path = std::env::args()
//!                 .nth(3)
//!                 .expect("Failed to give enough arguments.");
//!             client::keygen_client::run("localhost", 3333, &path).await?;
//!         }
//!         ("server", "sign") => {
//!             let p = std::env::args()
//!                 .nth(3)
//!                 .expect("Failed to give enough arguments.")
//!                 .parse::<u32>()
//!                 .expect("Invalid arguments.");
//!             let t = std::env::args()
//!                 .nth(4)
//!                 .expect("Failed to give enough arguments.")
//!                 .parse::<u32>()
//!                 .expect("Invalid arguments.");
//!             server::sign_server::run("localhost", 3333, p, t)
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
//! ```
//!
//! ## Support
//!
//! See the [resources](https://eprint.iacr.org/2020/852.pdf) here.

use message::Message;
use serde::{Deserialize, Serialize};

pub mod keygen;
pub mod preprocess;
pub mod sign;

pub mod message;

pub mod client;
pub mod server;

#[cfg(test)]
mod test;

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
