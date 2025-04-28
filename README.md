  # frost-sig

  `frost-sig` is a threshold signature library that implements the FROST protocol.

  ## Features

  - Key Generation.
  - Preprocessing.
  - Signing Transactions.
  - Servers/Clients to use the protocol in a pratical setting.

  ## Usage Flow

  ![Activity Diagrams](./assets/frost-server.jpg)

  ## Dependencies

  - `rug` is a arbitrary precision numbers crate and provides infrastructure for the 256bit numbers and calculations.
  - `rand` is a random number generation crate and it is used to generate a random seed for the 256bit numbers generation.
  - `sha-256` is an implementation of SHA-256 and it is the predefined hashing algorythm for the threshold signature system.
  - `tokio` is an async runtime for Rust.
  - `serde` is a crate to serialize and deserialize JSON.

  ## Requirements

  - Cargo installed

  ## Example
  ```Rust
  use frost_sig::*;
  use std::error::Error;

  #[tokio::main]
  async fn main() -> Result<(), Box<dyn Error>> {
      let mode = std::env::args()
          .nth(1)
          .expect("Failed to give enough arguments.");
      let operation = std::env::args()
          .nth(2)
          .expect("Failed to give enough arguments.");

      match (mode.as_str(), operation.as_str()) {
          ("server", "keygen") => {
              let p = std::env::args()
                  .nth(3)
                  .expect("Failed to give enough arguments.")
                  .parse::<u32>()
                  .expect("Invalid arguments.");
              let t = std::env::args()
                  .nth(4)
                  .expect("Failed to give enough arguments.")
                  .parse::<u32>()
                  .expect("Invalid arguments.");
              server::keygen_server::run("localhost", 3333, p, t).await?;
          }
          ("client", "keygen") => {
              let path = std::env::args()
                  .nth(3)
                  .expect("Failed to give enough arguments.");
              client::keygen_client::run("localhost", 3333, &path).await?;
          }
          ("server", "sign") => {
              let p = std::env::args()
                  .nth(3)
                  .expect("Failed to give enough arguments.")
                  .parse::<u32>()
                  .expect("Invalid arguments.");
              let t = std::env::args()
                  .nth(4)
                  .expect("Failed to give enough arguments.")
                  .parse::<u32>()
                  .expect("Invalid arguments.");
              server::sign_server::run("localhost", 3333, p, t)
                  .await
                  .unwrap();
          }
          ("client", "sign") => {
              let path = std::env::args()
                  .nth(3)
                  .expect("Failed to give enough arguments.");
              client::sign_client::run("localhost", 3333, &path).await?;
          }
          _ => {
              eprintln!("Invalid arguments.");
          }
      }

      Ok(())
  }
 ```

  ## Support

  See the [resources](https://eprint.iacr.org/2020/852.pdf) here.
