//! Implementation of the Nano Node RPC communication.
//!
//! # Dependencies
//!
//! - `blake2` is an implementation of the BLAKE2 hash functions.
//! - `reqwest` is a crate that provides a convenient, higher-level HTTP Client.
//!
//! # Features
//!
//! - Sign transactions in Nano.
//! - See nano's account information.
//!
//! # Support
//!
//! See the [resources](https://docs.nano.org/integration-guides/) here.
pub mod sign {
    use super::rpc::{self, AccountKey};
    use blake2::{
        digest::{Update, VariableOutput},
        Blake2bVar,
    };
    use serde::{Deserialize, Serialize};
    use std::error::Error;

    /// Enum that represents the type of transactions that can be made with Nano.
    #[derive(Serialize, Deserialize, Debug)]
    pub enum Subtype {
        SEND,
        RECEIVE,
        OPEN,
    }

    impl Subtype {
        /// Function that converts the `Subtype` enum to string format.
        pub fn as_str(&self) -> &str {
            match self {
                Self::SEND => "send",
                Self::RECEIVE => "receive",
                Self::OPEN => "open",
            }
        }
    }

    /// Struct that represents a block that has yet to be signed by the FROST signature squeme.
    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub struct UnsignedBlock {
        pub r#type: String,
        pub account: String,
        pub previous: String,
        pub representative: String,
        pub balance: String,
        pub link: String,
    }

    impl UnsignedBlock {
        /// Function that creates a new `Unsigned Block`.
        pub fn new(
            account: String,
            previous: String,
            representative: String,
            balance: String,
            link: String,
        ) -> Self {
            Self {
                r#type: "state".to_string(),
                account,
                previous,
                representative,
                balance,
                link,
            }
        }

        /// Function that creates an empty `UnsignedBlock`.
        pub fn empty() -> Self {
            Self::new(
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
            )
        }

        /// Function that hashes an `UnsignedBlock` before signing.
        pub async fn to_hash(self, state: &rpc::RPCState) -> Result<String, Box<dyn Error>> {
            let mut block_state = [0u8; 32];
            block_state[31] = 6 as u8;
            let account = hex::decode(AccountKey::get_from_rpc(state, &self.account).await?.key)?;
            let representative = hex::decode(
                AccountKey::get_from_rpc(state, &self.representative)
                    .await?
                    .key,
            )?;
            let previous = match self.previous.as_str() {
                "0" => {
                    hex::decode("0000000000000000000000000000000000000000000000000000000000000000")?
                }
                _ => hex::decode(self.previous)?,
            };
            let link = hex::decode(self.link)?;
            let balance = self.balance.parse::<u128>()?.to_be_bytes();
            let mut hasher = Blake2bVar::new(32).unwrap();
            hasher.update(&block_state);
            hasher.update(&account);
            hasher.update(&previous);
            hasher.update(&representative);
            hasher.update(&balance);
            hasher.update(&link);
            let mut bytes = [0u8; 32];
            hasher.finalize_variable(&mut bytes).unwrap();
            Ok(hex::encode(&bytes))
        }

        /// Function that signs an `UnsignedBlock` with a signature and a proof of work.
        pub fn to_signed_block(self, signature: &str, work: &str) -> SignedBlock {
            SignedBlock::new(
                self.previous,
                self.account,
                self.representative,
                self.balance,
                self.link,
                signature.to_string(),
                work.to_string(),
            )
        }

        /// Function that creates a new block in the Nano blockchain that will open the account.
        pub async fn create_open(
            state: &rpc::RPCState,
            account_address: &str,
        ) -> Result<Self, Box<dyn std::error::Error>> {
            let receivable = rpc::Receivable::get_from_rpc(&state, account_address, 1).await?;
            let block = rpc::BlockInfo::get_from_rpc(&state, &receivable.blocks[0]).await?;

            let account = account_address.to_string();
            let previous = "0".to_string();
            let representative = account_address.to_string();
            let balance = block.amount;
            let link = receivable.blocks[0].clone();

            Ok(UnsignedBlock::new(
                account,
                previous,
                representative,
                balance,
                link,
            ))
        }

        pub async fn create_receive(
            state: &rpc::RPCState,
            account_address: &str,
        ) -> Result<Self, Box<dyn std::error::Error>> {
            let receivable = rpc::Receivable::get_from_rpc(&state, account_address, 1).await?;
            let block = rpc::BlockInfo::get_from_rpc(&state, &receivable.blocks[0]).await?;
            let previous = rpc::AccountInfo::get_from_rpc(&state, account_address)
                .await?
                .frontier;
            let account = account_address.to_string();
            let representative = account_address.to_string();
            let balance = rpc::AccountBalance::get_from_rpc(&state, &account_address)
                .await?
                .balance
                .parse::<u128>()?
                + block.amount.parse::<u128>()?;
            let link = receivable.blocks[0].clone();

            Ok(UnsignedBlock::new(
                account,
                previous,
                representative,
                balance.to_string(),
                link,
            ))
        }
        pub async fn create_send(
            state: &rpc::RPCState,
            own_account_address: &str,
            receiver_account_address: &str,
            amount_nano: &f64,
        ) -> Result<Self, Box<dyn std::error::Error>> {
            let ammount_raw = rpc::NanoToRaw::get_from_rpc(&state, &amount_nano)
                .await?
                .raw;
            let previous = rpc::AccountInfo::get_from_rpc(&state, own_account_address)
                .await?
                .frontier;
            let account = own_account_address.to_string();
            let representative = own_account_address.to_string();
            let balance = rpc::AccountBalance::get_from_rpc(&state, &own_account_address)
                .await?
                .balance
                .parse::<u128>()?
                - ammount_raw.parse::<u128>()?;
            let link = AccountKey::get_from_rpc(&state, receiver_account_address)
                .await?
                .key;

            Ok(UnsignedBlock::new(
                account,
                previous,
                representative,
                balance.to_string(),
                link,
            ))
        }
    }

    /// Struct that represents a `SignedBlock` that will be hashed and stored in the Nano blockchain.
    #[derive(Serialize, Deserialize)]
    pub struct SignedBlock {
        pub r#type: String,
        pub previous: String,
        pub account: String,
        pub representative: String,
        pub balance: String,
        pub link: String,
        pub signature: String,
        pub work: String,
    }

    impl SignedBlock {
        /// Function that creates a new `SignedBlock`.
        pub fn new(
            previous: String,
            account: String,
            representative: String,
            balance: String,
            link: String,
            signature: String,
            work: String,
        ) -> Self {
            Self {
                r#type: "state".to_string(),
                previous,
                account,
                representative,
                balance,
                link,
                signature,
                work,
            }
        }
    }

    /// Function that creates a new signed block with a valid signature and work.
    pub async fn create_signed_block(
        state: &rpc::RPCState,
        unsigned_block: UnsignedBlock,
        signature: &str,
        aggregate_public_key: &str,
    ) -> Result<SignedBlock, Box<dyn Error>> {
        let work = super::rpc::WorkGenerate::get_from_rpc(
            &state,
            match unsigned_block.previous.as_str() {
                "0" => aggregate_public_key,
                previous => previous,
            },
            &std::env::var("KEY")?,
        )
        .await?;
        Ok(unsigned_block.to_signed_block(&signature, &work.work))
    }
}

pub mod account {

    use blake2::{
        digest::{Update, VariableOutput},
        Blake2bVar,
    };
    use primitive_types::U512;

    /// Constant values to convert a public key into a Nano account address.
    const ACCOUNT_LOOKUP: &[char] = &[
        '1', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
        'k', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'w', 'x', 'y', 'z',
    ];

    /// Function that maps the public key to values in the lookup table.
    fn account_encode(value: u8) -> char {
        ACCOUNT_LOOKUP[value as usize]
    }

    /// Function that calculates the checksum that will be appended to the Nano account address.
    fn account_checksum(aggregate_public_key: &[u8; 32]) -> [u8; 5] {
        let mut check = [0u8; 5];
        let mut blake = Blake2bVar::new(check.len()).unwrap();
        blake.update(aggregate_public_key);
        blake.finalize_variable(&mut check).unwrap();
        check
    }

    /// Function that converts a 32 bytes public key into a Nano account address.
    pub fn public_key_to_nano_account(aggregate_public_key: &[u8; 32]) -> String {
        let mut number = U512::from_big_endian(aggregate_public_key);
        let check = U512::from_little_endian(&account_checksum(aggregate_public_key));
        number <<= 40;
        number |= check;
        let mut result = String::with_capacity(65);
        for _i in 0..60 {
            let r = number.byte(0) & 0x1f_u8;
            number >>= 5;
            result.push(account_encode(r));
        }
        result.push_str("_onan");
        result.chars().rev().collect()
    }
}

pub mod rpc {
    use reqwest::Client;
    use serde::{de::DeserializeOwned, Deserialize, Serialize};
    use serde_json::{json, Value};
    use std::error::Error;

    /// Struct that represents the state of the rpc the client will communicate with.
    pub struct RPCState {
        pub url: String,
        pub client: Client,
    }

    impl RPCState {
        /// Function that creates a new `RPCState`.
        pub fn new(url: &str) -> Self {
            Self {
                client: Client::new(),
                url: url.to_string(),
            }
        }

        /// Function to handle requests to the RPC. All of them are POST requests with different bodies.
        pub async fn request<T: DeserializeOwned>(
            &self,
            data: &Value,
        ) -> Result<T, Box<dyn Error>> {
            Ok(self
                .client
                .post(&self.url)
                .json(&data)
                .send()
                .await?
                .json::<T>()
                .await?)
        }
    }

    /// Struct that represents the result of Nano's nano_to_raw action.
    #[derive(Serialize, Deserialize)]
    pub struct NanoToRaw {
        pub raw: String,
    }

    impl NanoToRaw {
        pub async fn get_from_rpc(
            state: &RPCState,
            amount_nano: &f64,
        ) -> Result<Self, Box<dyn Error>> {
            let data = json!({
                "action": "nano_to_raw",
                "amount": amount_nano.to_string()
            });
            state.request::<Self>(&data).await
        }
    }

    /// Struct that represents the result of Nano's account_info action.
    #[derive(Serialize, Deserialize)]
    pub struct AccountInfo {
        pub frontier: String,
        pub open_block: String,
        pub representative_block: String,
        pub balance: String,
    }

    impl AccountInfo {
        /// Function that gets the `AccountInfo` from the rpc.
        pub async fn get_from_rpc(
            state: &RPCState,
            account_address: &str,
        ) -> Result<Self, Box<dyn Error>> {
            let data = json!({
                "action": "account_info",
                "account": account_address
            });
            state.request::<Self>(&data).await
        }
    }

    /// Struct that represents the result of Nano's account_balance action.
    #[derive(Serialize, Deserialize)]
    pub struct AccountBalance {
        pub balance: String,
        pub pending: String,
        pub receivable: String,
        pub balance_nano: String,
        pub pending_nano: String,
        pub receivable_nano: String,
    }

    impl AccountBalance {
        /// Function that gets the `AccountBalance` from the rpc.
        pub async fn get_from_rpc(
            state: &RPCState,
            account_address: &str,
        ) -> Result<Self, Box<dyn Error>> {
            let data = json!({
                "action": "account_balance",
                "account": account_address
            });
            state.request::<Self>(&data).await
        }
    }

    /// Struct that represents the result of Nano's account_key action.
    #[derive(Serialize, Deserialize)]
    pub struct AccountKey {
        pub key: String,
    }

    impl AccountKey {
        /// Function that gets the `AccountKey` from the rpc.
        pub async fn get_from_rpc(
            state: &RPCState,
            nano_account: &str,
        ) -> Result<Self, Box<dyn Error>> {
            let data = json!({
                "action": "account_key",
                "account": nano_account
            });
            state.request::<Self>(&data).await
        }
    }

    /// Struct that represents the result of Nano's work_generate action.
    #[derive(Serialize, Deserialize)]
    pub struct WorkGenerate {
        pub work: String,
        pub frontier: String,
    }

    impl WorkGenerate {
        /// Function that gets the `WorkGenerate` from the rpc.
        pub async fn get_from_rpc(
            state: &RPCState,
            hash: &str,
            key: &str,
        ) -> Result<Self, Box<dyn Error>> {
            let data = json!({
                "action": "work_generate",
                "hash": hash,
                "key": key
            });
            state.request::<Self>(&data).await
        }
    }

    /// Struct that represents the result of Nano's receivable action.
    #[derive(Serialize, Deserialize, Debug)]
    pub struct Receivable {
        pub blocks: Vec<String>,
    }

    impl Receivable {
        /// Function that gets the `Receivable` from the rpc.
        pub async fn get_from_rpc(
            state: &RPCState,
            account_address: &str,
            count: u32,
        ) -> Result<Self, Box<dyn Error>> {
            let data = json!({
                "action": "receivable",
                "account": account_address,
                "count": count.to_string()
            });
            state.request::<Self>(&data).await
        }
    }

    /// Struct that represents the result of Nano's `block_info` action.
    #[derive(Serialize, Deserialize)]
    pub struct BlockInfo {
        pub block_account: String,
        pub amount: String,
    }

    impl BlockInfo {
        /// Function that gets the `BlockInfo` from the rpc.
        pub async fn get_from_rpc(state: &RPCState, hash: &str) -> Result<Self, Box<dyn Error>> {
            let data = json!({
                "action": "block_info",
                "hash": hash,
            });
            state.request::<Self>(&data).await
        }
    }

    /// Struct that represents the result of Nano's `process` action.
    #[derive(Serialize, Deserialize)]
    pub struct Process {
        pub hash: String,
    }

    impl Process {
        /// Function that processes a `SignedBlock` in the rpc.
        pub async fn sign_in_rpc(
            state: &RPCState,
            subtype: &super::sign::Subtype,
            signed_block: &super::sign::SignedBlock,
        ) -> Result<Self, Box<dyn Error>> {
            let data = json!({
                "action": "process",
                "subtype": subtype.as_str(),
                "json_block": "true",
                "block": &signed_block
            });
            println!("{data}");
            state.request::<Self>(&data).await
        }
    }

    #[tokio::test]
    async fn test_rpc_receive() -> Result<(), Box<dyn Error>> {
        // load the enviroment variables
        dotenv::dotenv().ok();

        // the account to create the open/receive block
        let account = "nano_1smubapuampnxtq14taxt8c9rc5f97hj7e8kqer4u6p94cre5g6qq3yxa4f3";

        // the state of the RPC with the Nano node chosen
        let state = RPCState::new(&std::env::var("URL")?);

        // the unsigned block created and that will be signed
        let unsigned_block =
            crate::nano::sign::UnsignedBlock::create_open(&state, &account).await?;

        println!("{}", serde_json::to_string(&unsigned_block)?);
        assert!(true);

        Ok(())
    }

    #[tokio::test]
    async fn test_rpc_send() -> Result<(), Box<dyn Error>> {
        // load the enviroment variables
        dotenv::dotenv().ok();

        // the account to create the send block
        let sender = "nano_1smubapuampnxtq14taxt8c9rc5f97hj7e8kqer4u6p94cre5g6qq3yxa4f3";

        // the account that will receive
        let receiver = "nano_19kqrk7taqnprmy1hcchpkdcpfqnpm7knwdhn9qafhd7b94s99ofngf5ent1";

        // the state of the RPC with the Nano node chosen
        let state = RPCState::new(&std::env::var("URL")?);

        // the unsigned block created and that will be signed
        let unsigned_block =
            crate::nano::sign::UnsignedBlock::create_send(&state, &sender, &receiver, &0.00005)
                .await?;

        println!("{}", serde_json::to_string(&unsigned_block)?);
        assert!(true);

        Ok(())
    }
}
