pub mod sign {
    use serde::{Deserialize, Serialize};

    use super::rpc;

    #[derive(Serialize, Deserialize)]
    pub struct UnsignedBlock {
        pub r#type: String,
        pub account: String,
        pub previous: String,
        pub representative: String,
        pub balance: String,
        pub link: String,
        pub link_as_account: String,
    }

    impl UnsignedBlock {
        pub fn new(
            account: String,
            previous: String,
            representative: String,
            balance: String,
            link: String,
            link_as_account: String,
        ) -> Self {
            Self {
                r#type: "state".to_string(),
                account,
                previous,
                representative,
                balance,
                link,
                link_as_account,
            }
        }

        pub async fn create_open(
            state: &rpc::RPCState,
            account_address: &str,
        ) -> Result<Self, Box<dyn std::error::Error>> {
            let recievable = rpc::Receivable::get_from_rpc(&state, account_address, 1).await?;
            let block = rpc::BlockInfo::get_from_rpc(&state, &recievable.blocks[0]).await?;

            let account = account_address.to_string();
            let previous = "0".to_string();
            let representative = std::env::var("REPRESENTATIVE")?;
            let balance = block.amount;
            let link = recievable.blocks[0].clone();
            let link_as_account = block.block_account;

            Ok(UnsignedBlock::new(
                account,
                previous,
                representative,
                balance,
                link,
                link_as_account,
            ))
        }
    }

    #[derive(Serialize, Deserialize)]
    pub struct SignedBlock {
        pub block_type: String,
        pub previous_block: String,
        pub account_id: String,
        pub representative: String,
        pub balance: String,
        pub link: String,
        pub link_as_account: String,
        pub signature: String,
        pub work: String,
        pub subtype: Option<String>,
    }

    impl SignedBlock {
        pub fn new() {}
    }
}

pub mod account {
    use blake2::{
        digest::{Update, VariableOutput},
        Blake2bVar,
    };
    use primitive_types::U512;

    const ACCOUNT_LOOKUP: &[char] = &[
        '1', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
        'k', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'w', 'x', 'y', 'z',
    ];

    fn account_encode(value: u8) -> char {
        ACCOUNT_LOOKUP[value as usize]
    }

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

    fn account_checksum(aggregate_public_key: &[u8; 32]) -> [u8; 5] {
        let mut check = [0u8; 5];
        let mut blake = Blake2bVar::new(check.len()).unwrap();
        blake.update(aggregate_public_key);
        blake.finalize_variable(&mut check).unwrap();
        check
    }
}

pub mod rpc {
    use reqwest::Client;
    use serde::{de::DeserializeOwned, Deserialize, Serialize};
    use serde_json::{json, Value};
    use std::error::Error;

    use crate::nano::sign::UnsignedBlock;

    pub struct RPCState {
        pub url: String,
        pub client: Client,
    }

    impl RPCState {
        pub fn new(url: &str) -> Self {
            Self {
                client: Client::new(),
                url: url.to_string(),
            }
        }
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

    #[derive(Serialize, Deserialize)]
    pub struct AccountInfo {
        pub frontier: String,
        pub open_block: String,
        pub representative_block: String,
        pub balance: String,
        pub balance_nano: String,
        pub modified_timestamp: String,
        pub block_count: String,
        pub account_version: String,
        pub confirmation_height: String,
        pub confirmation_height_frontier: String,
    }

    impl AccountInfo {
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

    #[derive(Serialize, Deserialize)]
    pub struct WorkGenerate {
        pub difficulty: String,
        pub multiplier: String,
        pub work: String,
        pub frontier: String,
        pub duration: String,
        pub credits: u32,
        pub cached: bool,
    }

    impl WorkGenerate {
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

    #[derive(Serialize, Deserialize)]
    pub struct Receivable {
        pub blocks: Vec<String>,
    }

    impl Receivable {
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

    #[derive(Serialize, Deserialize)]
    pub struct BlockInfo {
        pub block_account: String,
        pub amount: String,
    }

    impl BlockInfo {
        pub async fn get_from_rpc(state: &RPCState, hash: &str) -> Result<Self, Box<dyn Error>> {
            let data = json!({
                "action": "block_info",
                "hash": hash,
            });
            state.request::<Self>(&data).await
        }
    }

    #[tokio::test]
    async fn test_rpc() -> Result<(), Box<dyn Error>> {
        dotenv::dotenv().ok();

        let account = "nano_1c4nmdix64gdmqx65fdh8qsqx9nfz4fo96pbqyhagpihpzxxrrugrt1rrgss";

        let state = RPCState::new(&std::env::var("URL")?);

        let unsigned_block = UnsignedBlock::create_open(&state, &account).await?;

        println!("{}", serde_json::to_string(&unsigned_block)?);
        assert!(true);
        Ok(())
    }
}
