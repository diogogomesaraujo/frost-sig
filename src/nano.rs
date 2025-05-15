pub mod sign {
    use std::error::Error;

    use super::rpc;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Debug)]
    pub enum Subtype {
        SEND,
        RECEIVE,
        OPEN,
    }

    impl Subtype {
        pub fn as_str(&self) -> &str {
            match self {
                Self::SEND => "send",
                Self::RECEIVE => "receive",
                Self::OPEN => "open",
            }
        }
    }

    #[derive(Serialize, Deserialize, Debug)]
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

        pub fn empty() -> Self {
            Self::new(
                String::from("to fill"),
                String::from("to fill"),
                String::from("to fill"),
                String::from("to fill"),
                String::from("to fill"),
                String::from("to fill"),
            )
        }

        pub fn to_signed_block(self, signature: &str, work: &str) -> SignedBlock {
            SignedBlock::new(
                self.previous,
                self.account,
                self.representative,
                self.balance,
                self.link,
                self.link_as_account,
                signature.to_string(),
                work.to_string(),
            )
        }

        pub async fn create_open(
            state: &rpc::RPCState,
            account_address: &str,
        ) -> Result<Self, Box<dyn std::error::Error>> {
            let receivable = rpc::Receivable::get_from_rpc(&state, account_address, 1).await?;
            let block = rpc::BlockInfo::get_from_rpc(&state, &receivable.blocks[0]).await?;

            let account = account_address.to_string();
            let previous = "0".to_string();
            let representative = std::env::var("REPRESENTATIVE")?;
            let balance = block.amount;
            let link = receivable.blocks[0].clone();
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
        pub r#type: String,
        pub previous: String,
        pub account: String,
        pub representative: String,
        pub balance: String,
        pub link: String,
        pub link_as_account: String,
        pub signature: String,
        pub work: String,
    }

    impl SignedBlock {
        pub fn new(
            previous: String,
            account: String,
            representative: String,
            balance: String,
            link: String,
            link_as_account: String,
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
                link_as_account,
                signature,
                work,
            }
        }
    }

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

    const ACCOUNT_LOOKUP: &[char] = &[
        '1', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
        'k', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'w', 'x', 'y', 'z',
    ];

    fn account_encode(value: u8) -> char {
        ACCOUNT_LOOKUP[value as usize]
    }

    fn account_checksum(aggregate_public_key: &[u8; 32]) -> [u8; 5] {
        let mut check = [0u8; 5];
        let mut blake = Blake2bVar::new(check.len()).unwrap();
        blake.update(aggregate_public_key);
        blake.finalize_variable(&mut check).unwrap();
        check
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
}

pub mod rpc {
    use reqwest::Client;
    use serde::{de::DeserializeOwned, Deserialize, Serialize};
    use serde_json::{json, Value};
    use std::error::Error;

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
        pub work: String,
        pub frontier: String,
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

    #[derive(Serialize, Deserialize, Debug)]
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

    #[derive(Serialize, Deserialize)]
    pub struct Process {
        pub hash: String,
    }

    impl Process {
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
    async fn test_rpc() -> Result<(), Box<dyn Error>> {
        dotenv::dotenv().ok();

        let account = "nano_14cn1otwksnjwg6kfsqu46te5rj4pgjskw63dxja7gdt9rgydt94jap7e6rw";

        let state = RPCState::new(&std::env::var("URL")?);

        let recievable = Receivable::get_from_rpc(&state, account, 1).await?;
        println!("{:?}", recievable);

        let unsigned_block =
            crate::nano::sign::UnsignedBlock::create_open(&state, &account).await?;

        println!("{}", serde_json::to_string(&unsigned_block)?);

        assert!(true);

        Ok(())
    }
}
