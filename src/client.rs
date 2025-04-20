use crate::FrostState;

#[derive(Debug)]
pub struct FrostClient {
    pub state: FrostState,
    pub own_id: u32,
}

impl FrostClient {
    pub fn new(state: FrostState, own_id: u32) -> Self {
        Self { state, own_id }
    }
}

pub mod keygen {
    use crate::{client::FrostClient, message::Message, FrostState};
    use std::error::Error;
    use tokio::net::TcpStream;
    use tokio_stream::StreamExt;
    use tokio_util::codec::{Framed, LinesCodec};

    pub async fn run(ip: &str, port: u32) -> Result<(), Box<dyn Error>> {
        let address = format!("{}:{}", ip, port);
        let stream = TcpStream::connect(address).await?;
        let mut lines = Framed::new(stream, LinesCodec::new());

        let client = {
            let id = {
                let line = lines
                    .next()
                    .await
                    .expect("Couldn't recieve the message.")
                    .expect("Couldn't recieve the message.");
                let message =
                    Message::from_json_string(line.as_str()).expect("Couldn't parse message.");
                match message {
                    Message::Id(id) => id,
                    _ => return Err("Couldn't parse the message.".into()),
                }
            };

            let state = {
                let line = lines
                    .next()
                    .await
                    .expect("Couldn't recieve the message.")
                    .expect("Couldn't recieve the message.");
                let message =
                    Message::from_json_string(line.as_str()).expect("Couldn't parse message.");
                match message {
                    Message::FrostState {
                        prime,
                        q,
                        generator,
                        participants,
                        threshold,
                    } => FrostState {
                        prime,
                        q,
                        generator,
                        participants,
                        threshold,
                    },
                    _ => return Err("Couldn't parse message.".into()),
                }
            };
            FrostClient::new(state, id)
        };

        println!("{:?}", client);

        Ok(())
    }
}
