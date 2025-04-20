use keygen::run;

use crate::server::FrostServer;

pub struct FrostClient {
    server_state: FrostServer,
    own_id: u32,
}

pub mod keygen {
    use crate::{message::Message, FrostState};
    use std::error::Error;
    use tokio::net::TcpStream;
    use tokio_stream::StreamExt;
    use tokio_util::codec::{Framed, LinesCodec};

    pub async fn run(ip: &str, port: u32) -> Result<(), Box<dyn Error>> {
        let address = format!("{}:{}", ip, port);
        let stream = TcpStream::connect(address).await?;
        let mut lines = Framed::new(stream, LinesCodec::new());

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

        println!("{:?}", state);

        Ok(())
    }
}
