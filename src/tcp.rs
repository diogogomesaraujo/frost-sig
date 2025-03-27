use crate::FrostState;
use rug::Integer;
use std::io::{Error, ErrorKind};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{unix::SocketAddr, TcpListener},
    sync::broadcast,
};

pub enum Address {
    Ip(String),
    SocketAddress(SocketAddr),
}

pub struct Participant {
    pub id: Integer,
    pub address: Address,
    pub broadcasts: Vec<String>,
}

pub struct Channel {
    pub state: FrostState,
    pub listener: TcpListener,
    pub main_participant: Participant,
    pub other_participants: Vec<Participant>,
}

impl Channel {
    pub async fn init(
        state_input: FrostState,
        main_participant_input: Participant,
    ) -> Result<Self, Error> {
        match &main_participant_input.address {
            Address::Ip(address) => Ok(Self {
                state: state_input,
                listener: TcpListener::bind(address).await.unwrap(),
                main_participant: main_participant_input,
                other_participants: Vec::new(),
            }),
            _ => Err(std::io::Error::new(
                ErrorKind::InvalidInput,
                "Insert an Ip Address not a Socket Address.",
            )),
        }
    }

    pub async fn serve(&self) {
        let (tx, _rx) = broadcast::channel(10);

        loop {
            let (mut socket, address) = self.listener.accept().await.unwrap();

            let tx = tx.clone();
            let mut rx = tx.subscribe();

            tokio::spawn(async move {
                let (socket_read, mut socket_write) = socket.split();

                let mut reader = BufReader::new(socket_read);
                let mut line = String::new();

                loop {
                    tokio::select! {
                        result = reader.read_line(&mut line) => {
                            if result.unwrap() == 0 {
                                break;
                            }

                            tx.send((line.clone(), address)).unwrap();
                            line.clear();
                        }
                        result = rx.recv() => {
                            let (message, message_address) = result.unwrap();

                            if address != message_address {
                                socket_write.write_all(&message.as_bytes()).await.unwrap();
                            }
                        }
                    }
                }
            });
        }
    }
}

impl Participant {
    pub fn init(id_input: Integer, address_input: Address) -> Self {
        Self {
            id: id_input,
            address: address_input,
            broadcasts: Vec::new(),
        }
    }
}
