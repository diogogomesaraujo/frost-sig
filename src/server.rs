//! Implementation of servers for FROST keygen and signing protocols.
//!
//! # Dependencies
//!
//! - `rug` is a arbitrary precision numbers crate and provides infrastructure for the 256bit numbers and calculations.
//! - `rand` is a random number generation crate and it is used to generate a random seed for the 256bit numbers generation.
//! - `tokio` is an async runtime for Rust.
//!
//! # Features
//!
//! - Keygen and sign CLI servers.

use crate::*;
use futures::{SinkExt, StreamExt};
use message::Message;
use rand::Rng;
use std::{collections::HashMap, error::Error, net::SocketAddr, sync::Arc};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{mpsc, Barrier, Mutex},
};
use tokio_util::codec::{Framed, LinesCodec};

/// Shorthandle for the transmit half of the message channel.
pub type Tx = mpsc::UnboundedSender<Message>;

/// Shorthandle for the receive half of the message channel.
pub type Rx = mpsc::UnboundedReceiver<Message>;

/// Struct that represents the server that will handle FROST operations in real-time for multiple participant's clients.
#[derive(Clone)]
pub struct FrostServer {
    /// The state that holds all the constants needed for the FROST computations.
    state: FrostState,
    /// The transmiter mapped to the socket address.
    by_addr: HashMap<SocketAddr, Tx>,
    /// The transmiter mapped to the participant's id.
    by_id: HashMap<u32, Tx>,
}

impl FrostServer {
    /// Function that creates a new `FrostServer`.
    pub fn new(rnd: &mut RandState, participants: u32, threshold: u32) -> Self {
        Self {
            state: FrostState::new(rnd, participants, threshold),
            by_addr: HashMap::new(),
            by_id: HashMap::new(),
        }
    }

    /// Function that sends a message to all participants but the one sending the message.
    pub async fn broadcast(&mut self, sender: &SocketAddr, message: Message) {
        for participant in self.by_addr.iter_mut() {
            if &*participant.0 != sender {
                let _ = participant.1.send(message.clone());
            }
        }
    }

    /// Function that sends a message to a specific client in the socket.
    pub async fn send_to(&mut self, reciever: u32, message: Message) {
        if let Some(tx) = self.by_id.get(&reciever) {
            let _ = tx.send(message);
        }
    }

    /// Function that handles the messages sent according to type to avoid mistakes.
    pub async fn send_message(
        &mut self,
        participant: &Participant,
        msg: Message,
    ) -> Result<(), Box<dyn Error>> {
        match &msg {
            Message::Broadcast {
                signature: _,
                commitments: _,
                participant_id: _,
            }
            | Message::PublicCommitment {
                participant_id: _,
                di: _,
                ei: _,
                public_share: _,
            } => {
                self.broadcast(&participant.addr, msg).await;
            }
            Message::SecretShare {
                sender_id: _,
                reciever_id,
                secret: _,
            } => {
                self.send_to(reciever_id.to_u32().unwrap(), msg).await; // Should not fail.
            }
            Message::Response {
                sender_id: _,
                value: _,
            } => {
                self.send_to(1, msg).await; // defaulted to 1 because SA should be the first one to enter. FIX LATER!
            }
            _ => return Err("Tried to send an invalid message".into()),
        }
        Ok(())
    }
}

/// Struct that represents the participants from the server's view.
pub struct Participant {
    /// Id of the participant inside a specific operation.
    /// It is dynamically assigned as participants join the server.
    pub id: u32,
    /// Recieve half of the participant's message channel.
    pub reciever: Rx,
    /// Send half of the participant's message channel.
    pub sender: Tx,
    /// Participant's address inside the server's socket.
    pub addr: SocketAddr,
}

impl Participant {
    /// Function that creates a new `Participant`.
    pub fn new(id: u32, reciever: Rx, sender: Tx, addr: SocketAddr) -> Self {
        Self {
            id,
            reciever,
            sender,
            addr,
        }
    }
}

/// Module that handles the server side logging.
pub mod logging {
    pub const YELLOW: &str = "\x1b[33m";
    pub const BLUE: &str = "\x1b[34m";
    pub const RESET: &str = "\x1b[0m";

    /// Function that logs messages on to the terminal.
    pub fn print(message: &str) {
        println!("{}Frost Server:{} {}", BLUE, RESET, message);
    }
}

/// Function that handles all participants who join the server.
pub async fn handle(
    id: u32,
    barrier: Arc<Barrier>,
    server: Arc<Mutex<FrostServer>>,
    stream: TcpStream,
    addr: SocketAddr,
) -> Result<(), Box<dyn Error>> {
    // init message channel
    let lines = Framed::new(stream, LinesCodec::new());
    let (mut writer, mut reader) = lines.split();
    let (tx, rx) = mpsc::unbounded_channel::<Message>();

    // add participant to the server
    {
        let mut server = server.lock().await;
        server.by_id.insert(id, tx.clone());
        server.by_addr.insert(addr, tx.clone());
    }
    let mut participant = Participant::new(id, rx, tx, addr);

    // send the assigned id to the participant
    participant
        .sender
        .send(Message::Id(participant.id.clone()))
        .unwrap();

    // wait for all participants to join
    barrier.wait().await;

    // handle all incoming and and outgoing messages
    loop {
        tokio::select! {
            Some(msg) = participant.reciever.recv() => {
                let msg_json = msg.to_json_string();
                writer.send(msg_json).await.unwrap();
            }
            Some(Ok(msg_json)) = reader.next() => {
                match Message::from_json_string(msg_json.as_str()) {
                    Some(msg) => server.lock().await.send_message(&participant, msg).await.unwrap(),
                    None => return Err("Tried to send invalid message.".into()),
                }
            }
        }
    }
}

/// Module that handles server operations in relation to the FROST keygen process.
pub mod keygen_server {
    use std::time::Duration;

    use super::*;
    use tokio::{sync::Barrier, time::sleep};

    /// Function that runs the keygen process server.
    pub async fn run(
        ip: &str,
        port: u32,
        participants: u32,
        threshold: u32,
    ) -> Result<(), Box<dyn Error>> {
        // init the socket
        let address = format!("{}:{}", ip, port);
        let listener = TcpListener::bind(&address).await?;

        // init the random state
        let seed: i32 = rand::rng().random();
        let mut rnd = RandState::new();
        rnd.seed(&rug::Integer::from(seed));

        // create the server instance
        let server = Arc::new(Mutex::new(FrostServer::new(
            &mut rnd,
            participants,
            threshold,
        )));

        logging::print(
            format!(
                "Keygen initialized on {}{}{}.",
                logging::YELLOW,
                address,
                logging::RESET
            )
            .as_str(),
        );

        // init id count and joining participants barrier
        let mut count: u32 = 0;
        let barrier = Arc::new(Barrier::new((participants + 1) as usize));

        while count < participants {
            // accept the participant's connection
            let (stream, addr) = listener.accept().await.unwrap();
            count += 1;

            let server = server.clone();
            let barrier = barrier.clone();

            // handle the participant in an isolated async thread
            tokio::spawn(async move {
                logging::print("Accepted a connection.");
                handle(count, barrier, server, stream, addr).await.unwrap();
            });
        }

        // Send the frost state.
        {
            // Block until all have joined.
            barrier.wait().await;

            let server = server.lock().await;

            // send the shared `FrostState` to the participant
            server.by_addr.values().into_iter().for_each(|tx| {
                tx.send(server.state.clone().to_message()).unwrap();
            });
        }

        // wait before closing the socket for messages that may be left unsent
        sleep(Duration::from_secs(1)).await;
        logging::print("Successfully generated the key.");
        Ok(())
    }
}

/// Module that handles server operations in relation to the FROST sign process.
pub mod sign_server {
    use super::*;
    use std::time::Duration;
    use tokio::{sync::Barrier, time::sleep};

    /// Function that runs the sign process server.
    pub async fn run(
        ip: &str,
        port: u32,
        participants: u32,
        threshold: u32,
    ) -> Result<(), Box<dyn Error>> {
        // init the socket
        let address = format!("{}:{}", ip, port);
        let listener = TcpListener::bind(&address).await?;

        // init random state
        let seed: i32 = rand::rng().random();
        let mut rnd = RandState::new();
        rnd.seed(&rug::Integer::from(seed));

        // create server instance
        let server = Arc::new(Mutex::new(FrostServer::new(
            &mut rnd,
            participants,
            threshold,
        )));

        logging::print(
            format!(
                "Sign initialized on {}{}{}.",
                logging::YELLOW,
                address,
                logging::RESET
            )
            .as_str(),
        );

        // init id count and joining participants barrier
        let mut count: u32 = 0;
        let barrier = Arc::new(Barrier::new(threshold as usize));

        while count < threshold {
            // accept participant connection
            let (stream, addr) = listener.accept().await?;
            count += 1;

            let server = server.clone();
            let barrier = barrier.clone();

            // handle participant's messages in an isolated async thread
            tokio::spawn(async move {
                logging::print("Accepted a connection.");
                handle(count, barrier, server, stream, addr).await.unwrap();
            });
        }

        // wait before closing the socket for messages that may be left unsent
        sleep(Duration::from_secs(1)).await;
        logging::print("Shutting down server.");
        Ok(())
    }
}
