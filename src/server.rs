use std::{collections::HashMap, error::Error, net::SocketAddr, sync::Arc};

use message::Message;
use rand::Rng;
use tokio::{
    net::TcpListener,
    sync::{mpsc, Mutex},
};

use crate::*;

/// Shorthandle for the transmit half of the message channel.
pub type Tx = mpsc::UnboundedSender<Message>;

/// Shorthandle for the receive half of the message channel.
pub type Rx = mpsc::UnboundedReceiver<Message>;

/// Struct that represents the server that will handle FROST operations in real-time for multiple participant's clients.
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

    /// Function that sends a message to all clients connected to the socket.
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
    pub async fn send_message(&mut self, participant: &Participant, msg: Message) {
        match &msg {
            Message::Broadcast {
                signature: _,
                commitments: _,
                participant_id: _,
            }
            | Message::FrostState {
                prime: _,
                q: _,
                generator: _,
                participants: _,
                threshold: _,
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
            Message::PublicCommitment {
                participant_id: _,
                di: _,
                ei: _,
                public_share: _,
            }
            | Message::Response {
                sender_id: _,
                value: _,
            } => {
                self.send_to(0, msg).await; // defaulted to 0 because SA should be the first one to enter. FIX LATER!
            }
        }
    }
}

/// Struct that represents the participants from the server's view.
pub struct Participant {
    pub id: u32,
    pub reciever: Rx,
    pub sender: Tx,
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

/// Module that handles server operations in relation to the FROST keygen process.
pub mod keygen {
    use futures::SinkExt;
    use message::Message;
    use tokio::net::TcpStream;
    use tokio_util::codec::{Framed, LinesCodec};

    use super::*;

    /// Function that runs the keygen process server.
    pub async fn run(
        ip: &str,
        port: u32,
        participants: u32,
        threshold: u32,
    ) -> Result<(), Box<dyn Error>> {
        let address = format!("{}:{}", ip, port);
        let listener = TcpListener::bind(&address).await.unwrap();

        let seed: i32 = rand::rng().random();
        let mut rnd = RandState::new();
        rnd.seed(&rug::Integer::from(seed));

        let server = Arc::new(Mutex::new(FrostServer::new(
            &mut rnd,
            participants,
            threshold,
        )));

        let state = Arc::new(Mutex::new(FrostState::new(
            &mut rnd,
            participants,
            threshold,
        )));

        println!("FrostServer: keygen running on -> {address}");

        let mut count: u32 = 0;

        while count < participants {
            let (stream, addr) = listener.accept().await.unwrap();
            count += 1;

            let server = server.clone();
            let state = state.clone();

            tokio::spawn(async move {
                println!("Accepted connection.");
                handle(count, server, state, stream, addr).await.unwrap();
            });
        }

        Ok(())
    }

    /// Function that handles all participants who join the server.
    pub async fn handle(
        id: u32,
        server: Arc<Mutex<FrostServer>>,
        state: Arc<Mutex<FrostState>>,
        stream: TcpStream,
        addr: SocketAddr,
    ) -> Result<(), Box<dyn Error>> {
        let mut lines = Framed::new(stream, LinesCodec::new());
        let (tx, rx) = mpsc::unbounded_channel::<Message>();

        {
            let mut server = server.lock().await;
            server.by_id.insert(id, tx.clone());
            server.by_addr.insert(addr, tx.clone());
        }

        let mut participant = Participant::new(id, rx, tx, addr);

        {
            let state = state.lock().await;
            participant.sender.send(state.clone().to_message()).unwrap();
        }

        // TEMPORARY
        loop {
            tokio::select! {
                Some(msg) = participant.reciever.recv() => {
                    lines.send(&msg.to_json_string()).await.unwrap();
                }
            }
        }
    }
}
