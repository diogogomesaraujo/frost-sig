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

pub struct FrostServer {
    /// The state that holds all the constants needed for the FROST computations.
    state: FrostState,
    /// The id of the session currently being processed.
    session: u32,
    /// The transmiter mapped to the socket address.
    by_addr: HashMap<SocketAddr, Tx>,
    /// The transmiter mapped to the participant's id.
    by_id: HashMap<u32, Tx>,
}

impl FrostServer {
    /// Function that creates a new `FrostServer`.
    pub fn new(rnd: &mut RandState, participants: u32, threshold: u32, session: u32) -> Self {
        Self {
            state: FrostState::new(rnd, participants, threshold),
            session,
            by_addr: HashMap::new(),
            by_id: HashMap::new(),
        }
    }

    pub async fn broadcast(&mut self, sender: SocketAddr, message: Message) {
        for participant in self.by_addr.iter_mut() {
            if *participant.0 != sender {
                let _ = participant.1.send(message.clone());
            }
        }
    }

    pub async fn send_to(&mut self, reciever: u32, message: Message) {
        if let Some(tx) = self.by_id.get(&reciever) {
            let _ = tx.send(message);
        }
    }
}

pub struct Participant {
    pub id: u32,
    pub reciever: Rx,
    pub sender: Tx,
}

impl Participant {
    pub fn new(id: u32, reciever: Rx, sender: Tx) -> Self {
        Self {
            id,
            reciever,
            sender,
        }
    }
}

mod keygen {
    use message::Message;
    use tokio::net::TcpStream;
    use tokio_util::codec::{Framed, LinesCodec};

    use super::*;

    pub async fn run(
        ip: &str,
        port: u32,
        participants: u32,
        threshold: u32,
        session: u32,
    ) -> Result<(), Box<dyn Error>> {
        let address = format!("{}{}", ip, port);
        let listener = TcpListener::bind(&address).await.unwrap();

        let seed: i32 = rand::rng().random();
        let mut rnd = RandState::new();
        rnd.seed(&rug::Integer::from(seed));

        let server = Arc::new(Mutex::new(FrostServer::new(
            &mut rnd,
            participants,
            threshold,
            session,
        ))); // session defaulted to 1 for now.

        let ctx = Arc::new(Mutex::new(CTX::new(
            "keygen",
            Integer::from(1),
            Integer::from(session),
        )));

        println!("FrostServer::Keygen running on: {address}");

        let mut count: u32 = 0;

        loop {
            let (stream, addr) = listener.accept().await.unwrap();
            count += 1;

            let server = server.clone();

            tokio::spawn(async move {
                println!("Accepted connection.");
                handle(count, server, stream, addr);
            });
        }
    }

    pub async fn handle(
        id: u32,
        server: Arc<Mutex<FrostServer>>,
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

        let participant = Participant::new(id, rx, tx);

        Ok(())
    }
}
