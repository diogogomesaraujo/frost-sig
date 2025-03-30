use crate::keygen::{round_1, ParticipantBroadcast};
use crate::{keygen, FrostState, CTX};
use futures::SinkExt;
use rand::Rng;
use rug::rand::RandState;
use rug::Integer;
use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio_stream::StreamExt;
use tokio_util::codec::{Framed, LinesCodec};

pub struct ChannelState {
    pub frost_state: FrostState,
    pub ip: String,
}

impl ChannelState {
    pub fn new(frost_state: FrostState, ip: String) -> Self {
        Self { frost_state, ip }
    }
    pub async fn serve_keygen(&self) -> Result<(), Box<dyn Error>> {
        let tcp_state = Arc::new(Mutex::new(Shared::new()));
        let frost_state = Arc::new(Mutex::new(self.frost_state.clone()));
        let ctx = Arc::new(Mutex::new(CTX::init(
            "keygen",
            Integer::from(1),
            Integer::from(1),
        )));
        let addr = env::args().nth(1).unwrap_or_else(|| self.ip.clone());
        let listener = TcpListener::bind(&addr).await.unwrap();
        tracing::info!("server running on {}", addr);
        let mut count: u32 = 0;

        loop {
            let (stream, addr) = listener.accept().await.unwrap();

            count += 1;

            let tcp_state = Arc::clone(&tcp_state);
            let frost_state = Arc::clone(&frost_state);
            let ctx = Arc::clone(&ctx);

            // Begin FROST keygen round 1
            tokio::spawn(async move {
                tracing::debug!("accepted connection");
                if let Err(e) = process(count, tcp_state, stream, addr, frost_state, ctx).await {
                    tracing::info!("an error occurred; error = {:?}", e);
                }
            });

            // Begin FROST keygen round 2
        }
    }
}

pub type Tx = mpsc::UnboundedSender<String>;
pub type Rx = mpsc::UnboundedReceiver<String>;

pub struct Shared {
    participants: HashMap<SocketAddr, Tx>,
}

impl Shared {
    pub fn new() -> Self {
        Shared {
            participants: HashMap::new(),
        }
    }

    async fn broadcast(&mut self, sender: SocketAddr, message: &str) {
        println!("Broadcasting message: {}", message);

        for peer in self.participants.iter_mut() {
            if *peer.0 != sender {
                let _ = peer.1.send(message.into());
            }
        }
    }
}

pub struct Participant {
    pub id: u32,
    pub username: String,
    pub lines: Framed<TcpStream, LinesCodec>,
    pub rx: Rx,
}

impl Participant {
    pub async fn new(
        id: u32,
        username: String,
        state: Arc<Mutex<Shared>>,
        lines: Framed<TcpStream, LinesCodec>,
    ) -> io::Result<Participant> {
        let addr = lines.get_ref().peer_addr()?;

        let (tx, rx) = mpsc::unbounded_channel();

        state.lock().await.participants.insert(addr, tx);

        Ok(Participant {
            id,
            username,
            lines,
            rx,
        })
    }
}

pub async fn process(
    id: u32,
    tcp_state: Arc<Mutex<Shared>>,
    stream: TcpStream,
    addr: SocketAddr,
    frost_state: Arc<Mutex<FrostState>>,
    ctx: Arc<Mutex<CTX>>,
) -> Result<(), Box<dyn Error>> {
    let mut lines = Framed::new(stream, LinesCodec::new());

    lines.send("Please enter your username:").await?;

    let username = match lines.next().await {
        Some(Ok(line)) => line,
        _ => {
            tracing::error!("Failed to get username from {}. Client disconnected.", addr);
            return Ok(());
        }
    };

    let participant = Participant::new(id, username, tcp_state.clone(), lines).await?;

    let seed: i32 = rand::rng().random();
    let mut rnd = RandState::new();
    rnd.seed(&rug::Integer::from(seed));

    {
        let frost_state = frost_state.lock().await;
        let ctx = ctx.lock().await;

        let pol = round_1::generate_polynomial(&frost_state, &mut rnd);
        let frost_participant_temp = keygen::Participant::init(Integer::from(id), pol);

        let signature = round_1::compute_proof_of_knowlodge(
            &frost_state,
            &mut rnd,
            &frost_participant_temp,
            &ctx,
        );
        let commitments =
            round_1::compute_public_commitments(&frost_state, &frost_participant_temp);

        let participant_broadcast =
            ParticipantBroadcast::init(frost_participant_temp.id.clone(), commitments, signature);

        let mut tcp_state = tcp_state.lock().await;

        tcp_state
            .broadcast(addr, &participant_broadcast.to_json_string())
            .await;
    }

    {
        let mut tcp_state = tcp_state.lock().await;
        let msg = format!("{} has joined the chat", participant.username);
        tracing::info!("{}", msg);
        tcp_state.broadcast(addr, &msg).await;
    }

    {
        let mut tcp_state = tcp_state.lock().await;
        tcp_state.participants.remove(&addr);

        let msg = format!("{} has left the chat", participant.username);
        tracing::info!("{}", msg);
        tcp_state.broadcast(addr, &msg).await;
    }

    Ok(())
}
