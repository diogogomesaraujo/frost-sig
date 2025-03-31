use crate::{keygen::*, FrostState, CTX};
use futures::SinkExt;
use rand::Rng;
use rug::rand::RandState;
use rug::Integer;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Barrier, Mutex};
use tokio_stream::StreamExt;
use tokio_util::codec::{Framed, LinesCodec};

pub type Tx = mpsc::UnboundedSender<String>;
pub type Rx = mpsc::UnboundedReceiver<String>;

pub struct ChannelState {
    pub frost_state: FrostState,
    pub ip: String,
}

impl ChannelState {
    pub fn new(frost_state: FrostState, ip: String) -> Self {
        Self { frost_state, ip }
    }

    pub async fn serve_keygen(&self) -> Result<(), Box<dyn Error>> {
        let barrier_wait_for_participants =
            Arc::new(Barrier::new(self.frost_state.participants.clone()));
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
            let barrier_wait_for_participants = Arc::clone(&barrier_wait_for_participants);
            let tcp_state = Arc::clone(&tcp_state);
            let frost_state = Arc::clone(&frost_state);
            let ctx = Arc::clone(&ctx);
            tokio::spawn(async move {
                tracing::debug!("accepted connection");
                if let Err(e) = process::participant_keygen(
                    count,
                    tcp_state,
                    stream,
                    addr,
                    frost_state,
                    ctx,
                    barrier_wait_for_participants,
                )
                .await
                {
                    tracing::info!("an error occurred; error = {:?}", e);
                }
            });
        }
    }
}

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

/// Struct that is the broadcast recieved by a participant to from all others.
#[derive(Serialize, Deserialize)]
pub struct ParticipantBroadcastJSON {
    pub action: String,
    /// `participant_id` is the id of the participant sending the broadcast.
    pub id: String,
    /// `commitments` are the public commitments sent by the participant.
    pub commitments: Vec<String>,
    /// `signature` is used to verify if a participant is not mallicious.
    pub signature: (String, String),
}

impl ParticipantBroadcastJSON {
    /// Function that converts the ParticipantBroadcastJSON to a ParticipantBroadcast.
    ///
    /// ## Parameters
    ///
    /// - `self` that is the ParticipantBroadcastJSON that will be converted.
    ///
    /// ## Returns
    ///
    /// - `ParticipantBroadcast` that is the converted `self`.
    pub fn from_json(&self) -> ParticipantBroadcast {
        let id = Integer::from_str_radix(self.id.as_str(), 32).unwrap();
        let commitments: Vec<Integer> = self
            .commitments
            .iter()
            .map(|c| Integer::from_str_radix(c, 32).unwrap())
            .collect();
        let signature = {
            let (l, r) = self.signature.clone();
            (
                Integer::from_str_radix(l.as_str(), 32).unwrap(),
                Integer::from_str_radix(r.as_str(), 32).unwrap(),
            )
        };
        ParticipantBroadcast::init(id, commitments, signature)
    }
}

pub mod process {
    use crate::keygen;

    use super::*;

    #[derive(Serialize, Deserialize)]
    struct MessageJSON {
        message: String,
    }

    impl MessageJSON {
        pub fn new(message: String) -> MessageJSON {
            MessageJSON { message }
        }
    }

    pub async fn get_username_terminal(
        lines: &mut Framed<TcpStream, LinesCodec>,
    ) -> Option<String> {
        lines.send("Please enter your username:").await.unwrap();
        match lines.next().await {
            Some(Ok(line)) => Some(line),
            _ => None,
        }
    }

    pub async fn joining_participants(
        tcp_state: &Arc<Mutex<Shared>>,
        participant: &Participant,
        addr: SocketAddr,
    ) {
        let mut tcp_state = tcp_state.lock().await;
        let msg_json = serde_json::to_string(&MessageJSON::new(format!(
            "{} as joined the chat",
            participant.username
        )))
        .unwrap();
        tracing::info!("{}", msg_json);
        tcp_state.broadcast(addr, &msg_json).await;
    }

    pub async fn get_all_broadcasts(
        participant: &mut Participant,
        frost_state: &Arc<Mutex<FrostState>>,
    ) -> Vec<ParticipantBroadcastJSON> {
        let mut participants_broadcasts: Vec<ParticipantBroadcastJSON> = Vec::new();
        loop {
            tokio::select! {
                Some(msg) = participant.rx.recv() => {
                    match serde_json::from_str::<ParticipantBroadcastJSON>(&msg) {
                        Ok(broadcast) => {
                            participants_broadcasts.push(broadcast);
                            participant.lines.send(&msg).await.unwrap();

                            let frost_state = frost_state.lock().await;

                            if participants_broadcasts.len() >= frost_state.participants - 1 {
                                break;
                            }
                        }
                        Err(_)  => {
                            participant.lines.send(&msg).await.unwrap();
                        }
                    }
                }
            }
        }
        participants_broadcasts
    }

    pub async fn keygen_round_1(
        id: u32,
        frost_state: &Arc<Mutex<FrostState>>,
        tcp_state: &Arc<Mutex<Shared>>,
        ctx: &Arc<Mutex<CTX>>,
        addr: SocketAddr,
    ) {
        let seed: i32 = rand::rng().random();
        let mut rnd = RandState::new();
        rnd.seed(&rug::Integer::from(seed));
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

    pub async fn keygen_round_2(
        frost_state: &Arc<Mutex<FrostState>>,
        ctx: &Arc<Mutex<CTX>>,
        participants_broadcasts: &[ParticipantBroadcastJSON],
        participant: &mut Participant,
    ) {
        let frost_state = frost_state.lock().await;
        let ctx = ctx.lock().await;
        let msg_json = serde_json::to_string(&MessageJSON::new(format!(
            "Recieved {} participants broadcasts from {} and {}.",
            participants_broadcasts.len(),
            participants_broadcasts[0].id,
            participants_broadcasts[1].id,
        )))
        .unwrap();
        participant.lines.send(&msg_json).await.unwrap();
        let participants_broadcasts: Vec<ParticipantBroadcast> = participants_broadcasts
            .iter()
            .map(|pb| pb.from_json())
            .collect();
        assert!(round_1::verify_proofs(
            &frost_state,
            &participants_broadcasts,
            &ctx
        ));
        let msg_json = serde_json::to_string(&MessageJSON::new(
            "Correctly verified all proofs.".to_string(),
        ))
        .unwrap();
        participant.lines.send(&msg_json).await.unwrap();
    }

    pub async fn participant_keygen(
        id: u32,
        tcp_state: Arc<Mutex<Shared>>,
        stream: TcpStream,
        addr: SocketAddr,
        frost_state: Arc<Mutex<FrostState>>,
        ctx: Arc<Mutex<CTX>>,
        barrier_wait_for_participants: Arc<Barrier>,
    ) -> Result<(), Box<dyn Error>> {
        let mut lines = Framed::new(stream, LinesCodec::new());
        let username = match get_username_terminal(&mut lines).await {
            Some(line) => line,
            _ => {
                tracing::error!("Failed to get username from {}. Client disconnected.", addr);
                return Ok(());
            }
        };
        let mut participant = Participant::new(id, username, tcp_state.clone(), lines).await?;
        joining_participants(&tcp_state, &participant, addr).await;
        barrier_wait_for_participants.wait().await;
        keygen_round_1(id.clone(), &frost_state, &tcp_state, &ctx, addr).await;
        let participants_broadcasts = get_all_broadcasts(&mut participant, &frost_state).await;
        keygen_round_2(
            &frost_state,
            &ctx,
            &participants_broadcasts,
            &mut participant,
        )
        .await;
        Ok(())
        /*
        {
            let mut tcp_state = tcp_state.lock().await;
            tcp_state.participants.remove(&addr);

            let msg = format!("{} has left the chat", participant.username);
            tracing::info!("{}", msg);
            tcp_state.broadcast(addr, &msg).await;
        }
        */
    }
}
