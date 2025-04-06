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
use std::str::FromStr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Barrier, Mutex};
use tokio_stream::StreamExt;
use tokio_util::codec::{Framed, LinesCodec};

/// Shorthandle for the transmit half of the message channel.
pub type Tx = mpsc::UnboundedSender<String>;

/// Shorthandle for the receive half of the message channel.
pub type Rx = mpsc::UnboundedReceiver<String>;

/// Struct that has the shared constants for everyone inside the Tcp Server.
pub struct ChannelState {
    /// State that has all the constants needed for FROST.
    pub frost_state: FrostState,
    /// IP of the machine running the server.
    pub ip: String,
}

impl ChannelState {
    /// Function that creates a new ChannelState.
    ///
    /// ## Parameters
    ///
    /// - `frost_state` it the state that has all the constants needed for FROST.
    /// - `ip` is IP of the computer serving the TCP Server.
    ///
    /// ## Returns
    ///
    /// - `ChannelState` with the constants recieved.
    pub fn new(frost_state: FrostState, ip: String) -> Self {
        Self { frost_state, ip }
    }

    /// Function that serves the TCP Server.
    ///
    /// ## Parameters
    ///
    /// - `self` that is the ChannelState where the server will be served.
    ///
    /// ## Returns
    ///
    /// - Nothing or an error.
    pub async fn serve_keygen(&self, ctx: CTX) -> Result<(), Box<dyn Error>> {
        let barrier_wait_for_participants =
            Arc::new(Barrier::new(self.frost_state.participants.clone()));
        let tcp_state = Arc::new(Mutex::new(Shared::new()));
        let frost_state = Arc::new(Mutex::new(self.frost_state.clone()));
        let ctx = Arc::new(Mutex::new(ctx));
        let addr = env::args().nth(1).unwrap_or_else(|| self.ip.clone());
        let listener = TcpListener::bind(&addr).await.unwrap();
        println!("Server running on {}.", addr);
        let mut count: u32 = 0;
        loop {
            let (stream, addr) = listener.accept().await.unwrap();
            count += 1;
            let barrier_wait_for_participants = Arc::clone(&barrier_wait_for_participants);
            let tcp_state = Arc::clone(&tcp_state);
            let frost_state = Arc::clone(&frost_state);
            let ctx = Arc::clone(&ctx);
            tokio::spawn(async move {
                println!("Accepted connection.");
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
                    eprintln!("An error occurred; error = {:?}", e);
                }
            });
        }
    }
}

/// Struct that contains every participant's socket address and transmiter.
pub struct Shared {
    /// The socket address and trasnmit half of the message channel of all participants.
    participants: HashMap<SocketAddr, Tx>,
    participants_with_id: HashMap<u32, Tx>, // TODO: make this more optimized and not have duplicated data!!!
}

impl Shared {
    /// Function that creates a new Shared.
    ///
    /// ## Returns
    ///
    /// - Empty `HashMap` to later store socket addresses and transmiters.
    pub fn new() -> Self {
        Shared {
            participants: HashMap::new(),
            participants_with_id: HashMap::new(),
        }
    }

    /// Function that broadcasts a message to the channel.
    ///
    /// ## Parameters
    ///
    /// - `self` that is the shared state with all the participant's addresses and trasmiters.
    async fn broadcast(&mut self, sender: SocketAddr, message: &str) {
        println!("Broadcasting message: {}", message);
        for participant in self.participants.iter_mut() {
            if *participant.0 != sender {
                let _ = participant.1.send(message.into());
            }
        }
    }

    async fn send_to(&mut self, reciever: u32, message: &str) {
        if let Some(tx) = self.participants_with_id.get(&reciever) {
            let _ = tx.send(message.to_string());
        }
    }
}

/// Struct that contains every participant's information needed for the TCP Server operations.
pub struct Participant {
    /// It is the identifying number for the participant and also used for the FROST operations.
    pub id: u32,
    /// It is the name given by the participants so others can identify him more easily.
    pub username: String,
    /// It is the TCP Stream and its enconder and decoder.
    pub lines: Framed<TcpStream, LinesCodec>,
    /// It is the recieve half of the message channel of the participant.
    pub rx: Rx,
}

impl Participant {
    /// Function that creates a new Participant.
    ///
    /// ## Parameters
    ///
    /// - `id` that is the identifying number for the participant and also used for the FROST operations.
    /// - `username` that is the name given by the participants so others can identify him more easily.
    /// - `state` that is the shared information across all participants.
    /// - `lines` that is the TCP Stream and its enconder and decoder.
    ///
    /// ## Returns
    ///
    /// - `Result<Participant>` that is the Participant initialized with all the given information or an error if it is unable to create the participant.
    pub async fn new(
        id: u32,
        username: String,
        state: Arc<Mutex<Shared>>,
        lines: Framed<TcpStream, LinesCodec>,
    ) -> io::Result<Participant> {
        let addr = lines.get_ref().peer_addr()?;
        let (tx, rx) = mpsc::unbounded_channel();
        let mut state = state.lock().await;
        state.participants.insert(addr, tx.clone());
        state.participants_with_id.insert(id, tx);
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
    /// It is the id of the participant sending the broadcast.
    pub id: String,
    /// They are the public commitments sent by the participant.
    pub commitments: Vec<String>,
    /// It is used to verify if a participant is not mallicious.
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

#[derive(Serialize, Deserialize)]
pub struct SecretShareJSON {
    pub action: String,
    pub reciever_id: String,
    pub secret: String,
}

impl SecretShareJSON {
    pub fn from_json(&self) -> SecretShare {
        let id = Integer::from_str(self.reciever_id.as_str()).unwrap();
        let secret = Integer::from_str_radix(&self.secret, 32).unwrap();
        SecretShare::init(id, secret)
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

    pub async fn keygen_round_1_broadcast_and_pol(
        id: u32,
        frost_state: &Arc<Mutex<FrostState>>,
        tcp_state: &Arc<Mutex<Shared>>,
        ctx: &Arc<Mutex<CTX>>,
        addr: SocketAddr,
    ) -> Vec<Integer> {
        let seed: i32 = rand::rng().random();
        let mut rnd = RandState::new();
        rnd.seed(&rug::Integer::from(seed));

        let (pol, broadcast) = {
            let frost_state = frost_state.lock().await;
            let ctx = ctx.lock().await;
            let pol = round_1::generate_polynomial(&frost_state, &mut rnd);
            let frost_participant_temp = keygen::Participant::init(Integer::from(id), pol.clone());
            let signature = round_1::compute_proof_of_knowlodge(
                &frost_state,
                &mut rnd,
                &frost_participant_temp,
                &ctx,
            );
            let commitments =
                round_1::compute_public_commitments(&frost_state, &frost_participant_temp);
            let participant_broadcast = ParticipantBroadcast::init(
                frost_participant_temp.id.clone(),
                commitments,
                signature,
            );

            (pol, participant_broadcast)
        };

        let mut tcp_state = tcp_state.lock().await;
        tcp_state.broadcast(addr, &broadcast.to_json_string()).await;

        pol
    }

    pub async fn keygen_round_1_confirm_broadcast(
        frost_state: &Arc<Mutex<FrostState>>,
        ctx: &Arc<Mutex<CTX>>,
        participants_broadcasts: &[ParticipantBroadcastJSON],
        participant: &mut Participant,
    ) {
        let frost_state = frost_state.lock().await;
        let ctx = ctx.lock().await;
        let msg_json = serde_json::to_string(&MessageJSON::new(format!(
            "Recieved {} participants broadcasts from ({} ).",
            participants_broadcasts.len(),
            participants_broadcasts
                .iter()
                .fold(String::new(), |acc, pb| { format!("{acc} {}", pb.id) })
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
                eprintln!("Failed to get username from {}. Client disconnected.", addr);
                return Ok(());
            }
        };
        let mut participant = Participant::new(id, username, tcp_state.clone(), lines).await?;
        joining_participants(&tcp_state, &participant, addr).await;
        barrier_wait_for_participants.wait().await;
        let pol =
            keygen_round_1_broadcast_and_pol(id.clone(), &frost_state, &tcp_state, &ctx, addr)
                .await;
        let participants_broadcasts = get_all_broadcasts(&mut participant, &frost_state).await;
        keygen_round_1_confirm_broadcast(
            &frost_state,
            &ctx,
            &participants_broadcasts,
            &mut participant,
        )
        .await;
        let participants_broadcasts: Vec<ParticipantBroadcast> = participants_broadcasts
            .iter()
            .map(|pb| {
                let pb = pb.from_json();
                pb
            })
            .collect();

        {
            let (_p, _own_share, shares_to_send) = {
                let frost_state = frost_state.lock().await;

                let p = keygen::Participant::init(Integer::from(participant.id.clone()), pol);

                let own_share = round_2::create_own_secret_share(&frost_state, &p);

                let shares_to_send: Vec<SecretShare> = participants_broadcasts
                    .iter()
                    .map(|_pb| round_2::create_share_for(&frost_state, &p, &p.id))
                    .collect();

                (p, own_share, shares_to_send)
            };

            for ss in shares_to_send.iter() {
                let message = ss.to_json_string();
                tcp_state
                    .lock()
                    .await
                    .send_to(ss.participant_id.to_u32().unwrap(), message.as_str())
                    .await;
            }

            let mut secret_shares: Vec<SecretShare> = vec![];

            loop {
                tokio::select! {
                    Some(msg) = participant.rx.recv() => {
                        match serde_json::from_str::<SecretShareJSON>(&msg) {
                            Ok(secret_share) => {
                                secret_shares.push(secret_share.from_json());
                                participant.lines.send(&msg).await.unwrap();

                                if secret_shares.len() >= frost_state.lock().await.participants - 1 {
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
        };

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
