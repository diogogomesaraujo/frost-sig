use crate::FrostState;
use futures::SinkExt;
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
    pub async fn serve(&self) -> Result<(), Box<dyn Error>> {
        let state = Arc::new(Mutex::new(Shared::new()));

        let addr = env::args().nth(1).unwrap_or_else(|| self.ip.clone());

        let listener = TcpListener::bind(&addr).await.unwrap();

        tracing::info!("server running on {}", addr);

        let mut count: u32 = 0;

        loop {
            let (stream, addr) = listener.accept().await.unwrap();

            count += 1;

            let state = Arc::clone(&state);

            tokio::spawn(async move {
                tracing::debug!("accepted connection");
                if let Err(e) = process(count, state, stream, addr).await {
                    tracing::info!("an error occurred; error = {:?}", e);
                }
            });
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
        for peer in self.participants.iter_mut() {
            if *peer.0 != sender {
                let _ = peer.1.send(message.into());
            }
        }
    }
}

pub struct Participant {
    id: u32,
    username: String,
    lines: Framed<TcpStream, LinesCodec>,
    rx: Rx,
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
    state: Arc<Mutex<Shared>>,
    stream: TcpStream,
    addr: SocketAddr,
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

    let mut participant = Participant::new(id, username, state.clone(), lines).await?;

    {
        let mut state = state.lock().await;
        let msg = format!("{} has joined the chat", participant.username);
        tracing::info!("{}", msg);
        state.broadcast(addr, &msg).await;
    }

    loop {
        tokio::select! {
            Some(msg) = participant.rx.recv() => {
                participant.lines.send(&msg).await?;
            }
            result = participant.lines.next() => match result {
                Some(Ok(msg)) => {
                    let mut state = state.lock().await;
                    let msg = format!("{}: {msg}", participant.username);

                    state.broadcast(addr, &msg).await;
                }
                Some(Err(e)) => {
                    tracing::error!(
                        "an error occurred while processing messages for {}; error = {:?}",
                        participant.username,
                        e
                    );
                }
                None => break,
            },
        }
    }

    {
        let mut state = state.lock().await;
        state.participants.remove(&addr);

        let msg = format!(
            "{}:{} has left the chat",
            participant.id, participant.username
        );
        tracing::info!("{}", msg);
        state.broadcast(addr, &msg).await;
    }

    Ok(())
}
