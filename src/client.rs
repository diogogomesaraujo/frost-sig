use crate::{message::Message, FrostState, FrostStateJSON, RADIX};
use rug::Integer;
use serde::{Deserialize, Serialize};
use std::error::Error;
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
};
use tokio_stream::StreamExt;
use tokio_util::codec::{Framed, LinesCodec};

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

pub async fn recieve_message(
    lines: &mut Framed<TcpStream, LinesCodec>,
) -> Result<Message, Box<dyn Error>> {
    let line = lines.next().await.expect("Couldn't recieve the message.")?;
    Ok(Message::from_json_string(line.as_str()).expect("Couldn't recieve the message."))
}

/// Module that handles the client side logging.
pub mod logging {
    pub const BLUE: &str = "\x1b[34m";
    pub const YELLOW: &str = "\x1b[33m";
    pub const RESET: &str = "\x1b[0m";

    pub fn print(message: &str) {
        println!("{}Frost Client:{} {}", BLUE, RESET, message);
    }
}

#[derive(Debug)]
pub struct SignInput {
    state: FrostState,
    public_aggregated_key: Integer,
    own_public_share: Integer,
    own_private_share: Integer,
    message: String,
}

impl SignInput {
    pub async fn from_file(path: &str) -> Result<SignInput, Box<dyn Error>> {
        let file = File::open(path).await?;

        let mut buf_reader = BufReader::new(file);
        let mut contents = String::new();
        buf_reader.read_to_string(&mut contents).await?;

        match serde_json::from_str::<SignInputJSON>(&contents) {
            Ok(input_json) => {
                let public_aggregated_key =
                    Integer::from_str_radix(&input_json.public_aggregated_key, RADIX)?;
                let own_public_share =
                    Integer::from_str_radix(&input_json.own_public_share, RADIX)?;
                let own_private_share =
                    Integer::from_str_radix(&input_json.own_private_share, RADIX)?;
                let state = input_json.state.from_json();
                Ok(SignInput {
                    state,
                    public_aggregated_key,
                    own_public_share,
                    own_private_share,
                    message: input_json.message,
                })
            }
            Err(e) => return Err(e.into()),
        }
    }

    pub async fn to_file(&self, path: &str) -> Result<(), Box<dyn Error>> {
        let write_to_file = SignInputJSON {
            state: FrostStateJSON {
                prime: self.state.prime.to_string_radix(RADIX),
                q: self.state.q.to_string_radix(RADIX),
                generator: self.state.generator.to_string_radix(RADIX),
                participants: self.state.participants,
                threshold: self.state.threshold,
            },
            public_aggregated_key: self.public_aggregated_key.to_string_radix(RADIX),
            own_public_share: self.own_public_share.to_string_radix(RADIX),
            own_private_share: self.own_private_share.to_string_radix(RADIX),
            message: self.message.clone(),
        };
        let mut file = File::create(path).await?;
        file.write_all(serde_json::to_string(&write_to_file)?.as_bytes())
            .await?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
pub struct SignInputJSON {
    state: FrostStateJSON,
    public_aggregated_key: String,
    own_public_share: String,
    own_private_share: String,
    message: String,
}

pub mod keygen_client {
    use super::{logging, recieve_message, FrostClient, SignInput};
    use crate::{
        keygen::{self, round_1, round_2},
        message::Message,
        FrostState, RADIX,
    };
    use futures::SinkExt;
    use rand::Rng;
    use rug::{rand::RandState, Integer};
    use std::error::Error;
    use tokio::net::TcpStream;
    use tokio_util::codec::{Framed, LinesCodec};

    pub async fn run(ip: &str, port: u32, path: &str) -> Result<(), Box<dyn Error>> {
        // connect
        let address = format!("{}:{}", ip, port);
        let stream = TcpStream::connect(address).await?;
        let mut lines = Framed::new(stream, LinesCodec::new());

        // init client
        let client = {
            let id = {
                match recieve_message(&mut lines).await? {
                    Message::Id(id) => id,
                    _ => return Err("Couldn't parse the message.".into()),
                }
            };

            let state = {
                match recieve_message(&mut lines).await? {
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

        // init random state
        let mut rnd = {
            let seed: i32 = rand::rng().random();
            let mut rnd = RandState::new();
            rnd.seed(&rug::Integer::from(seed));

            rnd
        };

        // execute round 1
        let (own_broadcast, broadcasts, participant_self) = {
            let polynomial = keygen::round_1::generate_polynomial(&client.state, &mut rnd);

            let participant_self =
                keygen::Participant::new(Integer::from(client.own_id), polynomial);

            let signature =
                round_1::compute_proof_of_knowlodge(&client.state, &mut rnd, &participant_self);
            let commitments = round_1::compute_public_commitments(&client.state, &participant_self);

            let own_broadcast = Message::Broadcast {
                participant_id: participant_self.id.clone(),
                commitments,
                signature,
            };
            lines.send(own_broadcast.to_json_string()).await?;

            let broadcasts = {
                let mut broadcasts = vec![];
                for _i in 1..(client.state.participants) {
                    let message = recieve_message(&mut lines).await?;
                    match message {
                        Message::Broadcast {
                            participant_id: _,
                            commitments: _,
                            signature: _,
                        } => broadcasts.push(message),
                        _ => return Err("Couldn't parse the message.".into()),
                    }
                }
                broadcasts
            };

            assert!(round_1::verify_proofs(&client.state, &broadcasts));

            (own_broadcast, broadcasts, participant_self)
        };

        // execute round 2
        let (own_public_key, aggregate_public_key, private_key_share) = {
            let own_share = round_2::create_own_secret_share(&client.state, &participant_self);

            for i in 1..=client.state.participants {
                if i != participant_self.id {
                    let share_to_send = round_2::create_share_for(
                        &client.state,
                        &participant_self,
                        &Integer::from(i),
                    );
                    lines.send(share_to_send.to_json_string()).await?;
                }
            }

            let secret_shares = {
                let mut secret_shares = vec![];
                for _i in 1..(client.state.participants) {
                    let message = recieve_message(&mut lines).await?;
                    match message {
                        Message::SecretShare {
                            sender_id: _,
                            reciever_id: _,
                            secret: _,
                        } => secret_shares.push(message),
                        _ => return Err("Couldn't parse the message.".into()),
                    }
                }
                secret_shares
            };

            secret_shares.iter().for_each(|s| {
                let broadcast = broadcasts
                    .iter()
                    .find(|&b| match (b, s) {
                        (
                            Message::Broadcast {
                                participant_id,
                                commitments: _,
                                signature: _,
                            },
                            Message::SecretShare {
                                sender_id,
                                reciever_id: _,
                                secret: _,
                            },
                        ) => participant_id == sender_id,
                        _ => false,
                    })
                    .unwrap();
                assert!(round_2::verify_share_validity(
                    &client.state,
                    &participant_self,
                    &s,
                    &broadcast
                ))
            });

            let private_key =
                round_2::compute_private_key(&client.state, &own_share, &secret_shares)?;

            logging::print(
                format!(
                    "This is your {}private key share{}: {}.",
                    logging::YELLOW,
                    logging::RESET,
                    private_key.to_string_radix(RADIX),
                )
                .as_str(),
            );

            let own_public_key_share =
                round_2::compute_own_verification_share(&client.state, &private_key);

            logging::print(
                format!(
                    "This is your {}public key share{}: {}",
                    logging::YELLOW,
                    logging::RESET,
                    own_public_key_share.to_string_radix(RADIX),
                )
                .as_str(),
            );

            let broadcasts = {
                let mut temp = broadcasts;
                temp.push(own_broadcast);
                temp
            };

            {
                let verification_shares: Vec<Integer> = broadcasts
                    .iter()
                    .map(|b| {
                        round_2::compute_participant_verification_share(
                            &client.state,
                            &participant_self,
                            &b,
                        )
                        .unwrap()
                    })
                    .collect();

                let others_verification_shares =
                    round_2::compute_others_verification_share(&client.state, &verification_shares);

                assert_eq!(
                    own_public_key_share, others_verification_shares,
                    "Couldn't confirm others' shares."
                )
            }

            let aggregated_public_key =
                round_2::compute_group_public_key(&client.state, &broadcasts)?;

            logging::print(
                format!(
                    "This is the {}group public key{}: {}.",
                    logging::YELLOW,
                    logging::RESET,
                    aggregated_public_key.to_string_radix(RADIX),
                )
                .as_str(),
            );

            (own_public_key_share, aggregated_public_key, private_key)
        };

        {
            let sign_input = SignInput {
                state: client.state,
                own_public_share: own_public_key,
                own_private_share: private_key_share,
                public_aggregated_key: aggregate_public_key,
                message: String::new(),
            };
            sign_input.to_file(path).await?;
        }

        Ok(())
    }
}

pub mod sign_client {
    use crate::{
        preprocess::generate_nonces_and_commitments,
        sign::{
            compute_aggregate_response, compute_group_commitment_and_challenge,
            compute_own_response, lagrange_coefficient, verify_participant,
        },
    };

    use super::*;
    use futures::SinkExt;
    use rand::Rng;
    use rug::{rand::RandState, Integer};
    use std::{collections::HashSet, error::Error};
    use tokio_util::codec::{Framed, LinesCodec};

    pub async fn run(ip: &str, port: u32, path: &str) -> Result<(), Box<dyn Error>> {
        // wallet and participant info needed from file
        let sign_input = SignInput::from_file(path).await?;

        // connect
        let address = format!("{}:{}", ip, port);
        let stream = TcpStream::connect(address).await?;
        let mut lines = Framed::new(stream, LinesCodec::new());

        // init client
        let client = {
            let id = {
                match recieve_message(&mut lines).await? {
                    Message::Id(id) => id,
                    _ => return Err("Couldn't parse the message.".into()),
                }
            };

            let state = sign_input.state;
            FrostClient::new(state, id)
        };

        let own_id = Integer::from(client.own_id);

        // init random state
        let mut rnd = {
            let seed: i32 = rand::rng().random();
            let mut rnd = RandState::new();
            rnd.seed(&rug::Integer::from(seed));

            rnd
        };

        // preprocess nonces and commitments
        let nonces_and_commitments = generate_nonces_and_commitments(&client.state, &mut rnd);

        // compute public commitment to send
        let own_public_commitment = Message::PublicCommitment {
            participant_id: own_id.clone(),
            di: nonces_and_commitments.1 .0.clone(),
            ei: nonces_and_commitments.1 .1.clone(),
            public_share: sign_input.own_public_share.clone(),
        };

        lines.send(own_public_commitment.to_json_string()).await?;

        // recieving others commitments
        let public_commitments = {
            let mut seen = HashSet::new();
            seen.insert(sign_input.own_public_share);
            let mut public_commitments = vec![own_public_commitment.clone()];
            for _i in 1..(client.state.threshold) {
                let message = recieve_message(&mut lines).await?;
                match &message {
                    Message::PublicCommitment {
                        participant_id: _,
                        di: _,
                        ei: _,
                        public_share,
                    } => match seen.insert(public_share.clone()) {
                        true => public_commitments.push(message.clone()),
                        false => return Err("Multiple instances of the same participant tried to sign the operation.".into())
                    },
                    _ => return Err("Couldn't parse the message.".into()),
                }
            }

            public_commitments
        };

        let (_group_commitment, challenge) = compute_group_commitment_and_challenge(
            &client.state,
            &public_commitments,
            &sign_input.message,
            sign_input.public_aggregated_key.clone(),
        )?;

        let lagrange_coefficient = lagrange_coefficient(&client.state, &own_id);

        let own_response = compute_own_response(
            &client.state,
            own_id.clone(),
            &own_public_commitment,
            &sign_input.own_private_share,
            &nonces_and_commitments.0,
            &lagrange_coefficient,
            &challenge,
            &sign_input.message,
        )?;

        match client.own_id {
            // if the participant is the SA.
            1 => {
                let responses = {
                    let mut responses = vec![own_response];
                    for _i in 1..(client.state.threshold) {
                        let message = recieve_message(&mut lines).await?;
                        match message {
                            Message::Response {
                                sender_id: _,
                                value: _,
                            } => responses.push(message),
                            _ => return Err("Couldn't parse the message ya ya.".into()),
                        }
                    }
                    responses
                };

                responses
                    .iter()
                    .try_for_each(|r| -> Result<(), Box<dyn Error>> {
                        match r {
                            Message::Response {
                                sender_id,
                                value: _,
                            } => {
                                let participant_commitment = public_commitments
                                    .iter()
                                    .find(|pc| match pc {
                                        Message::PublicCommitment {
                                            participant_id,
                                            di: _,
                                            ei: _,
                                            public_share: _,
                                        } => participant_id == sender_id,
                                        _ => false,
                                    })
                                    .expect("Couldn't get participant's id.");

                                let verify = verify_participant(
                                    &client.state,
                                    &participant_commitment,
                                    &sign_input.message,
                                    &r,
                                    &challenge,
                                )?;

                                assert!(verify);
                                Ok(())
                            }
                            _ => return Err("Couldn't parse message.".into()),
                        }
                    })?;

                let aggregate_response = compute_aggregate_response(&client.state, &responses)?;

                logging::print(&format!(
                    "The group {} computed this response {} with this message \"{}\".",
                    sign_input.public_aggregated_key.to_string_radix(32),
                    aggregate_response.to_string_radix(32),
                    sign_input.message
                ));
            }
            // if the participant is not the SA.
            _ => {
                lines.send(&own_response.to_json_string()).await?;
            }
        }

        Ok(())
    }
}
