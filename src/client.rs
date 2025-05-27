//! Implementation of clients for FROST keygen and signing protocols.
//!
//! # Dependencies
//!
//! - `rand` is a random number generation crate and it is used to generate a random seed for the 256bit numbers generation.
//! - `serde` is a framework for serializing and deserializing Rust data structures efficiently and generically.
//! - `tokio` is a runtime for writting reliable async Rust code.
//!
//! # Features
//!a
//! - Keygen and sign CLI clients.

use crate::{
    keygen::{round_1::verify_proofs, round_2::compute_group_public_key},
    message::Message,
    nano::sign::{Subtype, UnsignedBlock},
    FrostState,
};
use curve25519_dalek::{edwards::CompressedEdwardsY, Scalar};
use serde::{Deserialize, Serialize};
use std::error::Error;
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
};
use tokio_stream::StreamExt;
use tokio_util::codec::{Framed, LinesCodec};

/// Struct that holds the state for the FROST operations and the id of the participant.
#[derive(Debug)]
pub struct FrostClient {
    /// State that holds all the constants needed for the FROST computation.
    pub state: FrostState,
    /// Id of the participant using the client.
    pub own_id: u32,
}

impl FrostClient {
    /// Function that creates a new `FrostClient`.
    pub fn new(state: FrostState, own_id: u32) -> Self {
        Self { state, own_id }
    }
}

/// Function that receives a `Message` of any type.
pub async fn receive_message(
    lines: &mut Framed<TcpStream, LinesCodec>,
) -> Result<Message, Box<dyn Error>> {
    let line = lines.next().await.expect("Couldn't receive the message.")?;
    Ok(Message::from_json_string(line.as_str()).expect("Couldn't receive the message."))
}

/// Module that handles the client side logging.
pub mod logging {
    pub const BLUE: &str = "\x1b[34m";
    pub const YELLOW: &str = "\x1b[33m";
    pub const RESET: &str = "\x1b[0m";

    /// Function that logs messages on to the terminal.
    pub fn print(message: &str) {
        println!("{}Frost Client:{} {}", BLUE, RESET, message);
    }
}

/// Struct that has the information retrieved from the JSON file needed for the signing process.
/// It is created during the keygen phase but you need to update the message before signing.
#[derive(Debug, Serialize, Deserialize)]
pub struct SignInput {
    id: u32,
    /// State that holds all the constants needed for the FROST computations.
    state: FrostState,
    /// Aggregated public key shared by the group.
    public_aggregated_key: CompressedEdwardsY,
    /// Public key that identifies the participant within' the group.
    own_public_share: CompressedEdwardsY,
    /// Private key that is needed for a participant to sign a transaction.
    own_private_share: Scalar,
    /// Participants' broadcasts sent during keygen.
    participants_proofs: Vec<Message>,
    /// Subtype of the transaction (if it is to receive, send or open a block).
    subtype: Subtype,
    /// Message being signed.
    message: UnsignedBlock,
}

impl SignInput {
    /// Function that creates a `SignInput` from the file at the given path.
    pub async fn from_file(path: &str) -> Result<SignInput, Box<dyn Error>> {
        let file = File::open(path).await?;

        let mut buf_reader = BufReader::new(file);
        let mut contents = String::new();
        buf_reader.read_to_string(&mut contents).await?;

        Ok(serde_json::from_str::<SignInput>(&contents)?)
    }

    /// Function that writes a Sign Input to a file.
    pub async fn to_file(&self, path: &str) -> Result<(), Box<dyn Error>> {
        let mut file = File::create(path).await?;
        file.write_all(serde_json::to_string_pretty(&self)?.as_bytes())
            .await?;
        Ok(())
    }

    /// Function that verifies if the data retrieved from the `SignInput` is valid or if it was modified.
    /// It performs mathematically checks if the proofs make sense and also check if the number of people signing is valid as well.
    pub fn verify(&self) -> Result<(), Box<dyn Error>> {
        {
            // verify if proofs were tampered with
            assert!(
                verify_proofs(&self.participants_proofs)?,
                "You are trying to perform a signature with tampered data."
            );

            // verify if threshold was tampered with again
            match &self.participants_proofs[0] {
                Message::Broadcast {
                    participant_id: _,
                    commitments,
                    signature: _,
                } => {
                    assert!(
                        commitments.len() as u32 == self.state.threshold,
                        "You are trying to perform a signature with tampered data."
                    )
                }
                _ => return Err("You are trying to perform a signature with tampered data.".into()),
            }

            // verify if the public aggregated key was tampered with
            assert_eq!(
                compute_group_public_key(&self.participants_proofs)?,
                self.public_aggregated_key,
                "You are trying to perform a signature with tampered data."
            );

            Ok(())
        }
    }
}

/// Module that has the functions needed to run the client used for key generation.
pub mod keygen_client {
    use super::{logging, receive_message, FrostClient, SignInput};
    use crate::{
        keygen::{self, round_1, round_2},
        message::Message,
        nano::{
            account::public_key_to_nano_account,
            sign::{Subtype, UnsignedBlock},
        },
        FrostState,
    };
    use curve25519_dalek::edwards::CompressedEdwardsY;
    use futures::SinkExt;
    use rand::rngs::OsRng;
    use std::error::Error;
    use tokio::net::TcpStream;
    use tokio_util::codec::{Framed, LinesCodec};

    /// Function that runs the keygen client.
    pub async fn run(ip: &str, port: u32, path: &str) -> Result<(), Box<dyn Error>> {
        // connect
        let address = format!("{}:{}", ip, port);
        let stream = TcpStream::connect(address).await?;
        let mut lines = Framed::new(stream, LinesCodec::new());

        logging::print("Connected to the server successfully.");

        // init client
        let client = {
            // get id from the server
            let id = {
                match receive_message(&mut lines).await? {
                    Message::Id(id) => id,
                    _ => return Err("Couldn't parse the message.".into()),
                }
            };

            // get state from the server
            let state = {
                match receive_message(&mut lines).await? {
                    Message::FrostState {
                        participants,
                        threshold,
                    } => FrostState {
                        participants,
                        threshold,
                    },
                    _ => return Err("Couldn't parse message.".into()),
                }
            };
            FrostClient::new(state, id)
        };

        // init random state
        let mut rng = OsRng;

        // execute round 1
        let (own_broadcast, broadcasts, participant_self) = {
            // generate the secret polynomial
            let polynomial = keygen::round_1::generate_polynomial(&client.state, &mut rng);

            // initiate the participant used for the keygen
            let participant_self = keygen::Participant::new(client.own_id, polynomial);

            // compute signature
            let signature = round_1::compute_proof_of_knowlodge(&mut rng, &participant_self);

            // compute commitments
            let commitments = round_1::compute_public_commitments(&participant_self);

            // generate broadcast message
            let own_broadcast = Message::Broadcast {
                participant_id: participant_self.id.clone(),
                commitments,
                signature,
            };

            // send broadcast message
            lines.send(own_broadcast.to_json_string()?).await?;

            // get other participants' broadcast messages
            let broadcasts = {
                let mut broadcasts = vec![];
                for _i in 1..(client.state.participants) {
                    let message = receive_message(&mut lines).await?;
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

            // verify other participants' broadcast messages
            assert!(round_1::verify_proofs(&broadcasts)?);

            (own_broadcast, broadcasts, participant_self)
        };

        // execute round 2
        let (own_public_key, aggregate_public_key, private_key_share, all_broadcasts) = {
            // compute own secret share
            let own_share = round_2::create_own_secret_share(&participant_self);

            // create and send secret shares for all other participants
            for i in 1..=client.state.participants {
                if i != participant_self.id {
                    let share_to_send = round_2::create_share_for(&participant_self, &i);
                    lines.send(share_to_send.to_json_string()?).await?;
                }
            }

            // get secret shares sent by other participants
            let secret_shares = {
                let mut secret_shares = vec![];
                for _i in 1..(client.state.participants) {
                    let message = receive_message(&mut lines).await?;
                    match message {
                        Message::SecretShare {
                            sender_id: _,
                            receiver_id: _,
                            secret: _,
                        } => secret_shares.push(message),
                        _ => return Err("Couldn't parse the message.".into()),
                    }
                }
                secret_shares
            };

            // verify other participants' secret shares
            secret_shares
                .iter()
                .try_for_each(|s| -> Result<(), Box<dyn Error>> {
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
                                    receiver_id: _,
                                    secret: _,
                                },
                            ) => participant_id == sender_id,
                            _ => false,
                        })
                        .unwrap();
                    assert!(round_2::verify_share_validity(
                        &participant_self,
                        &s,
                        &broadcast
                    )?);
                    Ok(())
                })?;

            // compute private key share with the secret shares
            let private_key = round_2::compute_private_key(&own_share, &secret_shares)?;

            // compute own public key share from the private key.
            let own_public_key_share = round_2::compute_own_public_share(&private_key);

            let all_broadcasts = {
                let mut temp = broadcasts;
                temp.push(own_broadcast);
                temp
            };

            // verify others' public key shares
            {
                let verification_shares: Vec<CompressedEdwardsY> = all_broadcasts
                    .iter()
                    .map(|b| {
                        round_2::compute_participant_verification_share(&participant_self, &b)
                            .unwrap()
                    })
                    .collect();

                let others_verification_shares =
                    round_2::compute_others_verification_share(&verification_shares)?;

                assert_eq!(
                    own_public_key_share, others_verification_shares,
                    "Couldn't confirm others' shares."
                )
            }

            // compute aggregated public key from the broadcast messages
            let aggregate_public_key = round_2::compute_group_public_key(&all_broadcasts)?;

            logging::print(
                format!(
                    "This is the group's nano account {}{}{}.",
                    logging::YELLOW,
                    public_key_to_nano_account(&aggregate_public_key.as_bytes()),
                    logging::RESET,
                )
                .as_str(),
            );

            logging::print(
                format!(
                    "The keygen process information was stored in {}{}{}.",
                    logging::YELLOW,
                    path,
                    logging::RESET,
                )
                .as_str(),
            );

            (
                own_public_key_share,
                aggregate_public_key,
                private_key,
                all_broadcasts,
            )
        };

        // write the shared and private information to a file
        {
            let sign_input = SignInput {
                id: client.own_id,
                state: client.state,
                own_public_share: own_public_key,
                own_private_share: private_key_share,
                public_aggregated_key: aggregate_public_key,
                participants_proofs: all_broadcasts,
                subtype: Subtype::OPEN,
                message: UnsignedBlock::empty(),
            };
            sign_input.to_file(path).await?;
        }

        Ok(())
    }
}

/// Module that has the functions needed to run the client used for signing.
pub mod sign_client {
    use super::*;
    use crate::{
        nano::{
            rpc::{Process, RPCState},
            sign::create_signed_block,
        },
        preprocess::generate_nonces_and_commitments,
        sign::{
            compute_aggregate_response, compute_group_commitment_and_challenge,
            compute_own_response, computed_response_to_signature, lagrange_coefficient,
            verify_participant,
        },
    };
    use ed25519_dalek_blake2b::{PublicKey, Signature, Verifier};
    use futures::SinkExt;
    use rand::rngs::OsRng;
    use std::{collections::HashSet, error::Error};
    use tokio_util::codec::{Framed, LinesCodec};

    /// Function that runs the sign client.
    pub async fn run(ip: &str, port: u32, path: &str) -> Result<(), Box<dyn Error>> {
        // wallet and participant info needed from file
        let sign_input = SignInput::from_file(path).await?;

        // verify mallicious behaviour (don't know if this is the right way to do it)
        sign_input.verify()?;

        // connect
        let address = format!("{}:{}", ip, port);
        let stream = TcpStream::connect(address).await?;
        let mut lines = Framed::new(stream, LinesCodec::new());

        // init client
        let (client, sign_id) = {
            // get id from the server
            let sign_id = {
                match receive_message(&mut lines).await? {
                    Message::Id(id) => id,
                    _ => return Err("Couldn't parse the message.".into()),
                }
            };

            (FrostClient::new(sign_input.state, sign_input.id), sign_id)
        };

        // init random state
        let mut rng = OsRng;

        // preprocess nonces and commitments
        let nonces_and_commitments = generate_nonces_and_commitments(&mut rng);

        // compute public commitment to send
        let own_public_commitment = Message::PublicCommitment {
            participant_id: client.own_id,
            di: nonces_and_commitments.1 .0.clone(),
            ei: nonces_and_commitments.1 .1.clone(),
            public_share: sign_input.own_public_share.clone(),
        };

        // send public commitment
        lines.send(own_public_commitment.to_json_string()?).await?;

        // receiving others commitments
        let (public_commitments, ids) = {
            let mut seen = HashSet::new();
            seen.insert((sign_input.own_public_share, client.own_id));
            let mut public_commitments = vec![own_public_commitment.clone()];
            for _i in 1..(client.state.threshold) {
                let message = receive_message(&mut lines).await?;
                match &message {
                    Message::PublicCommitment {
                        participant_id,
                        di: _,
                        ei: _,
                        public_share,
                    } => match seen.insert((*public_share, *participant_id)) {
                        true => public_commitments.push(message.clone()),
                        false => return Err("Multiple instances of the same participant tried to sign the operation.".into())
                    },
                    _ => return Err("Couldn't parse the message.".into()),
                }
            }

            let ids = seen.iter().map(|(_, i)| *i).collect::<Vec<u32>>();

            // sort commitments
            public_commitments.sort_by_key(|c| match c {
                Message::PublicCommitment {
                    participant_id,
                    di: _,
                    ei: _,
                    public_share: _,
                } => participant_id.clone(),
                _ => 0u32,
            });

            (public_commitments, ids)
        };

        // load enviroment variables
        dotenv::dotenv().ok();

        // create the state for the rpc
        let state = RPCState::new(&std::env::var("URL")?);

        // hash the message
        let message = sign_input.message.clone().to_hash(&state).await?;

        // compute group commitment and challenge
        let (group_commitment, challenge) = compute_group_commitment_and_challenge(
            &public_commitments,
            &message,
            sign_input.public_aggregated_key,
            &[],
        )?;

        // compute the lagrange coefficient
        let lagrange_coefficient = lagrange_coefficient(&ids, &client.own_id);

        // compute the response
        let own_response = compute_own_response(
            client.own_id,
            &own_public_commitment,
            &public_commitments,
            &sign_input.own_private_share,
            &nonces_and_commitments.0,
            &lagrange_coefficient,
            &challenge,
            &message,
            &sign_input.public_aggregated_key,
            &[],
        )?;

        match sign_id {
            // if the participant is the SA
            1 => {
                // collect other participants' responses
                let responses = {
                    let mut responses = vec![own_response];
                    for _i in 1..(client.state.threshold) {
                        let message = receive_message(&mut lines).await?;
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

                // verify responses
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
                                    &participant_commitment,
                                    &public_commitments,
                                    &message,
                                    &r,
                                    &challenge,
                                    &sign_input.public_aggregated_key,
                                    &[],
                                    &ids,
                                )?;

                                assert!(verify);
                                Ok(())
                            }
                            _ => return Err("Couldn't parse message.".into()),
                        }
                    })?;

                // compute aggregate response
                let aggregate_response = compute_aggregate_response(&responses)?;

                // start the blockchain signing process
                {
                    let signature = Signature::from_bytes(&computed_response_to_signature(
                        &aggregate_response,
                        &group_commitment,
                    ))
                    .expect("Couldn't create the signature!");

                    {
                        let verifying_key =
                            PublicKey::from_bytes(sign_input.public_aggregated_key.as_bytes())
                                .expect("Couldn't create the public key!");
                        verifying_key
                            .verify(message.as_bytes(), &signature)
                            .expect("Couldn't verify the signature with the public key!");
                    }

                    // create signed block
                    let signed_block = create_signed_block(
                        &state,
                        sign_input.message,
                        &hex::encode(&signature.to_bytes()).to_uppercase(),
                        &hex::encode(&sign_input.public_aggregated_key.as_bytes()),
                    )
                    .await?;

                    // process signature
                    let process =
                        Process::sign_in_rpc(&state, &sign_input.subtype, &signed_block).await?;

                    // print hash from the generated block in the blockchain
                    logging::print(&format!(
                        "The block was successfully created with the hash: {}{}{}",
                        logging::YELLOW,
                        process.hash,
                        logging::RESET
                    ));
                }

                // print aggregated response
                logging::print(&format!(
                    "The group {}{:?}{} computed this response {}{:?}{} with this message {}\"{}\"{}.",
                    logging::YELLOW,
                    sign_input.public_aggregated_key.as_bytes(),
                    logging::RESET,
                    logging::YELLOW,
                    aggregate_response.as_bytes(),
                    logging::RESET,
                    logging::YELLOW,
                    message,
                    logging::RESET,
                ));
            }
            // if the participant is not the SA
            _ => {
                // send response to the SA
                lines.send(&own_response.to_json_string()?).await?;
            }
        }

        Ok(())
    }
}
