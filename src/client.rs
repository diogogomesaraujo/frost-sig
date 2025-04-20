use crate::FrostState;

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

pub mod keygen {
    use crate::{
        client::FrostClient,
        keygen::{self, round_1, round_2},
        message::Message,
        FrostState, RADIX,
    };
    use futures::SinkExt;
    use rand::Rng;
    use rug::{rand::RandState, Integer};
    use std::error::Error;
    use tokio::net::TcpStream;
    use tokio_stream::StreamExt;
    use tokio_util::codec::{Framed, LinesCodec};

    pub async fn run(ip: &str, port: u32) -> Result<(), Box<dyn Error>> {
        let address = format!("{}:{}", ip, port);
        let stream = TcpStream::connect(address).await?;
        let mut lines = Framed::new(stream, LinesCodec::new());

        let client = {
            let id = {
                let line = lines.next().await.expect("Couldn't recieve the message.")?;
                let message =
                    Message::from_json_string(line.as_str()).expect("Couldn't parse message.");
                match message {
                    Message::Id(id) => id,
                    _ => return Err("Couldn't parse the message.".into()),
                }
            };

            let state = {
                let line = lines.next().await.expect("Couldn't recieve the message.")?;
                let message =
                    Message::from_json_string(line.as_str()).expect("Couldn't parse message.");
                match message {
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

        let seed: i32 = rand::rng().random();
        let mut rnd = RandState::new();
        rnd.seed(&rug::Integer::from(seed));

        // ROUND 1
        let polynomial = round_1::generate_polynomial(&client.state, &mut rnd);
        let participant_self = keygen::Participant::new(Integer::from(client.own_id), polynomial);
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
                let line = lines.next().await.expect("Couldn't recieve the message.")?;
                let message =
                    Message::from_json_string(line.as_str()).expect("Couldn't parse message.");
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

        // ROUND 2
        let own_share = round_2::create_own_secret_share(&client.state, &participant_self);
        for i in 1..=client.state.participants {
            if i != participant_self.id {
                let share_to_send =
                    round_2::create_share_for(&client.state, &participant_self, &Integer::from(i));
                lines.send(share_to_send.to_json_string()).await?;
            }
        }
        let secret_shares = {
            let mut secret_shares = vec![];
            for _i in 1..(client.state.participants) {
                let line = lines.next().await.expect("Couldn't recieve the message.")?;
                let message =
                    Message::from_json_string(line.as_str()).expect("Couldn't parse message.");
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
        let private_key = round_2::compute_private_key(&client.state, &own_share, &secret_shares)?;
        println!(
            "This is your private key: {}.",
            private_key.to_string_radix(RADIX)
        );
        let own_public_key = round_2::compute_own_verification_share(&client.state, &private_key);
        let broadcasts = {
            let mut temp = broadcasts;
            temp.push(own_broadcast);
            temp
        };
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
            own_public_key, others_verification_shares,
            "Couldn't confirm others' shares."
        );

        let aggregated_public_key = round_2::compute_group_public_key(&client.state, &broadcasts);

        println!(
            "This is the group public key: {}",
            aggregated_public_key.to_string_radix(RADIX)
        );

        Ok(())
    }
}
