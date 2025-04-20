use rug::Integer;
use serde::{Deserialize, Serialize};

use crate::RADIX;

/// Enum that represents all the messages that will be sent during the FROST protocol operations.
#[derive(Clone, Debug)]
pub enum Message {
    /// Message utilized during the keygen round 1 phase.
    /// It represents the commitments and signature used to validate a user and create the aggregate public key.
    Broadcast {
        participant_id: Integer,
        commitments: Vec<Integer>,
        signature: (Integer, Integer),
    },

    /// Message that is sent during the keygen round 2 phase.
    /// It represents the secret sent from every participant to all others and it is used to calculate a participant's private key.
    SecretShare {
        sender_id: Integer,
        reciever_id: Integer,
        secret: Integer,
    },

    /// Message that is sent during the signature phase.
    /// It is used by the main participant (SA) for others to verify the commitments chosen by the SA.
    PublicCommitment {
        participant_id: Integer,
        di: Integer,
        ei: Integer,
        public_share: Integer,
    },

    /// Message that is sent during the signature phase.
    /// It is used to compute the aggregate response and is sent by every participant to the SA.
    Response {
        sender_id: Integer,
        value: Integer,
    },

    /// Message that is sent at the beginning of a FROST operation.
    /// It is used to do all the calculations needed for all the FROST operations.
    FrostState {
        prime: Integer,
        q: Integer,
        generator: Integer,
        participants: u32,
        threshold: u32,
    },

    Id(u32),
}

impl Message {
    pub fn to_json_string(&self) -> String {
        match self {
            Message::Broadcast {
                participant_id,
                commitments,
                signature,
            } => {
                let participant_id = participant_id.to_string_radix(RADIX);
                let commitments: Vec<String> = commitments
                    .iter()
                    .map(|c| c.to_string_radix(RADIX))
                    .collect();
                let signature = {
                    let (left, right) = signature;
                    (left.to_string_radix(RADIX), right.to_string_radix(RADIX))
                };
                let message = MessageJSON::Broadcast {
                    participant_id,
                    commitments,
                    signature,
                };
                serde_json::to_string(&message).unwrap()
            }
            Message::SecretShare {
                sender_id,
                reciever_id,
                secret,
            } => {
                let sender_id = sender_id.to_string_radix(RADIX);
                let reciever_id = reciever_id.to_string_radix(RADIX);
                let secret = secret.to_string_radix(RADIX);
                let message = MessageJSON::SecretShare {
                    sender_id,
                    reciever_id,
                    secret,
                };
                serde_json::to_string(&message).unwrap()
            }
            Message::PublicCommitment {
                participant_id,
                di,
                ei,
                public_share,
            } => {
                let participant_id = participant_id.to_string_radix(RADIX);
                let di = di.to_string_radix(RADIX);
                let ei = ei.to_string_radix(RADIX);
                let public_share = public_share.to_string_radix(RADIX);
                let message = MessageJSON::PublicCommitment {
                    participant_id,
                    di,
                    ei,
                    public_share,
                };
                serde_json::to_string(&message).unwrap()
            }
            Message::Response { sender_id, value } => {
                let sender_id = sender_id.to_string_radix(RADIX);
                let value = value.to_string_radix(RADIX);
                let message = MessageJSON::Response { sender_id, value };
                serde_json::to_string(&message).unwrap()
            }
            Message::FrostState {
                prime,
                q,
                generator,
                participants,
                threshold,
            } => {
                let prime = prime.to_string_radix(RADIX);
                let q = q.to_string_radix(RADIX);
                let generator = generator.to_string_radix(RADIX);
                let participants = participants.clone();
                let threshold = threshold.clone();
                let message = MessageJSON::FrostState {
                    prime,
                    q,
                    generator,
                    participants,
                    threshold,
                };
                serde_json::to_string(&message).unwrap()
            }
            Message::Id(id) => serde_json::to_string(&MessageJSON::Id(id.clone())).unwrap(),
        }
    }

    pub fn from_json_string(message: &str) -> Option<Message> {
        match serde_json::from_str::<MessageJSON>(&message) {
            Ok(message_json) => Some(message_json.from_json()),
            Err(_) => None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MessageJSON {
    Broadcast {
        participant_id: String,
        commitments: Vec<String>,
        signature: (String, String),
    },
    SecretShare {
        sender_id: String,
        reciever_id: String,
        secret: String,
    },
    PublicCommitment {
        participant_id: String,
        di: String,
        ei: String,
        public_share: String,
    },
    Response {
        sender_id: String,
        value: String,
    },
    FrostState {
        prime: String,
        q: String,
        generator: String,
        participants: u32,
        threshold: u32,
    },
    Id(u32),
}

impl MessageJSON {
    pub fn from_json(&self) -> Message {
        match self {
            Self::Broadcast {
                participant_id,
                commitments,
                signature,
            } => {
                let participant_id = Integer::from_str_radix(participant_id, RADIX).unwrap();
                let commitments: Vec<Integer> = commitments
                    .iter()
                    .map(|c| Integer::from_str_radix(c, RADIX).unwrap())
                    .collect();
                let signature = {
                    let (left, right) = signature;
                    (
                        Integer::from_str_radix(left, RADIX).unwrap(),
                        Integer::from_str_radix(right, RADIX).unwrap(),
                    )
                };
                Message::Broadcast {
                    participant_id,
                    commitments,
                    signature,
                }
            }
            Self::PublicCommitment {
                participant_id,
                di,
                ei,
                public_share,
            } => {
                let participant_id = Integer::from_str_radix(participant_id, RADIX).unwrap();
                let di = Integer::from_str_radix(di, RADIX).unwrap();
                let ei = Integer::from_str_radix(ei, RADIX).unwrap();
                let public_share = Integer::from_str_radix(public_share, RADIX).unwrap();
                Message::PublicCommitment {
                    participant_id,
                    di,
                    ei,
                    public_share,
                }
            }
            Self::SecretShare {
                sender_id,
                reciever_id,
                secret,
            } => {
                let sender_id = Integer::from_str_radix(sender_id, RADIX).unwrap();
                let reciever_id = Integer::from_str_radix(reciever_id, RADIX).unwrap();
                let secret = Integer::from_str_radix(secret, RADIX).unwrap();
                Message::SecretShare {
                    sender_id,
                    reciever_id,
                    secret,
                }
            }
            Self::Response { sender_id, value } => {
                let sender_id = Integer::from_str_radix(sender_id, RADIX).unwrap();
                let value = Integer::from_str_radix(value, RADIX).unwrap();
                Message::Response { sender_id, value }
            }
            Self::FrostState {
                prime,
                q,
                generator,
                participants,
                threshold,
            } => {
                let prime = Integer::from_str_radix(prime, RADIX).unwrap();
                let q = Integer::from_str_radix(q, RADIX).unwrap();
                let generator = Integer::from_str_radix(generator, RADIX).unwrap();
                let participants = participants.clone();
                let threshold = threshold.clone();
                Message::FrostState {
                    prime,
                    q,
                    generator,
                    participants,
                    threshold,
                }
            }
            Self::Id(id) => Message::Id(id.clone()),
        }
    }
}
