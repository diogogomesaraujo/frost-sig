use rug::Integer;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug)]
pub enum Message {
    Broadcast {
        participant_id: Integer,
        commitments: Vec<Integer>,
        signature: (Integer, Integer),
    },

    SecretShare {
        sender_id: Integer,
        reciever_id: Integer,
        secret: Integer,
    },
}
