use rug::Integer;

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

    PublicCommitment {
        participant_id: Integer,
        di: Integer,
        ei: Integer,
        public_share: Integer,
    },
}
