use rug::Integer;

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
    Response { sender_id: Integer, value: Integer },
}
