use rug::Integer;
use sha256::digest;

use crate::{modular, FrostState};

pub struct PublicCommitment {
    pub participant_id: Integer,
    pub di: Integer,
    pub ei: Integer,
}

impl PublicCommitment {
    pub fn new(participant_id: Integer, di: Integer, ei: Integer) -> Self {
        Self {
            participant_id,
            di,
            ei,
        }
    }

    pub fn to_string(&self) -> String {
        format!("{}::{}::{}", self.participant_id, self.di, self.ei)
    }
}

pub fn compute_group_commitment_and_challenge(
    state: &FrostState,
    participants_commitments: &[PublicCommitment],
    message: &str,
    group_public_key: Integer,
) -> (Integer, Integer) {
    let group_commitment = participants_commitments
        .iter()
        .fold(Integer::from(1), |acc, pc| {
            let binding_value = Integer::from_str_radix(
                digest(format!(
                    "{}::::{}::::{}",
                    pc.participant_id,
                    message,
                    pc.to_string()
                ))
                .as_str(),
                16,
            )
            .unwrap();

            modular::mul(
                acc.clone(),
                modular::pow(&pc.ei, &binding_value, &state.prime),
                &state.prime,
            )
        });
    let challenge = Integer::from_str_radix(
        digest(format!(
            "{}::{}::{}",
            group_commitment, group_public_key, message
        ))
        .as_str(),
        16,
    )
    .unwrap();
    (group_commitment, challenge)
}

pub fn compute_participant_response() {}

pub fn verify_and_aggregate_signature() {}
