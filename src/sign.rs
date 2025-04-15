//! Implementation of FROST's sign step that is used to sign transactions.
//!
//! # Dependencies
//!
//! - `rug` is a arbitrary precision numbers crate and provides infrastructure for the 256bit numbers and calculations.
//! - `rand` is a random number generation crate and it is used to generate a random seed for the 256bit numbers generation.
//! - `sha-256` is an implementation of SHA-256 and it is the predefined hashing algorythm for the threshold signature system.
//!
//! # Features
//!
//! - Sign a transaction.
//! - Verification of other participants.
//!
//! # Support
//!
//! Let SA denote the signature aggregator (who himself can be one of the t signature participants),
//! S be the set of participants selected for this signature operation,
//! B = < (i, Dij, Eij) for i in S> denote the ordered list of participant indexes corresponding to each participant Pi,
//! and Li be the set of available commitment values for Pi announced in the preprocessing phase.
//! Each identifier i is coupled to the jth commitment (Dij, Eij) published by Pi that will be used for this particular signature operation.
//! Let H1, H2 be hash functions whose outputs are in Zq*.
//!
//! SA first obtains the next available commitment from Li for each participant Pi in S and constructs B.
//!
//! For each i in S, SA sends a tuple (m, B) to Pi.
//!
//! After receiving (m, B), each Pi first verifies the message m and then checks Dp_j, Ep_j in G* for each commitment in B.
//! If either check fails, it aborts.
//!
//! Then, each Pi computes the set of bound values r_p = H1(p, m, B) for each p in S.
//! Each Pi then derives the set of commitments R = PROD(Dp_j * (Ep_j)^(r_p), for p in S), and the challenge c = H2(m, R).
//!
//! Each Pi computes their response by computing z_i = d_ij + (e_ij * r_i) + L_i * s_i * c, using their long-term secret shared s_i,
//! and using S to determine L_i.
//!
//! Each Pi safely removes ((d_ij, D_ij), (e_ij, E_ij)) from their local storage and returns z_i to SA.
//!
//! The signature aggregator SA performs the following steps:
//!
//!   - Derive r_i = H1(i, m, B) and compute R_i = D_ij * (E_ij)^(r_i) for each i in S.
//!
//!   - Compute overall R = PROD(R_i, for i in S) and then recalculate c = H2(m, R).
//!
//!   - For each signature share z_i, verify that g^(z_i) ?= R_i * (Y_i)^(c * L_i).
//!     If any check fails, identify and report misbehaving participants and then abort. Otherwise, continue.
//!
//!   - Compute the group response z = SUM(z_i, for i in S).
//!
//!   - Publish the signature SIG = (z, c) with the message m.
//!
//! SA finally checks whether the z_i reported by each participant matches with their committed shares (D_ij, E_ij)
//! and their public key shares Y_i. If each participant has issued the correct z_i, then the sum of the z_i values
//! together with c constitutes the Schnorr signature on m.
//! This signature will be correctly verified by a verifier who does not know that FROST was used to generate the signature,
//! and who verifies it with Y as the public key using the standard one-sided Schnorr verification equation (Section 2.4).
//!
//! Handling transient pending shares:
//! Since each nonce and commitment share generated in the preprocessing phase can be used at most once,
//! the participant removes these values after using them in the signing operation (as shown in step 5 of the signing algorithm).
//! An accidental reuse of (d_ij, e_ij) leads to the exposure of the participant's long-term secret s_i, so the participant
//! must securely remove them and defend against snapshot rollback attacks as any Schnorr signature implementation would.
//! However, if the SA chooses to reuse a commitment set (d_ij, e_ij) during the signing protocol, doing so simply
//! causes the participant Pi to abort the protocol and therefore does not increase the SA's power.
//!
//! See the [resources](https://eprint.iacr.org/2020/852.pdf) here.

use crate::{modular, FrostState};
use rand::Rng;
use rug::Integer;
use sha256::digest;

/// Struct that represents the public commitment sent from a participant to others.
#[derive(Clone)]
pub struct PublicCommitment {
    /// `participant_id` is the id of the participant sending the public commitment.
    pub participant_id: Integer,
    /// `di` is part of the public commitment being sent.
    pub di: Integer,
    /// `ei` is part of the public commitment being sent.
    pub ei: Integer,
    /// `public_share` is the public key share that identifies a participant.
    pub public_share: Integer,
}

impl PublicCommitment {
    /// Function that creates a new `PublicCommitment`. It is initialized with the parameters given.
    pub fn new(participant_id: Integer, di: Integer, ei: Integer, public_share: Integer) -> Self {
        Self {
            participant_id,
            di,
            ei,
            public_share,
        }
    }

    /// Function that converts a `PublicCommitment` to a string. It uses this format: *id::di::ei*.
    pub fn to_string(&self) -> String {
        format!("{}::{}::{}", self.participant_id, self.di, self.ei)
    }
}

/// Function that computes the binding values for a participant.
/// It recieves the message that will be signed and creates a hashed value that will be used to verify the participants commitment.
/// It follows this format: *id::::message::::commitment*.
pub fn compute_binding_value(
    state: &FrostState,
    participant_commitment: &PublicCommitment,
    message: &str,
) -> Integer {
    Integer::from_str_radix(
        digest(format!(
            "{}::::{}::::{}",
            participant_commitment.participant_id,
            message,
            participant_commitment.to_string()
        ))
        .as_str(),
        16,
    )
    .unwrap()
    .modulo(&state.q)
}

/// Function that computes the aggregate group commitment and a challenge that will be verified by other participants.
pub fn compute_group_commitment_and_challenge(
    state: &FrostState,
    participants_commitments: &[PublicCommitment],
    message: &str,
    group_public_key: Integer,
) -> (Integer, Integer) {
    let group_commitment = participants_commitments
        .iter()
        .fold(Integer::from(1), |acc, pc| {
            let binding_value = compute_binding_value(&state, &pc, &message);
            modular::mul(
                modular::mul(acc.clone(), pc.di.clone(), &state.prime),
                modular::pow(&pc.ei, &binding_value, &state.prime),
                &state.prime,
            )
        });
    let challenge = Integer::from_str_radix(
        digest(format!(
            "{}::::{}::::{}",
            group_commitment, group_public_key, message
        ))
        .as_str(),
        16,
    )
    .unwrap()
    .modulo(&state.q);
    (group_commitment, challenge)
}

/// Function that calculates the lagrange_coefficient of a participant.
pub fn lagrange_coefficient(
    state: &FrostState,
    participant_id: &Integer,
    signers_ids: &[Integer],
) -> Integer {
    signers_ids.iter().fold(Integer::from(1), |acc, j| {
        if j == participant_id {
            acc
        } else {
            let j = Integer::from(j);
            modular::mul(
                acc.clone(),
                modular::div(
                    j.clone(),
                    modular::sub(j, participant_id.clone(), &state.q),
                    &state.q,
                ),
                &state.q,
            )
        }
    })
}

/// Function that calculates a participant's response that will be sent to the SA (main participant).
/// It is computed from the users private nonces and secret keys.
pub fn compute_own_response(
    state: &FrostState,
    participant_commitment: &PublicCommitment,
    private_key: &Integer,
    private_nonces: &(Integer, Integer),
    lagrange_coefficient: &Integer,
    challenge: &Integer,
    message: &str,
) -> Integer {
    let binding_value = compute_binding_value(&state, &participant_commitment, &message);
    let (di, ei) = private_nonces;
    modular::add(
        di.clone(),
        modular::add(
            modular::mul(ei.clone(), binding_value, &state.q),
            modular::mul(
                modular::mul(lagrange_coefficient.clone(), private_key.clone(), &state.q),
                challenge.clone(),
                &state.q,
            ),
            &state.q,
        ),
        &state.q,
    )
}

/// Function that verifies if a participant is malicious or not by analysing the commitments other's sent.
pub fn verify_participant(
    state: &FrostState,
    participant_commitment: &PublicCommitment,
    message: &str,
    response: &Integer,
    challenge: &Integer,
    signers_ids: &[Integer],
) -> bool {
    let gz: Integer = modular::pow(&state.generator, &response, &state.prime);
    let binding_value = compute_binding_value(&state, &participant_commitment, &message);
    let ri = modular::mul(
        participant_commitment.di.clone(),
        modular::pow(&participant_commitment.ei, &binding_value, &state.prime),
        &state.prime,
    );
    let to_validate = {
        let exponent = modular::mul(
            challenge.clone(),
            lagrange_coefficient(&state, &participant_commitment.participant_id, &signers_ids),
            &state.q,
        );
        modular::mul(
            ri,
            modular::pow(
                &participant_commitment.public_share,
                &exponent,
                &state.prime,
            ),
            &state.prime,
        )
    };
    assert_eq!(
        gz, to_validate,
        "Failed to validate participant {}.",
        participant_commitment.participant_id
    );
    gz == to_validate
}

/// Function that computes the aggregate response created from all responses.
pub fn compute_aggregate_response(
    state: &FrostState,
    participants_responses: &[Integer],
) -> Integer {
    participants_responses
        .iter()
        .fold(Integer::from(0), |acc, pr| {
            modular::add(acc, pr.clone(), &state.q)
        })
}
