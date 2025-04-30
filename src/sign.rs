//! Implementation of FROST's sign step that is used to sign transactions.
//!
//! # Dependencies
//!
//! - `blake2` is an implementation of the BLAKE2 hash functions.
//! - `curve25519_dalek` is a crate for elliptic curve cryptography.
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

use crate::{message::Message, FrostState};
use blake2::Blake2b512;
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::CompressedRistretto, traits::Identity,
    RistrettoPoint, Scalar,
};
use std::error::Error;

/// Function that computes the binding values for a participant.
/// It recieves the message that will be signed and creates a hashed value that will be used to verify the participants commitment.
/// It follows this format: *id::::message::::commitment*.
pub fn compute_binding_value(
    participant_commitment: &Message,
    message: &str,
) -> Result<Scalar, Box<dyn Error>> {
    match participant_commitment {
        Message::PublicCommitment {
            participant_id,
            di,
            ei,
            public_share,
        } => Ok({
            let mut buf = vec![];
            buf.extend_from_slice(&participant_id.to_le_bytes());
            buf.extend_from_slice(message.as_bytes());
            buf.extend_from_slice(di.as_bytes());
            buf.extend_from_slice(ei.as_bytes());
            buf.extend_from_slice(public_share.as_bytes());

            Scalar::hash_from_bytes::<Blake2b512>(&buf)
        }),
        _ => Err("Message was not of the desired type.".into()),
    }
}

/// Function that computes the aggregate group commitment and a challenge that will be verified by other participants.
pub fn compute_group_commitment_and_challenge(
    participants_commitments: &[Message],
    message: &str,
    group_public_key: CompressedRistretto,
) -> Result<(CompressedRistretto, Scalar), Box<dyn Error>> {
    let group_commitment = participants_commitments
        .iter()
        .try_fold(
            RistrettoPoint::identity(),
            |acc, pc| -> Result<RistrettoPoint, Box<dyn Error>> {
                match pc {
                    Message::PublicCommitment {
                        participant_id: _,
                        di,
                        ei,
                        public_share: _,
                    } => Ok({
                        let binding_value = compute_binding_value(&pc, &message)?;
                        acc + (di.decompress().unwrap()
                            + (ei.decompress().unwrap() * binding_value))
                    }),
                    _ => Err("Message was not of the desired type.".into()),
                }
            },
        )?
        .compress();
    let challenge = {
        let mut buf = vec![];
        buf.extend_from_slice(group_commitment.as_bytes());
        buf.extend_from_slice(group_public_key.as_bytes());
        buf.extend_from_slice(message.as_bytes());

        Scalar::hash_from_bytes::<Blake2b512>(&buf)
    };
    Ok((group_commitment, challenge))
}

/// Function that calculates the lagrange_coefficient of a participant.
pub fn lagrange_coefficient(state: &FrostState, participant_id: &u32) -> Scalar {
    let id = Scalar::from(*participant_id);
    (1..=state.threshold)
        .into_iter()
        .fold(Scalar::ONE, |acc, j| {
            if &j == participant_id {
                acc
            } else {
                let j = Scalar::from(j);
                acc * (j * (j - id).invert())
            }
        })
}

/// Function that calculates a participant's response that will be sent to the SA (main participant).
/// It is computed from the users private nonces and secret keys.
pub fn compute_own_response(
    participant_id: u32,
    participant_commitment: &Message,
    private_key: &Scalar,
    private_nonces: &(Scalar, Scalar),
    lagrange_coefficient: &Scalar,
    challenge: &Scalar,
    message: &str,
) -> Result<Message, Box<dyn Error>> {
    let binding_value = compute_binding_value(&participant_commitment, &message)?;
    let (di, ei) = private_nonces;

    Ok(Message::Response {
        sender_id: participant_id,
        value: di + (ei * binding_value) + (lagrange_coefficient * private_key * challenge),
    })
}

/// Function that verifies if a participant is malicious or not by analysing the commitments other's sent.
pub fn verify_participant(
    state: &FrostState,
    participant_commitment: &Message,
    message: &str,
    response: &Message,
    challenge: &Scalar,
) -> Result<bool, Box<dyn Error>> {
    match (participant_commitment, response) {
        (
            Message::PublicCommitment {
                participant_id,
                di,
                ei,
                public_share,
            },
            Message::Response {
                sender_id: _,
                value,
            },
        ) => {
            let gz = value * RISTRETTO_BASEPOINT_POINT;
            let binding_value = compute_binding_value(participant_commitment, message)?;
            let ri = di.decompress().unwrap() + (ei.decompress().unwrap() * binding_value);
            let to_validate = {
                let exponent = challenge * lagrange_coefficient(state, participant_id);
                ri + (public_share.decompress().unwrap() * exponent)
            };
            assert_eq!(
                gz, to_validate,
                "Failed to validate participant {}.",
                participant_id
            );
            Ok(gz == to_validate)
        }
        _ => Err("Failed to give the correct parameters.".into()),
    }
}

/// Function that computes the aggregate response created from all responses.
pub fn compute_aggregate_response(
    participants_responses: &[Message],
) -> Result<Scalar, Box<dyn Error>> {
    participants_responses
        .iter()
        .try_fold(Scalar::ZERO, |acc, pr| match pr {
            Message::Response {
                sender_id: _,
                value,
            } => Ok(acc + value),
            _ => Err("Message was not of the desired type.".into()),
        })
}
