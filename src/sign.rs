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

use crate::{decompress, hash_to_array, hash_to_scalar, message::Message};
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT, edwards::CompressedEdwardsY, traits::Identity,
    EdwardsPoint, Scalar,
};
use ed25519_dalek_blake2b::Signature;
use std::error::Error;

/// Function that computes the binding values for a participant.
/// It receives the message that will be signed and creates a hashed value that will be used to verify the participants commitment.
pub fn compute_binding_value(
    participant_commitment: &Message,
    all_commitments: &[Message],
    message: &str,
    verifying_key: &CompressedEdwardsY,
    additional_prefix: &[u8],
) -> Result<Scalar, Box<dyn Error>> {
    match participant_commitment {
        Message::PublicCommitment {
            participant_id,
            di: _,
            ei: _,
            public_share: _,
        } => Ok({
            let mut binding_value = vec![];
            binding_value.extend_from_slice(&verifying_key.to_bytes());
            binding_value.extend_from_slice(&hash_to_array(&[message.as_bytes()]));
            let commitments_hash = {
                let mut hasher = vec![];
                all_commitments
                    .iter()
                    .try_for_each(|c| -> Result<(), Box<dyn Error>> {
                        match c {
                            Message::PublicCommitment {
                                participant_id: _,
                                di,
                                ei,
                                public_share: _,
                            } => {
                                hasher.extend_from_slice(di.as_bytes());
                                hasher.extend_from_slice(ei.as_bytes());
                                Ok(())
                            }
                            _ => return Err("Message was not a Public Commitment.".into()),
                        }
                    })?;
                hasher
            };
            binding_value.extend_from_slice(&commitments_hash);
            binding_value.extend_from_slice(&additional_prefix);
            binding_value.extend_from_slice(&participant_id.to_le_bytes());
            hash_to_scalar(&[&binding_value[..]])
        }),
        _ => Err("Message was not of the desired type.".into()),
    }
}

/// Function that computes the aggregate group commitment and a challenge that will be verified by other participants.
pub fn compute_group_commitment_and_challenge(
    participants_commitments: &[Message],
    message: &str,
    group_public_key: CompressedEdwardsY,
    additional_prefix: &[u8],
) -> Result<(CompressedEdwardsY, Scalar), Box<dyn Error>> {
    let group_commitment = participants_commitments
        .iter()
        .try_fold(
            EdwardsPoint::identity(),
            |acc, pc| -> Result<EdwardsPoint, Box<dyn Error>> {
                match pc {
                    Message::PublicCommitment {
                        participant_id: _,
                        di,
                        ei,
                        public_share: _,
                    } => Ok({
                        let binding_value = compute_binding_value(
                            &pc,
                            &participants_commitments,
                            &message,
                            &group_public_key,
                            &additional_prefix,
                        )?;
                        acc + (decompress(di)? + (decompress(ei)? * binding_value))
                    }),
                    _ => Err("Message was not of the desired type.".into()),
                }
            },
        )?
        .compress();
    let challenge = {
        let mut hasher = vec![];
        hasher.extend_from_slice(group_commitment.as_bytes());
        hasher.extend_from_slice(group_public_key.as_bytes());
        hasher.extend_from_slice(message.as_bytes());
        hash_to_scalar(&[&hasher[..]])
    };
    Ok((group_commitment, challenge))
}

/// Function that calculates the lagrange_coefficient of a participant.
pub fn lagrange_coefficient(ids: &[u32], target_id: &u32) -> Scalar {
    let id = Scalar::from(target_id.clone());
    ids.iter()
        .filter(|&&j| &j != target_id)
        .fold(Scalar::ONE, |acc, &j| {
            let j = Scalar::from(j);
            acc * (j * (j - id).invert())
        })
}

/// Function that calculates a participant's response that will be sent to the SA (main participant).
/// It is computed from the users private nonces and secret keys.
pub fn compute_own_response(
    participant_id: u32,
    participant_commitment: &Message,
    all_commitments: &[Message],
    private_key: &Scalar,
    private_nonces: &(Scalar, Scalar),
    lagrange_coefficient: &Scalar,
    challenge: &Scalar,
    message: &str,
    verifying_key: &CompressedEdwardsY,
    additional_prefix: &[u8],
) -> Result<Message, Box<dyn Error>> {
    let binding_value = compute_binding_value(
        &participant_commitment,
        &all_commitments,
        &message,
        &verifying_key,
        &additional_prefix,
    )?;
    let (di, ei) = private_nonces;
    Ok(Message::Response {
        sender_id: participant_id,
        value: di + (ei * binding_value) + (lagrange_coefficient * private_key * challenge),
    })
}

/// Function that verifies if a participant is malicious or not by analysing the commitments other's sent.
pub fn verify_participant(
    participant_commitment: &Message,
    all_commitments: &[Message],
    message: &str,
    response: &Message,
    challenge: &Scalar,
    verifying_key: &CompressedEdwardsY,
    additional_prefix: &[u8],
    ids: &[u32],
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
            let gz = value * ED25519_BASEPOINT_POINT;
            let binding_value = compute_binding_value(
                participant_commitment,
                &all_commitments,
                message,
                verifying_key,
                additional_prefix,
            )?;
            let ri = decompress(di)? + (decompress(ei)? * binding_value);
            let to_validate = {
                let exponent = challenge * lagrange_coefficient(&ids, &participant_id);
                ri + (decompress(public_share)? * exponent)
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

/// Function that converts the aggregate response and group commitment into a valid 64 bytes ed25519 signature.
pub fn computed_response_to_signature(
    aggregate_response: &Scalar,
    group_commitment: &CompressedEdwardsY,
) -> Result<(Signature, String), Box<dyn Error>> {
    let mut bytes = [0; 64];
    bytes[0..32].copy_from_slice(group_commitment.as_bytes());
    bytes[32..].copy_from_slice(&aggregate_response.to_bytes());

    match Signature::from_bytes(&bytes) {
        Ok(sig) => Ok((sig, hex::encode(&bytes))),
        Err(_) => Err("Couldn't compute signature.".into()),
    }
}
