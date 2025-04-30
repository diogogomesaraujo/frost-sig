//! Implementation of FROST's keygen used for wallet creation.
//!
//! # Dependencies
//!
//! - `rug` is a arbitrary precision numbers crate and provides infrastructure for the 256bit numbers and calculations.
//! - `rand` is a random number generation crate and it is used to generate a random seed for the 256bit numbers generation.
//! - `sha-256` is an implementation of SHA-256 and it is the predefined hashing algorythm for the threshold signature system.
//!
//! # Features
//!
//! - Generation of a participant's secret share, verifying key and the group's public key.
//! - Verification of other participants' public commitments and verifying keys.
//!
//! # Support
//!
//! - The keygen process should only occur **when creating the wallet** as it generates a group public key and private shares for each participant.
//! - What should be saved? The participant should only save their **private key**, the **group public key** and their **verification share**.
//! - To learn more about the algorythms used for the key-generation process, bellow is a detailed explanation of each step:
//!
//! ### Round 1
//!
//! 1. Each participant Pi draws t random values (ai0, . , ai(t-1))) <-$-Zq and uses these values as coefficients to define a polynomial fi(x) = SUM(aij xj, j=0.. .t-1).
//! 2. Each Pi computes a proof of knowledge corresponding to the secret ai0 by using ai0 as the key to compute the Schnorr signature SIGi = (wi, ci) such that k <-$- Zq, Ri = gk, ci = H(i, CTX, g^{ai0}, Ri), wi = k + ai0* ci, where CTX is the context string to prevent replay attacks.
//! 3. Each participant Pi computes a public commitment Ci = < Ai0, . , Ai(t-1) >, where Aij = g^{aij}, 0 <= j <= t-1
//! 4. Each Pi broadcasts Ci, SIGi to all other participants.
//! 5. After receiving Cp, SIGi from participant 1 <= p <= n, p ! = i for Cp, SIGp, participant Pi verifies SIGp = (wp, cp) and terminates on failure, checking: cp =? = H(p, CTX, Ap0, g^{wp} * Ap0^{ cp})
//!
//! ### Round 2
//!
//! 1. Each Pi securely sends a secret share (p, fi(p)) to the other participants Pp and keeps (i, fi(i)) for itself.
//! 2. Each Pi sends a secret share to the other Pi by computing: g^{fp(i)} =? = PROD(Apk(i^k mod q),k=0.. .t-1) to verify their shares and abort if the check fails.
//! 3. Each Pi calculates their share by computing si = SUM(fp(i), p=1... . n) to compute their long-standing private signature shares and store si securely.
//! 4. Each Pi computes their public verification share Yi = g^{si} and the group's public key Y = PROD(Aj0, j=1... .n). Any participant can compute the public key by computing Yi = PROD( (Ajk)(i^k mod q), j=1... .n, k=0... .t-1) to calculate the publicly verified share of any other participant.
//!
//! See the [resources](https://eprint.iacr.org/2020/852.pdf) here.

use crate::message::Message;
use curve25519_dalek::Scalar;

/// Struct that represents the participant.
pub struct Participant {
    /// Parameter that is the identifier for the participant.
    pub id: u32,
    /// Parameter that is the participant's secret polynomial even to himself. It should only be used for calculations.
    pub polynomial: Vec<Scalar>,
}

impl Participant {
    /// Function that creates a `Participant`.
    pub fn new(id: u32, polynomial: Vec<Scalar>) -> Self {
        Self { id, polynomial }
    }
}

/// The first round is responsible for generating nonces and commitments that will be used to generate the aggregated key if all the participants are verified.
pub mod round_1 {
    use super::*;
    use crate::*;
    use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, ristretto::CompressedRistretto};
    use message::Message;
    use rand::rngs::OsRng;
    use sha2::Sha512;

    /// Function that generates a participant's polynomial that will be used to compute his nonces (`ex: ax^2 + bx + c -> [c, b, a]`).
    pub fn generate_polynomial(state: &FrostState, rng: &mut OsRng) -> Vec<Scalar> {
        let mut polynomial: Vec<Scalar> = Vec::new();
        for _i in 0..state.threshold {
            let a = Scalar::random(rng);
            polynomial.push(a);
        }
        polynomial
    }

    /// Function that computes a participant's challenge and encrypted response.
    pub fn compute_proof_of_knowlodge(
        rng: &mut OsRng,
        participant: &Participant,
    ) -> (Scalar, Scalar) {
        let k = Scalar::random(rng);
        let ri = k * RISTRETTO_BASEPOINT_POINT;
        let ci = {
            let mut buf = vec![];
            buf.extend_from_slice(&participant.id.to_le_bytes());
            buf.extend_from_slice(
                (participant.polynomial[0] * RISTRETTO_BASEPOINT_POINT)
                    .compress()
                    .as_bytes(),
            );
            buf.extend_from_slice(ri.compress().as_bytes());
            Scalar::hash_from_bytes::<Sha512>(&buf)
        };
        let wi = k + participant.polynomial[0] * ci;
        (wi, ci)
    }

    /// Function that computes a participant's public commitment that will be broadcasted and used to verify him.
    pub fn compute_public_commitments(participant: &Participant) -> Vec<CompressedRistretto> {
        participant
            .polynomial
            .iter()
            .map(|coefficient| (coefficient * RISTRETTO_BASEPOINT_POINT).compress())
            .collect()
    }

    /// Function that is used by a participant to verify if other participants are valid or not.
    pub fn verify_proofs(participants_broadcasts: &[Message]) -> bool {
        participants_broadcasts
            .iter()
            .fold(true, |acc, pb| match pb {
                Message::Broadcast {
                    signature: (wp, cp),
                    commitments,
                    participant_id,
                } => {
                    let rp = {
                        let temp1 = wp * RISTRETTO_BASEPOINT_POINT;
                        let temp2 = commitments[0].decompress().unwrap() * cp;
                        temp1 - temp2
                    };
                    let reconstructed_cp = {
                        let mut buf = vec![];
                        buf.extend_from_slice(&participant_id.to_le_bytes());
                        buf.extend_from_slice(commitments[0].as_bytes());
                        buf.extend_from_slice(rp.compress().as_bytes());
                        Scalar::hash_from_bytes::<Sha512>(&buf)
                    };
                    acc && (&reconstructed_cp == cp)
                }
                _ => false,
            })
    }
}

/// The second round is responsible for generating partial signatures for every participant and aggregate them to form the group keys that will be used to sign transactions.
pub mod round_2 {
    use super::Participant;
    use crate::message::Message;
    use curve25519_dalek::{
        constants::RISTRETTO_BASEPOINT_POINT, ristretto::CompressedRistretto, traits::Identity,
        RistrettoPoint, Scalar,
    };
    use std::error::Error;

    /// Function that calculates the y value for a given polinomial and an x.
    /// It utilizes the Horner's method.
    pub fn calculate_y(x: &Scalar, pol: &[Scalar]) -> Scalar {
        pol.iter().rev().fold(Scalar::ZERO, |acc, p| acc * x + p)
    }

    /// Function that creates a participant's secret share to verify shares sent by other participants.
    pub fn create_own_secret_share(participant: &Participant) -> Message {
        let secret = calculate_y(&Scalar::from(participant.id), &participant.polynomial);
        Message::SecretShare {
            sender_id: participant.id.clone(),
            reciever_id: participant.id.clone(),
            secret,
        }
    }

    /// Function that creates a participant's secret share for other participants to verify.
    pub fn create_share_for(sender: &Participant, reciever_id: &u32) -> Message {
        let secret = calculate_y(&Scalar::from(*reciever_id), &sender.polynomial);
        Message::SecretShare {
            reciever_id: reciever_id.clone(),
            sender_id: sender.id.clone(),
            secret,
        }
    }

    /// Function that verifies a sender using the reciever's share and a sender's broadcast.
    pub fn verify_share_validity(
        participant: &Participant,
        secret_share: &Message,
        participant_broadcast: &Message,
    ) -> bool {
        match (secret_share, participant_broadcast) {
            (
                Message::SecretShare {
                    sender_id: _,
                    reciever_id: _,
                    secret,
                },
                Message::Broadcast {
                    participant_id: _,
                    commitments,
                    signature: _,
                },
            ) => {
                let own = secret * RISTRETTO_BASEPOINT_POINT;
                let others = commitments.iter().enumerate().fold(
                    RistrettoPoint::identity(),
                    |acc, (k, apk)| {
                        acc + (apk.decompress().unwrap()
                            * Scalar::from(participant.id.pow(k as u32)))
                    },
                );
                own == others
            }
            _ => false,
        }
    }

    /// Function that verifies a sender using the reciever's share and a sender's broadcast.
    pub fn compute_private_key(
        own_secret_share: &Message,
        others_secret_shares: &[Message],
    ) -> Result<Scalar, Box<dyn Error>> {
        match own_secret_share {
            Message::SecretShare {
                sender_id: _,
                reciever_id: _,
                secret,
            } => Ok(secret
                + others_secret_shares.iter().try_fold(
                    Scalar::ZERO,
                    |acc, pc| -> Result<_, Box<dyn Error>> {
                        match pc {
                            Message::SecretShare {
                                sender_id: _,
                                reciever_id: _,
                                secret,
                            } => Ok(acc + secret),
                            _ => Err("Message was not of the desired type.".into()),
                        }
                    },
                )?),
            _ => Err("Message was not of the desired type.".into()),
        }
    }

    /// Function that computes a participant's verification share.
    pub fn compute_own_verification_share(private_key: &Scalar) -> CompressedRistretto {
        (private_key * RISTRETTO_BASEPOINT_POINT).compress()
    }

    /// Function that computes the group public key used to sign transactions and identify the group.
    pub fn compute_group_public_key(
        participants_broadcasts: &[Message],
    ) -> Result<CompressedRistretto, Box<dyn Error>> {
        Ok(participants_broadcasts
            .iter()
            .try_fold(
                RistrettoPoint::identity(),
                |acc, pb| -> Result<RistrettoPoint, Box<dyn Error>> {
                    match pb {
                        Message::Broadcast {
                            participant_id: _,
                            commitments,
                            signature: _,
                        } => Ok(commitments[0].decompress().unwrap() + acc),
                        _ => Err("Message was not of the desired type.".into()),
                    }
                },
            )?
            .compress())
    }

    /// Function that computes a participant's verification share.
    pub fn compute_participant_verification_share(
        participant: &Participant,
        participant_broadcast: &Message,
    ) -> Result<CompressedRistretto, Box<dyn Error>> {
        match participant_broadcast {
            Message::Broadcast {
                participant_id: _,
                commitments,
                signature: _,
            } => Ok(commitments
                .iter()
                .enumerate()
                .fold(RistrettoPoint::identity(), |acc, (k, apk)| {
                    acc + (apk.decompress().unwrap() * Scalar::from(participant.id.pow(k as u32)))
                })
                .compress()),
            _ => Err("Message is not a participant broadcast".into()),
        }
    }

    /// Function that computes other participants' verification share.
    pub fn compute_others_verification_share(
        verifying_shares: &[CompressedRistretto],
    ) -> CompressedRistretto {
        verifying_shares
            .iter()
            .fold(RistrettoPoint::identity(), |acc, share| {
                acc + share.decompress().unwrap()
            })
            .compress()
    }
}
