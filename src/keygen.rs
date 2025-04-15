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

use crate::{modular, CTX, RADIX};
use rand::Rng;
use rug::{rand::RandState, Integer};
use sha256::digest;

/// Struct that represents the participant.
pub struct Participant {
    /// Parameter that is the identifier for the participant.
    pub id: Integer,
    /// Parameter that is the participant's secret polynomial even to himself. It should only be used for calculations.
    pub polynomial: Vec<Integer>,
}

impl Participant {
    /// Function that creates a `Participant`.
    pub fn new(id: Integer, polynomial: Vec<Integer>) -> Self {
        Self { id, polynomial }
    }
}

/// Function that creates the CTX for the keygen operation.
pub fn keygen_ctx(group_id: Integer, session_id: Integer) -> CTX {
    CTX::new("keygen", group_id, session_id)
}

/// The first round is responsible for generating nonces and commitments that will be used to generate the aggregated key if all the participants are verified.
pub mod round_1 {
    use message::Message;

    use super::*;
    use crate::*;

    /// Function that generates a participant's polynomial that will be used to compute his nonces (`ex: ax^2 + bx + c -> [c, b, a]`).
    pub fn generate_polynomial(state: &FrostState, rnd: &mut RandState) -> Vec<Integer> {
        let mut polynomial: Vec<Integer> = Vec::new();
        for _i in 0..state.threshold {
            let a = generate_integer(&state, rnd);
            polynomial.push(a);
        }
        polynomial
    }

    /// Function that computes a participant's challenge and encrypted response.
    pub fn compute_proof_of_knowlodge(
        state: &FrostState,
        rnd: &mut RandState,
        participant: &Participant,
        ctx: &CTX,
    ) -> (Integer, Integer) {
        let k = generate_integer(&state, rnd);
        let r = modular::pow(&state.generator, &k, &state.prime);
        let ci = Integer::from_str_radix(
            digest(format!(
                "{}::::{}::::{}::::{}",
                &participant.id,
                CTX::to_string(&ctx),
                modular::pow(&state.generator, &participant.polynomial[0], &state.prime),
                r
            ))
            .as_str(),
            16,
        )
        .unwrap()
        .modulo(&state.q);
        let wi = modular::add(
            k,
            modular::mul(participant.polynomial[0].clone(), ci.clone(), &state.q),
            &state.q,
        );
        (wi, ci)
    }

    /// Function that computes a participant's public commitment that will be broadcasted and used to verify him.
    pub fn compute_public_commitments(
        state: &FrostState,
        participant: &Participant,
    ) -> Vec<Integer> {
        participant
            .polynomial
            .iter()
            .map(|coefficient| modular::pow(&state.generator, &coefficient, &state.prime))
            .collect()
    }

    /// Function that is used by a participant to verify if other participants are valid or not.
    pub fn verify_proofs(
        state: &FrostState,
        participants_broadcasts: &[Message],
        ctx: &CTX,
    ) -> bool {
        participants_broadcasts
            .iter()
            .fold(true, |acc, pb| match pb {
                Message::Broadcast {
                    signature,
                    commitments,
                    participant_id,
                } => {
                    let (wp, cp) = signature.clone();
                    let rp = modular::mul(
                        modular::pow(&state.generator, &wp, &state.prime),
                        modular::pow(&commitments[0], &Integer::from(-&cp), &state.prime),
                        &state.prime,
                    );
                    let reconstructed_cp = Integer::from_str_radix(
                        digest(format!(
                            "{}::::{}::::{}::::{}",
                            &participant_id,
                            CTX::to_string(&ctx),
                            &commitments[0],
                            rp,
                        ))
                        .as_str(),
                        16,
                    )
                    .unwrap()
                    .modulo(&state.q);
                    acc && (reconstructed_cp == cp)
                }
                _ => false,
            })
    }
}

/// The second round is responsible for generating partial signatures for every participant and aggregate them to form the group keys that will be used to sign transactions.
pub mod round_2 {
    use std::io::Error;

    use super::Participant;
    use crate::{message::Message, modular, FrostState};
    use rug::Integer;

    /// Function that calculates the y value for a given polinomial and an x.
    pub fn calculate_y(x: &Integer, pol: &[Integer], q: &Integer) -> Integer {
        pol.iter().enumerate().fold(Integer::ZERO, |acc, (i, p)| {
            modular::add(
                acc,
                modular::mul(p.clone(), modular::pow(x, &Integer::from(i), q), q),
                q,
            )
        })
    }

    /// Function that creates a participant's secret share to verify shares sent by other participants.
    pub fn create_own_secret_share(state: &FrostState, participant: &Participant) -> Message {
        let secret = calculate_y(&participant.id, &participant.polynomial, &state.q);
        Message::SecretShare {
            sender_id: participant.id.clone(),
            reciever_id: participant.id.clone(),
            secret,
        }
    }

    /// Function that creates a participant's secret share for other participants to verify.
    pub fn create_share_for(
        state: &FrostState,
        sender: &Participant,
        reciever_id: &Integer,
    ) -> Message {
        let secret = calculate_y(&reciever_id, &sender.polynomial, &state.q);
        Message::SecretShare {
            reciever_id: reciever_id.clone(),
            sender_id: sender.id.clone(),
            secret,
        }
    }

    /// Function that verifies a sender using the reciever's share and a sender's broadcast.
    pub fn verify_share_validity(
        state: &FrostState,
        participant: &Participant,
        own_secret_share: &Message,
        participant_broadcast: &Message,
    ) -> bool {
        match (own_secret_share, participant_broadcast) {
            (
                Message::SecretShare {
                    sender_id,
                    reciever_id,
                    secret,
                },
                Message::Broadcast {
                    participant_id,
                    commitments,
                    signature,
                },
            ) => {
                let own = modular::pow(&state.generator, &secret, &state.prime);
                let others =
                    commitments
                        .iter()
                        .enumerate()
                        .fold(Integer::from(1), |acc, (k, apk)| {
                            modular::mul(
                                acc,
                                modular::pow(
                                    &apk,
                                    &modular::pow(&participant.id, &Integer::from(k), &state.q),
                                    &state.prime,
                                ),
                                &state.prime,
                            )
                        });
                own == others
            }
            _ => false,
        }
    }

    /// Function that verifies a sender using the reciever's share and a sender's broadcast.
    pub fn compute_private_key(
        state: &FrostState,
        own_secret_share: &Message,
        others_secret_shares: &[Message],
    ) -> Result<Integer, Error> {
        match own_secret_share {
            Message::SecretShare {
                sender_id,
                reciever_id,
                secret,
            } => Ok(modular::add(
                others_secret_shares
                    .iter()
                    .fold(Integer::from(0), |acc, pc| match pc {
                        Message::SecretShare {
                            sender_id,
                            reciever_id,
                            secret,
                        } => modular::add(acc, secret.clone(), &state.q),
                        _ => {
                            panic!("That is not a valid message!") // make this better error handling
                        }
                    }),
                secret.clone(),
                &state.q,
            )),
            _ => Err(Error::new(
                std::io::ErrorKind::InvalidInput,
                "Message is not a secret share",
            )),
        }
    }

    /// Function that computes a participant's verification share.
    pub fn compute_own_verification_share(state: &FrostState, private_key: &Integer) -> Integer {
        modular::pow(&state.generator, &private_key, &state.prime)
    }

    /// Function that computes the group public key used to sign transactions and identify the group.
    pub fn compute_group_public_key(
        state: &FrostState,
        participants_broadcasts: &[&Message],
    ) -> Integer {
        participants_broadcasts
            .iter()
            .fold(Integer::from(1), |acc, pb| match pb {
                Message::Broadcast {
                    participant_id,
                    commitments,
                    signature,
                } => modular::mul(commitments[0].clone(), acc, &state.prime),
                _ => {
                    panic!("Sent a message with the wrong format!");
                }
            })
    }

    /// Function that computes a participant's verification share.
    pub fn compute_participant_verification_share(
        state: &FrostState,
        participant: &Participant,
        participant_broadcast: &Message,
    ) -> Result<Integer, Error> {
        match participant_broadcast {
            Message::Broadcast {
                participant_id,
                commitments,
                signature,
            } => Ok(commitments
                .iter()
                .enumerate()
                .fold(Integer::from(1), |acc, (k, apk)| {
                    modular::mul(
                        acc,
                        modular::pow(
                            &apk,
                            &modular::pow(&participant.id, &Integer::from(k), &state.q),
                            &state.prime,
                        ),
                        &state.prime,
                    )
                })),
            _ => Err(Error::new(
                std::io::ErrorKind::InvalidInput,
                "Message is not a participant broadcast",
            )),
        }
    }

    /// Function that computes other participants' verification share.
    pub fn compute_others_verification_share(
        state: &FrostState,
        verifying_shares: &[Integer],
    ) -> Integer {
        verifying_shares
            .iter()
            .fold(Integer::from(1), |acc, share| {
                modular::mul(acc, share.clone(), &state.prime)
            })
    }
}
