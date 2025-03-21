//! Implementation of the FROST key generation step.
//!
//! ## Dependencies
//!
//! - `rug` is a arbitrary precision numbers crate and provides infrastructure for the 256bit numbers and calculations.
//! - `rand` is a random number generation crate and it is used to generate a random seed for the 256bit numbers generation.
//! - `sha-256` is an implementation of SHA-256 and it is the predefined hashing algorythm for the threshold signature system.
//!
//! ## Features
//!
//! - Generation of a participant's secret share, public commitments and the group public key and verifying key.
//! - Verification of other participants' public commitments and verifying keys.
//!
//! ## Support
//!
//! The steps to generate keys using FROST are computed using the following steps.
//!
//! ### Round 1:
//!
//! 1. Each participant Pi draws t random values (ai0, . , ai(t-1))) <-$-Zq and uses these values as coefficients to define a polynomial fi(x) = SUM(aij xj, j=0.. .t-1).
//! 2. Each Pi computes a proof of knowledge corresponding to the secret ai0 by using ai0 as the key to compute the Schnorr signature SIGi = (wi, ci) such that k <-$- Zq, Ri = gk, ci = H(i, CTX, g^{ai0}, Ri), wi = k + ai0* ci, where CTX is the context string to prevent replay attacks.
//! 3. Each participant Pi computes a public commitment Ci = < Ai0, . , Ai(t-1) >, where Aij = g^{aij}, 0 <= j <= t-1
//! 4. Each Pi broadcasts Ci, SIGi to all other participants.
//! 5. After receiving Cp, SIGi from participant 1 <= p <= n, p ! = i for Cp, SIGp, participant Pi verifies SIGp = (wp, cp) and terminates on failure, checking: cp =? = H(p, CTX, Ap0, g^{wp} * Ap0^{ cp})
//!
//! ### Round 2：
//!
//! 1. Each Pi securely sends a secret share (p, fi(p)) to the other participants Pp and keeps (i, fi(i)) for itself.
//! 2. Each Pi sends a secret share to the other Pi by computing: g^{fp(i)} =? = PROD(Apk(i^k mod q),k=0.. .t-1) to verify their shares and abort if the check fails.
//! 3. Each Pi calculates their share by computing si = SUM(fp(i), p=1... . n) to compute their long-standing private signature shares and store si securely.
//! 4. Each Pi computes their public verification share Yi = g^{si} and the group's public key Y = PROD(Aj0, j=1... .n). Any participant can compute the public key by computing Yi = PROD( (Ajk)(i^k mod q), j=1... .n, k=0... .t-1) to calculate the publicly verified share of any other participant.
//!
//! ## Example
//!
//!

use crate::{modular, PRIME};
use rand::Rng;
use round_2::{compute_group_public_key, compute_own_verification_share, compute_private_key};
use rug::{rand::RandState, Integer};
use sha256::digest;
use std::str::FromStr;

pub struct FrostState {
    pub prime: Integer,
    pub q: Integer,
    pub generator: Integer,
    pub participants: usize,
    pub threshold: usize,
}

impl FrostState {
    pub fn init(participants_input: usize, threshold_input: usize) -> Self {
        Self {
            prime: Integer::from_str(PRIME).expect("Shouldn't happen."),
            q: Integer::from((Integer::from_str(PRIME).expect("Shouldn't happen.") - 1) / 2),
            generator: Integer::from(4),
            participants: participants_input,
            threshold: threshold_input,
        }
    }
}

#[derive(Clone, Debug)]
pub struct CTX {
    pub protocol: String,
    pub group_id: Integer,
    pub session_id: Integer,
}

impl CTX {
    pub fn init(protocol: &str, group_id_input: Integer, session_id_input: Integer) -> Self {
        Self {
            protocol: protocol.to_string(),
            group_id: group_id_input,
            session_id: session_id_input,
        }
    }

    pub fn to_string(ctx: &CTX) -> String {
        format!("{}::{}::{}", ctx.protocol, ctx.group_id, ctx.session_id)
    }
}

#[derive(Clone, Debug)]
pub struct ParticipantBroadcast {
    pub participant_id: Integer,
    pub commitments: Vec<Integer>,
    pub signature: (Integer, Integer),
}

impl ParticipantBroadcast {
    pub fn init(
        participant_id_input: Integer,
        commitments_input: Vec<Integer>,
        signature_input: (Integer, Integer),
    ) -> Self {
        Self {
            participant_id: participant_id_input,
            commitments: commitments_input,
            signature: signature_input,
        }
    }
}

pub struct Participant {
    pub id: Integer,
    pub polynomial: Vec<Integer>,
}

impl Participant {
    pub fn init(id_input: Integer, polynomial_input: Vec<Integer>) -> Self {
        Self {
            id: id_input,
            polynomial: polynomial_input,
        }
    }
}

pub struct SecretShare {
    pub participant_id: Integer,
    pub secret: Integer,
}

impl SecretShare {
    pub fn init(participant_id_input: Integer, secret_input: Integer) -> Self {
        Self {
            participant_id: participant_id_input,
            secret: secret_input,
        }
    }
}

pub fn generate_integer(state: &FrostState, rnd: &mut RandState) -> Integer {
    Integer::from(Integer::random_below(state.q.clone(), rnd))
}

pub fn keygen_ctx(group_id: Integer, session_id: Integer) -> CTX {
    CTX::init("keygen", group_id, session_id)
}

pub mod round_1 {
    use super::*;

    pub fn generate_polynomial(state: &FrostState, rnd: &mut RandState) -> Vec<Integer> {
        let mut polynomial: Vec<Integer> = Vec::new();
        for _i in 0..state.threshold {
            let a = generate_integer(&state, rnd);
            polynomial.push(a);
        }
        polynomial
    }

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

    pub fn verify_proofs(
        state: &FrostState,
        participants_broadcasts: &[ParticipantBroadcast],
        ctx: &CTX,
    ) -> bool {
        participants_broadcasts.iter().fold(true, |acc, pb| {
            let (wp, cp) = pb.signature.clone();
            let rp = modular::mul(
                modular::pow(&state.generator, &wp, &state.prime),
                modular::pow(&pb.commitments[0], &Integer::from(-&cp), &state.prime),
                &state.prime,
            );
            let reconstructed_cp = Integer::from_str_radix(
                digest(format!(
                    "{}::::{}::::{}::::{}",
                    &pb.participant_id,
                    CTX::to_string(&ctx),
                    &pb.commitments[0],
                    rp,
                ))
                .as_str(),
                16,
            )
            .unwrap()
            .modulo(&state.q);
            acc && (reconstructed_cp == cp)
        })
    }
}

pub mod round_2 {
    use super::{FrostState, Participant, ParticipantBroadcast, SecretShare};
    use crate::modular;
    use rug::Integer;

    pub fn calculate_y(x: &Integer, pol: &[Integer], q: &Integer) -> Integer {
        pol.iter().enumerate().fold(Integer::ZERO, |acc, (i, p)| {
            modular::add(
                acc,
                modular::mul(p.clone(), modular::pow(x, &Integer::from(i), q), q),
                q,
            )
        })
    }

    pub fn create_secret_share(state: &FrostState, participant: &Participant) -> SecretShare {
        let secret = calculate_y(&participant.id, &participant.polynomial, &state.q);
        SecretShare::init(participant.id.clone(), secret)
    }

    pub fn verify_secret_shares(
        state: &FrostState,
        participant: &Participant,
        own_secret_share: &SecretShare,
        participant_broadcast: &ParticipantBroadcast,
    ) -> bool {
        let own = modular::pow(&state.generator, &own_secret_share.secret, &state.prime);
        let others = participant_broadcast.commitments.iter().enumerate().fold(
            Integer::from(1),
            |acc, (k, apk)| {
                modular::mul(
                    acc,
                    modular::pow(
                        &apk,
                        &modular::pow(&participant.id, &Integer::from(k), &state.q),
                        &state.prime,
                    ),
                    &state.prime,
                )
            },
        );
        own == others
    }

    pub fn compute_private_key(
        state: &FrostState,
        own_secret_share: &SecretShare,
        others_secret_shares: &[Integer],
    ) -> Integer {
        modular::add(
            others_secret_shares
                .iter()
                .fold(Integer::from(0), |acc, pc| {
                    modular::add(acc, pc.clone(), &state.q)
                }),
            own_secret_share.secret.clone(),
            &state.q,
        )
    }

    pub fn compute_own_verification_share(state: &FrostState, private_key: &Integer) -> Integer {
        modular::pow(&state.generator, &private_key, &state.prime)
    }

    pub fn compute_group_public_key(state: &FrostState, commitments: &[&[Integer]]) -> Integer {
        commitments
            .iter()
            .fold(Integer::from(1), |acc, participant_commitments| {
                modular::mul(participant_commitments[0].clone(), acc, &state.prime)
            })
    }

    pub fn compute_public_verification_share(
        state: &FrostState,
        participant: &Participant,
        participant_broadcast: &ParticipantBroadcast,
    ) -> Integer {
        participant_broadcast.commitments.iter().enumerate().fold(
            Integer::from(1),
            |acc, (k, apk)| {
                modular::mul(
                    acc,
                    modular::pow(
                        &apk,
                        &modular::pow(&participant.id, &Integer::from(k), &state.q),
                        &state.prime,
                    ),
                    &state.prime,
                )
            },
        )
    }
}

#[test]
pub fn test_keygen_commitments_and_proofs() {
    // Initializing state for random number generation.
    let seed: i32 = rand::rng().random();
    let mut rnd = RandState::new();
    rnd.seed(&rug::Integer::from(seed));

    // Initializing the ctx and the state that will be used for the key generation session (common across all participants).
    let ctx = keygen_ctx(Integer::from(1), Integer::from(1));
    let state = FrostState::init(3, 2);

    // ROUND 1

    // Creating polynomials for each participant. No one but the server should have access to them.
    let pol_1 = round_1::generate_polynomial(&state, &mut rnd);
    let pol_2 = round_1::generate_polynomial(&state, &mut rnd);
    let pol_3 = round_1::generate_polynomial(&state, &mut rnd);

    // Creating three participants for the example with their respective id and poynomial.
    let participant_1 = Participant::init(Integer::from(1), pol_1);
    let participant_2 = Participant::init(Integer::from(2), pol_2);
    let participant_3 = Participant::init(Integer::from(3), pol_3);

    // Creating signatures for each participant.
    let signature_1 = round_1::compute_proof_of_knowlodge(&state, &mut rnd, &participant_1, &ctx);
    let signature_2 = round_1::compute_proof_of_knowlodge(&state, &mut rnd, &participant_2, &ctx);
    let signature_3 = round_1::compute_proof_of_knowlodge(&state, &mut rnd, &participant_3, &ctx);

    // Creating public commitments for each participant.
    let commitments_1 = round_1::compute_public_commitments(&state, &participant_1);
    let commitments_2 = round_1::compute_public_commitments(&state, &participant_2);
    let commitments_3 = round_1::compute_public_commitments(&state, &participant_3);

    // Creating a broadcast for each participant that will be sent to all.
    let participant_broadcast_1 =
        ParticipantBroadcast::init(participant_1.id.clone(), commitments_1, signature_1);
    let participant_broadcast_2 =
        ParticipantBroadcast::init(participant_2.id.clone(), commitments_2, signature_2);
    let participant_broadcast_3 =
        ParticipantBroadcast::init(participant_3.id.clone(), commitments_3, signature_3);

    // Verifying the other participants broadcasts.
    assert!(round_1::verify_proofs(
        &state,
        &[
            participant_broadcast_2.clone(),
            participant_broadcast_3.clone(),
        ],
        &ctx
    ));

    // ROUND 2

    // Create participant's private share.
    let own_share_1 = round_2::create_secret_share(&state, &participant_1);

    // Create shares that will be sent to other participants.
    let share_from_3_to_1 = round_2::create_secret_share(
        &state,
        &Participant::init(participant_1.id.clone(), participant_3.polynomial.clone()),
    );
    let share_from_2_to_1 = round_2::create_secret_share(
        &state,
        &Participant::init(participant_1.id.clone(), participant_2.polynomial.clone()),
    );

    // Verify the shares recieved from other participants.
    assert!(round_2::verify_secret_shares(
        &state,
        &participant_1,
        &share_from_3_to_1,
        &participant_broadcast_3,
    ));
    assert!(round_2::verify_secret_shares(
        &state,
        &participant_1,
        &share_from_2_to_1,
        &participant_broadcast_2,
    ));

    // Create the account's private key. It should not be saved.
    let private_key_1 = compute_private_key(
        &state,
        &own_share_1,
        &[share_from_2_to_1.secret, share_from_3_to_1.secret],
    );

    // Create the verification share that will be used to confirm other's verification shares.
    let own_verification_share_1 = compute_own_verification_share(&state, &private_key_1);

    // Compute public verification share from commitments of all other participants.
    let public_verification_share_1 = round_2::compute_public_verification_share(
        &state,
        &participant_1,
        &participant_broadcast_1,
    );
    let public_verification_share_1_from_2 = round_2::compute_public_verification_share(
        &state,
        &participant_1,
        &participant_broadcast_2,
    );
    let public_verification_share_1_from_3 = round_2::compute_public_verification_share(
        &state,
        &participant_1,
        &participant_broadcast_3,
    );

    // Combine the other verification shares.
    let public_verification_share_1 = modular::mul(
        modular::mul(
            public_verification_share_1,
            public_verification_share_1_from_2,
            &state.prime,
        ),
        public_verification_share_1_from_3,
        &state.prime,
    );

    // Verify if the verification shares are valid.
    assert_eq!(own_verification_share_1, public_verification_share_1);

    // Create the group public key that will be used to sign.
    let group_public_key = compute_group_public_key(
        &state,
        &[
            &participant_broadcast_1.commitments.clone(),
            &participant_broadcast_2.commitments.clone(),
            &participant_broadcast_3.commitments.clone(),
        ],
    );

    println!("The generated group public key is: {group_public_key}.");
}
