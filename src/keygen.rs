//! Implementation of FROST's key-gen step.
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

use crate::{modular, CTX};
use rand::Rng;
use rug::{rand::RandState, Integer};
use sha256::digest;

/// Struct that is the broadcast sent by a participant to all others.
#[derive(Clone, Debug)]
pub struct ParticipantBroadcast {
    /// `participant_id` is the id of the participant sending the broadcast.
    pub participant_id: Integer,
    /// `commitments` are the public commitments sent by the participant.
    pub commitments: Vec<Integer>,
    /// `signature` is used to verify if a participant is not mallicious.
    pub signature: (Integer, Integer),
}

impl ParticipantBroadcast {
    /// Function that initializes the ParticipantBroadcast.
    ///
    /// ## Parameters
    ///
    /// - `participant_id` is the input for the participant id.
    /// - `commitments` is the input for the public commitments of the participant.
    /// - `signature` is the input for the signature of the participant.
    ///
    /// ## Returns
    ///
    /// - `ParticipantBroadcast` initialized with a participant id, public commitments and signature.
    pub fn init(
        participant_id: Integer,
        commitments: Vec<Integer>,
        signature: (Integer, Integer),
    ) -> Self {
        Self {
            participant_id,
            commitments,
            signature,
        }
    }

    // make something more robust later
    pub fn to_string(&self) -> String {
        format!(
            "{:?}\n{:?}\n{:?}\n",
            self.participant_id, self.commitments, self.signature
        )
    }
}

/// Struct that represents the participant.
pub struct Participant {
    /// `id` is the identifier for the participant.
    pub id: Integer,
    /// `polynomial` is used for calculations but shouldn't be accessible not even by the participant.
    pub polynomial: Vec<Integer>,
}

impl Participant {
    /// Function that initializes the Participant.
    ///
    /// ## Parameters
    ///
    /// - `id` is the input for the participant id.
    /// - `polynomial` is a randomly generated vector that is used for important calculations.
    ///
    ///
    /// ## Returns
    ///
    /// - `Participant` with it's id and polynomial.
    pub fn init(id: Integer, polynomial: Vec<Integer>) -> Self {
        Self { id, polynomial }
    }
}

/// Struct that represents a participant's secret share and the recomputed shares from other participants.
pub struct SecretShare {
    pub participant_id: Integer,
    pub secret: Integer,
}

impl SecretShare {
    /// Function that initializes the SecretShare.
    ///
    /// ## Parameters
    ///
    /// - `participant_id` is the input for the participant id.
    /// - `secret` is the input for the secret calculated by the participant.
    ///
    ///
    /// ## Returns
    ///
    /// - `SecretShare` with the participant's id and corresponding secret.
    pub fn init(participant_id: Integer, secret: Integer) -> Self {
        Self {
            participant_id,
            secret,
        }
    }
}

/// Function that initializes the CTX for the keygen operation.
///
/// ## Parameters
///
/// - `group_id` is the id of the group generating the key.
/// - `session_id` is the id of the current session.
///
///
/// ## Returns
///
/// - `CTX` with with the group, session and the protocol "keygen".
pub fn keygen_ctx(group_id: Integer, session_id: Integer) -> CTX {
    CTX::init("keygen", group_id, session_id)
}

/// The first round is responsible for generating nonces and commitments that will be used to generate the aggregated key if all the participants are verified.
pub mod round_1 {
    use super::*;
    use crate::*;

    /// Function that generates a participant's polynomial that will be used to compute his nonces.
    ///
    /// ## Parameters
    ///
    /// - `state` has all the constansts needed for FROST signature operations.
    /// - `rnd` `rnd` is the state for generating random 256bit numbers.
    ///
    ///
    /// ## Returns
    ///
    /// - `Vec<Integer>` with all the constant values of the polynomial (ex: ax^2 + bx + c -> [c, b, a]).
    pub fn generate_polynomial(state: &FrostState, rnd: &mut RandState) -> Vec<Integer> {
        let mut polynomial: Vec<Integer> = Vec::new();
        for _i in 0..state.threshold {
            let a = generate_integer(&state, rnd);
            polynomial.push(a);
        }
        polynomial
    }

    /// Function that computes a participant's challenge and encrypted response.
    ///
    /// ## Parameters
    ///
    /// - `state` has all the constansts needed for FROST signature operations.
    /// - `rnd` `rnd` is the state for generating random 256bit numbers.
    /// - `participant` has the participant's information needed for computations.
    /// - `ctx` identifies the protocol, group and session.
    ///
    ///
    /// ## Returns
    ///
    /// - `(Integer, Integer)` that is that are the challenge and response of a certain participant.
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
    ///
    /// ## Parameters
    ///
    /// - `state` has all the constansts needed for FROST signature operations.
    /// - `participant` has the participant's information needed for computations.
    ///
    /// ## Returns
    ///
    /// - `Vec<Integer>` that is the collection of all the participant's commitments.
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
    ///
    /// ## Parameters
    ///
    /// - `state` has all the constansts needed for FROST signature operations.
    /// - `participants_broadcasts` has the participant's information that other participants need to verify him.
    /// - `ctx` identifies the protocol, group and session.
    ///
    /// ## Returns
    ///
    /// - `bool` that is true if all the participants are correctly verified and false if they are not.
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

/// The second round is responsible for generating partial signatures for every participant and aggregate them to form the group keys that will be used to sign transactions.
pub mod round_2 {
    use super::{Participant, ParticipantBroadcast, SecretShare};
    use crate::{modular, FrostState};
    use rug::Integer;

    /// Function that calculates the y value for a given polinomial and an x.
    ///
    /// ## Parameters
    ///
    /// - `x` is the value of the x axis.
    /// - `pol` is the function that represents the threshold of participants needed to recover the secret.
    /// - `prime` is the prime number used for the modular arithmetic operations.
    ///
    /// ## Returns
    ///
    /// - `Integer` that is the resulting y from the x and pol given.
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
    ///
    /// ## Parameters
    ///
    /// - `state` has all the constansts needed for FROST signature operations.
    /// - `participant` has the participant's information needed for computations.
    ///
    /// ## Returns
    ///
    /// - `SecretShare` that has a participant's secret and his id.
    pub fn create_own_secret_share(state: &FrostState, participant: &Participant) -> SecretShare {
        let secret = calculate_y(&participant.id, &participant.polynomial, &state.q);
        SecretShare::init(participant.id.clone(), secret)
    }

    /// Function that creates a participant's secret share for other participants to verify.
    ///
    /// ## Parameters
    ///
    /// - `state` has all the constansts needed for FROST signature operations.
    /// - `sender` has the sender's information needed for computations.
    /// - `reciever_id` is the id of the reciever.
    ///
    /// ## Returns
    ///
    /// - `SecretShare` that has a sender's secret and the reciever's id.
    pub fn create_share_for(
        state: &FrostState,
        sender: &Participant,
        reciever_id: &Integer,
    ) -> SecretShare {
        let secret = calculate_y(&reciever_id, &sender.polynomial, &state.q);
        SecretShare::init(reciever_id.clone(), secret)
    }

    /// Function that verifies a sender using the reciever's share and a sender's broadcast.
    ///
    /// ## Parameters
    ///
    /// - `state` has all the constansts needed for FROST signature operations.
    /// - `participant` has the participant's information needed for computations.
    /// - `own_secret_share` is the reciever's secret share.
    /// - `participant_broadcast` has the participant's information that other participants need to verify him.
    ///
    /// ## Returns
    ///
    /// - `bool` that is true if it is able to verify the sender and false if it isn't.
    pub fn verify_share_validity(
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

    /// Function that verifies a sender using the reciever's share and a sender's broadcast.
    ///
    /// ## Parameters
    ///
    /// - `state` has all the constansts needed for FROST signature operations.
    /// - `participant` has the participant's information needed for computations.
    /// - `own_secret_share` is a participant's secret share
    /// - `other_secret_shares` are the secret shares sent by other participants.
    ///
    /// ## Returns
    ///
    /// - `Integer` that is the private key the participant should store to sign transactions.
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

    /// Function that computes a participant's verification share.
    ///
    /// ## Parameters
    ///
    /// - `state` has all the constansts needed for FROST signature operations.
    /// - `private_key` is the secret key saved by the participant to sign transactions.
    ///
    /// ## Returns
    ///
    /// - `Integer` that is the verification share that is used to verify a participant's integrety.
    pub fn compute_own_verification_share(state: &FrostState, private_key: &Integer) -> Integer {
        modular::pow(&state.generator, &private_key, &state.prime)
    }

    /// Function that computes the group public key used to sign transactions and identify the group.
    ///
    /// ## Parameters
    ///
    /// - `state` has all the constansts needed for FROST signature operations.
    /// - `commitments` are all the public commitments from all the participants.
    ///
    /// ## Returns
    ///
    /// - `Integer` that is the group public key that identifies the group.
    pub fn compute_group_public_key(state: &FrostState, commitments: &[&[Integer]]) -> Integer {
        commitments
            .iter()
            .fold(Integer::from(1), |acc, participant_commitments| {
                modular::mul(participant_commitments[0].clone(), acc, &state.prime)
            })
    }

    /// Function that computes a participant's verification share.
    ///
    /// ## Parameters
    ///
    /// - `state` has all the constansts needed for FROST signature operations.
    /// - `participant` has the participant's information needed for computations.
    /// - `participant_broadcast` has the participant's information that other participants need to verify him.
    ///
    /// ## Returns
    ///
    /// - `Integer` that is the verification share to verify a participant's integrety.
    pub fn compute_participant_verification_share(
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

    /// Function that computes other participants' verification share.
    ///
    /// ## Parameters
    ///
    /// - `state` has all the constansts needed for FROST signature operations.
    /// - `verifying_shares` has all the verification shares from all participants.
    ///
    /// ## Returns
    ///
    /// - `Integer` that is the verification share to verify others' integrety.
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

#[test]
pub fn test_keygen() {
    let seed: i32 = rand::rng().random();
    let mut rnd = RandState::new();
    rnd.seed(&rug::Integer::from(seed));

    let ctx = keygen_ctx(Integer::from(1), Integer::from(1));
    let state = crate::FrostState::init(&mut rnd, 3, 2);

    // ROUND 1

    let pol_1 = round_1::generate_polynomial(&state, &mut rnd);
    let pol_2 = round_1::generate_polynomial(&state, &mut rnd);
    let pol_3 = round_1::generate_polynomial(&state, &mut rnd);

    let participant_1 = Participant::init(Integer::from(1), pol_1);
    let participant_2 = Participant::init(Integer::from(2), pol_2);
    let participant_3 = Participant::init(Integer::from(3), pol_3);

    let signature_1 = round_1::compute_proof_of_knowlodge(&state, &mut rnd, &participant_1, &ctx);
    let signature_2 = round_1::compute_proof_of_knowlodge(&state, &mut rnd, &participant_2, &ctx);
    let signature_3 = round_1::compute_proof_of_knowlodge(&state, &mut rnd, &participant_3, &ctx);

    let commitments_1 = round_1::compute_public_commitments(&state, &participant_1);
    let commitments_2 = round_1::compute_public_commitments(&state, &participant_2);
    let commitments_3 = round_1::compute_public_commitments(&state, &participant_3);

    let participant_broadcast_1 =
        ParticipantBroadcast::init(participant_1.id.clone(), commitments_1, signature_1);
    let participant_broadcast_2 =
        ParticipantBroadcast::init(participant_2.id.clone(), commitments_2, signature_2);
    let participant_broadcast_3 =
        ParticipantBroadcast::init(participant_3.id.clone(), commitments_3, signature_3);

    assert!(round_1::verify_proofs(
        &state,
        &[
            participant_broadcast_2.clone(),
            participant_broadcast_3.clone(),
        ],
        &ctx
    ));

    // ROUND 2

    let own_share_1 = round_2::create_own_secret_share(&state, &participant_1);

    let share_from_3_to_1 = round_2::create_share_for(&state, &participant_3, &participant_1.id);
    let share_from_2_to_1 = round_2::create_share_for(&state, &participant_2, &participant_1.id);

    assert!(round_2::verify_share_validity(
        &state,
        &participant_1,
        &share_from_3_to_1,
        &participant_broadcast_3,
    ));
    assert!(round_2::verify_share_validity(
        &state,
        &participant_1,
        &share_from_2_to_1,
        &participant_broadcast_2,
    ));

    let private_key_1 = round_2::compute_private_key(
        &state,
        &own_share_1,
        &[share_from_2_to_1.secret, share_from_3_to_1.secret],
    );

    println!("This is your private key. save it in a secure place: {private_key_1}.");

    let own_verification_share_1 = round_2::compute_own_verification_share(&state, &private_key_1);

    let public_verification_share_1 = round_2::compute_participant_verification_share(
        &state,
        &participant_1,
        &participant_broadcast_1,
    );
    let public_verification_share_1_from_2 = round_2::compute_participant_verification_share(
        &state,
        &participant_1,
        &participant_broadcast_2,
    );
    let public_verification_share_1_from_3 = round_2::compute_participant_verification_share(
        &state,
        &participant_1,
        &participant_broadcast_3,
    );

    let public_verification_share_1 = round_2::compute_others_verification_share(
        &state,
        &[
            public_verification_share_1,
            public_verification_share_1_from_2,
            public_verification_share_1_from_3,
        ],
    );

    assert_eq!(own_verification_share_1, public_verification_share_1);

    let group_public_key_1 = round_2::compute_group_public_key(
        &state,
        &[
            &participant_broadcast_1.commitments.clone(),
            &participant_broadcast_2.commitments.clone(),
            &participant_broadcast_3.commitments.clone(),
        ],
    );

    println!("The generated group public key is:                   {group_public_key_1}.");
}
