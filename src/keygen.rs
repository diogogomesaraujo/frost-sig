use crate::{modular, PRIME};
use commitments_and_proofs::*;
use rand::Rng;
use rug::{rand::RandState, Integer};
use secret_sharing::{create_secret_share, verify_secret_shares};
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

pub mod commitments_and_proofs {
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

pub mod secret_sharing {
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

    pub fn compute_verification_share(state: &FrostState, private_key: &Integer) -> Integer {
        modular::pow(&state.generator, &private_key, &state.prime)
    }

    pub fn compute_group_public_key(state: &FrostState, commitments: &[&[Integer]]) -> Integer {
        commitments
            .iter()
            .fold(Integer::from(1), |acc, participant_commitments| {
                modular::mul(participant_commitments[0].clone(), acc, &state.prime)
            })
    }
}

#[test]
pub fn test_keygen_commitments_and_proofs() {
    // part 1
    let seed: i32 = rand::rng().random();
    let mut rnd = RandState::new();
    rnd.seed(&rug::Integer::from(seed));

    let ctx = keygen_ctx(Integer::from(1), Integer::from(1));
    let state = FrostState::init(3, 2);

    let pol_1 = commitments_and_proofs::generate_polynomial(&state, &mut rnd);
    let pol_2 = commitments_and_proofs::generate_polynomial(&state, &mut rnd);
    let pol_3 = commitments_and_proofs::generate_polynomial(&state, &mut rnd);

    let participant_1 = Participant::init(Integer::from(1), pol_1);
    let participant_2 = Participant::init(Integer::from(2), pol_2);
    let participant_3 = Participant::init(Integer::from(3), pol_3);

    let signature_1 = compute_proof_of_knowlodge(&state, &mut rnd, &participant_1, &ctx);
    let signature_2 = compute_proof_of_knowlodge(&state, &mut rnd, &participant_2, &ctx);
    let signature_3 = compute_proof_of_knowlodge(&state, &mut rnd, &participant_3, &ctx);

    let commitments_1 = compute_public_commitments(&state, &participant_1);
    let commitments_2 = compute_public_commitments(&state, &participant_2);
    let commitments_3 = compute_public_commitments(&state, &participant_3);

    let participant_broadcast_1 =
        ParticipantBroadcast::init(participant_1.id.clone(), commitments_1, signature_1);
    let participant_broadcast_2 =
        ParticipantBroadcast::init(participant_2.id.clone(), commitments_2, signature_2);
    let participant_broadcast_3 =
        ParticipantBroadcast::init(participant_3.id.clone(), commitments_3, signature_3);

    assert!(verify_proofs(
        &state,
        &[
            participant_broadcast_2.clone(),
            participant_broadcast_3.clone(),
        ],
        &ctx
    ));

    assert!(verify_proofs(
        &state,
        &[
            participant_broadcast_2.clone(),
            participant_broadcast_3.clone()
        ],
        &ctx
    ));

    assert!(verify_proofs(
        &state,
        &[
            participant_broadcast_1.clone(),
            participant_broadcast_3.clone()
        ],
        &ctx
    ));

    // part 2

    let share_from_3_to_1 = create_secret_share(
        &state,
        &Participant::init(participant_1.id.clone(), participant_3.polynomial.clone()),
    );
    let share_from_2_to_1 = create_secret_share(
        &state,
        &Participant::init(participant_1.id.clone(), participant_2.polynomial.clone()),
    );

    let share_from_1_to_2 = create_secret_share(
        &state,
        &Participant::init(participant_2.id.clone(), participant_1.polynomial.clone()),
    );
    let share_from_3_to_2 = create_secret_share(
        &state,
        &Participant::init(participant_2.id.clone(), participant_3.polynomial.clone()),
    );

    let share_from_1_to_3 = create_secret_share(
        &state,
        &Participant::init(participant_3.id.clone(), participant_1.polynomial.clone()),
    );
    let share_from_2_to_3 = create_secret_share(
        &state,
        &Participant::init(participant_3.id.clone(), participant_2.polynomial.clone()),
    );

    assert!(verify_secret_shares(
        &state,
        &participant_1,
        &share_from_3_to_1,
        &participant_broadcast_3,
    ));
    assert!(verify_secret_shares(
        &state,
        &participant_1,
        &share_from_2_to_1,
        &participant_broadcast_2,
    ));

    assert!(verify_secret_shares(
        &state,
        &participant_2,
        &share_from_1_to_2,
        &participant_broadcast_1,
    ));
    assert!(verify_secret_shares(
        &state,
        &participant_2,
        &share_from_3_to_2,
        &participant_broadcast_3,
    ));

    assert!(verify_secret_shares(
        &state,
        &participant_3,
        &share_from_1_to_3,
        &participant_broadcast_1,
    ));
    assert!(verify_secret_shares(
        &state,
        &participant_3,
        &share_from_2_to_3,
        &participant_broadcast_2,
    ));
}
