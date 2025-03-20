use crate::{modular, PRIME};
use commitments_and_proofs::{
    compute_proof_of_knowlodge, compute_public_commitments, verify_proofs,
};
use rand::Rng;
use rug::{rand::RandState, Integer};
use sha256::digest;
use std::str::FromStr;

pub struct FrostState {
    pub participant_id: Integer,
    pub prime: Integer,
    pub q: Integer,
    pub generator: Integer,
    pub participants: usize,
    pub threshold: usize,
    pub ctx: CTX,
}

impl FrostState {
    pub fn init(
        participant_id_input: Integer,
        participants_input: usize,
        threshold_input: usize,
        ctx_input: CTX,
    ) -> FrostState {
        FrostState {
            participant_id: participant_id_input,
            prime: Integer::from_str(PRIME).expect("Shouldn't happen."),
            q: Integer::from((Integer::from_str(PRIME).expect("Shouldn't happen.") - 1) / 2),
            generator: Integer::from(4),
            participants: participants_input,
            threshold: threshold_input,
            ctx: ctx_input,
        }
    }
}

#[derive(Clone)]
pub struct CTX {
    pub protocol: String,
    pub group_id: Integer,
    pub session_id: Integer,
}

impl CTX {
    pub fn init(group_id_input: Integer, session_id_input: Integer) -> CTX {
        CTX {
            protocol: "frost-keygen".to_string(),
            group_id: group_id_input,
            session_id: session_id_input,
        }
    }

    pub fn to_string(ctx: &CTX) -> String {
        format!("{}::{}::{}", ctx.protocol, ctx.group_id, ctx.session_id)
    }
}

#[derive(Clone)]
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
    ) -> ParticipantBroadcast {
        ParticipantBroadcast {
            participant_id: participant_id_input,
            commitments: commitments_input,
            signature: signature_input,
        }
    }
}

pub fn generate_integer(state: &FrostState, rnd: &mut RandState) -> Integer {
    Integer::from(Integer::random_below(state.q.clone(), rnd))
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
        generated_polynomial: &[Integer],
    ) -> (Integer, Integer) {
        let k = generate_integer(&state, rnd);
        let r = modular::pow(&state.generator, &k, &state.prime);
        let ci = Integer::from_str_radix(
            digest(format!(
                "{}::::{}::::{}::::{}",
                &state.participant_id,
                CTX::to_string(&state.ctx),
                modular::pow(&state.generator, &generated_polynomial[0], &state.prime),
                r
            ))
            .as_str(),
            16,
        )
        .unwrap()
        .modulo(&state.q);
        let wi = modular::add(
            k,
            modular::mul(generated_polynomial[0].clone(), ci.clone(), &state.q),
            &state.q,
        );
        (wi, ci)
    }

    pub fn compute_public_commitments(
        state: &FrostState,
        generated_polynomial: &[Integer],
    ) -> Vec<Integer> {
        generated_polynomial
            .iter()
            .map(|coefficient| modular::pow(&state.generator, &coefficient, &state.prime))
            .collect()
    }

    pub fn verify_proofs(
        state: &FrostState,
        participants_broadcasts: &[ParticipantBroadcast],
    ) -> bool {
        participants_broadcasts.iter().fold(true, |acc, pb| {
            let (wp, cp) = pb.signature.clone();
            let rp = modular::mul(
                modular::pow(&state.generator, &wp, &state.prime),
                modular::pow(&pb.commitments[0], &Integer::from(-&cp), &state.prime),
                &state.prime,
            );
            acc && (cp
                == Integer::from_str_radix(
                    digest(format!(
                        "{}::::{}::::{}::::{}",
                        &pb.participant_id,
                        CTX::to_string(&state.ctx),
                        &pb.commitments[0],
                        rp,
                    ))
                    .as_str(),
                    16,
                )
                .unwrap()
                .modulo(&state.q))
        })
    }
}

#[test]
pub fn test_keygen_commitments_and_proofs() {
    let seed: i32 = rand::rng().random();
    let mut rnd = RandState::new();
    rnd.seed(&rug::Integer::from(seed));

    let ctx = CTX::init(Integer::from(1), Integer::from(1));

    let state_1 = FrostState::init(Integer::from(1), 3, 2, ctx.clone());
    let state_2 = FrostState::init(Integer::from(2), 3, 2, ctx.clone());
    let state_3 = FrostState::init(Integer::from(3), 3, 2, ctx.clone());

    let pol_1 = commitments_and_proofs::generate_polynomial(&state_1, &mut rnd);
    let pol_2 = commitments_and_proofs::generate_polynomial(&state_2, &mut rnd);
    let pol_3 = commitments_and_proofs::generate_polynomial(&state_3, &mut rnd);

    let signature_1 = compute_proof_of_knowlodge(&state_1, &mut rnd, &pol_1);
    let signature_2 = compute_proof_of_knowlodge(&state_2, &mut rnd, &pol_2);
    let signature_3 = compute_proof_of_knowlodge(&state_3, &mut rnd, &pol_3);

    let commitments_1 = compute_public_commitments(&state_1, &pol_1);
    let commitments_2 = compute_public_commitments(&state_2, &pol_2);
    let commitments_3 = compute_public_commitments(&state_3, &pol_3);

    let participant_broadcast_1 =
        ParticipantBroadcast::init(state_1.participant_id.clone(), commitments_1, signature_1);
    let participant_broadcast_2 =
        ParticipantBroadcast::init(state_2.participant_id.clone(), commitments_2, signature_2);
    let participant_broadcast_3 =
        ParticipantBroadcast::init(state_3.participant_id.clone(), commitments_3, signature_3);

    // verify the first one
    assert!(verify_proofs(
        &state_1,
        &[
            participant_broadcast_2.clone(),
            participant_broadcast_3.clone()
        ]
    ));

    // verify the second one
    assert!(verify_proofs(
        &state_2,
        &[
            participant_broadcast_1.clone(),
            participant_broadcast_3.clone()
        ]
    ));

    // verify the third one
    assert!(verify_proofs(
        &state_2,
        &[
            participant_broadcast_1.clone(),
            participant_broadcast_3.clone()
        ]
    ));
}
