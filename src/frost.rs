use crate::{modular, BITS, PRIME};
use rug::{rand::RandState, Integer};
use sha256::digest;
use std::str::FromStr;

pub struct FrostState {
    participant_id: Integer,
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
        format!(
            "{}::{}::{}",
            ctx.protocol,
            ctx.group_id.to_string_radix(16),
            ctx.session_id.to_string_radix(16)
        )
    }
}

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

pub fn generate_polynomial(state: &FrostState, rnd: &mut RandState) -> Vec<Integer> {
    let mut polynomial: Vec<Integer> = Vec::new();
    for _i in 0..state.threshold {
        let a = Integer::from(Integer::random_below(state.q.clone(), rnd));
        polynomial.push(a);
    }
    polynomial
}

pub fn compute_proof_of_knowlodge(
    state: &FrostState,
    rnd: &mut RandState,
    generated_polynomial: &[Integer],
) -> (Integer, Integer) {
    let k = Integer::from(Integer::random_below(state.q.clone(), rnd));
    let r = modular::pow(&state.generator, &k, &state.prime);
    let ci = Integer::from_str_radix(
        digest(format!(
            "{}::::{}:::::{}:::::{}",
            &state.participant_id.to_string_radix(16),
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
    state: FrostState,
    generated_polynomial: &[Integer],
) -> Vec<Integer> {
    generated_polynomial
        .iter()
        .map(|coefficient| modular::pow(&state.generator, &coefficient, &state.prime))
        .collect()
}

pub fn verify_proofs(state: &FrostState, participants_broadcasts: &[ParticipantBroadcast]) -> bool {
    participants_broadcasts.iter().fold(true, |acc, pb| {
        let (wp, cp) = pb.signature.clone();

        let ap0 = modular::pow(&pb.commitments[0], &Integer::from(-&cp), &state.prime);

        let rp = modular::mul(
            modular::pow(&state.generator, &wp, &state.prime),
            ap0.clone(),
            &state.prime,
        );

        acc && (cp
            == Integer::from_str_radix(
                digest(format!(
                    "{}::::{}::::{}::::{}",
                    &pb.participant_id.to_string_radix(16),
                    CTX::to_string(&state.ctx),
                    ap0,
                    rp
                ))
                .as_str(),
                16,
            )
            .unwrap()
            .modulo(&state.q))
    })
}
