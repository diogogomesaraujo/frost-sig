use crate::*;
use keygen::*;
use preprocess::*;
use rand::Rng;
use rug::{rand::RandState, Integer};
use sign::*;

#[test]
pub fn test_keygen() {
    let seed: i32 = rand::rng().random();
    let mut rnd = RandState::new();
    rnd.seed(&rug::Integer::from(seed));

    let ctx = keygen_ctx(Integer::from(1), Integer::from(1));
    let state = crate::FrostState::new(&mut rnd, 3, 2);

    // ROUND 1

    let pol_1 = round_1::generate_polynomial(&state, &mut rnd);
    let pol_2 = round_1::generate_polynomial(&state, &mut rnd);
    let pol_3 = round_1::generate_polynomial(&state, &mut rnd);

    let participant_1 = Participant::new(Integer::from(1), pol_1);
    let participant_2 = Participant::new(Integer::from(2), pol_2);
    let participant_3 = Participant::new(Integer::from(3), pol_3);

    let signature_1 = round_1::compute_proof_of_knowlodge(&state, &mut rnd, &participant_1, &ctx);
    let signature_2 = round_1::compute_proof_of_knowlodge(&state, &mut rnd, &participant_2, &ctx);
    let signature_3 = round_1::compute_proof_of_knowlodge(&state, &mut rnd, &participant_3, &ctx);

    let commitments_1 = round_1::compute_public_commitments(&state, &participant_1);
    let commitments_2 = round_1::compute_public_commitments(&state, &participant_2);
    let commitments_3 = round_1::compute_public_commitments(&state, &participant_3);

    let participant_broadcast_1 =
        ParticipantBroadcast::new(participant_1.id.clone(), commitments_1, signature_1);
    let participant_broadcast_2 =
        ParticipantBroadcast::new(participant_2.id.clone(), commitments_2, signature_2);
    let participant_broadcast_3 =
        ParticipantBroadcast::new(participant_3.id.clone(), commitments_3, signature_3);

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

    let nonces_and_commitments_of_participants: Vec<((Integer, Integer), (Integer, Integer))> = (0
        ..state.threshold)
        .map(|_| generate_nonces_and_commitments(&state, &mut rnd))
        .collect();
}
