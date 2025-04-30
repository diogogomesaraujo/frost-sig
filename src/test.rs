use crate::keygen::*;
use crate::message::*;
use crate::preprocess::*;
use crate::sign::*;
use rand::rngs::OsRng;
use std::error::Error;

#[test]
pub fn test_keygen() -> Result<(), Box<dyn Error>> {
    let mut rng = OsRng;

    // let ctx = keygen_ctx(Integer::from(1), Integer::from(1));
    let state = crate::FrostState::new(3, 2);

    // KEYGEN ROUND 1

    let pol_1 = round_1::generate_polynomial(&state, &mut rng);
    let pol_2 = round_1::generate_polynomial(&state, &mut rng);
    let pol_3 = round_1::generate_polynomial(&state, &mut rng);

    let participant_1 = Participant::new(1, pol_1);
    let participant_2 = Participant::new(2, pol_2);
    let participant_3 = Participant::new(3, pol_3);

    let signature_1 = round_1::compute_proof_of_knowlodge(&mut rng, &participant_1);
    let signature_2 = round_1::compute_proof_of_knowlodge(&mut rng, &participant_2);
    let signature_3 = round_1::compute_proof_of_knowlodge(&mut rng, &participant_3);

    let commitments_1 = round_1::compute_public_commitments(&participant_1);
    let commitments_2 = round_1::compute_public_commitments(&participant_2);
    let commitments_3 = round_1::compute_public_commitments(&participant_3);

    let participant_broadcast_1 = Message::Broadcast {
        participant_id: participant_1.id.clone(),
        commitments: commitments_1,
        signature: signature_1,
    };
    let participant_broadcast_2 = Message::Broadcast {
        participant_id: participant_2.id.clone(),
        commitments: commitments_2,
        signature: signature_2,
    };
    let participant_broadcast_3 = Message::Broadcast {
        participant_id: participant_3.id.clone(),
        commitments: commitments_3,
        signature: signature_3,
    };

    assert!(round_1::verify_proofs(&[
        participant_broadcast_2.clone(),
        participant_broadcast_3.clone(),
    ]));

    // KEYGEN ROUND 2

    let own_share_1 = round_2::create_own_secret_share(&participant_1);
    let own_share_2 = round_2::create_own_secret_share(&participant_2);

    let share_from_3_to_1 = round_2::create_share_for(&participant_3, &participant_1.id);
    let share_from_2_to_1 = round_2::create_share_for(&participant_2, &participant_1.id);

    let share_from_3_to_2 = round_2::create_share_for(&participant_3, &participant_2.id);
    let share_from_1_to_2 = round_2::create_share_for(&participant_1, &participant_2.id);

    assert!(round_2::verify_share_validity(
        &participant_1,
        &share_from_3_to_1,
        &participant_broadcast_3,
    ));
    assert!(round_2::verify_share_validity(
        &participant_1,
        &share_from_2_to_1,
        &participant_broadcast_2,
    ));

    assert!(round_2::verify_share_validity(
        &participant_2,
        &share_from_3_to_2,
        &participant_broadcast_3,
    ));
    assert!(round_2::verify_share_validity(
        &participant_2,
        &share_from_1_to_2,
        &participant_broadcast_1,
    ));

    let private_key_1 =
        round_2::compute_private_key(&own_share_1, &[share_from_2_to_1, share_from_3_to_1])
            .unwrap();

    let private_key_2 =
        round_2::compute_private_key(&own_share_2, &[share_from_3_to_2, share_from_1_to_2])
            .unwrap();

    println!(
        "This is your private key. save it in a secure place: {:?}.",
        private_key_1.as_bytes()
    );

    let own_verification_share_1 = round_2::compute_own_verification_share(&private_key_1);
    let own_verification_share_2 = round_2::compute_own_verification_share(&private_key_2);

    let public_verification_share_1 =
        round_2::compute_participant_verification_share(&participant_1, &participant_broadcast_1)
            .unwrap();
    let public_verification_share_1_from_2 =
        round_2::compute_participant_verification_share(&participant_1, &participant_broadcast_2)
            .unwrap();
    let public_verification_share_1_from_3 =
        round_2::compute_participant_verification_share(&participant_1, &participant_broadcast_3)
            .unwrap();

    let public_verification_share_1 = round_2::compute_others_verification_share(
        &state,
        &[
            public_verification_share_1,
            public_verification_share_1_from_2,
            public_verification_share_1_from_3,
        ],
    );

    assert_eq!(own_verification_share_1, public_verification_share_1);

    let group_public_key_1 = round_2::compute_group_public_key(&[
        participant_broadcast_1.clone(),
        participant_broadcast_2.clone(),
        participant_broadcast_3.clone(),
    ])?;

    println!(
        "The generated group public key is:                   {:?}.",
        group_public_key_1.as_bytes()
    );

    // SIGN

    let message = "Send Bob 10 bucks";

    let public_share_1 = own_verification_share_1;
    let public_share_2 = own_verification_share_2;

    let participant_commitment_1 = generate_nonces_and_commitments(&mut rng);
    let participant_commitment_2 = generate_nonces_and_commitments(&mut rng);

    let public_commitment_1 = Message::PublicCommitment {
        participant_id: participant_1.id.clone(),
        di: participant_commitment_1.1 .0.clone(),
        ei: participant_commitment_1.1 .1.clone(),
        public_share: public_share_1,
    };

    let public_commitment_2 = Message::PublicCommitment {
        participant_id: participant_2.id.clone(),
        di: participant_commitment_2.1 .0.clone(),
        ei: participant_commitment_2.1 .1.clone(),
        public_share: public_share_2,
    };

    let (_group_commitment, challenge) = compute_group_commitment_and_challenge(
        &[public_commitment_2.clone(), public_commitment_1.clone()],
        message,
        group_public_key_1.clone(),
    )?;

    let lagrange_coefficient_1 = lagrange_coefficient(&state, &participant_1.id);
    let lagrange_coefficient_2 = lagrange_coefficient(&state, &participant_2.id);

    let response_1 = compute_own_response(
        participant_1.id.clone(),
        &public_commitment_1,
        &private_key_1,
        &participant_commitment_1.0,
        &lagrange_coefficient_1,
        &challenge,
        &message,
    )?;
    let response_2 = compute_own_response(
        participant_2.id.clone(),
        &public_commitment_2,
        &private_key_2,
        &participant_commitment_2.0,
        &lagrange_coefficient_2,
        &challenge,
        &message,
    )?;

    let verify_1 = verify_participant(
        &state,
        &public_commitment_1,
        message,
        &response_1,
        &challenge,
    )?;

    let verify_2 = verify_participant(
        &state,
        &public_commitment_2,
        message,
        &response_2,
        &challenge,
    )?;

    assert!(verify_1);
    assert!(verify_2);

    let aggregate_response = compute_aggregate_response(&[response_1, response_2])?;
    println!(
        "The group {:?} computed this response {:?} with this message \"{}\".",
        group_public_key_1.as_bytes(),
        aggregate_response.as_bytes(),
        message
    );

    Ok(())
}
