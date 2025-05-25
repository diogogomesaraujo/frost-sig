use crate::keygen::*;
use crate::message::*;
use crate::nano::account::public_key_to_nano_account;
use crate::preprocess::*;
use crate::sign::*;
use ed25519_dalek_blake2b::Signature;
use ed25519_dalek_blake2b::{PublicKey, Verifier};
use rand::rngs::OsRng;
use std::error::Error;

#[test]
pub fn test_keygen_and_sign() -> Result<(), Box<dyn Error>> {
    // This example shows the FROST keygen, preprocess and signature flow for 3 participants with a threshold of 2.

    // get the os generator
    let mut rng = OsRng;

    // create the state with the desired number of participants and threshold
    let state = crate::FrostState::new(3, 2);

    // keygen
    // round 1

    // each participant computes his polynomial
    let walter_polynomial = round_1::generate_polynomial(&state, &mut rng);
    let jessie_polynomial = round_1::generate_polynomial(&state, &mut rng);
    let skylar_polynomial = round_1::generate_polynomial(&state, &mut rng);

    // each participant initializes his state with his id and the polynomial
    let walter = Participant::new(1, walter_polynomial);
    let jessie = Participant::new(2, jessie_polynomial);
    let skylar = Participant::new(3, skylar_polynomial);

    // each participant computes his signature
    let walter_signature = round_1::compute_proof_of_knowlodge(&mut rng, &walter);
    let jessie_signature = round_1::compute_proof_of_knowlodge(&mut rng, &jessie);
    let skylar_signature = round_1::compute_proof_of_knowlodge(&mut rng, &skylar);

    // each participant computes his commitments
    let walter_commitments = round_1::compute_public_commitments(&walter);
    let jessie_commitments = round_1::compute_public_commitments(&jessie);
    let skylar_commitments = round_1::compute_public_commitments(&skylar);

    // each participant computes and sends his broadcast
    let walter_broadcast = Message::Broadcast {
        participant_id: walter.id.clone(),
        commitments: walter_commitments,
        signature: walter_signature,
    };
    let jessie_broadcast = Message::Broadcast {
        participant_id: jessie.id.clone(),
        commitments: jessie_commitments,
        signature: jessie_signature,
    };
    let skylar_broadcast = Message::Broadcast {
        participant_id: skylar.id.clone(),
        commitments: skylar_commitments,
        signature: skylar_signature,
    };

    // each participant verifies all broadcasts received
    assert!(round_1::verify_proofs(&[
        jessie_broadcast.clone(),
        skylar_broadcast.clone(),
    ])?);
    assert!(round_1::verify_proofs(&[
        walter_broadcast.clone(),
        skylar_broadcast.clone(),
    ])?);
    assert!(round_1::verify_proofs(&[
        walter_broadcast.clone(),
        jessie_broadcast.clone(),
    ])?);

    // round 2

    // each participant computes his how secret share
    let walter_own_share = round_2::create_own_secret_share(&walter);
    let jessie_own_share = round_2::create_own_secret_share(&jessie);
    let skylar_own_share = round_2::create_own_secret_share(&skylar);

    // each participant computes a share for each other participant and sends it
    let share_from_skylar_to_walter = round_2::create_share_for(&skylar, &walter.id);
    let share_from_jessie_to_walter = round_2::create_share_for(&jessie, &walter.id);

    let share_from_skylar_to_jessie = round_2::create_share_for(&skylar, &jessie.id);
    let share_from_walter_to_jessie = round_2::create_share_for(&walter, &jessie.id);

    let share_from_jessie_to_skylar = round_2::create_share_for(&jessie, &skylar.id);
    let share_from_walter_to_skylar = round_2::create_share_for(&walter, &skylar.id);

    // each participant verifies the secret shares received
    {
        assert!(round_2::verify_share_validity(
            &walter,
            &share_from_skylar_to_walter,
            &skylar_broadcast,
        )?);
        assert!(round_2::verify_share_validity(
            &walter,
            &share_from_jessie_to_walter,
            &jessie_broadcast,
        )?);
    }
    {
        assert!(round_2::verify_share_validity(
            &jessie,
            &share_from_skylar_to_jessie,
            &skylar_broadcast,
        )?);
        assert!(round_2::verify_share_validity(
            &jessie,
            &share_from_walter_to_jessie,
            &walter_broadcast,
        )?);
    }
    {
        assert!(round_2::verify_share_validity(
            &skylar,
            &share_from_walter_to_skylar,
            &walter_broadcast,
        )?);
        assert!(round_2::verify_share_validity(
            &skylar,
            &share_from_jessie_to_skylar,
            &jessie_broadcast,
        )?);
    }

    // each participant computes their own public key
    let walter_private_key = round_2::compute_private_key(
        &walter_own_share,
        &[
            share_from_jessie_to_walter.clone(),
            share_from_skylar_to_walter.clone(),
        ],
    )?;
    let jessie_private_key = round_2::compute_private_key(
        &jessie_own_share,
        &[
            share_from_walter_to_jessie.clone(),
            share_from_skylar_to_jessie.clone(),
        ],
    )?;
    let skylar_private_key = round_2::compute_private_key(
        &skylar_own_share,
        &[share_from_jessie_to_skylar, share_from_walter_to_skylar],
    )?;

    // each participant computes their own public key
    let walter_public_key = round_2::compute_own_public_share(&walter_private_key);
    let jessie_public_key = round_2::compute_own_public_share(&jessie_private_key);
    let skylar_public_key = round_2::compute_own_public_share(&skylar_private_key);

    // each participant computes a verification share
    let walter_own_verification_share =
        round_2::compute_participant_verification_share(&walter, &walter_broadcast)?;
    let walter_jessie_verification_share =
        round_2::compute_participant_verification_share(&walter, &jessie_broadcast)?;
    let walter_skylar_verification_share =
        round_2::compute_participant_verification_share(&walter, &skylar_broadcast)?;

    let jessie_own_verification_share =
        round_2::compute_participant_verification_share(&jessie, &jessie_broadcast)?;
    let jessie_walter_verification_share =
        round_2::compute_participant_verification_share(&jessie, &walter_broadcast)?;
    let jessie_skylar_verification_share =
        round_2::compute_participant_verification_share(&jessie, &skylar_broadcast)?;

    let skylar_own_verification_share =
        round_2::compute_participant_verification_share(&skylar, &skylar_broadcast)?;
    let skylar_jessie_verification_share =
        round_2::compute_participant_verification_share(&skylar, &jessie_broadcast)?;
    let skylar_walter_verification_share =
        round_2::compute_participant_verification_share(&skylar, &walter_broadcast)?;

    // each participant computes the aggregate verification share from the received secret shares
    let walter_aggregate_verification_share = round_2::compute_others_verification_share(&[
        walter_own_verification_share,
        walter_jessie_verification_share,
        walter_skylar_verification_share,
    ])?;
    let jessie_aggregate_verification_share = round_2::compute_others_verification_share(&[
        jessie_own_verification_share,
        jessie_walter_verification_share,
        jessie_skylar_verification_share,
    ])?;
    let skylar_aggregate_verification_share = round_2::compute_others_verification_share(&[
        skylar_own_verification_share,
        skylar_walter_verification_share,
        skylar_jessie_verification_share,
    ])?;

    // each participant verifies if the public key matches the aggregate verification share
    assert_eq!(walter_public_key, walter_aggregate_verification_share);
    assert_eq!(jessie_public_key, jessie_aggregate_verification_share);
    assert_eq!(skylar_public_key, skylar_aggregate_verification_share);

    // each participant computes the group public key from the commitments
    let group_public_key =
        round_2::compute_group_public_key(&[walter_broadcast, jessie_broadcast, skylar_broadcast])?;

    println!(
        "Aggregate Public Key: {}",
        public_key_to_nano_account(&group_public_key.as_bytes())
    );

    // sign

    // the message that will be signed
    let message = "Send Gustavo 10 bucks.";

    // For signing, we'll use Walter (ID=1) and Skylar (ID=3) as signers
    // each participant generates nonces and commitments for the signature
    let walter_commitments = generate_nonces_and_commitments(&mut rng);
    let skylar_commitments = generate_nonces_and_commitments(&mut rng);

    // each participant sends the commitments to others - FIXED PARTICIPANT IDs
    let walter_commitments_message = Message::PublicCommitment {
        participant_id: walter.id.clone(), // Use walter.id (1)
        di: walter_commitments.1 .0.clone(),
        ei: walter_commitments.1 .1.clone(),
        public_share: walter_public_key,
    };
    let skylar_commitments_message = Message::PublicCommitment {
        participant_id: skylar.id.clone(), // Use skylar.id (3), not jessie.id
        di: skylar_commitments.1 .0.clone(),
        ei: skylar_commitments.1 .1.clone(),
        public_share: skylar_public_key,
    };

    let commitments = vec![
        walter_commitments_message.clone(),
        skylar_commitments_message.clone(),
    ];

    // each participant computes the group commitment and challenge from the received commitments
    let (group_commitment, challenge) = compute_group_commitment_and_challenge(
        &commitments, // Use the commitments vector consistently
        message,
        group_public_key,
        &[],
    )?;

    let ids = vec![walter.id, skylar.id]; // IDs of actual signers: [1, 3]

    // each participant calculates all the participants' lagrange coefficients
    let walter_lagrange_coefficient = lagrange_coefficient(&ids, &walter.id);
    let skylar_lagrange_coefficient = lagrange_coefficient(&ids, &skylar.id); // Use skylar.id, not jessie.id

    // each participant computes their response and sends to the sa
    let walter_response = compute_own_response(
        walter.id.clone(),
        &walter_commitments_message,
        &commitments,
        &walter_private_key,
        &walter_commitments.0,
        &walter_lagrange_coefficient,
        &challenge,
        &message,
        &group_public_key, // Use group public key for verifying key
        &[],
    )?;
    let skylar_response = compute_own_response(
        skylar.id.clone(), // Use skylar.id
        &skylar_commitments_message,
        &commitments,
        &skylar_private_key,
        &skylar_commitments.0,
        &skylar_lagrange_coefficient,
        &challenge,
        &message,
        &group_public_key, // Use group public key for verifying key
        &[],
    )?;

    // sa verifies others' responses
    let verify_walter = verify_participant(
        &walter_commitments_message,
        &commitments,
        &message,
        &walter_response,
        &challenge,
        &group_public_key, // Use group public key for verifying key
        &[],
        &ids,
    )?;
    let verify_skylar = verify_participant(
        &skylar_commitments_message,
        &commitments,
        &message,
        &skylar_response,
        &challenge,
        &group_public_key, // Use group public key for verifying key
        &[],
        &ids,
    )?;
    assert!(verify_walter);
    assert!(verify_skylar);

    // sa computes the aggregate response
    let aggregate_response = compute_aggregate_response(&[walter_response, skylar_response])?;

    // sa computes signature
    let signature = Signature::from_bytes(&computed_response_to_signature(
        &aggregate_response,
        &group_commitment,
    ))
    .expect("Couldn't create the signature!");

    // Verify the signature
    {
        let verifying_key = PublicKey::from_bytes(group_public_key.as_bytes())
            .expect("Couldn't create the public key!");
        verifying_key
            .verify(message.as_bytes(), &signature)
            .expect("Couldn't verify the signature with the public key!");
    }

    Ok(())
}
