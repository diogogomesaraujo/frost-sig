//! Implementation of the Sign operation benchmarks.

use criterion::{
    criterion_group, criterion_main, measurement::WallTime, BenchmarkGroup, Criterion,
};
use curve25519_dalek::{edwards::CompressedEdwardsY, Scalar};
use ed25519_dalek_blake2b::{PublicKey, Verifier};
use frost_sig::{
    keygen::{round_1, round_2},
    message::Message,
    preprocess::generate_nonces_and_commitments,
    sign::{
        compute_aggregate_response, compute_group_commitment_and_challenge, compute_own_response,
        computed_response_to_signature, lagrange_coefficient,
    },
    FrostState,
};
use rand::rngs::OsRng;

/// Function used execute the sign process for any number of participants and threshold.
/// The benchmark is then added to the given group.
fn generate_signature_values(
    group: &mut BenchmarkGroup<'_, WallTime>,
    state: &FrostState,
) -> Result<(), Box<dyn std::error::Error + Sync + Send>> {
    // get the os generator
    let mut rng = OsRng;

    // generate keys that will be used for the sign process
    // round 1

    // each participant computes his polynomial
    let participants: Vec<frost_sig::keygen::Participant> = (0..state.participants)
        .into_iter()
        .map(|n| {
            frost_sig::keygen::Participant::new(n, round_1::generate_polynomial(&state, &mut rng))
        })
        .collect();

    // each participant computes his proof
    let proofs: Vec<(Scalar, Scalar)> = participants
        .iter()
        .map(|p| round_1::compute_proof_of_knowlodge(&mut rng, &p))
        .collect();

    // each participant computes his commitments
    let commitments: Vec<Vec<CompressedEdwardsY>> = participants
        .iter()
        .map(|p| round_1::compute_public_commitments(&p))
        .collect();

    // each participant computes his broadcast
    let broadcasts: Vec<Message> = participants
        .iter()
        .zip(commitments.iter())
        .zip(proofs.iter())
        .map(|((participant, commitment), proof)| Message::Broadcast {
            participant_id: participant.id,
            commitments: commitment.clone(),
            signature: *proof,
        })
        .collect();

    // verify each broadcast
    assert!(round_1::verify_proofs(&broadcasts)?);

    // round 2

    // each participant computes his how secret share
    let own_secret_shares: Vec<Message> = participants
        .iter()
        .map(|p| round_2::create_own_secret_share(&p))
        .collect();

    // each participant computes a share for each other participant and sends it
    let secret_shares_to_send: Vec<Vec<Message>> = participants
        .iter()
        .map(|sender| {
            participants
                .iter()
                .map(|receiver| round_2::create_share_for(&sender, &receiver.id))
                .collect()
        })
        .collect();

    // each participant verifies the secret shares received
    participants.iter().enumerate().try_for_each(
        |(receiver_id, receiver)| -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            participants.iter().enumerate().try_for_each(
                |(sender_id, _)| -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                    match (sender_id, receiver_id) {
                        (sender_id, receiver_id) if sender_id == receiver_id => {
                            let share = &secret_shares_to_send[sender_id][receiver_id];
                            let sender_broadcast = &broadcasts[sender_id];
                            assert!(round_2::verify_share_validity(
                                receiver,
                                share,
                                sender_broadcast,
                            )?);
                            Ok(())
                        }
                        _ => Ok(()),
                    }
                },
            )?;
            Ok(())
        },
    )?;

    // each participant computes their own private key
    let private_keys: Vec<Scalar> = participants
        .iter()
        .enumerate()
        .map(|(id, _)| {
            let own_share = &own_secret_shares[id];
            let received_shares: Vec<Message> = secret_shares_to_send
                .iter()
                .enumerate()
                .filter(|(sender_idx, _)| *sender_idx != id)
                .map(|(_, shares)| shares[id].clone())
                .collect();

            round_2::compute_private_key(own_share, &received_shares)
        })
        .collect::<Result<Vec<_>, _>>()?;

    // each participant computes their own public key
    let own_public_shares = private_keys
        .iter()
        .map(|pk| round_2::compute_own_public_share(&pk))
        .collect::<Vec<CompressedEdwardsY>>();

    // each participant computes verification shares for all participants
    let verification_shares: Vec<Vec<_>> = participants
        .iter()
        .map(|participant| {
            broadcasts
                .iter()
                .map(|broadcast| {
                    round_2::compute_participant_verification_share(participant, broadcast)
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<_>, _>>()?;

    // each participant computes the aggregate verification share
    let aggregate_verification_shares: Vec<_> = verification_shares
        .iter()
        .map(|shares| round_2::compute_others_verification_share(shares))
        .collect::<Result<Vec<_>, _>>()?;

    // each participant verifies if the public key matches the aggregate verification share
    own_public_shares
        .iter()
        .zip(aggregate_verification_shares.iter())
        .for_each(|(public_key, aggregate_verification_share)| {
            assert_eq!(*public_key, *aggregate_verification_share)
        });

    // begin the actual sign process

    // compute the group public key from the commitments
    let group_public_key = round_2::compute_group_public_key(&broadcasts)?;

    // default message that will be used for testing
    let message = "53656e6420426f62203130206275636b732e";

    // calculate each participants nonces and commitments pair
    let commitments: Vec<((Scalar, Scalar), (CompressedEdwardsY, CompressedEdwardsY))> = (0..state
        .threshold)
        .into_iter()
        .map(|_| generate_nonces_and_commitments(&mut rng))
        .collect();

    // convert the commitments into messages that can be sent to others
    let commitments_messages: Vec<Message> = commitments
        .iter()
        .enumerate()
        .map(|(i, c)| Message::PublicCommitment {
            participant_id: i as u32,
            di: c.1 .0.clone(),
            ei: c.1 .1.clone(),
            public_share: own_public_shares[i],
        })
        .collect();

    // compute the group commitment and challenge that the group will use to compute responses
    let (_group_commitment, challenge) = compute_group_commitment_and_challenge(
        &commitments_messages,
        message,
        group_public_key,
        &[],
    )?;

    // get a vector with every participant's id
    let ids: Vec<u32> = (0..state.threshold).into_iter().map(|i| i as u32).collect();

    // calculate each participants' lagrange coefficient
    let lagrange_coefficients: Vec<Scalar> =
        ids.iter().map(|i| lagrange_coefficient(&ids, &i)).collect();

    // compute each participants' partial response
    let responses: Vec<Message> = (0..state.threshold)
        .into_iter()
        .map(|i| {
            compute_own_response(
                i,
                &commitments_messages[i as usize],
                &commitments_messages,
                &private_keys[i as usize],
                &commitments[i as usize].0,
                &lagrange_coefficients[i as usize],
                &challenge,
                message,
                &group_public_key,
                &[],
            )
            .unwrap()
        })
        .collect();

    // benchmark computation executed by one participant
    group.bench_function(
        &format!("({},{})", state.participants, state.threshold),
        |b| {
            b.iter(|| {
                let i = 0u32; // participant id defaulted to 0
                let (group_commitment, challenge) = compute_group_commitment_and_challenge(
                    &commitments_messages,
                    message,
                    group_public_key,
                    &[],
                )
                .unwrap();
                let lagrange_coefficients = lagrange_coefficient(&ids, &i);
                let _response = compute_own_response(
                    i,
                    &commitments_messages[i as usize],
                    &commitments_messages,
                    &private_keys[i as usize],
                    &commitments[i as usize].0,
                    &lagrange_coefficients,
                    &challenge,
                    message,
                    &group_public_key,
                    &[],
                )
                .unwrap();
                let aggregate_response = compute_aggregate_response(&responses).unwrap();
                let (signature, _) =
                    computed_response_to_signature(&aggregate_response, &group_commitment).unwrap();

                {
                    let verifying_key = PublicKey::from_bytes(group_public_key.as_bytes())
                        .expect("Couldn't create the public key!");
                    verifying_key
                        .verify(&hex::decode(&message).unwrap(), &signature)
                        .expect("Couldn't verify the signature with the public key!");
                }
            })
        },
    );

    Ok(())
}

/// Function that benchmarks the Sign operation for different (n, t) pairs..
fn sign_benchmark(c: &mut Criterion) {
    // group that will benchmark how the number of participants influences performance
    let mut group = c.benchmark_group(
        "FROST Sign - Impact of the Total Number of Participants for the Same Threshold",
    );
    generate_signature_values(&mut group, &FrostState::new(2, 2)).unwrap();
    generate_signature_values(&mut group, &FrostState::new(3, 2)).unwrap();
    generate_signature_values(&mut group, &FrostState::new(4, 2)).unwrap();
    generate_signature_values(&mut group, &FrostState::new(5, 2)).unwrap();
    generate_signature_values(&mut group, &FrostState::new(6, 2)).unwrap();
    generate_signature_values(&mut group, &FrostState::new(7, 2)).unwrap();
    generate_signature_values(&mut group, &FrostState::new(8, 2)).unwrap();
    generate_signature_values(&mut group, &FrostState::new(9, 2)).unwrap();
    group.finish();

    // group that will benchmark how the threshold influences performance
    let mut group = c.benchmark_group(
        "FROST Sign - Impact of Different Thresholds for the Same Number of Participants",
    );
    generate_signature_values(&mut group, &FrostState::new(9, 2)).unwrap();
    generate_signature_values(&mut group, &FrostState::new(9, 3)).unwrap();
    generate_signature_values(&mut group, &FrostState::new(9, 4)).unwrap();
    generate_signature_values(&mut group, &FrostState::new(9, 5)).unwrap();
    generate_signature_values(&mut group, &FrostState::new(9, 6)).unwrap();
    generate_signature_values(&mut group, &FrostState::new(9, 7)).unwrap();
    generate_signature_values(&mut group, &FrostState::new(9, 8)).unwrap();
    generate_signature_values(&mut group, &FrostState::new(9, 9)).unwrap();
    group.finish();
}

criterion_group!(benches, sign_benchmark);
criterion_main!(benches);
