//! Implementation of the Keygen operation benchmarks.

use criterion::{
    criterion_group, criterion_main, measurement::WallTime, BenchmarkGroup, Criterion,
};
use curve25519_dalek::{edwards::CompressedEdwardsY, Scalar};
use frost_sig::{
    keygen::{round_1, round_2},
    message::Message,
    FrostState,
};
use rand::rngs::OsRng;
use std::error::Error;

/// Function used execute the key generation process for any number of participants and threshold.
/// The benchmark is then added to the given group.
pub fn generate_keygen_values(
    group: &mut BenchmarkGroup<'_, WallTime>,
    state: &FrostState,
) -> Result<(), Box<dyn Error + Sync + Send>> {
    // get the os generator
    let mut rng = OsRng;

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
        |(receiver_id, receiver)| -> Result<(), Box<dyn Error + Send + Sync>> {
            participants.iter().enumerate().try_for_each(
                |(sender_id, _)| -> Result<(), Box<dyn Error + Send + Sync>> {
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

    // compute the group public key from the commitments
    let _group_public_key = round_2::compute_group_public_key(&broadcasts)?;

    // benchmark computation executed by one participant
    group.bench_function(
        &format!("({},{})", state.participants, state.threshold),
        |b| {
            b.iter(|| {
                let _polynomial = round_1::generate_polynomial(state, &mut rng);
                let participant =
                    frost_sig::keygen::Participant::new(0, participants[0].polynomial.clone());
                let signature = round_1::compute_proof_of_knowlodge(&mut rng, &participant);
                let commitments = round_1::compute_public_commitments(&participant);
                let _broadcast = Message::Broadcast {
                    participant_id: participant.id,
                    commitments,
                    signature,
                };
                assert!(round_1::verify_proofs(&broadcasts[1..]).unwrap());
                let own_share = round_2::create_own_secret_share(&participant);
                let shares_for: Vec<Message> = participants[1..]
                    .iter()
                    .map(|p| round_2::create_share_for(&p, &participant.id))
                    .collect();
                shares_for
                    .iter()
                    .zip(broadcasts[1..].iter())
                    .for_each(|(s, b)| {
                        assert!(round_2::verify_share_validity(&participant, &s, &b,).unwrap());
                    });
                let private_key = round_2::compute_private_key(&own_share, &shares_for).unwrap();
                let public_key = round_2::compute_own_public_share(&private_key);
                let others_verification_shares: Vec<CompressedEdwardsY> = broadcasts
                    .iter()
                    .map(|b| {
                        round_2::compute_participant_verification_share(&participant, b).unwrap()
                    })
                    .collect();
                let aggregate_verification_share =
                    round_2::compute_others_verification_share(&others_verification_shares)
                        .unwrap();
                assert_eq!(public_key, aggregate_verification_share);
                let _group_public_key = round_2::compute_group_public_key(&broadcasts).unwrap();
            })
        },
    );

    Ok(())
}

/// Function that benchmarks the Key Generation operation for different (n, t) pairs.
fn keygen_benchmark(c: &mut Criterion) {
    // group that will benchmark how the number of participants influences performance
    let mut group = c.benchmark_group(
        "FROST Key Generation - Impact of the Total Number of Participants for the Same Threshold",
    );
    generate_keygen_values(&mut group, &FrostState::new(2, 2)).unwrap();
    generate_keygen_values(&mut group, &FrostState::new(3, 2)).unwrap();
    generate_keygen_values(&mut group, &FrostState::new(4, 2)).unwrap();
    generate_keygen_values(&mut group, &FrostState::new(5, 2)).unwrap();
    generate_keygen_values(&mut group, &FrostState::new(6, 2)).unwrap();
    generate_keygen_values(&mut group, &FrostState::new(7, 2)).unwrap();
    generate_keygen_values(&mut group, &FrostState::new(8, 2)).unwrap();
    generate_keygen_values(&mut group, &FrostState::new(9, 2)).unwrap();
    group.finish();

    // group that will benchmark how the threshold influences performance
    let mut group = c.benchmark_group(
        "FROST Key Generation - Impact of Different Thresholds for the Same Number of Participants",
    );
    generate_keygen_values(&mut group, &FrostState::new(9, 2)).unwrap();
    generate_keygen_values(&mut group, &FrostState::new(9, 3)).unwrap();
    generate_keygen_values(&mut group, &FrostState::new(9, 4)).unwrap();
    generate_keygen_values(&mut group, &FrostState::new(9, 5)).unwrap();
    generate_keygen_values(&mut group, &FrostState::new(9, 6)).unwrap();
    generate_keygen_values(&mut group, &FrostState::new(9, 7)).unwrap();
    generate_keygen_values(&mut group, &FrostState::new(9, 8)).unwrap();
    generate_keygen_values(&mut group, &FrostState::new(9, 9)).unwrap();
    group.finish();
}

criterion_group!(benches, keygen_benchmark);
criterion_main!(benches);
