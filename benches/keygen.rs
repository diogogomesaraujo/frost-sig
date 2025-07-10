use criterion::{criterion_group, criterion_main, Criterion};
use curve25519_dalek::{edwards::CompressedEdwardsY, Scalar};
use frost_sig::{
    keygen::{round_1, round_2},
    message::Message,
    FrostState,
};
use rand::rngs::OsRng;
use std::error::Error;

pub fn generate_keygen_values(state: &FrostState) -> Result<(), Box<dyn Error + Sync + Send>> {
    // get the os generator
    let mut rng = OsRng;

    // keygen
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
    for (public_key, aggregate_verification_share) in own_public_shares
        .iter()
        .zip(aggregate_verification_shares.iter())
    {
        assert_eq!(*public_key, *aggregate_verification_share);
    }

    // compute the group public key from the commitments
    let _group_public_key = round_2::compute_group_public_key(&broadcasts)?;

    Ok(())
}

fn keygen_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("FROST Key Generation Changing Participants");

    group.bench_function("(2,2)", |b| {
        b.iter(|| generate_keygen_values(&FrostState::new(2, 2)))
    });
    group.bench_function("(3,2)", |b| {
        b.iter(|| generate_keygen_values(&FrostState::new(3, 2)))
    });
    group.bench_function("(4,2)", |b| {
        b.iter(|| generate_keygen_values(&FrostState::new(4, 2)))
    });
    group.bench_function("(5,2)", |b| {
        b.iter(|| generate_keygen_values(&FrostState::new(5, 2)))
    });

    group.finish();

    let mut group = c.benchmark_group("FROST Key Generation Changing Threshold");

    group.bench_function("(5,2)", |b| {
        b.iter(|| generate_keygen_values(&FrostState::new(5, 2)))
    });
    group.bench_function("(5,3)", |b| {
        b.iter(|| generate_keygen_values(&FrostState::new(5, 3)))
    });
    group.bench_function("(5,4)", |b| {
        b.iter(|| generate_keygen_values(&FrostState::new(5, 4)))
    });
    group.bench_function("(5,5)", |b| {
        b.iter(|| generate_keygen_values(&FrostState::new(5, 5)))
    });

    group.finish();
}

criterion_group!(benches, keygen_benchmark);
criterion_main!(benches);
