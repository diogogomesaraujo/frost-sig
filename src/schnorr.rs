//! Implementation of the Schnorr threshold signatures (simplified).

use crate::{modular, BITS, PRIME};
use rand::Rng;
use rug::{rand::RandState, Integer};
use sha256::digest;
use std::str::FromStr;

/// Struct that saves the state of the constants for the schnorr threshold signature operations.
pub struct SchnorrThresholdState {
    pub prime: Integer,
    pub q: Integer,
    pub generator: Integer,
    pub participants: usize,
    pub threshold: usize,
}

impl SchnorrThresholdState {
    /// Function to init the State and get all the constants needed for the operations.
    pub fn init(p: usize, t: usize) -> SchnorrThresholdState {
        SchnorrThresholdState {
            prime: Integer::from_str(PRIME).expect("Shouldn't happen."),
            q: Integer::from((Integer::from_str(PRIME).expect("Shouldn't happen.") - 1) / 2),
            generator: Integer::from(4),
            participants: p,
            threshold: t,
        }
    }
}

/// Function to generate private shares.
pub fn generate_shares(state: &SchnorrThresholdState, rnd: &mut RandState) -> Vec<Integer> {
    (0..state.participants)
        .map(|_| Integer::from(Integer::random_bits(BITS, rnd)))
        .collect()
}

/// Function to generate the shared key from the private shares given.
pub fn generate_shared_key(
    state: &SchnorrThresholdState,
    secret_keys_subset: &[Integer],
) -> Integer {
    secret_keys_subset.iter().fold(Integer::from(1), |acc, sk| {
        modular::mul(
            acc,
            modular::pow(&(state.generator), &sk, &state.prime),
            &state.prime,
        )
    })
}

/// Function to sign a message using a subset of the private shares (the number of shares should match the threshold).
pub fn sign(
    state: &SchnorrThresholdState,
    rnd: &mut RandState,
    message: &str,
    secret_keys: &[Integer],
) -> (Integer, Integer) {
    let nonces: Vec<Integer> = (0..state.threshold)
        .map(|_| Integer::from(Integer::random_bits(BITS, rnd)))
        .collect();
    let points: Vec<Integer> = nonces
        .iter()
        .map(|nonce| modular::pow(&(state.generator), &nonce, &state.prime))
        .collect();

    let shared_nonce = nonces.iter().fold(Integer::ZERO, |acc, nonce| {
        modular::add(acc, (*nonce).clone(), &state.q)
    });
    let shared_commitment = points.iter().fold(Integer::from(1), |acc, point| {
        modular::mul(acc, (*point).clone(), &state.prime)
    });
    let shared_secret_key = secret_keys.iter().fold(Integer::ZERO, |acc, sk| {
        modular::add(acc, (*sk).clone(), &state.q)
    });

    let challenge_hash = Integer::from(
        Integer::from_str_radix(digest(format!("{shared_commitment}{message}")).as_str(), 16)
            .expect("Shouldn't happen."),
    );
    let challenge = Integer::from(challenge_hash % &state.q);

    let signature_response = Integer::from(modular::sub(
        shared_nonce,
        modular::mul(shared_secret_key, challenge, &(state.q)),
        &(state.q),
    ));

    (shared_commitment, signature_response)
}

/// Function to verify a message using the shared public key.
pub fn verify(
    state: &SchnorrThresholdState,
    message: &str,
    shared_commitment: &Integer,
    response: &Integer,
    shared_public_key: &Integer,
) -> bool {
    let challenge_hash = Integer::from(
        Integer::from_str_radix(digest(format!("{shared_commitment}{message}")).as_str(), 16)
            .expect("Shouldn't happen."),
    );
    let challenge = Integer::from(challenge_hash % &(state.q));

    let expected_point = Integer::from(modular::mul(
        modular::pow(&(state.generator), &response, &(state.prime)),
        modular::pow(shared_public_key, &challenge, &(state.prime)),
        &(state.prime),
    ));

    expected_point == *shared_commitment
}

#[test]
fn test_schnorr_bulk() {
    let mut handles = Vec::new();

    for _i in 0..20 {
        let handle = std::thread::spawn(|| {
            let seed: i32 = rand::rng().random();
            let mut rnd = RandState::new();
            rnd.seed(&rug::Integer::from(seed));

            let state = SchnorrThresholdState::init(10, 5);

            for _i in 0..100 {
                let shares = generate_shares(&state, &mut rnd);
                let subset = &shares[0..(state.threshold)];
                let shared_public_key = generate_shared_key(&state, subset);

                let message = "send Bob 10 bucks.";
                let (r, s) = sign(&state, &mut rnd, message, subset);
                let valid = verify(&state, message, &r, &s, &shared_public_key);

                assert!(valid);

                println!(
                    "
                    Shared Public Key: {:?}\n
                    Shares:            {:?}\n
                    Message:           {}\n
                    Valid:             {}\n",
                    shared_public_key, shares, message, valid
                );
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }
}
