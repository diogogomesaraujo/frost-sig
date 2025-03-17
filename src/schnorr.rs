//! Implementation of the Schnorr threshold signatures (simplified).

use crate::{modular, BITS, PRIME};
use rand::Rng;
use rug::{rand::RandState, Integer};
use sha256::digest;
use std::str::FromStr;

/// Struct that saves the state of the constants for the schnorr threshold signature operations.
pub struct SchnorrThresholdState {
    prime: Integer,
    q: Integer,
    generator: Integer,
    participants: usize,
    threshold: usize,
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

/// Function to generate the shared public key and private shares.
pub fn generate_shared_key_and_shares(
    state: &SchnorrThresholdState,
    rnd: &mut RandState,
) -> (Integer, Vec<Integer>) {
    let secret_keys: Vec<Integer> = (0..state.participants)
        .map(|_| Integer::from(Integer::random_bits(BITS, rnd)))
        .collect();
    let shared_public_key = secret_keys.iter().fold(Integer::ZERO, |acc, sk| {
        modular::mul(
            acc,
            modular::pow(&(state.generator), &sk, &state.prime),
            &state.prime,
        )
    });
    (shared_public_key, secret_keys)
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
    let shared_point = points.iter().fold(Integer::ZERO, |acc, point| {
        modular::mul(acc, (*point).clone(), &state.prime)
    });
    let shared_secret_key = secret_keys.iter().fold(Integer::ZERO, |acc, sk| {
        modular::add(acc, (*sk).clone(), &state.q)
    });
    let hash = Integer::from(
        Integer::from_str_radix(digest(format!("{shared_point}{message}")).as_str(), 16)
            .expect("Shouldn't happen."),
    );
    let e = Integer::from(hash % &state.q);
    let s = Integer::from(modular::sub(
        shared_nonce,
        modular::mul(shared_secret_key, e, &(state.q)),
        &(state.q),
    ));
    (shared_point, s)
}

/// Function to verify a message using the shared public key.
pub fn verify(
    state: &SchnorrThresholdState,
    message: &str,
    shared_point: &Integer,
    s: &Integer,
    shared_public_key: &Integer,
) -> bool {
    let hash = Integer::from(
        Integer::from_str_radix(digest(format!("{shared_point}{message}")).as_str(), 16)
            .expect("Shouldn't happen."),
    );
    let e = Integer::from(hash % &(state.q));
    let v1 = Integer::from(modular::mul(
        modular::pow(&(state.generator), &s, &(state.prime)),
        modular::pow(shared_public_key, &e, &(state.prime)),
        &(state.prime),
    ));
    println!("{} ------ {}", v1, *shared_point);
    v1 == *shared_point
}

#[test]
fn test_schnorr_bulk() {
    let mut handles = Vec::new();

    for _i in 0..20 {
        let handle = std::thread::spawn(|| {
            let seed: i32 = rand::rng().random();
            let mut rnd = RandState::new();
            rnd.seed(&rug::Integer::from(seed));

            let state = SchnorrThresholdState::init(5, 3);

            for _i in 0..10000 {
                let (shared_public_key, shares) = generate_shared_key_and_shares(&state, &mut rnd);

                let message = "send Bob 10 bucks.";
                let (r, s) = sign(&state, &mut rnd, message, &shares[0..(state.threshold)]);

                assert!(verify(&state, message, &r, &s, &shared_public_key));
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }
}
