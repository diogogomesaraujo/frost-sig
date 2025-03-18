//! Implementation of the Schnorr threshold signatures (simplified).
//! It uses 256bit integers, modular arythmetic to simplify calculations and handles all the operations for server-side usage.

use crate::{modular, BITS, PRIME};
use rand::Rng;
use rug::{rand::RandState, Integer};
use sha256::digest;
use std::str::FromStr;

/// Struct that saves the constants needed for all Schnorr Threshold Signature operations.
pub struct SchnorrThresholdState {
    pub prime: Integer,
    pub q: Integer,
    pub generator: Integer,
    pub participants: usize,
    pub threshold: usize,
}

impl SchnorrThresholdState {
    /// Function that initializes the SchnorrThresholdState.
    /// Recieves two parameters: number of participants and threshold that will determine how many shares are generated and the minimum used for signing operations.
    /// The rest of the parameters are initialized internally.
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

/// Function that generates private shares according to the number of participants in the SchnorrThresholdState.
/// Each share should be stored securly by each participant.
pub fn generate_secret_shares(state: &SchnorrThresholdState, rnd: &mut RandState) -> Vec<Integer> {
    (0..state.participants)
        .map(|_| Integer::from(Integer::random_bits(BITS, rnd)))
        .collect()
}

/// Function that generates a shared (public) key for the specific subset of secret shares given.
/// The number of shares should match with the threshold in the SchnorrTresholdState.
pub fn generate_shared_key(
    state: &SchnorrThresholdState,
    secret_shares_subset: &[Integer],
) -> Integer {
    secret_shares_subset
        .iter()
        .fold(Integer::from(1), |acc, sk| {
            modular::mul(
                acc,
                modular::pow(&(state.generator), &sk, &state.prime),
                &state.prime,
            )
        })
}

/// Function that signs a message using a subset of the private shares (the number of shares should match the threshold).
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

/// Function that verifies a message using the shared key and the signature response that was recieved.
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

/// Bulk test for the Schnorr Threshold Signature library using randomly generated numbers.
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
                let shares = generate_secret_shares(&state, &mut rnd);
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
