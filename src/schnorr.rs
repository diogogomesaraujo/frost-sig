//! Implementation of the Schnorr Threshold Signatures.
//!
//! ## Dependencies
//!
//! - `rug` is a arbitrary precision numbers crate and provides infrastructure for the 256bit numbers and calculations.
//! - `rand` is a random number generation crate and it is used to generate a random seed for the 256bit numbers generation.
//! - `sha-256` is an implementation of SHA-256 and it is the predefined hashing algorythm for the threshold signature system.
//!
//! ## Features
//!
//! - Generation of each participant's secret share.
//! - Generation of the public key for the subset of the participants that will sign the message.
//! - Validation of the signing operation.
//!
//! ## Usage
//!
//! This variant of Schnorr Threshold Signatures is designed for a server-focused system, where the server is responsible for all operations.
//! The participants only sign transactions with their key.
//! It shouldn't be used in decentralized scenarios (unlike FROST implementations).
//!
//! ## Support
//!
//! To understand the algorythm read this [article](https://medium.com/@barchitect/ecdsa-eddsa-and-schnorr-the-anatomy-of-elliptic-curve-based-signature-schemes-583bb96df076).
//!
//! ## Example
//!
//! ```
//! let seed: i32 = rand::rng().random();
//! let mut rnd = RandState::new();
//! rnd.seed(&rug::Integer::from(seed));
//!
//! let state = SchnorrThresholdState::init(10, 5);
//!
//! let shares = generate_secret_shares(&state, &mut rnd);
//! let subset = &shares[0..(state.threshold)];
//! let shared_public_key = generate_shared_key(&state, subset);
//!
//! let message = "send Bob 10 bucks.";
//! let (shared_commitment, signature_response) = sign(&state, &mut rnd, message, subset);
//! let valid = verify(&state, message, &shared_commitment, &signature_response, &shared_public_key);
//!
//! assert!(valid);
//!
//! let shares: Vec<String> = shares
//!     .iter()
//!     .map(|share| share.to_string_radix(16))
//!     .collect();
//! let shared_public_key = shared_public_key.to_string_radix(16);
//!
//! println!(
//!     "
//!     Shared Public Key: {:?}\n
//!     Shares:            {:?}\n
//!     Message:           {}\n
//!     Valid:             {}\n",
//!     shared_public_key, shares, message, valid
//! );
//! ```

use crate::{modular, BITS, PRIME};
use rand::Rng;
use rug::{rand::RandState, Integer};
use sha256::digest;
use std::str::FromStr;

/// Struct that saves the constants needed for all Schnorr Threshold Signature operations.
pub struct SchnorrThresholdState {
    /// `prime` is a prime number bigger than any possible key or share generated and is used for modular arithmetic.
    pub prime: Integer,
    /// `q` is computed as `(prime - 1) / 2` and it is also used for modular arithmetic.
    pub q: Integer,
    /// `generator` is a constant value used for generating secret shares.
    pub generator: Integer,
    /// `participants` is the chosen number of participants that hold a secret share and can participate in signing operations.
    pub participants: usize,
    /// `threshold` is the minimum ammount of participants needed to sign a message.
    pub threshold: usize,
}

impl SchnorrThresholdState {
    /// Function that initializes the SchnorrThresholdState.
    ///
    /// ## Parameters
    ///
    /// - `p` is the number of participants.
    /// - `t` is the threshold.
    ///
    /// They will determine how many shares are generated and the minimum used for signing operations.
    /// The rest of the parameters are initialized internally.
    ///
    /// ## Returns
    ///
    /// - `SchnorrThresholdState` initialized with the participants and threshold defined.
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
///
/// ## Parameters
///
/// - `state` has the constants needed for Schnorr Threshold operations.
/// - `rnd` is a state for generating the 256bit integers.
///
/// ## Returns
///
/// - `Vec<Integer>` that contains a secret share for each participant.
///
/// It is a good practice for a participant to store the key himself.
pub fn generate_secret_shares(state: &SchnorrThresholdState, rnd: &mut RandState) -> Vec<Integer> {
    (0..state.participants)
        .map(|_| Integer::from(Integer::random_bits(BITS, rnd)))
        .collect()
}

/// Function that generates a shared (public) key for the specific subset of secret shares given.
///
/// ## Parameters
///
/// - `state` has the constants needed for Schnorr Threshold operations.
/// - `secret_shares_subset` is a subset of the participants whose size should match the threshold in the state.
///
/// ## Returns
///
/// - `Integer` that is a generated shared public key for the subset of participants given.
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

/// Function that signs a message using a subset of the private shares.
///
/// ## Parameters
///
/// - `state` has the constants needed for Schnorr Threshold operations.
/// - `rnd` is a state for generating the 256bit integers.
/// - `message` is a string that will be signed by the subset of participants.
/// - `secret_shares_subset` is the subset of participants whose size should match the threshold in the state and that will sign the operation.
///
/// ## Returns
///
/// - `Integer` that is the shared commitment that will validate the response.
/// - `Integer` that is the signed message.
pub fn sign(
    state: &SchnorrThresholdState,
    rnd: &mut RandState,
    message: &str,
    secret_shares_subset: &[Integer],
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
    let shared_secret_key = secret_shares_subset.iter().fold(Integer::ZERO, |acc, sk| {
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
///
/// ## Parameters
///
/// - `state` has the constants needed for Schnorr Threshold operations.
/// - `message` is a string that will be signed by the subset of participants.
/// - `shared_commitment` is used to validate the response and is unique to the subset used for the signing operation and the message signed.
/// - `signature_response` is the message after it was signed by a subset of participants.
/// - `shared_public_key` is used to identify the group that signed the operation.
///
/// ## Returns
///
/// - `bool` that is true or false depending if it was able to validate the signature or not.
pub fn verify(
    state: &SchnorrThresholdState,
    message: &str,
    shared_commitment: &Integer,
    signature_response: &Integer,
    shared_public_key: &Integer,
) -> bool {
    let challenge_hash = Integer::from(
        Integer::from_str_radix(digest(format!("{shared_commitment}{message}")).as_str(), 16)
            .expect("Shouldn't happen."),
    );
    let challenge = Integer::from(challenge_hash % &(state.q));

    let expected_point = Integer::from(modular::mul(
        modular::pow(&(state.generator), &signature_response, &(state.prime)),
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

                let shares: Vec<String> = shares
                    .iter()
                    .map(|share| share.to_string_radix(16))
                    .collect();
                let shared_public_key = shared_public_key.to_string_radix(16);

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
