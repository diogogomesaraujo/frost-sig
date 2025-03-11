//! Implementation of the Schnorr threshold signatures.

use crate::{modular, BITS, PRIME};
use rand::Rng;
use rug::{rand::RandState, Integer};
use sha256::digest;
use std::str::FromStr;

/// Struct that saves the state of the constants for the schnorr signature operations.
pub struct SchnorrState {
    prime: Integer,
    q: Integer,
    generator: Integer,
}

impl SchnorrState {
    /// Function to init the State and get all the constants needed for the operations.
    pub fn init() -> SchnorrState {
        SchnorrState {
            prime: Integer::from_str(PRIME).expect("Shouldn't happen."),
            q: Integer::from((Integer::from_str(PRIME).expect("Shouldn't happen.") - 1) / 2),
            generator: Integer::from(4),
        }
    }
}

/// Function to generate the public and private key pair.
pub fn generate_keys(state: &SchnorrState, rnd: &mut RandState) -> (Integer, Integer) {
    let private_key = Integer::from(Integer::random_bits(BITS, rnd));
    let public_key = modular::pow(&(state.generator), &private_key, &(state.prime));
    (public_key, private_key)
}

/// Function to sign a message using a private key.
pub fn sign(
    state: &SchnorrState,
    rnd: &mut RandState,
    message: &str,
    private_key: Integer,
) -> (Integer, Integer) {
    let k = Integer::from(Integer::random_bits(BITS, rnd));
    let r = modular::pow(&(state.generator), &k, &(state.prime));
    let hash = Integer::from(
        Integer::from_str_radix(digest(format!("{r}{message}")).as_str(), 16).unwrap(),
    );
    let e = Integer::from(hash % &(state.q));
    let s = Integer::from(modular::sub(
        k,
        modular::mul(private_key, e, &(state.q)),
        &(state.q),
    ));
    (r, s)
}

/// Function to verify a message using the public key.
pub fn verify(
    state: &SchnorrState,
    message: &str,
    r: &Integer,
    s: &Integer,
    public_key: &Integer,
) -> bool {
    let hash = Integer::from(
        Integer::from_str_radix(digest(format!("{r}{message}")).as_str(), 16).unwrap(),
    );
    let e = Integer::from(hash % &(state.q));
    let v1 = Integer::from(modular::mul(
        modular::pow(&(state.generator), &s, &(state.prime)),
        modular::pow(public_key, &e, &(state.prime)),
        &(state.prime),
    ));
    v1 == *r
}

#[test]
fn test_frost_key_generation_bulk() {
    let mut handles = Vec::new();

    for _i in 0..20 {
        let handle = std::thread::spawn(|| {
            let seed: i32 = rand::rng().random();
            let mut rnd = RandState::new();
            rnd.seed(&rug::Integer::from(seed));

            let state = SchnorrState::init();

            for _i in 0..50000 {
                let (public_key, private_key) = generate_keys(&state, &mut rnd);

                let message = "send Bob 10 bucks.";
                let (r, s) = sign(&state, &mut rnd, message, private_key);

                assert!(verify(&state, message, &r, &s, &public_key));
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }
}
