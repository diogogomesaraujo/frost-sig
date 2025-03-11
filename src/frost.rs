use crate::{modular, BITS, PRIME};
use rand::Rng;
use rug::{rand::RandState, Integer};
use sha256::digest;
use std::str::FromStr;

/// Const value of the generator in str.
const GENERATOR: &str = "4";

/// Function to get all the constants needed for the operations.
pub fn get_prime_q_gen() -> (Integer, Integer, Integer) {
    let prime = Integer::from_str(PRIME).expect("Shouldn't happen.");
    let q = Integer::from((Integer::from_str(PRIME).expect("Shouldn't happen.") - 1) / 2);
    let generator = Integer::from_str(GENERATOR).expect("Shouldn't happen.");
    (prime, q, generator)
}

/// Function to generate the public and private key pair.
pub fn generate_keys(
    generator: &Integer,
    rnd: &mut RandState,
    prime: &Integer,
    q: &Integer,
) -> (Integer, Integer) {
    let private_key = Integer::from(Integer::random_bits(BITS, rnd));
    let public_key = modular::pow(generator, &private_key, &prime);
    (public_key, private_key)
}

/// Function to sign a message using a private key.
pub fn sign(
    message: &str,
    private_key: Integer,
    rnd: &mut RandState,
    generator: &Integer,
    prime: &Integer,
    q: &Integer,
) -> (Integer, Integer) {
    let k = Integer::from(Integer::random_bits(BITS, rnd));
    let r = modular::pow(generator, &k, prime);
    let hash = Integer::from(
        Integer::from_str_radix(digest(format!("{r}{message}")).as_str(), 16).unwrap(),
    );
    let e = Integer::from(hash % q);
    let s = Integer::from((k - private_key * e) % q);
    (r, s)
}

/// Function to verify a message using the public key.
pub fn verify(
    message: &str,
    r: &Integer,
    s: &Integer,
    public_key: &Integer,
    prime: &Integer,
    q: &Integer,
    generator: &Integer,
) -> bool {
    let hash = Integer::from(
        Integer::from_str_radix(digest(format!("{r}{message}")).as_str(), 16).unwrap(),
    );
    let e = Integer::from(hash % q);
    let v1 = Integer::from(modular::mul(
        modular::pow(generator, &s, prime),
        modular::pow(public_key, &e, prime),
        prime,
    ));
    println!("{v1} --------- {r}");
    v1 == *r
}

#[test]
fn test_frost_key_generation() {
    let mut handles = Vec::new();

    for i in 0..20 {
        let handle = std::thread::spawn(|| {
            let seed: i32 = rand::rng().random();
            let mut rnd = RandState::new();
            rnd.seed(&rug::Integer::from(seed));

            let (prime, q, generator) = get_prime_q_gen();

            for _i in 0..50000 {
                let (public_key, private_key) = generate_keys(&generator, &mut rnd, &prime, &q);

                let message = "send Bob 10 bucks";
                let (r, s) = sign(message, private_key, &mut rnd, &generator, &prime, &q);

                assert!(verify(message, &r, &s, &public_key, &prime, &q, &generator));
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }
}
