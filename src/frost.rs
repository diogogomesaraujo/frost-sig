use crate::{modular, BITS, PRIME};
use rand::Rng;
use rug::{rand::RandState, Integer};
use sha256::digest;
use std::str::FromStr;

pub fn generate_keys_and_prime(
    generator: &Integer,
    rnd: &mut RandState,
) -> ((Integer, Integer), (Integer, Integer)) {
    let prime = Integer::from_str(PRIME).expect("Shouldn't happen.");
    let q = modular::div(Integer::from(&prime - 1), Integer::from(2), &prime);

    let private_key = Integer::from(Integer::random_bits(BITS, rnd));
    let public_key = modular::pow(generator, &private_key, &prime);

    ((public_key, private_key), (prime, q))
}

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
    let s = Integer::from(modular::sub(k, modular::mul(private_key, e, q), q));

    (r, s)
}

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
    let v1 = Integer::from(
        modular::mul(
            modular::pow(generator, &s, prime),
            modular::pow(public_key, &e, prime),
            prime,
        ) % prime,
    );
    println!("{v1} --------- {r}");
    v1 == *r
}

#[test]
fn test_frost_key_generation() {
    let seed: i32 = rand::rng().random();
    let mut rnd = RandState::new();
    rnd.seed(&rug::Integer::from(seed));

    for _i in 0..1000 {
        let generator = Integer::from(Integer::random_bits(BITS, &mut rnd));
        let ((public_key, private_key), (prime, q)) = generate_keys_and_prime(&generator, &mut rnd);

        let message = "send Bob 10 bucks";
        let (r, s) = sign(message, private_key, &mut rnd, &generator, &prime, &q);

        assert!(verify(message, &r, &s, &public_key, &prime, &q, &generator));
    }
}
