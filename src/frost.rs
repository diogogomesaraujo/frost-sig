use std::str::FromStr;

use rug::{rand::RandState, Integer};

use crate::{modular, BITS, PRIME};

pub fn generate_keys_and_prime(
    generator: Integer,
    rnd: &mut RandState,
) -> ((Integer, Integer), Integer) {
    let prime = Integer::from_str(PRIME).expect("Shouldn't happen.");

    let public_key = Integer::from(Integer::random_bits(BITS, rnd));
    let private_key = modular::pow(&generator, &public_key, &prime);

    ((public_key, private_key), prime)
}
