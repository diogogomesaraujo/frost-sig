//! Implementation of the Shamir Secret Sharing threshold signatures.
//! It uses 256bit integers and uses modular arythmetic to simplify calculations.
//!
//! ## Dependencies
//!
//! - `rug` is a arbitrary precision numbers crate and provides infrastructure for the 256bit numbers and calculations.
//! - `rand` is a random number generation crate and it is used to generate a random seed for the 256bit numbers generation.
//!
//! ## Features
//!
//! - Divide a secret into multiple shares according to the number of participants and the threshold.
//! - Recover the secret from the divided shares using the Lagrange polinomial.
//!
//! ## Support
//!
//! To understand the algorythm read this [article](https://www.geeksforgeeks.org/shamirs-secret-sharing-algorithm-cryptography/).
//!
//! ## Example
//!
//! ```
//! let seed: i32 = rand::rng().random();
//! let mut rnd = RandState::new();
//! rnd.seed(&rug::Integer::from(seed));
//!
//! let prime = Integer::from_str(PRIME).expect("Shouldn't happen.");
//!
//! let key = generate_key(&mut rnd, &prime);
//! let k = 7;
//! let n = 10;
//!
//! let shares = create_secret_shares(key.clone(), k, n, &prime, &mut rnd);
//! let subset = &shares[0..(k as usize)];
//!
//! let recovered_key = recover_secret(subset, &prime);
//!
//! assert_eq!(
//!     key, recovered_key,
//!     "Secret Shares: {:?} \n{key} compared to {recovered_key}\n",
//!     shares
//! );
//!
//! println!(
//!     "The generated key was {key} and the recovered key from the shares was {recovered_key}",
//!     key = key.to_string_radix(16),
//!     recovered_key = recovered_key.to_string_radix(16)
//! );
//! ```

use crate::{modular, BITS, PRIME};
use rand::Rng;
use rug::{rand::RandState, Integer};
use std::str::FromStr;

/// Function that calculates the y value for a given polinomial and an x.
///
/// ## Parameters
///
/// - `x` is the value of the x axis.
/// - `pol` is the function that represents the threshold of participants needed to recover the secret.
/// - `prime` is the prime number used for the modular arithmetic operations.
///
/// ## Returns
///
/// - `Integer` that is the resulting y from the x and pol given.
///
/// It is used to generate part of the secret shares.
pub fn calculate_y(x: &Integer, pol: &[Integer], prime: &Integer) -> Integer {
    pol.iter().enumerate().fold(Integer::ZERO, |acc, (i, p)| {
        modular::add(
            acc,
            modular::mul(p.clone(), modular::pow(x, &Integer::from(i), prime), prime),
            prime,
        )
    })
}

/// Function that calculates the lagrange polinomial.
///
/// ## Parameters
///
/// - `x` is the value of the x axis.
/// - `pol` is the function that represents the threshold of participants needed to recover the secret.
/// - `prime` is the prime number used for the modular arithmetic operations.
///
/// ## Returns
///
/// - `Integer` that is the recovered secret.
///
/// It is used to recover a secret using a subset with an equal or bigger size to the threshold defined.
pub fn lagrange_pol(x: &Integer, pol: &[(Integer, Integer)], prime: &Integer) -> Integer {
    let n = pol.len();
    let mut result = Integer::from(0);

    for i in 0..n {
        let (xi, yi) = pol[i].clone();

        let mut num = Integer::from(1);
        let mut den = Integer::from(1);

        for j in 0..n {
            if j != i {
                let (xj, _) = pol[j].clone();
                num = modular::mul(
                    num.clone(),
                    modular::sub(Integer::from(x), Integer::from(&xj), prime),
                    prime,
                );
                den = modular::mul(den, modular::sub(xi.clone(), xj, prime), prime);
            }
        }
        let div = modular::div(num, den, prime);
        let term = modular::mul(yi, div, prime);

        result = modular::add(result, term, prime);
    }

    result
}

/// Function that generates a unique number for a given vector.
/// ## Parameters
///
/// - `rnd` is a state for generating the 256bit integers.
/// - `v` is used to compare to the generated value to ensure that it is unique.
///
/// ## Returns
///
/// - `Integer` that is unique in relation to the given vector.
pub fn generate_unique(rnd: &mut RandState, v: &[Integer]) -> Integer {
    let r = Integer::from(Integer::random_bits(BITS, rnd));

    match v.iter().find(|&i| i == &r) {
        Some(_) => generate_unique(rnd, v),
        None => r,
    }
}

/// Function that generates a polinomial.
/// It is used to divide the secret into multiple shares that can be used to sign a secret.
/// ## Parameters
///
/// - `key` is the generated key.
/// - `k` is the threshold of participants needed to recover the secret.
/// - `rnd` is a state for generating the 256bit integers.
///
/// ## Returns
///
/// - `Integer` that is the recovered secret.
pub fn generate_pol(key: Integer, k: u64, rnd: &mut RandState) -> Vec<Integer> {
    let mut pol: Vec<Integer> = vec![key];

    for _i in 1..k {
        let r = generate_unique(rnd, &pol);
        pol.push(r);
    }

    pol
}

/// Function that creates the secret shares according to the number of participants (n).
/// It uses a pol according to the threshold (k) to generate the shares.
/// ## Parameters
///
/// - `key` is the generated key.
/// - `n` is the number of participants and the number of shares generated.
/// - `k` is the threshold of participants needed to recover the secret and will determin the polinomial.
/// - `prime` is the prime number used for modular arythmetic.
/// - `rnd` is a state for generating the 256bit integers.
///
/// ## Returns
///
/// - `Vec<(Integer, Integer)>` that is a tuple of points generated for each participant.
pub fn create_secret_shares(
    key: Integer,
    n: u64,
    k: u64,
    prime: &Integer,
    rnd: &mut RandState,
) -> Vec<(Integer, Integer)> {
    let pol = generate_pol(key, k, rnd);
    let mut shares: Vec<(Integer, Integer)> = Vec::new();
    let mut xs = Vec::new();

    for _i in 0..n {
        let x = generate_unique(rnd, &xs);
        xs.push(x.clone());

        let y = calculate_y(&x, &pol, prime);
        shares.push((x, y));
    }

    shares
}

/// Function that generates a secret key.
///
/// ## Parameters
///
/// - `rnd` is a state for generating the 256bit integers.
/// - `prime` is the prime number used for modular arythmetic.
///
/// ## Returns
///
/// - `Integer` that is the generated key.
pub fn generate_key(rnd: &mut RandState, prime: &Integer) -> Integer {
    Integer::from(Integer::random_bits(BITS, rnd)).modulo(&prime)
}

/// Function that recovers the secret from the given private shares.
/// It is only able to recover the secret if the number of shares is at least as big as the threshold.
///
/// ## Parameters
///
/// - `shares` represents the subset of shares that will be used to recover the secret.
/// - `prime` is the prime number used for modular arythmetic.
///
/// ## Returns
///
/// - `Integer` is the recovered secret.
pub fn recover_secret(shares: &[(Integer, Integer)], prime: &Integer) -> Integer {
    lagrange_pol(&Integer::from(0), shares, prime)
}

/// Bulk test for the Shamir Secret Sharing module using randomly generated numbers.
#[test]
fn test_create_recover_bulk() {
    let mut handles = Vec::new();

    for _i in 0..20 {
        let handle = std::thread::spawn(|| {
            let seed: i32 = rand::rng().random();
            let mut rnd = RandState::new();
            rnd.seed(&rug::Integer::from(seed));

            let prime = Integer::from_str(PRIME).expect("Shouldn't happen.");

            for _i in 0..50000 {
                let key = generate_key(&mut rnd, &prime);
                let k = 2;
                let n = 3;

                let shares = create_secret_shares(key.clone(), n, k, &prime, &mut rnd);
                let subset = &shares[0..(k as usize)];

                let recovered_key = recover_secret(subset, &prime);

                assert_eq!(
                    key, recovered_key,
                    "Secret Shares: {:?} \n{key} compared to {recovered_key}\n",
                    shares
                );
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }
}
