//! Implementation of the modular arythmetic functions.

use rug::{rand::RandState, Integer};

use crate::BITS;

/// Function to calculate the modular addition of two values.
pub fn add(a: Integer, b: Integer, m: &Integer) -> Integer {
    ((a.modulo(m)) + (b.modulo(m))).modulo(m)
}

/// Function to calculate the modular subtraction of two values.
pub fn sub(a: Integer, b: Integer, m: &Integer) -> Integer {
    ((a.modulo(m)) - (b.modulo(m)) + m).modulo(m)
}

/// Function to calculate the modular multiplication of two values.
pub fn mul(a: Integer, b: Integer, m: &Integer) -> Integer {
    ((a.modulo(m)) * (b.modulo(m))).modulo(m)
}

/// Function to calculate the modular division of two values.
pub fn div(a: Integer, b: Integer, m: &Integer) -> Integer {
    let a = a.modulo(m);
    let inv = b.invert(m).expect("No modular inverse exists");
    (inv * a).modulo(m)
}

/// Function to calculate the modular power of two values.
pub fn pow(x: &Integer, y: &Integer, p: &Integer) -> Integer {
    match x.clone().pow_mod(y, p) {
        Ok(i) => i,
        Err(_) => unreachable!(),
    }
}
