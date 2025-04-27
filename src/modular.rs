//! Implementation of the modular arithmetic functions used for FROST.
//!
//! # Dependencies
//!
//! - `rug` is a arbitrary precision numbers crate and provides infrastructure for the 256bit numbers and calculations.
//!
//! # Features
//!
//! - Modular Addition.
//! - Modular Multiplication.
//! - Modular Division.
//! - Modular Power.
//!
//! # Support
//!
//! - This module is used to do arythmetic operations over finite fields.
//! - To learn more about the algorythms used for the modular arythmetic process see the [resources](https://en.wikipedia.org/wiki/Modular_arithmetic) here.

use rug::Integer;

/// Function that performs modular addition
pub fn add(a: Integer, b: Integer, m: &Integer) -> Integer {
    ((a.modulo(m)) + (b.modulo(m))).modulo(m)
}

/// Function that performs modular subtraction.
pub fn sub(a: Integer, b: Integer, m: &Integer) -> Integer {
    ((a.modulo(m)) - (b.modulo(m)) + m).modulo(m)
}

/// Function that performs modular multiplication.
pub fn mul(a: Integer, b: Integer, m: &Integer) -> Integer {
    ((a.modulo(m)) * (b.modulo(m))).modulo(m)
}

/// Function that performs modular division.
pub fn div(a: Integer, b: Integer, m: &Integer) -> Option<Integer> {
    let a = a.modulo(m);
    match b.invert(m).map(|inv| (inv * a).modulo(m)) {
        Ok(val) => Some(val),
        Err(_) => None,
    }
}

/// Function that performs modular power.
pub fn pow(x: &Integer, y: &Integer, p: &Integer) -> Integer {
    match x.clone().pow_mod(y, p) {
        Ok(i) => i,
        Err(_) => unreachable!(),
    }
}
