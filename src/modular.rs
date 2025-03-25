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
///
/// ## Parameters
///
/// - `a` is the first value of the addition.
/// - `b` is the second value of the addition.
/// - `m` is the value used for the modulo operation.
///
/// ## Returns
///
/// - `Integer` that is the result of the modular addition of a and b with modulo m.
pub fn add(a: Integer, b: Integer, m: &Integer) -> Integer {
    ((a.modulo(m)) + (b.modulo(m))).modulo(m)
}

/// Function that performs modular subtraction.
///
/// ## Parameters
///
/// - `a` is the first value of the subtraction.
/// - `b` is the second value of the subtraction.
/// - `m` is the value used for the modulo operation.
///
/// ## Returns
///
/// - `Integer` that is the result of the modular subtraction of a and b with modulo m.
pub fn sub(a: Integer, b: Integer, m: &Integer) -> Integer {
    ((a.modulo(m)) - (b.modulo(m)) + m).modulo(m)
}

/// Function that performs modular multiplication.
///
/// ## Parameters
///
/// - `a` is the first value of the multiplication.
/// - `a` is the second value of the multiplication.
/// - `m` is the value used for the modulo operation.
///
/// ## Returns
///
/// - `Integer` that is the result of the modular multiplication of a and b with modulo m.
pub fn mul(a: Integer, b: Integer, m: &Integer) -> Integer {
    ((a.modulo(m)) * (b.modulo(m))).modulo(m)
}

/// Function that performs modular division.
///
/// ## Parameters
///
/// - `a` is the first value of the division.
/// - `a` is the second value of the division.
/// - `m` is the value used for the modulo operation.
///
/// ## Returns
///
/// - `Integer` that is the result of the modular division of a and b with modulo m.
pub fn div(a: Integer, b: Integer, m: &Integer) -> Integer {
    let a = a.modulo(m);
    let inv = b.invert(m).expect("No modular inverse exists");
    (inv * a).modulo(m)
}

/// Function that performs modular power.
///
/// ## Parameters
///
/// - `a` is the first value of the power.
/// - `a` is the second value of the power.
/// - `m` is the value used for the modulo operation.
///
/// ## Returns
///
/// - `Integer` that is the result of the modular a power b with modulo m.
pub fn pow(x: &Integer, y: &Integer, p: &Integer) -> Integer {
    match x.clone().pow_mod(y, p) {
        Ok(i) => i,
        Err(_) => unreachable!(),
    }
}
