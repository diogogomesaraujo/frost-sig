use rug::Integer;

pub fn add(a: Integer, b: Integer, m: Integer) -> Integer {
    ((a.modulo(&m)) + (b.modulo(&m))).modulo(&m)
}

pub fn sub(a: Integer, b: Integer, m: Integer) -> Integer {
    ((a.modulo(&m)) - (b.modulo(&m)) + &m).modulo(&m)
}

pub fn mul(a: Integer, b: Integer, m: Integer) -> Integer {
    ((a.modulo(&m)) * (b.modulo(&m))).modulo(&m)
}

pub fn div(a: Integer, b: Integer, m: Integer) -> Integer {
    let a = a.modulo(&m);
    let inv = b.invert(&m).expect("No modular inverse exists");
    (inv * a).modulo(&m)
}

pub fn pow(x: Integer, y: Integer, p: Integer) -> Integer {
    match x.pow_mod(&y, &p) {
        Ok(i) => i,
        Err(_) => unreachable!(),
    }
}
