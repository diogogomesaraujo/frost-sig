pub fn add(a: u64, b: u64, m: u64) -> u64 {
    ((a.rem_euclid(m)).wrapping_add(b.rem_euclid(m))).rem_euclid(m)
}

pub fn sub(a: u64, b: u64, m: u64) -> u64 {
    ((a.rem_euclid(m))
        .wrapping_sub(b.rem_euclid(m))
        .wrapping_add(m))
    .rem_euclid(m)
}

pub fn mul(a: u64, b: u64, m: u64) -> u64 {
    ((a.rem_euclid(m)).wrapping_mul(b.rem_euclid(m))).rem_euclid(m)
}

pub fn inverse(a: u64, m: u64) -> u64 {
    pow(a, (m.wrapping_sub(2)) as u64, m)
}

pub fn div(a: u64, b: u64, m: u64) -> u64 {
    let a = a.rem_euclid(m);
    let inv = inverse(b, m);
    (inv.wrapping_mul(a)).rem_euclid(m)
}

pub fn pow(x: u64, y: u64, p: u64) -> u64 {
    let mut res: u64 = 1;
    let mut x = x.rem_euclid(p);
    let mut y = y;
    if x == 0 {
        return 0;
    }
    while y > 0 {
        if (y & 1) != 0 {
            res = (res.wrapping_mul(x)).rem_euclid(p);
        }
        y >>= 1;
        x = (x.wrapping_mul(x)).rem_euclid(p);
    }
    res
}
