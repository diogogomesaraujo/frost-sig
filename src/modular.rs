pub fn add(a: i64, b: i64, m: i64) -> i64 {
    ((a.rem_euclid(m)).wrapping_add(b.rem_euclid(m))).rem_euclid(m)
}

pub fn sub(a: i64, b: i64, m: i64) -> i64 {
    ((a.rem_euclid(m))
        .wrapping_sub(b.rem_euclid(m))
        .wrapping_add(m))
    .rem_euclid(m)
}

pub fn mul(a: i64, b: i64, m: i64) -> i64 {
    ((a.rem_euclid(m)).wrapping_mul(b.rem_euclid(m))).rem_euclid(m)
}

pub fn inverse(a: i64, m: i64) -> i64 {
    pow(a, (m.wrapping_sub(2)) as u64, m)
}

pub fn div(a: i64, b: i64, m: i64) -> i64 {
    let a = a.rem_euclid(m);
    let inv = inverse(b, m);
    (inv.wrapping_mul(a)).rem_euclid(m)
}

pub fn pow(x: i64, y: u64, p: i64) -> i64 {
    let mut res: i64 = 1;
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
