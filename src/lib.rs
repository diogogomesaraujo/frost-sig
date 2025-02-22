use rand::{rngs::ThreadRng, Rng};

fn calculate_y(x: i64, pol: &[i64]) -> i64 {
    pol.iter().enumerate().fold(0, |acc, (i, &p)| {
        acc.wrapping_add(p.wrapping_mul(x.wrapping_pow(i as u32)))
    })
}

fn lagrange_pol(x: i64, pol: &[(i64, i64)]) -> i64 {
    let n = pol.len();
    let mut result: i64 = 0;

    for i in 0..n {
        let (xi, yi) = pol[i];
        let mut term = yi;
        for j in 0..n {
            if j != i {
                let (xj, _) = pol[j];
                term = term.wrapping_mul((x.wrapping_sub(xj)).wrapping_div(xi.wrapping_sub(xj)));
            }
        }
        result = result.wrapping_add(term);
    }

    result
}

fn generate_unique(rgn: &mut ThreadRng, v: &[i64]) -> i64 {
    let mut r: i64 = rgn.random();
    r %= 997;

    match v.contains(&r) {
        true => generate_unique(rgn, v),
        false => r,
    }
}

fn generate_pol(key: i64, k: u64, rgn: &mut ThreadRng) -> Vec<i64> {
    let mut pol: Vec<i64> = vec![key];

    for _i in 1..k {
        let r: i64 = generate_unique(rgn, &pol);
        pol.push(r);
    }

    pol
}

pub fn create_secret_shares(key: i64, k: u64, n: u64) -> Vec<(i64, i64)> {
    let mut rgn = rand::rng();

    let pol = generate_pol(key, k, &mut rgn);
    let mut shares: Vec<(i64, i64)> = Vec::new();
    let mut xs = Vec::new();

    for _i in 0..n {
        let x = generate_unique(&mut rgn, &xs);
        xs.push(x);

        let y = calculate_y(x, &pol);
        shares.push((x, y));
    }

    shares
}

pub fn recover_secret(shares: &[(i64, i64)]) -> i64 {
    lagrange_pol(0, shares)
}

#[test]
fn test_create_recover() {
    let mut rgn = rand::rng();

    let key: i64 = rgn.random();
    let k = 2;
    let n = 5;

    let shares = create_secret_shares(key, k, n);
    let subset = &shares[0..(k as usize)];

    let recovered_key = recover_secret(subset);

    assert_eq!(key, recovered_key, "{key} compared to {recovered_key}");
}
