use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use primitive_types::U512;

const ACCOUNT_LOOKUP: &[char] = &[
    '1', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k',
    'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'w', 'x', 'y', 'z',
];

fn account_encode(value: u8) -> char {
    ACCOUNT_LOOKUP[value as usize]
}

pub fn public_key_to_nano_account(aggregate_public_key: &[u8; 32]) -> String {
    let mut number = U512::from_big_endian(aggregate_public_key);
    let check = U512::from_little_endian(&account_checksum(aggregate_public_key));
    number <<= 40;
    number |= check;

    let mut result = String::with_capacity(65);

    for _i in 0..60 {
        let r = number.byte(0) & 0x1f_u8;
        number >>= 5;
        result.push(account_encode(r));
    }
    result.push_str("_onan");
    result.chars().rev().collect()
}

fn account_checksum(aggregate_public_key: &[u8; 32]) -> [u8; 5] {
    let mut check = [0u8; 5];
    let mut blake = Blake2bVar::new(check.len()).unwrap();
    blake.update(aggregate_public_key);
    blake.finalize_variable(&mut check).unwrap();
    check
}
