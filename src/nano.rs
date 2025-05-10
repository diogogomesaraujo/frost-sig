use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use data_encoding::Specification;
use regex::Regex;
use std::error::Error;

pub fn is_nano_account(public_address: &str) -> Result<bool, Box<dyn Error>> {
    let re = Regex::new(r"^(nano|xrb)_[13]{1}[13456789abcdefghijkmnopqrstuwxyz]{59}$")?;
    Ok(re.is_match(public_address))
}

pub fn public_key_to_nano_account(public_key: &[u8; 32]) -> Result<String, Box<dyn Error>> {
    let base32 = {
        let mut spec = Specification::new();
        spec.symbols.push_str("13456789abcdefghijkmnopqrstuwxyz");
        spec.encoding()?
    };

    let pk = base32.encode(public_key);
    let cs = {
        let mut hasher = Blake2bVar::new(5)?;
        hasher.update(public_key);
        let mut buf = [0u8; 5];
        hasher.finalize_variable(&mut buf)?;
        base32.encode(&buf)
    }
    .to_lowercase();

    let nano_address = format!("nano_{}{}", pk, cs);

    assert!(is_nano_account(&nano_address)?);

    Ok(nano_address)
}
