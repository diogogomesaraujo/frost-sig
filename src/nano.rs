use base32::Alphabet;
use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use std::error::Error;

pub fn public_key_to_nano_account(public_key: &[u8; 32]) -> Result<String, Box<dyn Error>> {
    let pk = base32::encode(Alphabet::Crockford, public_key).to_lowercase();
    let cs = {
        let mut hasher = Blake2bVar::new(5)?;
        hasher.update(public_key);
        let mut buf = [0u8; 5];
        hasher.finalize_variable(&mut buf)?;
        base32::encode(Alphabet::Crockford, &buf)
    }
    .to_lowercase();
    Ok(format!("nano_{}{}", pk, cs))
}
