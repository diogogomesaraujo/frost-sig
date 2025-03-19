# thresh-sig

`thresh-sig` is a threshold signature library that implements threshold algorythms for 256bit integers.

## Features

- Shamir Secret Sharing.
- Schnorr Threshold Signatures.
- Modular Arythmetic for `rug` integers.

## Dependencies

- `rug` is a arbitrary precision numbers crate and provides infrastructure for the 256bit numbers and calculations.
- `rand` is a random number generation crate and it is used to generate a random seed for the 256bit numbers generation.
- `sha-256` is an implementation of SHA-256 and it is the predefined hashing algorythm for the threshold signature system.

## Usage

**Run the program**:
   ```bash
   cargo run
   ```
   Run `cargo test --lib` to test the crate on bulk.

## Documentation
**Generate documentation and open**:
  ```bash
  cargo doc --open
  ```

## Requirements

- Cargo installed

## Future Work

- Implement FROST.
