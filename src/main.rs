use frost_sig::*;
use rand::Rng;
use rug::rand::RandState;

#[tokio::main]
async fn main() {
    let mode = std::env::args().nth(1).expect("no pattern given");
    let operation = std::env::args().nth(2).expect("no pattern given");

    match (mode.as_str(), operation.as_str()) {
        ("server", "keygen") => {
            let seed: i32 = rand::rng().random();
            let mut rnd = RandState::new();
            rnd.seed(&rug::Integer::from(seed));

            frost_sig::server::keygen::run("localhost", 3333, 3, 2)
                .await
                .unwrap();
        }
        ("client", "keygen") => {
            client::keygen::run("localhost", 3333).await.unwrap();
        }
        _ => {
            eprintln!("Invalid arguments.");
        }
    }
}
