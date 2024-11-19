use num_bigint::BigUint;
use std::io::stdin;

pub mod zkp_auth {
    include!("./zkp_auth.rs");
}

use zkp_auth::{auth_client::AuthClient, RegisterRequest};
use zkp_chaum_pedersen::ZKP;

#[tokio::main]
async fn main() {
    let mut buf = String::new();

    let (alpha, beta, p, q) = ZKP::get_constants();

    let zkp = ZKP {
        alpha: alpha.clone(),
        beta: beta.clone(),
        p: p.clone(),
        q: q.clone(),
    };

    let mut client = AuthClient::connect("http://127.0.0.1:50051")
        .await
        .expect("could not connect to the server");

    println!("Connected to the server ");

    println!("Please provide username:");
    stdin()
        .read_line(&mut buf)
        .expect("Could not get the username from stdin");
    let username = buf.trim().to_string();

    println!("Please provide password:");
    stdin()
        .read_line(&mut buf)
        .expect("Could not get the username from stdin");
    let password = BigUint::from_bytes_be(buf.trim().as_bytes());

    let y1 = ZKP::exponentiate(&alpha, &password, &p);
    let y2 = ZKP::exponentiate(&beta, &password, &p);

    let request = RegisterRequest {
        user: username,
        y1: y1.to_bytes_be(),
        y2: y2.to_bytes_be(),
    };
    let _response = client
        .register(request)
        .await
        .expect("Could not register to event");

    println!("{:?}", _response);
}
