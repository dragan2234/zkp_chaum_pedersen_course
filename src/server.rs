use num_bigint::BigUint;
use std::{collections::HashMap, sync::Mutex};
use tonic::{transport::Server, Code, Request, Response, Status};
use zkp_chaum_pedersen::ZKP;

pub mod zkp_auth {
    include!("./zkp_auth.rs");
}

use zkp_auth::{
    auth_server::{Auth, AuthServer},
    AuthenticationAnswerRequest, AuthenticationAnswerResponse, AuthenticationChallengeRequest,
    AuthenticationChallengeResponse, RegisterRequest, RegisterResponse,
};

#[derive(Debug, Default)]
pub struct AuthImpl {
    pub user_info: Mutex<HashMap<String, UserInfo>>,
    pub auth_id_to_user_hashmap: Mutex<HashMap<String, String>>,
}

#[derive(Debug, Default)]
pub struct UserInfo {
    pub user_name: String,
    pub y1: BigUint,
    pub y2: BigUint,
    pub r1: BigUint,
    pub r2: BigUint,
    pub c: BigUint,
    pub s: BigUint,
    pub session_id: BigUint,
}

#[tonic::async_trait]
impl Auth for AuthImpl {
    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        println!("Processing Register: {:?}", request);

        let request = request.into_inner();

        let user_name = request.user;

        let mut user_info = UserInfo::default();

        user_info.user_name = user_name.clone();
        user_info.y1 = BigUint::from_bytes_be(&request.y1);
        user_info.y2 = BigUint::from_bytes_be(&request.y2);

        let mut user_info_hashmap = &mut self.user_info.lock().unwrap();

        user_info_hashmap.insert(user_name, user_info);

        Ok(Response::new(RegisterResponse {}))
    }

    async fn create_authentication_challenge(
        &self,
        request: Request<AuthenticationChallengeRequest>,
    ) -> Result<Response<AuthenticationChallengeResponse>, Status> {
        println!("Processing Challenge Request: {:?}", request);

        let request = request.into_inner();

        let user_name = request.user;

        let mut user_info_hashmap = &mut self.user_info.lock().unwrap();

        if let Some(user_info) = user_info_hashmap.get_mut(&user_name) {
            user_info.r1 = BigUint::from_bytes_be(&request.r1);
            user_info.r2 = BigUint::from_bytes_be(&request.r2);

            let c = BigUint::from(666u32);
            let auth_id = ZKP::generate_random_string(12);

            let mut auth_id_to_user_hashmap = &mut self.auth_id_to_user_hashmap.lock().unwrap();

            auth_id_to_user_hashmap.insert(auth_id.clone(), user_name);

            return Ok(Response::new(AuthenticationChallengeResponse {
                auth_id,
                c: c.to_bytes_be(),
            }));
        } else {
            return Err((Status::new(
                Code::NotFound,
                format!("User: {} not found in database", user_name),
            )));
        }
    }

    async fn verify_authentication(
        &self,
        request: Request<AuthenticationAnswerRequest>,
    ) -> Result<Response<AuthenticationAnswerResponse>, Status> {
        println!("Processing Verification Request: {:?}", request);

        let request = request.into_inner();

        let auth_id = request.auth_id;

        let mut auth_id_to_user_hashmap = &mut self.auth_id_to_user_hashmap.lock().unwrap();

        if let Some(user_name) = auth_id_to_user_hashmap.get_mut(&auth_id) {
            let mut user_info_hashmap = &mut self.user_info.lock().unwrap();
            let user_info = user_info_hashmap
                .get(user_name)
                .expect("AuthId not found on hashmap");

            let s = request.s;

            let (alpha, beta, p, q) = ZKP::get_constants();

            let zkp = ZKP { alpha, beta, p, q };

            let verification = zkp.verify(
                &user_info.r1,
                &user_info.r2,
                &user_info.y1,
                &user_info.y2,
                &user_info.c,
                &user_info.s,
            );

            if verification {
                let session_id = ZKP::generate_random_string(12);

                return Ok(Response::new(AuthenticationAnswerResponse { session_id }));
            } else {
                return Err(Status::new(
                    Code::PermissionDenied,
                    format!("AuthId: {} sent a bad solution to the challenge", auth_id),
                ));
            }
        } else {
            return Err(Status::new(
                (Code::NotFound),
                format!("AuthId: {} not found in database", auth_id),
            ));
        }

        todo!()
    }
}

#[tokio::main]
async fn main() {
    let addr = "127.0.0.1:50051".to_string();

    println!("✅ Running the server in {}", addr);

    let auth_impl = AuthImpl::default();

    Server::builder()
        .add_service(AuthServer::new(auth_impl))
        .serve(addr.parse().expect("could not convert address"))
        .await
        .unwrap();
}
