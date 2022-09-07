use tonic::{transport::Server, Request, Response, Status};

use lime::lime_server::{Lime, LimeServer};
use lime::Message;

use self::lime::{EmptyRequest, BroadcastSsiDs, ProbeSsiDs, Handshakes};

pub mod lime {
    tonic::include_proto!("lime");
}

#[derive(Debug, Default)]
pub struct LimeService {}

#[tonic::async_trait]
impl Lime for LimeService {
    async fn echo(&self, request: Request<Message>) -> Result<Response<Message>, Status> {

        let reply = lime::Message {
            name: format!("{}", request.into_inner().name).into(),
        };

        Ok(Response::new(reply))
    }

    async fn get_broadcast(&self, _request: Request<EmptyRequest>) -> Result<Response<BroadcastSsiDs>, Status> {

        let ssids = crate::cache::get_bssid_list();
        
        if ssids.len() == 0 {
            return Err(Status::new(tonic::Code::NotFound, "No SSIDs found"));
        }

        let ssids = crate::cache::get_bssids();

        let result = lime::BroadcastSsiDs {
            ssids: ssids,
        };

        Ok(Response::new(result))
    }

    async fn get_probes(&self, _request: Request<EmptyRequest>) -> Result<Response<ProbeSsiDs>, Status> {

        let probes = crate::cache::get_probes();

        let result = lime::ProbeSsiDs {
            ssids: probes,
        };

        Ok(Response::new(result))
    }

    async fn get_handshakes(&self, _request: Request<EmptyRequest>) -> Result<Response<Handshakes>, Status> {
        println!("Got a request for handshakes");

        let result = lime::Handshakes {
            handshakes: vec![lime::Handshake {
                ssid: "test".to_string(),
                eapol: "test_eapol".to_string(),
            }]
        };

        Ok(Response::new(result))
    }
}

pub async fn run_grpc_server() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse()?;
    let lime_service = LimeService::default();

    Server::builder()
        .add_service(LimeServer::new(lime_service))
        .serve(addr)
        .await?;

    Ok(())
}