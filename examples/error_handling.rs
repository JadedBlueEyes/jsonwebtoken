use jwks_client::error::{Error, ErrorKind};
use jwks_client::keyset::KeyStore;
use jsonwebtoken::Validation;
use serde_json::Value;

#[rustfmt::skip]
#[tokio::main]
async fn main() {
    let url = "https://raw.githubusercontent.com/jfbilodeau/jwks-client/0.1.3/test/test-jwks.json";
    let token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ.eyJuYW1lIjoiQWRhIExvdmVsYWNlIiwiaXNzIjoiaHR0cHM6Ly9jaHJvbm9nZWFycy5jb20vdGVzdCIsImF1ZCI6InRlc3QiLCJhdXRoX3RpbWUiOjEwMCwidXNlcl9pZCI6InVpZDEyMyIsInN1YiI6InNidTEyMyIsImlhdCI6MjAwLCJleHAiOjUwMCwibmJmIjozMDAsImVtYWlsIjoiYWxvdmVsYWNlQGNocm9ub2dlYXJzLmNvbSJ9.eTQnwXrri_uY55fS4IygseBzzbosDM1hP153EZXzNlLH5s29kdlGt2mL_KIjYmQa8hmptt9RwKJHBtw6l4KFHvIcuif86Ix-iI2fCpqNnKyGZfgERV51NXk1THkgWj0GQB6X5cvOoFIdHa9XvgPl_rVmzXSUYDgkhd2t01FOjQeeT6OL2d9KdlQHJqAsvvKVc3wnaYYoSqv2z0IluvK93Tk1dUBU2yWXH34nX3GAVGvIoFoNRiiFfZwFlnz78G0b2fQV7B5g5F8XlNRdD1xmVZXU8X2-xh9LqRpnEakdhecciFHg0u6AyC4c00rlo_HBb69wlXajQ3R4y26Kpxn7HA";

    let key_set = KeyStore::new_from(url.into()).await.unwrap();
    let validation = Validation::default();

    match key_set.verify(token, &validation) {
        Ok(jwt) => {
            let x: jsonwebtoken::TokenData<Value> = jwt;
            println!("name={:?}", x.claims.get("name").unwrap());
        }
        Err(e) => {
            eprintln!("Something went wrong. Message {:?}", e);
        }
    }
}
