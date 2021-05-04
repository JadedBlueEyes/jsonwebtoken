use jsonwebtoken::{TokenData, Validation};
use jwks_client::keyset::KeyStore;
use serde_json::Value;

fn main() {
    let key_store = KeyStore::new();
    let validation = Validation::default();

    let token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ.eyJuYW1lIjoiQWRhIExvdmVsYWNlIiwiaXNzIjoiaHR0cHM6Ly9jaHJvbm9nZWFycy5jb20vdGVzdCIsImF1ZCI6InRlc3QiLCJhdXRoX3RpbWUiOjEwMCwidXNlcl9pZCI6InVpZDEyMyIsInN1YiI6InNidTEyMyIsImlhdCI6MjAwLCJleHAiOjUwMCwibmJmIjozMDAsImVtYWlsIjoiYWxvdmVsYWNlQGNocm9ub2dlYXJzLmNvbSJ9.eTQnwXrri_uY55fS4IygseBzzbosDM1hP153EZXzNlLH5s29kdlGt2mL_KIjYmQa8hmptt9RwKJHBtw6l4KFHvIcuif86Ix-iI2fCpqNnKyGZfgERV51NXk1THkgWj0GQB6X5cvOoFIdHa9XvgPl_rVmzXSUYDgkhd2t01FOjQeeT6OL2d9KdlQHJqAsvvKVc3wnaYYoSqv2z0IluvK93Tk1dUBU2yWXH34nX3GAVGvIoFoNRiiFfZwFlnz78G0b2fQV7B5g5F8XlNRdD1xmVZXU8X2-xh9LqRpnEakdhecciFHg0u6AyC4c00rlo_HBb69wlXajQ3R4y26Kpxn7HA";

    let jwt: TokenData<Value> = key_store.verify(token, &validation).unwrap();

    let result = jwt.claims.get("name").unwrap().as_str();

    match result {
        Some(name) => {
            println!("Welcome, {}!", name);
        }
        None => {
            println!("Welcome, anonymous");
        }
    }
}
