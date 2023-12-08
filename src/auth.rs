use bfsp::auth::{CreateUserRequest, LoginRequest};
use reqwest::StatusCode;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthErr {
    #[error("HTTP error: {0}")]
    HTTPError(#[from] reqwest::Error),
    #[error("Invalid email or password")]
    InvalidLogin,
    #[error("Unknown error: status code {0}")]
    UnknownError(StatusCode),
}

/// Returns a macaroon if the login was successful.
pub async fn login(email: String, password: String) -> Result<String, AuthErr> {
    let auth = LoginRequest { email, password };
    let resp = reqwest::Client::new()
        .post("http://127.0.0.1:3000/login_user")
        .json(&auth)
        .send()
        .await?;

    if resp.status() == StatusCode::OK {
        Ok(resp.text().await?)
    } else if resp.status() == StatusCode::UNAUTHORIZED {
        Err(AuthErr::InvalidLogin)
    } else {
        Err(AuthErr::UnknownError(resp.status()))
    }
}

pub async fn signup(email: String, password: String) -> Result<(), AuthErr> {
    let auth = CreateUserRequest { email, password };
    let resp = reqwest::Client::new()
        .post("http://127.0.0.1:3000/create_user")
        .json(&auth)
        .send()
        .await?;

    if resp.status() == StatusCode::OK {
        Ok(())
    } else if resp.status() == StatusCode::UNAUTHORIZED {
        Err(AuthErr::InvalidLogin)
    } else {
        Err(AuthErr::UnknownError(resp.status()))
    }
}
