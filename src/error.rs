use std::io::ErrorKind;

use actix_web::ResponseError;
use reqwest::header::ToStrError;
use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum Error {
    #[error("Internal: {0}")]
    Internal(String),
    #[error("Configuration: {0}")]
    Configuration(String),
    #[error("Reqwest: {0}")]
    Reqwest(String),
    #[error("Webhook: {0}")]
    Webhook(String),
    #[error("Serde: {0}")]
    Serde(String),
}

impl ResponseError for Error {
    fn status_code(&self) -> reqwest::StatusCode {
        reqwest::StatusCode::INTERNAL_SERVER_ERROR
    }
}

impl std::convert::From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Self {
        Error::Reqwest(err.to_string())
    }
}

impl std::convert::From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::Serde(err.to_string())
    }
}

impl std::convert::From<ToStrError> for Error {
    fn from(err: ToStrError) -> Self {
        Error::Reqwest(err.to_string())
    }
}

impl std::convert::From<Error> for std::io::Error {
    fn from(err: Error) -> Self {
        std::io::Error::new(ErrorKind::Other, err.to_string())
    }
}
