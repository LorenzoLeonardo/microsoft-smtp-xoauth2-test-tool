// Standard libraries
use std::fmt::Debug;
use std::{error::Error, str::FromStr};

// 3rd party crates
use oauth2::{
    url, ConfigurationError, ErrorResponseType, RequestTokenError, StandardErrorResponse,
};
use serde::{Deserialize, Serialize};
use strum_macros::EnumString;

#[derive(Serialize, Deserialize, Debug, PartialEq, EnumString)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ErrorCodes {
    BadRequest,
    Unauthorized,
    Forbidden,
    InvalidRequest,
    UnauthorizedClient,
    AccessDenied,
    UnsupportedResponseType,
    InvalidScope,
    ServerError,
    TemporarilyUnavailable,
    InvalidClient,
    InvalidGrant,
    UnsupportedTokenType,
    UnsupportedGrantType,
    AuthorizationPending,
    AuthorizationDeclined,
    SlowDown,
    ExpiredToken,
    InteractionRequired,
    LoginRequired,
    ConfigurationError,
    UrlParseError,
    SerdeJsonParseError,
    IoError,
    NoToken,
    RequestError,
    ParseError,
    OtherError,
}

impl From<String> for ErrorCodes {
    fn from(str: String) -> Self {
        ErrorCodes::from_str(str.as_str()).unwrap_or(ErrorCodes::OtherError)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OAuth2Error {
    pub error_code: ErrorCodes,
    pub error_code_desc: String,
}

impl OAuth2Error {
    pub fn new(error_code: ErrorCodes, error_code_desc: String) -> Self {
        Self {
            error_code,
            error_code_desc,
        }
    }
}

impl From<ConfigurationError> for OAuth2Error {
    fn from(e: ConfigurationError) -> Self {
        OAuth2Error::new(ErrorCodes::ConfigurationError, e.to_string())
    }
}

impl From<url::ParseError> for OAuth2Error {
    fn from(e: url::ParseError) -> Self {
        OAuth2Error::new(ErrorCodes::UrlParseError, e.to_string())
    }
}

impl<O> From<StandardErrorResponse<O>> for ErrorCodes
where
    O: ErrorResponseType + 'static + ToString,
{
    fn from(e: StandardErrorResponse<O>) -> Self {
        ErrorCodes::from(e.error().to_string())
    }
}

impl<E, O> From<RequestTokenError<E, StandardErrorResponse<O>>> for OAuth2Error
where
    E: Error + 'static,
    O: ErrorResponseType + 'static + ToString + Clone,
{
    fn from(e: RequestTokenError<E, StandardErrorResponse<O>>) -> Self {
        match e {
            RequestTokenError::ServerResponse(err) => {
                OAuth2Error::new(ErrorCodes::from(err.clone()), format!("{:?}", err))
            }
            RequestTokenError::Request(err) => {
                OAuth2Error::new(ErrorCodes::RequestError, err.to_string())
            }
            RequestTokenError::Parse(err, _data) => {
                OAuth2Error::new(ErrorCodes::ParseError, err.to_string())
            }
            RequestTokenError::Other(err) => OAuth2Error::new(ErrorCodes::OtherError, err),
        }
    }
}

impl From<serde_json::Error> for OAuth2Error {
    fn from(e: serde_json::Error) -> Self {
        OAuth2Error::new(ErrorCodes::SerdeJsonParseError, e.to_string())
    }
}

impl From<std::io::Error> for OAuth2Error {
    fn from(e: std::io::Error) -> Self {
        OAuth2Error::new(ErrorCodes::IoError, e.to_string())
    }
}

pub type OAuth2Result<T> = Result<T, OAuth2Error>;

#[cfg(test)]
mod tests {
    use super::ErrorCodes;

    #[test]
    fn test_error_codes_to_json_snake_case() {
        assert_eq!(
            serde_json::to_string(&ErrorCodes::BadRequest)
                .unwrap_or(String::from("\"bad_request\"")),
            String::from("\"bad_request\"")
        );
        assert_eq!(
            serde_json::to_string(&ErrorCodes::Unauthorized)
                .unwrap_or(String::from("\"unauthorized\"")),
            String::from("\"unauthorized\"")
        );
        assert_eq!(
            serde_json::to_string(&ErrorCodes::Forbidden).unwrap_or(String::from("\"forbidden\"")),
            String::from("\"forbidden\"")
        );
        assert_eq!(
            serde_json::to_string(&ErrorCodes::InvalidRequest)
                .unwrap_or(String::from("\"invalid_request\"")),
            String::from("\"invalid_request\"")
        );
        assert_eq!(
            serde_json::to_string(&ErrorCodes::UnauthorizedClient)
                .unwrap_or(String::from("\"unauthorized_client\"")),
            String::from("\"unauthorized_client\"")
        );
        assert_eq!(
            serde_json::to_string(&ErrorCodes::AccessDenied)
                .unwrap_or(String::from("\"access_denied\"")),
            String::from("\"access_denied\"")
        );
        assert_eq!(
            serde_json::to_string(&ErrorCodes::UnsupportedResponseType)
                .unwrap_or(String::from("\"unsupported_response_type\"")),
            String::from("\"unsupported_response_type\"")
        );
        assert_eq!(
            serde_json::to_string(&ErrorCodes::InvalidScope)
                .unwrap_or(String::from("\"invalid_scope\"")),
            String::from("\"invalid_scope\"")
        );
        assert_eq!(
            serde_json::to_string(&ErrorCodes::ServerError)
                .unwrap_or(String::from("\"server_error\"")),
            String::from("\"server_error\"")
        );
        assert_eq!(
            serde_json::to_string(&ErrorCodes::TemporarilyUnavailable)
                .unwrap_or(String::from("\"temporarily_unavailable\"")),
            String::from("\"temporarily_unavailable\"")
        );
        assert_eq!(
            serde_json::to_string(&ErrorCodes::InvalidClient)
                .unwrap_or(String::from("\"invalid_client\"")),
            String::from("\"invalid_client\"")
        );
        assert_eq!(
            serde_json::to_string(&ErrorCodes::InvalidGrant)
                .unwrap_or(String::from("\"invalid_grant\"")),
            String::from("\"invalid_grant\"")
        );
        assert_eq!(
            serde_json::to_string(&ErrorCodes::UnsupportedTokenType)
                .unwrap_or(String::from("\"unsupported_token_type\"")),
            String::from("\"unsupported_token_type\"")
        );
        assert_eq!(
            serde_json::to_string(&ErrorCodes::UnsupportedGrantType)
                .unwrap_or(String::from("\"unsupported_grant_type\"")),
            String::from("\"unsupported_grant_type\"")
        );
        assert_eq!(
            serde_json::to_string(&ErrorCodes::AuthorizationPending)
                .unwrap_or(String::from("\"authorization_pending\"")),
            String::from("\"authorization_pending\"")
        );
        assert_eq!(
            serde_json::to_string(&ErrorCodes::SlowDown).unwrap_or(String::from("\"slow_down\"")),
            String::from("\"slow_down\"")
        );
        assert_eq!(
            serde_json::to_string(&ErrorCodes::ExpiredToken)
                .unwrap_or(String::from("\"expired_token\"")),
            String::from("\"expired_token\"")
        );
        assert_eq!(
            serde_json::to_string(&ErrorCodes::ConfigurationError)
                .unwrap_or(String::from("\"configuration_error\"")),
            String::from("\"configuration_error\"")
        );
        assert_eq!(
            serde_json::to_string(&ErrorCodes::UrlParseError)
                .unwrap_or(String::from("\"url_parse_error\"")),
            String::from("\"url_parse_error\"")
        );
        assert_eq!(
            serde_json::to_string(&ErrorCodes::OtherError)
                .unwrap_or(String::from("\"other_error\"")),
            String::from("\"other_error\"")
        );
    }
    #[test]
    fn test_json_snake_case_to_error_codes() {
        assert_eq!(
            serde_json::from_str("\"bad_request\"").unwrap_or(ErrorCodes::OtherError),
            ErrorCodes::BadRequest
        );
        assert_eq!(
            serde_json::from_str("\"unauthorized\"").unwrap_or(ErrorCodes::OtherError),
            ErrorCodes::Unauthorized
        );
        assert_eq!(
            serde_json::from_str("\"forbidden\"").unwrap_or(ErrorCodes::OtherError),
            ErrorCodes::Forbidden
        );
        assert_eq!(
            serde_json::from_str("\"invalid_request\"").unwrap_or(ErrorCodes::OtherError),
            ErrorCodes::InvalidRequest
        );
        assert_eq!(
            serde_json::from_str("\"unauthorized_client\"").unwrap_or(ErrorCodes::OtherError),
            ErrorCodes::UnauthorizedClient
        );
        assert_eq!(
            serde_json::from_str("\"access_denied\"").unwrap_or(ErrorCodes::OtherError),
            ErrorCodes::AccessDenied
        );
        assert_eq!(
            serde_json::from_str("\"unsupported_response_type\"").unwrap_or(ErrorCodes::OtherError),
            ErrorCodes::UnsupportedResponseType
        );
        assert_eq!(
            serde_json::from_str("\"invalid_scope\"").unwrap_or(ErrorCodes::OtherError),
            ErrorCodes::InvalidScope
        );
        assert_eq!(
            serde_json::from_str("\"server_error\"").unwrap_or(ErrorCodes::OtherError),
            ErrorCodes::ServerError
        );
        assert_eq!(
            serde_json::from_str("\"temporarily_unavailable\"").unwrap_or(ErrorCodes::OtherError),
            ErrorCodes::TemporarilyUnavailable
        );
        assert_eq!(
            serde_json::from_str("\"invalid_client\"").unwrap_or(ErrorCodes::OtherError),
            ErrorCodes::InvalidClient
        );
        assert_eq!(
            serde_json::from_str("\"invalid_grant\"").unwrap_or(ErrorCodes::OtherError),
            ErrorCodes::InvalidGrant
        );
        assert_eq!(
            serde_json::from_str("\"unsupported_token_type\"").unwrap_or(ErrorCodes::OtherError),
            ErrorCodes::UnsupportedTokenType
        );
        assert_eq!(
            serde_json::from_str("\"unsupported_grant_type\"").unwrap_or(ErrorCodes::OtherError),
            ErrorCodes::UnsupportedGrantType
        );
        assert_eq!(
            serde_json::from_str("\"authorization_pending\"").unwrap_or(ErrorCodes::OtherError),
            ErrorCodes::AuthorizationPending
        );
        assert_eq!(
            serde_json::from_str("\"slow_down\"").unwrap_or(ErrorCodes::OtherError),
            ErrorCodes::SlowDown
        );
        assert_eq!(
            serde_json::from_str("\"expired_token\"").unwrap_or(ErrorCodes::OtherError),
            ErrorCodes::ExpiredToken
        );
        assert_eq!(
            serde_json::from_str("\"configuration_error\"").unwrap_or(ErrorCodes::OtherError),
            ErrorCodes::ConfigurationError
        );
        assert_eq!(
            serde_json::from_str("\"url_parse_error\"").unwrap_or(ErrorCodes::OtherError),
            ErrorCodes::UrlParseError
        );
        assert_eq!(
            serde_json::from_str("\"other_error\"").unwrap_or(ErrorCodes::OtherError),
            ErrorCodes::OtherError
        );
    }
    #[test]
    fn test_string_snake_case_to_error_codes() {
        assert_eq!(
            ErrorCodes::from(String::from("bad_request")),
            ErrorCodes::BadRequest
        );
        assert_eq!(
            ErrorCodes::from(String::from("unauthorized")),
            ErrorCodes::Unauthorized
        );
        assert_eq!(
            ErrorCodes::from(String::from("forbidden")),
            ErrorCodes::Forbidden
        );
        assert_eq!(
            ErrorCodes::from(String::from("invalid_request")),
            ErrorCodes::InvalidRequest
        );
        assert_eq!(
            ErrorCodes::from(String::from("unauthorized_client")),
            ErrorCodes::UnauthorizedClient
        );
        assert_eq!(
            ErrorCodes::from(String::from("access_denied")),
            ErrorCodes::AccessDenied
        );
        assert_eq!(
            ErrorCodes::from(String::from("unsupported_response_type")),
            ErrorCodes::UnsupportedResponseType
        );
        assert_eq!(
            ErrorCodes::from(String::from("invalid_scope")),
            ErrorCodes::InvalidScope
        );
        assert_eq!(
            ErrorCodes::from(String::from("server_error")),
            ErrorCodes::ServerError
        );
        assert_eq!(
            ErrorCodes::from(String::from("temporarily_unavailable")),
            ErrorCodes::TemporarilyUnavailable
        );
        assert_eq!(
            ErrorCodes::from(String::from("invalid_client")),
            ErrorCodes::InvalidClient
        );
        assert_eq!(
            ErrorCodes::from(String::from("invalid_grant")),
            ErrorCodes::InvalidGrant
        );
        assert_eq!(
            ErrorCodes::from(String::from("unsupported_token_type")),
            ErrorCodes::UnsupportedTokenType
        );
        assert_eq!(
            ErrorCodes::from(String::from("unsupported_grant_type")),
            ErrorCodes::UnsupportedGrantType
        );
        assert_eq!(
            ErrorCodes::from(String::from("authorization_pending")),
            ErrorCodes::AuthorizationPending
        );
        assert_eq!(
            ErrorCodes::from(String::from("slow_down")),
            ErrorCodes::SlowDown
        );
        assert_eq!(
            ErrorCodes::from(String::from("expired_token")),
            ErrorCodes::ExpiredToken
        );
        assert_eq!(
            ErrorCodes::from(String::from("configuration_error")),
            ErrorCodes::ConfigurationError
        );
        assert_eq!(
            ErrorCodes::from(String::from("url_parse_error")),
            ErrorCodes::UrlParseError
        );
        assert_eq!(
            ErrorCodes::from(String::from("other_error")),
            ErrorCodes::OtherError
        );
    }
}
