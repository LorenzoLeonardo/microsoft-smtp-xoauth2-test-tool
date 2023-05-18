use http::{HeaderMap, HeaderValue};
use oauth2::{url::Url, AccessToken, HttpRequest};
use serde::{Deserialize, Serialize};

use crate::{
    error::{OAuth2Error, OAuth2Result},
    http_client::async_http_client,
};

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct SenderProfile {
    #[serde(rename = "@odata.context")]
    odata_context: String,
    #[serde(rename = "@odata.id")]
    odata_id: String,
    id: String,
    pub email_address: String,
    pub display_name: String,
    alias: String,
    mailbox_guid: String,
}

impl SenderProfile {
    pub async fn get_sender_profile(access_token: &AccessToken) -> OAuth2Result<Self> {
        let mut headers = HeaderMap::new();

        let header_val = format!("Bearer {}", access_token.secret().as_str());
        headers.insert(
            "Authorization",
            HeaderValue::from_str(&header_val).map_err(OAuth2Error::from)?,
        );

        let request = HttpRequest {
            url: Url::parse("https://outlook.office.com/api/v2.0/me/")?,
            method: http::method::Method::GET,
            headers,
            body: Vec::new(),
        };

        let response = async_http_client(request)
            .await
            .map_err(OAuth2Error::from)?;

        let body = String::from_utf8(response.body).unwrap_or(String::new());

        let sender_profile: SenderProfile = serde_json::from_str(&body)?;
        log::info!("Sender Name: {}", sender_profile.display_name.as_str());
        log::info!("Sender E-mail: {}", sender_profile.email_address.as_str());
        Ok(sender_profile)
    }
}
