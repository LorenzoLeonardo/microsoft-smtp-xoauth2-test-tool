use std::future::Future;

use crate::OAuth2Result;
use async_trait::async_trait;
use oauth2::{
    basic::BasicClient, devicecode::StandardDeviceAuthorizationResponse, AccessToken, AuthUrl,
    ClientId, ClientSecret, DeviceAuthorizationUrl, HttpRequest, HttpResponse, Scope,
    TokenResponse, TokenUrl,
};

#[async_trait]
pub trait Login {
    async fn request_login<
        F: Future<Output = Result<HttpResponse, RE>> + Send,
        RE: std::error::Error + 'static + Send,
        T: Fn(HttpRequest) -> F + Send + Sync,
    >(
        &self,
        async_http_callback: T,
    ) -> OAuth2Result<StandardDeviceAuthorizationResponse>;
    async fn poll_access_token<
        F: Future<Output = Result<HttpResponse, RE>> + Send,
        RE: std::error::Error + 'static + Send,
        T: Fn(HttpRequest) -> F + Send + Sync,
    >(
        &self,
        device_auth_response: StandardDeviceAuthorizationResponse,
        async_http_callback: T,
    ) -> OAuth2Result<AccessToken>;
}

pub struct LoginWorkFlow {
    client_id: ClientId,
    client_secret: Option<ClientSecret>,
    device_auth_endpoint: DeviceAuthorizationUrl,
    token_endpoint: TokenUrl,
}

#[async_trait]
impl Login for LoginWorkFlow {
    async fn request_login<
        F: Future<Output = Result<HttpResponse, RE>> + Send,
        RE: std::error::Error + 'static + Send,
        T: Fn(HttpRequest) -> F + Send + Sync,
    >(
        &self,
        async_http_callback: T,
    ) -> OAuth2Result<StandardDeviceAuthorizationResponse> {
        let client = self
            .create_client()?
            .set_device_authorization_url(self.device_auth_endpoint.to_owned());

        let device_auth_response = client
            .exchange_device_code()?
            .add_scope(Scope::new("offline_access".to_string()))
            .add_scope(Scope::new("Mail.Send".to_string()))
            .request_async(async_http_callback)
            .await?;

        eprintln!(
            "Open this URL in your browser:\n{}\nand enter the code: {}",
            &device_auth_response.verification_uri().as_str(),
            &device_auth_response.user_code().secret()
        );
        Ok(device_auth_response)
    }
    async fn poll_access_token<
        F: Future<Output = Result<HttpResponse, RE>> + Send,
        RE: std::error::Error + 'static + Send,
        T: Fn(HttpRequest) -> F + Send + Sync,
    >(
        &self,
        device_auth_response: StandardDeviceAuthorizationResponse,
        async_http_callback: T,
    ) -> OAuth2Result<AccessToken> {
        let client = self.create_client()?;
        let token_result = client
            .exchange_device_access_token(&device_auth_response)
            .request_async(async_http_callback, tokio::time::sleep, None)
            .await?;

        Ok(token_result.access_token().to_owned())
    }
}

impl LoginWorkFlow {
    pub fn new(
        client_id: ClientId,
        client_secret: Option<ClientSecret>,
        device_auth_endpoint: DeviceAuthorizationUrl,
        token_endpoint: TokenUrl,
    ) -> Self {
        Self {
            client_id,
            client_secret,
            device_auth_endpoint,
            token_endpoint,
        }
    }

    fn create_client(&self) -> OAuth2Result<BasicClient> {
        Ok(BasicClient::new(
            self.client_id.to_owned(),
            self.client_secret.to_owned(),
            AuthUrl::new(self.token_endpoint.to_owned().to_string())?,
            Some(self.token_endpoint.to_owned()),
        )
        .set_auth_type(oauth2::AuthType::RequestBody))
    }
}
