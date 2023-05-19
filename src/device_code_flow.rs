// Standard libraries
use std::{
    future::Future,
    path::{Path, PathBuf},
};

// 3rd party crates
use async_trait::async_trait;
use directories::UserDirs;
use oauth2::{
    basic::{BasicClient, BasicTokenType},
    devicecode::StandardDeviceAuthorizationResponse,
    AccessToken, AuthUrl, ClientId, ClientSecret, DeviceAuthorizationUrl, EmptyExtraTokenFields,
    HttpRequest, HttpResponse, Scope, StandardTokenResponse, TokenUrl,
};

// My crates
use crate::TokenKeeper;
use crate::{
    error::{ErrorCodes, OAuth2Error, OAuth2Result},
    http_client::async_http_client,
};

#[async_trait]
pub trait DeviceCodeFlowTrait {
    async fn request_device_code<
        F: Future<Output = Result<HttpResponse, RE>> + Send,
        RE: std::error::Error + 'static + Send,
        T: Fn(HttpRequest) -> F + Send + Sync,
    >(
        &self,
        scopes: Vec<Scope>,
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
    ) -> OAuth2Result<StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>>;
    async fn get_access_token<
        F: Future<Output = Result<HttpResponse, RE>> + Send,
        RE: std::error::Error + 'static + Send,
        T: Fn(HttpRequest) -> F + Send + Sync,
    >(
        &self,
        file_directory: &Path,
        file_name: &Path,
        async_http_callback: T,
    ) -> OAuth2Result<TokenKeeper>;
}

pub struct DeviceCodeFlow {
    client_id: ClientId,
    client_secret: Option<ClientSecret>,
    device_auth_endpoint: DeviceAuthorizationUrl,
    token_endpoint: TokenUrl,
}

#[async_trait]
impl DeviceCodeFlowTrait for DeviceCodeFlow {
    async fn request_device_code<
        F: Future<Output = Result<HttpResponse, RE>> + Send,
        RE: std::error::Error + 'static + Send,
        T: Fn(HttpRequest) -> F + Send + Sync,
    >(
        &self,
        scopes: Vec<Scope>,
        async_http_callback: T,
    ) -> OAuth2Result<StandardDeviceAuthorizationResponse> {
        log::info!("There is no Access token, please login.");
        let client = self
            .create_client()?
            .set_device_authorization_url(self.device_auth_endpoint.to_owned());

        let device_auth_response = client
            .exchange_device_code()?
            .add_scopes(scopes)
            .request_async(async_http_callback)
            .await?;

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
    ) -> OAuth2Result<StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>> {
        let client = self.create_client()?;
        let token_result = client
            .exchange_device_access_token(&device_auth_response)
            .request_async(async_http_callback, tokio::time::sleep, None)
            .await?;
        log::info!("Access token successfuly retrieved from the endpoint.");
        Ok(token_result)
    }

    async fn get_access_token<
        F: Future<Output = Result<HttpResponse, RE>> + Send,
        RE: std::error::Error + 'static + Send,
        T: Fn(HttpRequest) -> F + Send + Sync,
    >(
        &self,
        file_directory: &Path,
        file_name: &Path,
        async_http_callback: T,
    ) -> OAuth2Result<TokenKeeper> {
        let mut token_keeper = TokenKeeper::new(file_directory.to_path_buf());
        token_keeper.read(file_name)?;

        if token_keeper.has_access_token_expired() {
            match token_keeper.refresh_token {
                Some(ref_token) => {
                    log::info!(
                        "Access token has expired, contacting endpoint to get a new access token."
                    );
                    let response = self
                        .create_client()?
                        .exchange_refresh_token(&ref_token)
                        .request_async(async_http_callback)
                        .await;

                    match response {
                        Ok(res) => {
                            token_keeper = TokenKeeper::from(res);
                            token_keeper.set_directory(file_directory.to_path_buf());
                            token_keeper.save(file_name)?;
                            Ok(token_keeper)
                        }
                        Err(e) => {
                            let error = OAuth2Error::from(e);
                            if error.error_code == ErrorCodes::InvalidGrant {
                                let file = TokenKeeper::new(file_directory.to_path_buf());
                                file.delete(file_name).unwrap()
                            }
                            Err(error)
                        }
                    }
                }
                None => {
                    log::info!("Access token has expired but there is no refresh token, please login again.");
                    token_keeper.delete(file_name)?;
                    Err(OAuth2Error::new(
                        ErrorCodes::NoToken,
                        "There is no refresh token.".into(),
                    ))
                }
            }
        } else {
            Ok(token_keeper)
        }
    }
}

impl DeviceCodeFlow {
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

pub async fn device_code_flow(
    client_id: &str,
    client_secret: Option<ClientSecret>,
) -> OAuth2Result<AccessToken> {
    let oauth2_cloud = DeviceCodeFlow::new(
        ClientId::new(client_id.to_string()),
        client_secret,
        DeviceAuthorizationUrl::new(
            "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode".to_string(),
        )?,
        TokenUrl::new("https://login.microsoftonline.com/common/oauth2/v2.0/token".to_string())?,
    );
    let scopes = vec![
        Scope::new("offline_access".to_string()),
        Scope::new("https://outlook.office.com/SMTP.Send".to_string()),
        Scope::new("https://outlook.office.com/User.Read".to_string()),
    ];
    let directory = UserDirs::new().unwrap();
    let mut directory = directory.home_dir().to_owned();

    directory = directory.join("token");

    let token_file = PathBuf::from(format!("{}_device_code_flow.json", client_id));
    let mut token_keeper = TokenKeeper::new(directory.to_path_buf());

    // If there is no exsting token, get it from the cloud
    if let Err(_err) = token_keeper.read(&token_file) {
        let device_auth_response = oauth2_cloud
            .request_device_code(scopes, async_http_client)
            .await?;

        log::info!(
            "Open this link: {}",
            &device_auth_response.verification_uri().as_str(),
        );
        log::info!(
            "Input this code: {}",
            &device_auth_response.user_code().secret()
        );
        let token = oauth2_cloud
            .poll_access_token(device_auth_response, async_http_client)
            .await?;
        token_keeper = TokenKeeper::from(token);
        token_keeper.set_directory(directory.to_path_buf());

        token_keeper.save(&token_file)?;
    } else {
        token_keeper = oauth2_cloud
            .get_access_token(&directory, &token_file, async_http_client)
            .await?;
    }
    Ok(token_keeper.access_token)
}
