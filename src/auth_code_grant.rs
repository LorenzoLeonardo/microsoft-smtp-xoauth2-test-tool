// Standard libraries
use std::{future::Future, path::Path};

// 3rd party crates
use async_trait::async_trait;
use oauth2::AuthorizationCode;
use oauth2::{
    basic::BasicClient, url::Url, AuthUrl, ClientId, ClientSecret, CsrfToken, HttpRequest,
    HttpResponse, RedirectUrl, Scope, TokenUrl,
};

// My crates
use crate::error::{ErrorCodes, OAuth2Error, OAuth2Result};
use crate::TokenKeeper;

#[async_trait]
pub trait AuthCodeGrantTrait {
    async fn generate_authorization_url(
        &self,
        scopes: Vec<Scope>,
    ) -> OAuth2Result<(Url, CsrfToken)>;

    async fn exchange_auth_code<
        F: Future<Output = Result<HttpResponse, RE>> + Send,
        RE: std::error::Error + 'static + Send,
        T: Fn(HttpRequest) -> F + Send + Sync,
    >(
        &self,
        file_directory: &Path,
        file_name: &Path,
        auth_code: AuthorizationCode,
        async_http_callback: T,
    ) -> OAuth2Result<TokenKeeper>;

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

pub struct AuthCodeGrant {
    client_id: ClientId,
    client_secret: Option<ClientSecret>,
    auth_endpoint: AuthUrl,
    token_endpoint: TokenUrl,
}

#[async_trait]
impl AuthCodeGrantTrait for AuthCodeGrant {
    async fn generate_authorization_url(
        &self,
        scopes: Vec<Scope>,
    ) -> OAuth2Result<(Url, CsrfToken)> {
        log::info!("There is no Access token, please login.");
        let client = self.create_client()?.set_redirect_uri(
            RedirectUrl::new("http://localhost:8080".to_string()).expect("Invalid redirect URL"),
        );

        let (authorize_url, csrf_state) = client
            .authorize_url(CsrfToken::new_random)
            .add_scopes(scopes)
            .url();

        Ok((authorize_url, csrf_state))
    }

    async fn exchange_auth_code<
        F: Future<Output = Result<HttpResponse, RE>> + Send,
        RE: std::error::Error + 'static + Send,
        T: Fn(HttpRequest) -> F + Send + Sync,
    >(
        &self,
        file_directory: &Path,
        file_name: &Path,
        auth_code: AuthorizationCode,
        async_http_callback: T,
    ) -> OAuth2Result<TokenKeeper> {
        let client = self.create_client()?.set_redirect_uri(
            RedirectUrl::new("http://localhost:8080".to_string()).expect("Invalid redirect URL"),
        );
        let token_res = client
            .exchange_code(auth_code)
            .request_async(async_http_callback)
            .await?;
        let mut token_keeper = TokenKeeper::from(token_res);
        token_keeper.set_directory(file_directory.to_path_buf());
        token_keeper.save(file_name)?;
        Ok(token_keeper)
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
                        .await?;
                    token_keeper = TokenKeeper::from(response);
                    token_keeper.set_directory(file_directory.to_path_buf());
                    token_keeper.save(file_name)?;
                    Ok(token_keeper)
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

impl AuthCodeGrant {
    pub fn new(
        client_id: ClientId,
        client_secret: Option<ClientSecret>,
        auth_endpoint: AuthUrl,
        token_endpoint: TokenUrl,
    ) -> Self {
        Self {
            client_id,
            client_secret,
            auth_endpoint,
            token_endpoint,
        }
    }

    fn create_client(&self) -> OAuth2Result<BasicClient> {
        Ok(BasicClient::new(
            self.client_id.to_owned(),
            self.client_secret.to_owned(),
            self.auth_endpoint.to_owned(),
            Some(self.token_endpoint.to_owned()),
        )
        .set_auth_type(oauth2::AuthType::RequestBody))
    }
}
