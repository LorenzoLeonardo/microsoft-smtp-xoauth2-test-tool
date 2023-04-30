mod auth_code_grant;
mod device_code_flow;
mod error;
mod http_client;
mod token_keeper;

// Standard libraries
use std::{
    env,
    io::{BufRead, BufReader, Write},
    net::TcpListener,
    path::PathBuf,
    str::FromStr,
};

use auth_code_grant::{AuthCodeGrant, AuthCodeGrantTrait};
// 3rd party crates
use directories::UserDirs;
use env_logger::Env;
use mail_send::{mail_builder::MessageBuilder, Credentials, SmtpClientBuilder};
use oauth2::{
    url::Url, AccessToken, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    DeviceAuthorizationUrl, Scope, TokenUrl,
};
use strum_macros::EnumString;

// My crates
use device_code_flow::{DeviceCodeFlow, DeviceCodeFlowTrait};
use error::OAuth2Result;
use http_client::async_http_client;
use token_keeper::TokenKeeper;

#[derive(EnumString)]
enum OAuth2TokenGrantFlow {
    AuthorizationCodeGrant,
    DeviceCodeFlow,
}

impl From<String> for OAuth2TokenGrantFlow {
    fn from(str: String) -> Self {
        OAuth2TokenGrantFlow::from_str(str.as_str()).unwrap()
    }
}

fn init_logger(level: &str) {
    env_logger::Builder::from_env(Env::default().default_filter_or(level)).init();
}

async fn device_code_flow(
    client_id: &str,
    client_secret: Option<ClientSecret>,
    sender_email: &str,
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
        Scope::new("SMTP.Send".to_string()),
    ];
    let directory = UserDirs::new().unwrap();
    let mut directory = directory.home_dir().to_owned();

    directory = directory.join("token");

    let token_file = PathBuf::from(format!("{}_device_code_flow.json", sender_email));
    let mut token_keeper = TokenKeeper::new(directory.to_path_buf());

    // If there is no exsting token, get it from the cloud
    if let Err(_err) = token_keeper.read(&token_file) {
        let device_auth_response = oauth2_cloud
            .request_device_code(scopes, async_http_client)
            .await?;

        log::info!(
            "Open this URL in your browser:\n{}\nand enter the code: {}\n\n",
            &device_auth_response.verification_uri().as_str(),
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

async fn auth_code_grant(
    client_id: &str,
    client_secret: Option<ClientSecret>,
    sender_email: &str,
) -> OAuth2Result<AccessToken> {
    let auth_code_grant = AuthCodeGrant::new(
        ClientId::new(client_id.to_string()),
        client_secret,
        AuthUrl::new("https://login.microsoftonline.com/common/oauth2/v2.0/authorize".to_string())?,
        TokenUrl::new("https://login.microsoftonline.com/common/oauth2/v2.0/token".to_string())?,
    );
    let scopes = vec![
        Scope::new("offline_access".to_string()),
        Scope::new("SMTP.Send".to_string()),
    ];
    let directory = UserDirs::new().unwrap();
    let mut directory = directory.home_dir().to_owned();

    directory = directory.join("token");

    let token_file = PathBuf::from(format!("{}_auth_code_grant.json", sender_email));
    let mut token_keeper = TokenKeeper::new(directory.to_path_buf());

    // If there is no exsting token, get it from the cloud
    if let Err(_err) = token_keeper.read(&token_file) {
        let (authorize_url, _csrf_state) =
            auth_code_grant.generate_authorization_url(scopes).await?;
        log::info!(
            "Open this URL in your browser:\n{}\n",
            authorize_url.to_string()
        );

        let listener = TcpListener::bind("127.0.0.1:8080").unwrap();
        if let Some(mut stream) = listener.incoming().flatten().next() {
            let code;
            let _state;
            {
                let mut reader = BufReader::new(&stream);

                let mut request_line = String::new();
                reader.read_line(&mut request_line).unwrap();

                let redirect_url = request_line.split_whitespace().nth(1).unwrap();
                let url = Url::parse(&("http://localhost".to_string() + redirect_url)).unwrap();

                let code_pair = url
                    .query_pairs()
                    .find(|pair| {
                        let (key, _) = pair;
                        key == "code"
                    })
                    .unwrap();

                let (_, value) = code_pair;
                code = AuthorizationCode::new(value.into_owned());

                let state_pair = url
                    .query_pairs()
                    .find(|pair| {
                        let (key, _) = pair;
                        key == "state"
                    })
                    .unwrap();

                let (_, value) = state_pair;
                _state = CsrfToken::new(value.into_owned());
            }

            let message = "Go back to your terminal :)";
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{}",
                message.len(),
                message
            );
            stream.write_all(response.as_bytes()).unwrap();

            // Exchange the code with a token.
            token_keeper = auth_code_grant
                .exchange_auth_code(&directory, &token_file, code, async_http_client)
                .await?;

            // The server will terminate itself after collecting the first code.
        }
    } else {
        token_keeper = auth_code_grant
            .get_access_token(&directory, &token_file, async_http_client)
            .await?;
    }
    Ok(token_keeper.access_token)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> OAuth2Result<()> {
    let args: Vec<String> = env::args().collect();
    let client_secret = match args[2].as_str() {
        "None" => None,
        _ => Some(ClientSecret::new(args[2].to_string())),
    };
    let client_id = &args[3];
    let sender_email = &args[4];
    let sender_name = &args[5];
    let receiver_email = &args[6];
    let receiver_name = &args[7];
    init_logger(args[8].as_str());

    let access_token = match OAuth2TokenGrantFlow::from(args[1].to_string()) {
        OAuth2TokenGrantFlow::AuthorizationCodeGrant => {
            auth_code_grant(client_id, client_secret, sender_email).await?
        }
        OAuth2TokenGrantFlow::DeviceCodeFlow => {
            device_code_flow(client_id, client_secret, sender_email).await?
        }
    };

    // Start of sending Email
    let message = MessageBuilder::new()
        .from((sender_name.as_ref(), sender_email.as_ref()))
        .to(vec![(receiver_name.as_ref(), receiver_email.as_ref())])
        .subject("Microsoft - Test XOAUTH2 SMTP!")
        .html_body("<h1>Hello, world!</h1>")
        .text_body("Hello world!");

    let credentials =
        Credentials::new_xoauth2(sender_email.as_ref(), access_token.secret().as_str());
    log::info!("Authenticating SMTP XOAUTH2 Credentials....");
    let email_connect = SmtpClientBuilder::new("smtp.office365.com", 587)
        .implicit_tls(false)
        .credentials(credentials)
        .connect()
        .await;

    match email_connect {
        Ok(mut result) => {
            log::info!("Sending SMTP XOAUTH2 Email....");
            let send = result.send(message).await;
            match send {
                Ok(_result) => {}
                Err(err) => {
                    log::error!("SMTP Sending Error: {err:?}");
                }
            }
        }
        Err(err) => {
            log::error!("SMTP Connecting Error: {err:?}");
        }
    }
    Ok(())
}
