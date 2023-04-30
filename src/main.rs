mod auth_code_grant;
mod device_code_flow;
mod error;
mod http_client;
mod token_keeper;

// Standard libraries
use std::env;
use std::str::FromStr;

// 3rd party crates
use env_logger::Env;
use mail_send::{mail_builder::MessageBuilder, Credentials, SmtpClientBuilder};
use oauth2::ClientSecret;
use strum_macros::EnumString;

// My crates
use crate::auth_code_grant::auth_code_grant;
use crate::device_code_flow::device_code_flow;
use error::OAuth2Result;
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
