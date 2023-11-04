mod auth_code_grant;
mod curl;
mod device_code_flow;
mod error;
mod get_profile;
mod token_keeper;

// Standard libraries
use std::env;
use std::io::Write;
use std::str::FromStr;

// 3rd party crates
use chrono::Local;
use log::LevelFilter;
use mail_send::{mail_builder::MessageBuilder, Credentials, SmtpClientBuilder};
use oauth2::ClientSecret;
use strum_macros::EnumString;

// My crates
use crate::auth_code_grant::auth_code_grant;
use crate::curl::Curl;
use crate::device_code_flow::device_code_flow;
use crate::get_profile::SenderProfile;
use error::OAuth2Result;
use token_keeper::TokenKeeper;

enum ParamIndex {
    TokenGrantType = 1,
    ClientId,
    ClientSecret,
    RecipientEmail,
    RecipientName,
    DebugLevel,
}

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
    //env_logger::Builder::from_env(Env::default().default_filter_or(level)).init();
    let mut log_builder = env_logger::Builder::new();
    log_builder.format(|buf, record| {
        let mut module = "";
        if let Some(path) = record.module_path() {
            if let Some(split) = path.split("::").last() {
                module = split;
            }
        }

        writeln!(
            buf,
            "{}[{}]:{}: {}",
            Local::now().format("[%d-%m-%Y %H:%M:%S]"),
            record.level(),
            module,
            record.args()
        )
    });

    log_builder.filter_level(LevelFilter::from_str(level).unwrap_or(LevelFilter::Info));
    if let Err(e) = log_builder.try_init() {
        log::error!("{:?}", e);
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> OAuth2Result<()> {
    let args: Vec<String> = env::args().collect();
    let client_secret = match args[ParamIndex::ClientSecret as usize].as_str() {
        "None" => None,
        _ => Some(ClientSecret::new(
            args[ParamIndex::ClientSecret as usize].to_string(),
        )),
    };
    let client_id = &args[ParamIndex::ClientId as usize];
    let receiver_email = &args[ParamIndex::RecipientEmail as usize];
    let receiver_name = &args[ParamIndex::RecipientName as usize];
    if args.len() <= (ParamIndex::DebugLevel as usize) {
        init_logger("info");
    } else {
        init_logger(args[ParamIndex::DebugLevel as usize].as_str());
    }

    let curl = Curl::new();
    let access_token =
        match OAuth2TokenGrantFlow::from(args[ParamIndex::TokenGrantType as usize].to_string()) {
            OAuth2TokenGrantFlow::AuthorizationCodeGrant => {
                auth_code_grant(client_id, client_secret, curl.clone()).await?
            }
            OAuth2TokenGrantFlow::DeviceCodeFlow => {
                device_code_flow(client_id, client_secret, curl.clone()).await?
            }
        };

    let sender_profile = SenderProfile::get_sender_profile(&access_token, curl).await?;
    // Start of sending Email
    let message = MessageBuilder::new()
        .from((
            sender_profile.display_name.as_ref(),
            sender_profile.email_address.as_ref(),
        ))
        .to(vec![(receiver_name.as_ref(), receiver_email.as_ref())])
        .subject("Microsoft - Test XOAUTH2 SMTP!")
        .html_body("<h1>Hello, world!</h1>")
        .text_body("Hello world!");

    let credentials = Credentials::new_xoauth2(
        sender_profile.email_address.as_ref(),
        access_token.secret().as_str(),
    );
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
                Ok(_result) => {
                    log::info!("Sending Email success!!");
                }
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
