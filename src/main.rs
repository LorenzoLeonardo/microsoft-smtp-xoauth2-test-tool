mod cloud;
mod error;
mod http_client;
mod token_keeper;

// Standard libraries
use std::{env, path::PathBuf};

// 3rd party crates
use directories::UserDirs;
use mail_send::{mail_builder::MessageBuilder, Credentials, SmtpClientBuilder};
use oauth2::{ClientId, DeviceAuthorizationUrl, Scope, TokenUrl};

// My crates
use cloud::{Cloud, OAuth2Cloud};
use error::OAuth2Result;
use http_client::async_http_client;
use token_keeper::TokenKeeper;

#[tokio::main(flavor = "current_thread")]
async fn main() -> OAuth2Result<()> {
    let args: Vec<String> = env::args().collect();
    let client_id = &args[1];
    let sender_email = &args[2];
    let sender_name = &args[3];
    let receiver_email = &args[4];
    let receiver_name = &args[5];
    let oauth2_cloud = OAuth2Cloud::new(
        ClientId::new(client_id.to_string()),
        None,
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

    let token_file = PathBuf::from(format!("{}.json", sender_email.as_str()));
    let mut token_keeper = TokenKeeper::new(directory.to_path_buf());

    // If there is no exsting token, get it from the cloud
    if let Err(_err) = token_keeper.read(&token_file) {
        let device_auth_response = oauth2_cloud
            .request_login(scopes, async_http_client)
            .await?;

        eprintln!(
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

    // Start of sending Email
    let message = MessageBuilder::new()
        .from((sender_name.as_ref(), sender_email.as_ref()))
        .to(vec![(receiver_name.as_ref(), receiver_email.as_ref())])
        .subject("Microsoft - Test XOAUTH2 SMTP!")
        .html_body("<h1>Hello, world!</h1>")
        .text_body("Hello world!");

    let credentials = Credentials::new_xoauth2(
        sender_email.as_ref(),
        token_keeper.access_token.secret().as_str(),
    );
    eprintln!("Authenticating SMTP XOAUTH2 Credentials....");
    let email_connect = SmtpClientBuilder::new("smtp.office365.com", 587)
        .implicit_tls(false)
        .credentials(credentials)
        .connect()
        .await;

    match email_connect {
        Ok(mut result) => {
            eprintln!("Sending SMTP XOAUTH2 Email....");
            let send = result.send(message).await;
            match send {
                Ok(_result) => {}
                Err(err) => {
                    eprintln!("SMTP Sending Error: {err:?}");
                }
            }
        }
        Err(err) => {
            eprintln!("SMTP Connecting Error: {err:?}");
        }
    }
    Ok(())
}
