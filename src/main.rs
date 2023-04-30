mod cloud;
mod curl;
mod error;
mod token_keeper;

use std::{env, path::PathBuf};

// 3rd party crates
use directories::UserDirs;

// My crates
use cloud::{Cloud, OAuth2Cloud};
use error::OAuth2Result;
use mail_send::{mail_builder::MessageBuilder, Credentials, SmtpClientBuilder};
use oauth2::{ClientId, DeviceAuthorizationUrl, TokenUrl};

use crate::{curl::async_http_client, token_keeper::TokenKeeper};

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
    let directory = UserDirs::new().unwrap();
    let mut directory = directory.home_dir().to_owned();
    directory = directory.join("token");

    let token_file = PathBuf::from(format!("{}.json", sender_email.as_str()));
    let mut token_keeper = TokenKeeper::new(directory.to_path_buf());

    if let Err(err) = token_keeper.read(&token_file) {
        eprintln!("ERROR: {:?}", err);
        let device_auth_response = oauth2_cloud.request_login(async_http_client).await?;

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

    let message = MessageBuilder::new()
        .from((sender_name.as_ref(), sender_email.as_ref()))
        .to(vec![(receiver_name.as_ref(), receiver_email.as_ref())])
        .subject("Microsoft - Test XOAUTH SMTP!")
        .html_body("<h1>Hello, world!</h1>")
        .text_body("Hello world!");

    let credentials = Credentials::new_xoauth2(
        sender_email.as_ref(),
        token_keeper.access_token.secret().as_str(),
    );

    SmtpClientBuilder::new("smtp.office365.com", 587)
        .implicit_tls(false)
        .credentials(credentials)
        .connect()
        .await
        .unwrap()
        .send(message)
        .await
        .unwrap();

    Ok(())
}
