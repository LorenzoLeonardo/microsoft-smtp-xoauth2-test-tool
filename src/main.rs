mod curl;
mod error;
mod login;

use std::env;

// My crates
use error::OAuth2Result;
use login::login_workflow::{Login, LoginWorkFlow};
use mail_send::{mail_builder::MessageBuilder, Credentials, SmtpClientBuilder};
use oauth2::{ClientId, DeviceAuthorizationUrl, TokenUrl};

use crate::curl::async_http_client;

#[tokio::main(flavor = "current_thread")]
async fn main() -> OAuth2Result<()> {
    let args: Vec<String> = env::args().collect();
    let client_id = &args[1];
    let sender_email = &args[2];
    let sender_name = &args[3];
    let receiver_email = &args[4];
    let receiver_name = &args[5];

    let login = LoginWorkFlow::new(
        ClientId::new(client_id.to_string()),
        None,
        DeviceAuthorizationUrl::new(
            "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode".to_string(),
        )?,
        TokenUrl::new("https://login.microsoftonline.com/common/oauth2/v2.0/token".to_string())?,
    );
    let details = login.request_login(async_http_client).await?;
    let token = login.poll_access_token(details, async_http_client).await?;

    let message = MessageBuilder::new()
        .from((sender_name.as_ref(), sender_email.as_ref()))
        .to(vec![(receiver_name.as_ref(), receiver_email.as_ref())])
        .subject("Microsoft - Test XOAUTH SMTP!")
        .html_body("<h1>Hello, world!</h1>")
        .text_body("Hello world!");

    let credentials = Credentials::new_xoauth2(sender_email.as_ref(), token.secret().as_ref());

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
