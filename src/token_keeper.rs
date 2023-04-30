// Standard libraries
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

// 3rd party crates
use oauth2::basic::BasicTokenType;
use oauth2::{
    AccessToken, EmptyExtraTokenFields, RefreshToken, StandardTokenResponse, TokenResponse,
};
use serde::{Deserialize, Serialize};

// My crates
use crate::error::OAuth2Result;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenKeeper {
    pub access_token: AccessToken,
    pub refresh_token: Option<RefreshToken>,
    scopes: Option<Vec<String>>,
    expires_in: Option<Duration>,
    token_receive_time: Duration,
    #[serde(skip_serializing)]
    #[serde(skip_deserializing)]
    file_directory: PathBuf,
}

impl From<StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>> for TokenKeeper {
    fn from(
        token_response: StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>,
    ) -> TokenKeeper {
        let refresh_token = token_response
            .refresh_token()
            .map(|ref_tok| ref_tok.to_owned());

        let scopes = token_response
            .scopes()
            .map(|scope| scope.iter().map(|e| e.to_string()).collect());

        Self {
            access_token: token_response.access_token().to_owned(),
            refresh_token,
            scopes,
            expires_in: token_response.expires_in(),
            token_receive_time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards"),
            file_directory: PathBuf::new(),
        }
    }
}

impl TokenKeeper {
    pub fn new(file_directory: PathBuf) -> Self {
        Self {
            access_token: AccessToken::new(String::new()),
            refresh_token: None,
            scopes: None,
            expires_in: None,
            token_receive_time: Duration::new(0, 0),
            file_directory,
        }
    }

    pub fn set_directory(&mut self, file_directory: PathBuf) {
        self.file_directory = file_directory;
    }
    pub fn has_access_token_expired(&self) -> bool {
        let time_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");

        if let Some(expires) = self.expires_in {
            (time_now - self.token_receive_time) >= expires
        } else {
            true
        }
    }

    pub fn read(&mut self, file_name: &Path) -> OAuth2Result<()> {
        let temp_dir = self.file_directory.clone();
        let input_path = self.file_directory.join(file_name);
        let text = std::fs::read_to_string(input_path)?;

        *self = serde_json::from_str::<TokenKeeper>(&text)?;
        self.set_directory(temp_dir);
        Ok(())
    }

    pub fn save(&self, file_name: &Path) -> OAuth2Result<()> {
        let input_path = self.file_directory.join(file_name);
        let json = serde_json::to_string(self)?;

        fs::create_dir_all(self.file_directory.as_path())?;

        let mut file = File::create(input_path)?;

        file.write_all(json.as_bytes())?;

        Ok(())
    }

    pub fn delete(&self, file_name: &Path) -> OAuth2Result<()> {
        let input_path = self.file_directory.join(file_name);
        Ok(fs::remove_file(input_path)?)
    }
}
