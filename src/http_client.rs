// Standard libraries
use std::fmt;
use std::io::Read;

// 3rd party crates
use curl::easy::Easy;
use http::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
use http::method::Method;
use http::status::StatusCode;
use oauth2::url::Url;
use oauth2::{HttpRequest, HttpResponse};

///
/// Error type returned by failed curl HTTP requests.
///
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Error returned by curl crate.
    #[error("curl request failed")]
    Curl(#[source] curl::Error),
    /// Non-curl HTTP error.
    #[error("HTTP error")]
    Http(#[source] http::Error),
    /// Other error.
    #[error("Other error: {}", _0)]
    Other(String),
}

#[derive(Clone)]
struct DebugHttpRequest {
    url: Url,
    body: Vec<u8>,
    header: HeaderMap<HeaderValue>,
    method: Method,
}

impl From<&HttpRequest> for DebugHttpRequest {
    fn from(value: &HttpRequest) -> Self {
        Self {
            url: value.url.to_owned(),
            body: value.body.to_owned(),
            header: value.headers.to_owned(),
            method: value.method.to_owned(),
        }
    }
}

impl fmt::Display for DebugHttpRequest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Request:\n\tUrl:{}\n\tMethod:{}\n\tHeader:{:?}\n\tBody:{}",
            self.url,
            self.method,
            self.header,
            String::from_utf8(self.body.to_owned()).unwrap_or(String::new())
        )
    }
}
///
/// Synchronous HTTP client.
///
pub async fn async_http_client(request: HttpRequest) -> Result<HttpResponse, Error> {
    log::debug!("{}", DebugHttpRequest::from(&request));
    let mut easy = Easy::new();
    easy.url(&request.url.to_string()[..])
        .map_err(Error::Curl)?;

    let mut headers = curl::easy::List::new();
    request.headers.iter().try_for_each(|(name, value)| {
        headers
            .append(&format!(
                "{}: {}",
                name,
                value.to_str().map_err(|_| Error::Other(format!(
                    "invalid {} header value {:?}",
                    name,
                    value.as_bytes()
                )))?
            ))
            .map_err(Error::Curl)
    })?;

    easy.http_headers(headers).map_err(Error::Curl)?;

    if let Method::POST = request.method {
        easy.post(true).map_err(Error::Curl)?;
        easy.post_field_size(request.body.len() as u64)
            .map_err(Error::Curl)?;
    } else {
        assert_eq!(request.method, Method::GET);
    }

    let mut form_slice = &request.body[..];
    let mut data = Vec::new();
    {
        let mut transfer = easy.transfer();

        transfer
            .read_function(|buf| Ok(form_slice.read(buf).unwrap_or(0)))
            .map_err(Error::Curl)?;

        transfer
            .write_function(|new_data| {
                data.extend_from_slice(new_data);
                Ok(new_data.len())
            })
            .map_err(Error::Curl)?;

        transfer.perform().map_err(Error::Curl)?;
    }

    let status_code = easy.response_code().map_err(Error::Curl)? as u16;
    let response_header = easy
        .content_type()
        .map_err(Error::Curl)?
        .map(|content_type| {
            Ok(vec![(
                CONTENT_TYPE,
                HeaderValue::from_str(content_type).map_err(|err| Error::Http(err.into()))?,
            )]
            .into_iter()
            .collect::<HeaderMap>())
        })
        .transpose()?
        .unwrap_or_else(HeaderMap::new);

    log::debug!(
        "Response:\n\tHeader:{:?}\n\tBody:{}\n\tStatus Code:{}\n\n",
        &response_header,
        String::from_utf8(data.to_owned()).unwrap_or(String::new()),
        &status_code
    );
    Ok(HttpResponse {
        status_code: StatusCode::from_u16(status_code).map_err(|err| Error::Http(err.into()))?,
        headers: response_header,
        body: data,
    })
}
