// Standard libraries
use std::fmt;

// 3rd party crates
use async_curl::async_curl::AsyncCurl;
use async_curl::response_handler::ResponseHandler;
use curl::easy::Easy2;
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
    /// Error returned by curl crate.
    #[error("async curl request failed")]
    AsyncCurl(#[source] async_curl::async_curl_error::AsyncCurlError),
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
/// Asynchronous HTTP client.
///
pub async fn async_http_client(request: HttpRequest) -> Result<HttpResponse, Error> {
    log::debug!("{}", DebugHttpRequest::from(&request));
    let curl = AsyncCurl::new();
    let mut easy = Easy2::new(ResponseHandler::new());

    easy.url(&request.url.to_string()[..]).map_err(|e| {
        log::error!("{:?}", e);
        Error::Curl(e)
    })?;

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
            .map_err(|e| {
                log::error!("{:?}", e);
                Error::Curl(e)
            })
    })?;

    easy.http_headers(headers).map_err(|e| {
        log::error!("{:?}", e);
        Error::Curl(e)
    })?;

    if let Method::POST = request.method {
        easy.post(true).map_err(Error::Curl)?;
        easy.post_field_size(request.body.len() as u64)
            .map_err(|e| {
                log::error!("{:?}", e);
                Error::Curl(e)
            })?;
    } else {
        assert_eq!(request.method, Method::GET);
    }

    if !request.body.is_empty() {
        let form_slice = &request.body[..];
        easy.post_fields_copy(form_slice).map_err(|e| {
            log::error!("{:?}", e);
            Error::Curl(e)
        })?;
    }
    let mut easy = curl.send_request(easy).await.map_err(|e| {
        log::error!("{:?}", e);
        Error::AsyncCurl(e)
    })?;

    let data = easy.get_ref().to_owned().get_data();
    let status_code = easy.response_code().map_err(|e| {
        log::error!("{:?}", e);
        Error::Curl(e)
    })? as u16;
    let response_header = easy
        .content_type()
        .map_err(|e| {
            log::error!("{:?}", e);
            Error::Curl(e)
        })?
        .map(|content_type| {
            Ok(vec![(
                CONTENT_TYPE,
                HeaderValue::from_str(content_type).map_err(|err| {
                    log::error!("{:?}", err);
                    Error::Http(err.into())
                })?,
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
        status_code: StatusCode::from_u16(status_code).map_err(|err| {
            log::error!("{:?}", err);
            Error::Http(err.into())
        })?,
        headers: response_header,
        body: data,
    })
}
