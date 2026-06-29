use curl_http_client::{
    collector::Collector, dep::async_curl::CurlActor, error::Error, http_client::HttpClient,
};

#[derive(Clone)]
pub struct Curl {
    pub actor_handle: CurlActor<Collector>,
}

impl Curl {
    pub fn new() -> Self {
        Self {
            actor_handle: CurlActor::new(),
        }
    }

    pub async fn send(
        &self,
        request: oauth2::HttpRequest,
    ) -> Result<oauth2::HttpResponse, Error<Collector>> {
        log::debug!("Request Url: {}", request.uri());
        log::debug!("Request Header: {:?}", request.headers());
        log::debug!("Request Method: {}", request.method());
        log::debug!(
            "Request Body: {}",
            std::str::from_utf8(request.body()).unwrap_or_default()
        );

        let response = HttpClient::new(Collector::RamAndHeaders(Vec::new(), Vec::new()))
            .request(request)?
            .nonblocking(self.actor_handle.clone())
            .perform()
            .await?
            .map(|resp| resp.unwrap_or_default());

        log::debug!("Response Header: {:?}", response.headers());
        log::debug!(
            "Response Body: {}",
            std::str::from_utf8(response.body().as_slice()).unwrap_or_default()
        );
        log::debug!("Response Status: {}", response.status());
        Ok(response)
    }
}

impl Default for Curl {
    fn default() -> Self {
        Self::new()
    }
}
