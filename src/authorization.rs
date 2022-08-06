use crate::http::HttpClientError;
use crate::http::Provider;
use reqwest::{header::HeaderValue, Client};
use std::fmt;
use url::Url;
#[derive(Clone, Debug)]
pub enum Authorization {
    Basic(String),
    Bearer(String),
}

impl Authorization {
    pub fn basic(username: impl Into<String>, password: impl Into<String>) -> Self {
        let auth_secret = base64::encode(username.into() + ":" + &password.into());
        Self::Basic(auth_secret)
    }

    pub fn bearer(token: impl Into<String>) -> Self {
        Self::Bearer(token.into())
    }
}

impl fmt::Display for Authorization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Authorization::Basic(auth_secret) => write!(f, "Basic {}", auth_secret),
            Authorization::Bearer(token) => write!(f, "Bearer {}", token),
        }
    }
}

pub trait BasicAuth {
    fn new_with_auth(url: impl Into<Url>, auth: Authorization)
        -> Result<Provider, HttpClientError>;
}

impl BasicAuth for Provider {
    fn new_with_auth(
        url: impl Into<Url>,
        auth: Authorization,
    ) -> Result<Provider, HttpClientError> {
        let mut auth_value = HeaderValue::from_str(&auth.to_string())?;
        auth_value.set_sensitive(true);

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(reqwest::header::AUTHORIZATION, auth_value);

        let client = Client::builder().default_headers(headers).build()?;

        Ok(Provider::new_with_client(url, client))
    }
}
