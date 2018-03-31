#![deny(warnings)]

extern crate byteorder;
use byteorder::{BigEndian, WriteBytesExt};
#[macro_use] extern crate failure;
use failure::Error;
extern crate futures;
use futures::Future;
use futures::stream::Stream;
extern crate http;
use http::{Request, StatusCode};
extern crate hyper;
use hyper::Client;
use hyper::client::HttpConnector;
extern crate hyper_openssl;
use hyper_openssl::HttpsConnector;
extern crate openssl;
use openssl::ssl::{SslConnector, SslFiletype, SslMethod, SslOptions};
extern crate serde;
#[macro_use] extern crate serde_derive;
extern crate serde_json;
extern crate tokio_core;
use tokio_core::reactor::Core;
extern crate uuid;
use uuid::Uuid;

mod types;
pub use self::types::*;

mod error;
use self::error::*;

pub type APNsClient = Client<HttpsConnector<HttpConnector>>;

pub struct APNs {
    gateway: String,
    cert_path: String,
    key_path: String,
}

impl APNs {
    pub fn new(cert_path: String, key_path: String, production: bool) -> Result<Self, Error> {
        let gateway: String;
        if production {
            gateway = APN_URL_PRODUCTION.to_string();
        } else {
            gateway = APN_URL_DEV.to_string();
        }

        let apns = APNs {
            gateway: gateway,
            cert_path: cert_path,
            key_path: key_path,
        };
        Ok(apns)
    }

    pub fn new_client(&self) -> Result<APNsClient, Error> {
        let mut ssl = SslConnector::builder(SslMethod::tls())?;

        ssl.set_certificate_file(self.cert_path.as_str(), SslFiletype::PEM)?;
        ssl.set_private_key_file(self.key_path.as_str(), SslFiletype::PEM)?;

        ssl.set_options(SslOptions::NO_COMPRESSION);
        //ssl.set_alpn_protos(ALPN_PROTOCOLS);

        let core = Core::new()?;
        let mut http_connector = HttpConnector::new(1, &core.handle());
        http_connector.set_keepalive(None);
        let client = Client::configure()
            .connector(HttpsConnector::with_connector(http_connector,
                                                      ssl)?)
            .keep_alive(true)
            .keep_alive_timeout(None)
            .build(&core.handle());
        Ok(client)
    }

    /// Send a notification.
    /// Returns the UUID (either the configured one, or the one returned by the
    /// api).
    pub fn send(&self, notification: Notification, apns_client: &APNsClient) -> Result<Uuid, SendError> {
        let n = notification;

        // Just always generate a uuid client side for simplicity.
        let id = n.id.unwrap_or(Uuid::new_v4());

        let u32bytes = |i| {
            let mut wtr = vec![];
            wtr.write_u32::<BigEndian>(i).unwrap();
            wtr
        };
        let u64bytes = |i| {
            let mut wtr = vec![];
            wtr.write_u64::<BigEndian>(i).unwrap();
            wtr
        };

        let mut headers = Vec::new();
        headers.push(("apns-id", id.to_string().into_bytes()));
        headers.push(("apns-topic", n.topic.into_bytes()));
        n.expiration
            .map(|x| headers.push(("apns-expiration", u64bytes(x))));
        n.priority
            .map(|x| headers.push(("apns-priority", u32bytes(x.to_int()))));
        n.collapse_id
            .map(|x| headers.push(("apns-collapse-id", x.as_str().to_string().into_bytes())));

        let uri = format!("{}/3/device/{}", &self.gateway, &n.device_token);
        let mut request = Request::post(uri);
        let _ = headers
            .into_iter()
            .fold(&mut request, |r, (k, v)| {
                let bs: &[u8] = &v;
                r.header(k, bs)
            });

        let body = ApnsRequest { aps: n.payload, data: n.data };
        let raw_body = ::serde_json::to_vec(&body)?;

        let request = request.body(raw_body.into())?;
        let response = apns_client.request_compat(request).wait()?;

        let status = response.status();
        if status != StatusCode::OK {
            let body = response.into_body().concat2().wait()?;
            let reason = ErrorResponse::parse_payload(&body);
            let status = status.into();
            Err(ApiError { status, reason }.into())
        } else {
            Ok(id)
        }
    }
}

#[cfg(test)]
mod test {
    use std::env::var;
    use super::*;

    #[test]
    fn test_cert() {
        let cert_path = var("APNS_CERT_PATH").unwrap();
        let cert_pw = var("APNS_CERT_PW").unwrap();
        let topic = var("APNS_TOPIC").unwrap();
        let token = var("APNS_DEVICE_TOKEN").unwrap();

        let apns = APNs::new(cert_path, cert_pw, false).unwrap();
        let client = apns.new_client().unwrap();
        let n = NotificationBuilder::new(topic, token)
            .title("title")
            .build();
        apns.send(n, client).unwrap();
    }
}
