#![deny(warnings)]

extern crate curl;
#[macro_use]
extern crate failure;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate uuid;

extern crate byteorder;
use byteorder::{BigEndian, WriteBytesExt};

extern crate solicit;
extern crate openssl;

use std::net::TcpStream;


use solicit::client::SimpleClient;
use solicit::http::{HttpScheme, Header};
use openssl::ssl::SslMethod::Tlsv1_2;
use openssl::x509::X509;
use openssl::ssl::SSL_OP_NO_COMPRESSION;
use openssl::crypto::pkey::PKey;
use openssl::ssl::{Ssl, SslStream, SslContext};

use solicit::http::ALPN_PROTOCOLS;
use std::str;
use std::io::BufReader;
use std::fs::File;



mod types;
pub use self::types::*;

mod error;
use self::error::*;

use uuid::Uuid;
use failure::Error;

pub struct APNS {
    gateway: String,
    ssl_context: SslContext,
}

impl APNS {
    pub fn new(cert_path: &str, key_path: &str, production: bool) -> Result<Self, Error> {
        let mut ctx = SslContext::new(Tlsv1_2)?;

        let cert_reader = &mut BufReader::new(File::open(cert_path)?);
        let x509 = X509::from_pem(cert_reader)?;
        let _ = ctx.set_certificate(&x509);

        let pkey_reader = &mut BufReader::new(File::open(key_path)?);
        let pkey = PKey::private_rsa_key_from_pem(pkey_reader)?;
        let _ = ctx.set_private_key(&pkey);

        ctx.set_options(SSL_OP_NO_COMPRESSION);
        ctx.set_alpn_protocols(ALPN_PROTOCOLS);
        ctx.set_npn_protocols(ALPN_PROTOCOLS);

        let gateway: String;
        if production {
            gateway = APN_URL_PRODUCTION.to_string();
        } else {
            gateway = APN_URL_DEV.to_string();
        }

        let apns = APNS {
            gateway: gateway,
            ssl_context: ctx,
        };
        Ok(apns)
    }

    pub fn new_client(&self) -> Result<SimpleClient<SslStream<TcpStream>>, Error> {
        let ssl = Ssl::new(&self.ssl_context)?;

        let raw_tcp = TcpStream::connect(self.gateway.as_str())?;
        let mut ssl_stream = SslStream::connect(ssl, raw_tcp)?;

        solicit::http::client::write_preface(&mut ssl_stream)?;

        Ok(SimpleClient::with_stream(ssl_stream, self.gateway.clone(), HttpScheme::Https)?)
    }

    /// Send a notification.
    /// Returns the UUID (either the configured one, or the one returned by the
    /// api).
    pub fn send(&self, notification: Notification, client: &mut SimpleClient<SslStream<TcpStream>>) -> Result<Uuid, SendError> {
        let n = notification;
        let path = format!("/3/device/{}", &n.device_token).into_bytes();

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
        headers.push(Header::new(b"apns-id".to_vec(), id.to_string().into_bytes()));
        headers.push(Header::new(b"apns-topic".to_vec(), n.topic.as_bytes()));
        n.expiration
            .map(|x| headers.push(Header::new(b"apns-expiration".to_vec(),
                                              u64bytes(x))));
        n.priority
            .map(|x| headers.push(Header::new(b"apns-priority".to_vec(),
                                              u32bytes(x.to_int()))));
        n.collapse_id
            .map(|x| headers.push(Header::new(b"apns-collapse-id".to_vec(),
                                              x.as_str().to_string().into_bytes())));

        let request = ApnsRequest { aps: n.payload, data: n.data };
        let raw_request = ::serde_json::to_vec(&request)?;

        let post = client.post(&path, &headers, raw_request)?;
                //println!("{}", str::from_utf8(&response.body).unwrap());

        let status = post.status_code()?;
        if status != 200 {
            // Request failed.
            // Read json response with the error.
            let reason = ErrorResponse::parse_payload(&post.body);
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
        let cert_pw = Some(var("APNS_CERT_PW").unwrap());
        let topic = var("APNS_TOPIC").unwrap();
        let token = var("APNS_DEVICE_TOKEN").unwrap();

        let mut apns = ApnsSync::with_certificate(cert_path, cert_pw).unwrap();
        apns.set_verbose(true);
        let n = NotificationBuilder::new(topic, token)
            .title("title")
            .build();
        apns.send(n).unwrap();
    }
}
