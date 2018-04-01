//#![deny(warnings)]

extern crate pretty_env_logger;
extern crate byteorder;
use byteorder::{BigEndian, WriteBytesExt};
#[macro_use] extern crate failure;
use failure::Error;
extern crate futures;
use futures::Future;
use futures::future;
use futures::future::Either;
use futures::stream::Stream;
extern crate http;
extern crate hyper;
use hyper::{Request, StatusCode, Method, Uri};
use hyper::Client;
use hyper::client::HttpConnector;
extern crate hyper_tls;
use hyper_tls::HttpsConnector;
extern crate native_tls;
use native_tls::{Pkcs12, TlsConnector};
extern crate serde;
#[macro_use] extern crate serde_derive;
extern crate serde_json;
extern crate tokio_core;
use tokio_core::reactor::Core;
extern crate uuid;
use uuid::Uuid;

use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::str::FromStr;

mod types;
pub use self::types::*;

mod error;
use self::error::*;

pub struct APNsClient {
    core: Core,
    client: Client<HttpsConnector<HttpConnector>>,
}

pub struct APNs {
    gateway: String,
    p12_path: String,
    password: String,
}

impl APNs {
    pub fn new(p12_path: String, password: String, production: bool) -> Result<Self, Error> {
        let gateway: String;
        if production {
            gateway = APN_URL_PRODUCTION.to_string();
        } else {
            gateway = APN_URL_DEV.to_string();
        }

        let apns = APNs {
            gateway: gateway,
            p12_path: p12_path,
            password: password,
        };
        Ok(apns)
    }

    pub fn new_client(&self) -> Result<APNsClient, Error> {
        let core = Core::new()?;
        let mut http_connector = HttpConnector::new(1, &core.handle());
        http_connector.enforce_http(false);
        //http_connector.set_keepalive(None);

        let mut file = File::open(self.p12_path.clone()).unwrap();
        let mut pkcs12 = vec![];
        file.read_to_end(&mut pkcs12).unwrap();
        let pkcs12 = Pkcs12::from_der(&pkcs12, &self.password).unwrap();
        let mut tls = TlsConnector::builder()?;
        tls.identity(pkcs12)?;
        let tls = tls.build()?;
        let client = Client::configure()
            .connector(HttpsConnector::from((http_connector, tls)))
            //.keep_alive(true)
            //.keep_alive_timeout(None)
            .build(&core.handle());
        Ok(APNsClient { core, client })
    }

    /// Send a notification.
    /// Returns the UUID (either the configured one, or the one returned by the
    /// api).
    pub fn send(&self, notification: Notification, apns_client: &mut APNsClient) -> Result<(), SendError> {
        pretty_env_logger::init();

        let n = notification;
        let id = n.id.unwrap_or(Uuid::new_v4());
        //let uri = format!("{}/3/device/{}", &self.gateway, &n.device_token);
        let uri = "https://google.com";

        let mut core = &mut apns_client.core;
        let handle = core.handle();
        let client = hyper::Client::configure()
            .connector(hyper_tls::HttpsConnector::new(4, &handle).unwrap())
            .build(&handle);

        let request = Request::new(Method::Post, Uri::from_str(&uri).unwrap());

        let work = client.request(request).and_then(|res| {
            println!("Status: {}", res.status());
            println!("Headers:\n{}", res.headers());
            res.body().for_each(|chunk| {
                ::std::io::stdout().write_all(&chunk)
                    .map(|_| ())
                    .map_err(From::from)
            })
        });
        core.run(work).map_err(|e| e.into())


        //let _u32bytes = |i| {
            //let mut wtr = vec![];
            //wtr.write_u32::<BigEndian>(i).unwrap();
            //wtr
        //};
        //let _u64bytes = |i| {
            //let mut wtr = vec![];
            //wtr.write_u64::<BigEndian>(i).unwrap();
            //wtr
        //};

        //let mut headers = Vec::new();
        //headers.push(("apns-id", id.to_string().into_bytes()));
        //headers.push(("apns-topic", n.topic.into_bytes()));
        //n.expiration
            //.map(|x| headers.push(("apns-expiration", u64bytes(x))));
        //n.priority
            //.map(|x| headers.push(("apns-priority", u32bytes(x.to_int()))));
        //n.collapse_id
            //.map(|x| headers.push(("apns-collapse-id", x.as_str().to_string().into_bytes())));

        //let mut request = Request::post(uri);
        //let request = Request::new(Method::Post, Uri::from_str(&uri)?);
        //let _ = headers
            //.into_iter()
            //.fold(&mut request, |r, (k, v)| {
                //let bs: &[u8] = &v;
                //r.header(k, bs)
            //});

        //let body = ApnsRequest { aps: n.payload, data: n.data };
        //let raw_body = ::serde_json::to_vec(&body)?;

        //let request = request.body(raw_body.into())?;
        //let request = request.body("".into())?;
        //request.set_body("");
        //let future = apns_client.client.request(request).and_then(|response| {
            //println!("Response");
            //let status = response.status();
            //if status != StatusCode::Ok {
                //Either::A(response.body().concat2().and_then(move |body| {
                    //let reason = ErrorResponse::parse_payload(&body);
                    //let status = status.into();
                    //let send_error = SendError::from(ApiError { status, reason });
                    //future::ok(Err(send_error))
                //}))
            //} else {
                //Either::B(future::ok(Ok(id)))
            //}
        //});
        //apns_client.core.run(future)?
    }
}

#[cfg(test)]
mod test {
    use std::env::var;
    use super::*;

    #[test]
    fn test_cert() {
        let p12_path = var("APNS_P12_PATH").unwrap();
        let password = var("APNS_PASSWORD").unwrap();
        let topic = var("APNS_TOPIC").unwrap();
        let token = var("APNS_DEVICE_TOKEN").unwrap();

        let apns = APNs::new(p12_path, password, false).unwrap();
        let mut client = apns.new_client().unwrap();
        let n = NotificationBuilder::new(topic, token)
            .title("title")
            .body("body")
            .build();
        apns.send(n, &mut client).unwrap();
    }
}
