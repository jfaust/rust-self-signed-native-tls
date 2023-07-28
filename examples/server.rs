use futures::StreamExt;
use hyper::server::accept;
use hyper::server::conn::AddrIncoming;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server};
use rcgen::{Certificate, CertificateParams};
use rsa::pkcs8::EncodePrivateKey;
use std::convert::Infallible;
use std::future::ready;
use std::path::Path;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio_native_tls::native_tls::{Identity, TlsAcceptor};

fn generate_rsa_keypair() -> rcgen::KeyPair {
    let mut rng = rand::rngs::OsRng;
    let bits = 2048;
    let private_key = rsa::RsaPrivateKey::new(&mut rng, bits).unwrap();
    let private_key_der = private_key.to_pkcs8_der().unwrap();
    rcgen::KeyPair::try_from(private_key_der.as_bytes()).unwrap()
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bind_port: u16 = std::env::args()
        .nth(1)
        .unwrap_or("12345".to_string())
        .parse()
        .unwrap();
    let mut cert_params = CertificateParams::new(vec![]);

    cert_params.alg = &rcgen::PKCS_RSA_SHA256;
    cert_params.key_pair = Some(generate_rsa_keypair());

    let cert = Certificate::from_params(cert_params).unwrap();

    let cert_pem = cert.serialize_pem().unwrap();
    File::create(Path::new("server.crt"))
        .await
        .unwrap()
        .write_all(cert_pem.as_bytes())
        .await
        .unwrap();

    let identity = {
        let keypair = cert.get_key_pair();
        Identity::from_pkcs8(cert_pem.as_bytes(), keypair.serialize_pem().as_bytes()).unwrap()
    };

    let make_svc = make_service_fn(move |_conn| async move {
        Ok::<_, Infallible>(service_fn(move |req| async move {
            let result = handle_connection(req).await;
            if let Err(e) = &result {
                println!("Local Server Error: {e:?}");
            }

            result
        }))
    });

    let acceptor: tokio_native_tls::TlsAcceptor =
        TlsAcceptor::builder(identity).build().unwrap().into();

    let addr = ([0, 0, 0, 0], bind_port).into();
    let addr = AddrIncoming::bind(&addr)?;
    let local_addr = addr.local_addr();
    let listener = tls_listener::builder(acceptor).listen(addr).filter(|conn| {
        if let Err(err) = conn {
            eprintln!("TLS Error: {:?}", err);
            ready(false)
        } else {
            ready(true)
        }
    });

    let server = Server::builder(accept::from_stream(listener)).serve(make_svc);

    println!("Listening on https://{}", local_addr);

    Ok(server.await?)
}

async fn handle_connection(_: Request<Body>) -> Result<Response<Body>, Infallible> {
    println!("Received request");
    Ok(Response::new(Body::from("Finished")))
}
