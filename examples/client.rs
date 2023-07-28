use reqwest::{Certificate, Client};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let port: u16 = std::env::args()
        .nth(1)
        .unwrap_or("12345".to_string())
        .parse()
        .unwrap();
    let cert = std::fs::read_to_string("server.crt")?;
    let client = Client::builder()
        .add_root_certificate(Certificate::from_pem(cert.as_bytes())?)
        .danger_accept_invalid_hostnames(true)
        .connection_verbose(true)
        .tls_built_in_root_certs(false)
        .use_native_tls()
        .timeout(tokio::time::Duration::from_secs(2))
        .build()?;

    let response = client
        .get(format!("https://localhost:{port}/"))
        .send()
        .await?;

    println!("{}", response.text().await?);

    Ok(())
}
