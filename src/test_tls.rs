use std::io::{stderr, stdout, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use rustls_mbedcrypto_provider::mbedtls_crypto_provider;
use rustls_mbedpki_provider::MbedTlsServerCertVerifier;

pub fn test_rustls() {
    let server_cert_verifier = MbedTlsServerCertVerifier::new(Vec::new()).unwrap();
    let config = rustls::ClientConfig::builder_with_provider(mbedtls_crypto_provider().into())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(server_cert_verifier))
        .with_no_client_auth();

    let server_name = "www.rust-lang.org".try_into().unwrap();
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut sock = TcpStream::connect("www.rust-lang.org:443").unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
    tls.write_all(
        concat!(
            "GET / HTTP/1.1\r\n",
            "Host: www.rust-lang.org\r\n",
            "Connection: close\r\n",
            "Accept-Encoding: identity\r\n",
            "\r\n"
        )
        .as_bytes(),
    )
    .unwrap();
    let ciphersuite = tls.conn.negotiated_cipher_suite().unwrap();
    writeln!(
        &mut stderr(),
        "Current ciphersuite: {:?}",
        ciphersuite.suite()
    )
    .unwrap();
    let mut plaintext = Vec::new();
    tls.read_to_end(&mut plaintext).unwrap();
    stdout().write_all(&plaintext).unwrap();
}
