use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};

use anyhow::{anyhow, Context, Result};

use crate::SgxCollateral;

pub fn start_server(
    port: u16,
    quote: Vec<u8>,
    collateral: SgxCollateral,
    shared_pub_key: &[u8; 112],
) {
    let listener = TcpListener::bind(format!("0.0.0.0:{port}")).expect("Failed to bind to port");
    let collat_bytes = serde_json::to_string(&collateral)
        .expect("Failed to serialize collateral")
        .into_bytes();

    for stream in listener.incoming() {
        let Ok(stream) = stream else {
            continue;
        };
        let _ = handle_connection(stream, &quote, &collat_bytes, shared_pub_key);
    }
}

fn handle_connection(
    mut stream: TcpStream,
    quote: &[u8],
    collateral: &[u8],
    shared_pub_key: &[u8],
) -> Result<()> {
    let buf_reader = BufReader::new(&mut stream);
    let mut http_request = Vec::with_capacity(10);
    for line in buf_reader.lines() {
        let Ok(line) = line else {
            return Err(anyhow!("Failed to parse HTTP request"));
        };
        if line.is_empty() {
            break;
        }
        http_request.push(line);
    }

    let mut tokens = http_request
        .first()
        .context("Failed to parse HTTP request")?
        .split(" ");
    let method = tokens.next().context("Method missing from HTTP request")?;
    if method != "GET" {
        return Err(anyhow!("Unsupported request method: {method}"));
    }
    let path = tokens.next().context("Path missing from HTTP request")?;

    let (content_type, body) = match path {
        "/key" => ("text/plain", shared_pub_key),
        "/quote" => ("raw", quote),
        "/collateral" => ("application/json; charset=utf-8", collateral),
        p => return Err(anyhow!("Invalid path: {p}")),
    };

    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\r\n",
        body.len(),
    );

    stream.write_all(response.as_bytes())?;
    stream.write_all(body)?;
    Ok(())
}
