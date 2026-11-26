//! Exercise the real HTTP transport used by BitcoinClient, rather than mocking RpcError.
//! Bitcoin Core sends an unknown-transaction JSON-RPC error (-5) with HTTP 500.
use bitvmx_bitcoin_rpc::{
    bitcoin_client::{BitcoinClient, BitcoinClientApi},
    errors::BitcoinClientError,
    jsonrpc,
};
use redact::Secret;
use serde_json::{json, Value};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    thread,
    time::{Duration, Instant},
};

// One request per test, on an OS-assigned loopback port. No Bitcoin node or Docker needed.
fn with_unknown_transaction_response<T>(
    status: u16,
    rpc_body: bool,
    request: impl FnOnce(&BitcoinClient) -> T,
) -> T {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "RPC client never connected");
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("accept failed: {error}"),
            }
        };
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut content_length = None;
        loop {
            let mut line = String::new();
            assert_ne!(
                reader.read_line(&mut line).unwrap(),
                0,
                "incomplete HTTP request"
            );
            if line == "\r\n" {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                if name.eq_ignore_ascii_case("content-length") {
                    content_length = Some(value.trim().parse::<usize>().unwrap());
                }
            }
        }
        let content_length = content_length.expect("missing Content-Length");
        assert!(content_length < 8192);
        let mut bytes = vec![0; content_length];
        reader.read_exact(&mut bytes).unwrap();
        let request: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(request["method"], "getrawtransaction");
        let body = if rpc_body {
            json!({
                "result": null,
                "error": {
                    "code": -5,
                    "message": "No such mempool or blockchain transaction. Use gettransaction for wallet transactions."
                },
                "id": request["id"]
            })
            .to_string()
        } else {
            "upstream unavailable".to_owned()
        };
        write!(
            stream,
            "HTTP/1.1 {status} Response\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
    });
    let client = BitcoinClient::new(
        &Secret::new(url),
        &Secret::new(String::new()),
        &Secret::new(String::new()),
    )
    .unwrap();
    let result = request(&client);
    server.join().expect("mock Bitcoin RPC server failed");
    result
}

// The client field is private, so the raw getrawtransaction request goes through the public verbosity two method,
// which sends it and returns the node's error unchanged.
fn unknown_transaction_response(status: u16, rpc_body: bool) -> BitcoinClientError {
    let txid = "0257d69ee3f36d47b98aabda42cca1501da5e86af48f16f759fd458bbc011310"
        .parse()
        .unwrap();
    with_unknown_transaction_response(status, rpc_body, |client| {
        client
            .get_raw_transaction_verbosity_two(&txid)
            .expect_err("unknown transaction must return an RPC error")
    })
}

#[test]
fn http_500_preserves_transaction_not_found_rpc_error() {
    let error = unknown_transaction_response(500, true);
    // Regression: returning Transport here prevents is_not_found from matching -5.
    // Monitoring then aborts the coordinator tick before the queued tx is broadcast.
    assert!(
        matches!(&error, BitcoinClientError::RpcError(jsonrpc::Error::Rpc(rpc)) if rpc.code == -5),
        "expected JSON-RPC -5 from Bitcoin Core's HTTP 500 response, got {error:?}"
    );
    assert!(error.is_not_found());
}

// The trait method other crates call maps the HTTP 500 not-found answer to None instead of an error.
#[test]
fn get_raw_transaction_info_maps_http_500_not_found_to_none() {
    let txid = "0257d69ee3f36d47b98aabda42cca1501da5e86af48f16f759fd458bbc011310"
        .parse()
        .unwrap();
    let result = with_unknown_transaction_response(500, true, |client| {
        client.get_raw_transaction_info(&txid)
    });
    assert!(
        matches!(result, Ok(None)),
        "expected Ok(None) for an unknown transaction, got {result:?}"
    );
}

#[test]
fn bitcoin_client_api_preserves_the_same_rpc_error() {
    let txid = "0257d69ee3f36d47b98aabda42cca1501da5e86af48f16f759fd458bbc011310"
        .parse()
        .unwrap();
    let error = with_unknown_transaction_response(500, true, |client| {
        client
            .get_raw_transaction_verbosity_two(&txid)
            .expect_err("unknown transaction must return an RPC error")
    });

    assert!(
        matches!(
            &error,
            BitcoinClientError::RpcError(jsonrpc::Error::Rpc(rpc)) if rpc.code == -5
        ),
        "expected BitcoinClient API to preserve JSON-RPC -5, got {error:?}"
    );
}

#[test]
fn http_200_preserves_the_same_rpc_error() {
    let error = unknown_transaction_response(200, true);
    assert!(
        matches!(&error, BitcoinClientError::RpcError(jsonrpc::Error::Rpc(rpc)) if rpc.code == -5),
        "expected JSON-RPC -5, got {error:?}"
    );
}

#[test]
fn http_503_without_rpc_body_remains_a_transport_failure() {
    let error = unknown_transaction_response(503, false);
    assert!(
        matches!(
            &error,
            BitcoinClientError::RpcError(jsonrpc::Error::Transport(_))
        ),
        "a genuine HTTP failure must not be treated as a missing transaction: {error:?}"
    );
    assert!(error.is_node_unreachable());
    assert!(!error.is_not_found());
}
