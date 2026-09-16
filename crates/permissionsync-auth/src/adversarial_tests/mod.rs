//! Private, shared fixtures for adversarial auth-boundary tests.

mod cache;
mod jwt_claims;
mod support;
mod transport;

#[cfg(test)]
mod smoke {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_native_tls::TlsConnector;

    use super::{
        super::JwtAlgorithm,
        support::{HttpsFixture, SigningMaterial},
        transport::ScriptedResponse,
    };

    #[tokio::test]
    async fn local_tls_fixture_serves_a_scripted_response() {
        let signing = SigningMaterial::new(JwtAlgorithm::RS256, "smoke-key");
        let token = signing.token(
            &SigningMaterial::bearer_payload(Some("permissionsync:smoke")),
            &josekit::jws::JwsHeader::new(),
        );
        assert_eq!(token.split('.').count(), 3);
        assert!(!signing.jwks().is_empty());

        let fixture = HttpsFixture::start(vec![ScriptedResponse::json(
            200,
            br#"{"keys":[]}"#.to_vec(),
        )])
        .await;
        let connector = native_tls::TlsConnector::builder()
            .add_root_certificate(
                native_tls::Certificate::from_pem(fixture.trust_anchor_pem()).unwrap(),
            )
            .build()
            .unwrap();
        let stream = tokio::net::TcpStream::connect(fixture.address())
            .await
            .unwrap();
        let mut stream = TlsConnector::from(connector)
            .connect("127.0.0.1", stream)
            .await
            .unwrap();
        stream
            .write_all(b"GET /jwks HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200"));
        assert_eq!(fixture.request_count(), 1);
        fixture.shutdown().await;
    }
}
