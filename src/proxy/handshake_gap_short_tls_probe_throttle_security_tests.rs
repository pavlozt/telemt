use super::*;
use crate::stats::ReplayChecker;
use std::net::SocketAddr;
use std::time::Duration;

fn test_config_with_secret_hex(secret_hex: &str) -> ProxyConfig {
    let mut cfg = ProxyConfig::default();
    cfg.access.users.clear();
    cfg.access
        .users
        .insert("user".to_string(), secret_hex.to_string());
    cfg.access.ignore_time_skew = true;
    cfg
}

#[tokio::test]
async fn gap_t01_short_tls_probe_burst_is_throttled() {
    let _guard = auth_probe_test_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    clear_auth_probe_state_for_testing();

    let config = test_config_with_secret_hex("11111111111111111111111111111111");
    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "198.51.100.171:44361".parse().unwrap();

    let too_short = vec![0x16, 0x03, 0x01];

    for _ in 0..AUTH_PROBE_BACKOFF_START_FAILS {
        let result = handle_tls_handshake(
            &too_short,
            tokio::io::empty(),
            tokio::io::sink(),
            peer,
            &config,
            &replay_checker,
            &rng,
            None,
        )
        .await;
        assert!(matches!(result, HandshakeResult::BadClient { .. }));
    }

    assert!(
        auth_probe_fail_streak_for_testing(peer.ip())
            .is_some_and(|streak| streak >= AUTH_PROBE_BACKOFF_START_FAILS),
        "short TLS probe bursts must increase auth-probe fail streak"
    );
}
