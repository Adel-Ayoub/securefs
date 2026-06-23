// Network config parsing accepts valid ip:port and ports, and rejects malformed
// values with a message naming the offending variable.

use securefs_server::config::{parse_port, parse_socket_addr};

#[test]
fn accepts_valid_values() {
    assert_eq!(
        parse_socket_addr("SERVER_ADDR", "0.0.0.0:8080")
            .unwrap()
            .to_string(),
        "0.0.0.0:8080"
    );
    assert_eq!(parse_port("DB_PORT", "5432").unwrap(), 5432);
}

#[test]
fn rejects_malformed_values() {
    // A hostname is not an ip:port bind address.
    let e = parse_socket_addr("SERVER_ADDR", "localhost:8080").unwrap_err();
    assert!(e.to_string().contains("SERVER_ADDR"), "{}", e);

    let e = parse_port("DB_PORT", "not-a-port").unwrap_err();
    assert!(e.to_string().contains("DB_PORT"), "{}", e);

    assert!(parse_port("DB_PORT", "70000").is_err(), "out of u16 range");
}
