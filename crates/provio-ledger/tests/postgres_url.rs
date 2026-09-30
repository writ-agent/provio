//! Postgres ledger locations without a server: detection, redaction, and
//! failing closed when the `postgres` feature is off. Runs in every build.

use provio_ledger::{
    detect_store_kind, display_ledger, is_postgres_url, redact_postgres_url, StoreKind,
};

#[test]
fn postgres_urls_are_detected_before_the_filesystem() {
    for url in [
        "postgres://u:p@db.internal:5432/provio",
        "postgresql://u@db/provio?sslmode=verify-full",
        "POSTGRES://host/db",
    ] {
        assert!(is_postgres_url(url), "{url}");
        assert_eq!(
            detect_store_kind(url).unwrap(),
            StoreKind::Postgres,
            "{url}"
        );
    }
    for not in [
        "postgres:/x",
        "ledger.jsonl",
        "./postgres://x",
        "mysql://h/db",
        "pg://h",
    ] {
        assert!(!is_postgres_url(not), "{not}");
    }
}

#[test]
fn redaction_hides_every_password_form() {
    let cases = [
        (
            "postgres://alice:hunter2@db:5432/provio",
            "postgres://alice:***@db:5432/provio",
        ),
        ("postgres://alice@db/provio", "postgres://alice@db/provio"),
        ("postgres://db/provio", "postgres://db/provio"),
        // Unencoded '/' and '@' inside the password are still covered.
        (
            "postgres://alice:a/b@c@db/provio",
            "postgres://alice:***@db/provio",
        ),
        (
            "postgresql://db/provio?user=alice&password=hunter2&sslmode=require",
            "postgresql://db/provio?user=alice&password=***&sslmode=require",
        ),
    ];
    for (url, want) in cases {
        assert_eq!(redact_postgres_url(url), want);
        assert_eq!(display_ledger(url), want);
    }
    assert_eq!(
        display_ledger(".provio/ledger.jsonl"),
        ".provio/ledger.jsonl"
    );
}

#[cfg(not(feature = "postgres"))]
#[test]
fn postgres_ledgers_fail_closed_without_the_feature() {
    let url = "postgres://alice:hunter2@127.0.0.1:1/provio";
    let open = provio_ledger::open_store(url)
        .err()
        .expect("must fail")
        .to_string();
    let verify = provio_ledger::verify(url).unwrap_err().to_string();
    let sessions = provio_ledger::sessions(url).unwrap_err().to_string();
    for msg in [open, verify, sessions] {
        assert!(msg.contains("`postgres` feature"), "got {msg}");
        assert!(!msg.contains("hunter2"), "password leaked: {msg}");
    }
    // Never mistaken for a file path: nothing was created.
    assert!(!std::path::Path::new("postgres:").exists());
}

#[cfg(feature = "postgres")]
#[test]
fn malformed_locations_are_rejected_without_connecting() {
    use provio_ledger::PostgresLedgerStore;
    for (url, needle) in [
        ("postgres://h/db?provio_schema=Bad", "invalid provio_schema"),
        (
            "postgres://h/db?provio_table=x%3Bdrop",
            "invalid provio_table",
        ),
        ("postgres://h/db?sslmode=maybe", "invalid sslmode"),
        ("postgres://h/db?sslcert=/c.pem", "sslcert is not supported"),
        (
            "postgres://h/db?no_such_option=1",
            "invalid connection string",
        ),
        (
            "postgres://h/db?sslmode=verify-full&sslrootcert=/definitely/missing.pem",
            "sslrootcert",
        ),
    ] {
        let err = PostgresLedgerStore::open(url).unwrap_err().to_string();
        assert!(err.contains(needle), "{url}: got {err}");
    }
    let err = PostgresLedgerStore::open("postgres://u:hunter2@h/db?provio_table=X")
        .unwrap_err()
        .to_string();
    assert!(!err.contains("hunter2"), "password leaked: {err}");
}
