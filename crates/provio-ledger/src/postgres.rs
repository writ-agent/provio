//! `PostgresLedgerStore`: the ledger in a PostgreSQL table, behind the
//! `postgres` cargo feature — for cluster deployments where many hosts
//! append to one ledger.
//!
//! # Same evidence, different container
//!
//! Each row stores the record exactly as [`FileLedgerStore`] writes a JSONL
//! line: `serde_json::to_string(&LedgerRecord)`, in a `TEXT` column (never
//! `JSONB`, which would reorder keys and normalise whitespace). Hashes are
//! computed over the record, never over anything Postgres-specific, so a
//! JSONL → Postgres → JSONL copy is byte-for-byte identical and verifies
//! identically. The database must use the `UTF8` server encoding (checked
//! on connect), so no transcoding can alter a record.
//!
//! # Locating the ledger
//!
//! A `postgres://` or `postgresql://` URL (libpq syntax, parsed by
//! `tokio-postgres`). Three parameters are PROVIO's own and are removed
//! before the URL reaches the driver:
//!
//! - `provio_schema` (default `provio`) and `provio_table` (default `ledger`):
//!   where the ledger lives. Lower-case identifiers only
//!   (`[a-z_][a-z0-9_]*`); the schema must be dedicated to PROVIO ledgers.
//! - `sslmode` and `sslrootcert`: libpq semantics, see [TLS](#tls).
//!
//! `PGPASSWORD`, `PGSSLMODE` and `PGSSLROOTCERT` are honoured when the URL
//! does not set the value, so a password can stay out of command lines.
//! The password is never logged or included in an error: every message
//! names the ledger by [`redact_postgres_url`](crate::redact_postgres_url).
//!
//! # Schema (store version 1)
//!
//! ```sql
//! CREATE TABLE provio.ledger_meta (           -- marker + append lock
//!     singleton     BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
//!     application   TEXT    NOT NULL,       -- 'provio-ledger'
//!     store_version INTEGER NOT NULL,       -- 1
//!     ledger_table  TEXT    NOT NULL,       -- 'ledger'
//!     created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
//! );
//! CREATE TABLE provio.ledger (
//!     idx    BIGINT PRIMARY KEY CHECK (idx >= 0),
//!     record TEXT   NOT NULL,
//!     CONSTRAINT ledger_idx_is_record_index
//!         CHECK (idx = (provio.ledger_json_field(record, 'index'))::bigint)
//! );
//! -- ledger_json_field: one top-level field as text, parsing the record
//! --   with the escape \u0000 mapped to \u0001 (Postgres' JSON operators
//! --   refuse \u0000 anywhere in a document)
//! -- + BEFORE INSERT row trigger: locks the marker row, then requires
//! --   idx = ledger length and prev_hash = tip record_hash (genesis: 64 zeros)
//! -- + BEFORE UPDATE / DELETE / TRUNCATE statement triggers on both
//! --   tables: RAISE EXCEPTION
//! ```
//!
//! Opening refuses a schema that holds anything other than PROVIO ledgers, a
//! marker with another application or store version, and a `ledger` table
//! without a marker — it never adds tables to a foreign schema.
//!
//! # Tamper-evidence, not prevention
//!
//! The triggers and constraints stop accidental rewrites and stray writers
//! (a `psql` session, a migration tool) from editing or forking the chain.
//! They are not a security boundary: the table owner can `ALTER TABLE ...
//! DISABLE TRIGGER`, and a superuser can do anything. What survives that is
//! the hash chain — [`verify_postgres`] (and `provio verify`) report the exact
//! index of any edited, deleted or reordered record. Running writers as a
//! role that does not own the tables (see `docs/ledger-postgres.md`) makes
//! the triggers binding for those writers.
//!
//! # Concurrency: many writers, one chain
//!
//! [`append`](LedgerStore::append) runs in one `READ COMMITTED`
//! transaction that
//! 1. locks the single marker row (`SELECT ... FOR UPDATE`), which every
//!    appender — this store on any host, or the insert trigger for raw SQL —
//!    takes before reading the tip, so appends are serialized across all
//!    connections;
//! 2. re-reads the tip from the table (a fresh snapshot, taken after the
//!    lock was granted — never a cached value);
//! 3. rejects the record unless its `index` and `prev_hash` extend that tip
//!    (and, before any of this, unless its `record_hash` is its own);
//! 4. inserts (the trigger re-checks the same rule inside Postgres) and
//!    commits.
//!
//! A writer that built its record on a tip that has since moved gets
//! `ProvioError::Ledger("append rejected: ...")`, worded exactly as by the
//! file and SQLite stores, so [`retry_append`](crate::retry_append) and
//! [`is_append_race`](crate::is_append_race) work unchanged. Waiting for
//! the lock is bounded by [`LOCK_TIMEOUT`](crate::LOCK_TIMEOUT); a writer
//! that cannot get it fails closed.
//!
//! Durability: `synchronous_commit` is raised to `on` for the session if
//! the server default is `off`, so an acknowledged append survives a crash
//! of the database server (ADR-003).
//!
//! # TLS
//!
//! rustls with the `ring` provider; trust roots from `sslrootcert` (a PEM
//! file) or, when that is absent or `system`, the operating system's store.
//! `sslmode` follows libpq:
//!
//! | `sslmode` | TLS | server certificate |
//! |---|---|---|
//! | `disable` | never | — |
//! | `allow`, `prefer` (default) | if the server offers it | not checked, unless `sslrootcert` is set (then as `verify-ca`) |
//! | `require` | required | not checked, unless `sslrootcert` is set (then as `verify-ca`) |
//! | `verify-ca` | required | chains to a trusted root |
//! | `verify-full` | required | chains to a trusted root and matches the host name |
//!
//! Use `verify-full` across any network you do not control.
//!
//! [`FileLedgerStore`]: crate::FileLedgerStore

use std::cell::{Cell, RefCell, RefMut};
use std::collections::VecDeque;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use ::postgres::{Client, Config, GenericClient};
use provio_core::error::{ProvioError, Result};
use provio_core::ledger::{LedgerRecord, LedgerStore, VerifyReport, GENESIS_HASH};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme,
};
use tokio_postgres_rustls::MakeRustlsConnect;

use crate::file_store::LOCK_TIMEOUT;
use crate::store::{is_postgres_url, redact_postgres_url};
use crate::verify::verify_records;

/// `application` value in the marker table of every PROVIO ledger.
pub const APPLICATION: &str = "provio-ledger";
/// The Postgres store's table layout version (marker `store_version`).
/// Independent of `LedgerRecord::schema_version`, which versions records.
pub const STORE_VERSION: i32 = 1;
/// Schema used when the URL has no `provio_schema` parameter.
pub const DEFAULT_SCHEMA: &str = "provio";
/// Table used when the URL has no `provio_table` parameter.
pub const DEFAULT_TABLE: &str = "ledger";
/// Connect timeout applied when the URL sets none (`connect_timeout`).
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Oldest supported server (`EXECUTE FUNCTION` in trigger DDL).
const MIN_SERVER_VERSION: i32 = 110_000;

/// Rows fetched per query by the lazy iterators.
const PAGE_SIZE: i64 = 512;

// ---------------------------------------------------------------------------
// Connection target: URL parsing, TLS, names
// ---------------------------------------------------------------------------

/// libpq `sslmode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SslChoice {
    Disable,
    Allow,
    Prefer,
    Require,
    VerifyCa,
    VerifyFull,
}

impl SslChoice {
    fn parse(value: &str) -> Result<Self> {
        Ok(match value {
            "disable" => SslChoice::Disable,
            "allow" => SslChoice::Allow,
            "prefer" => SslChoice::Prefer,
            "require" => SslChoice::Require,
            "verify-ca" => SslChoice::VerifyCa,
            "verify-full" => SslChoice::VerifyFull,
            other => {
                return Err(ProvioError::Ledger(format!(
                    "invalid sslmode {other:?} (expected disable, allow, prefer, require, \
                     verify-ca or verify-full)"
                )))
            }
        })
    }

    fn driver_mode(self) -> ::postgres::config::SslMode {
        use ::postgres::config::SslMode;
        match self {
            SslChoice::Disable => SslMode::Disable,
            // tokio-postgres has no "try plaintext first"; allow behaves as prefer.
            SslChoice::Allow | SslChoice::Prefer => SslMode::Prefer,
            SslChoice::Require | SslChoice::VerifyCa | SslChoice::VerifyFull => SslMode::Require,
        }
    }
}

/// How the server certificate is checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CertCheck {
    None,
    Chain,
    ChainAndName,
}

/// Everything needed to (re)connect to one ledger.
#[derive(Clone)]
struct Target {
    config: Config,
    tls: MakeRustlsConnect,
    names: Names,
    /// The URL with its password replaced; the only form ever displayed.
    redacted: String,
}

impl Target {
    fn err(&self, what: &str, e: ::postgres::Error) -> ProvioError {
        ProvioError::Ledger(format!(
            "postgres ledger {}: {what}: {}",
            self.redacted,
            describe(&e)
        ))
    }
}

/// Qualified, quoted object names for one ledger.
#[derive(Debug, Clone)]
struct Names {
    schema: String,
    table: String,
    ledger: String,
    meta: String,
    guard_fn: String,
    reject_fn: String,
    field_fn: String,
}

impl Names {
    fn new(schema: &str, table: &str) -> Result<Self> {
        check_ident("provio_schema", schema, 63)?;
        // Longest derived name: `<table>_append_guard` (13 more bytes).
        check_ident("provio_table", table, 50)?;
        let q = |obj: &str| format!("\"{schema}\".\"{obj}\"");
        Ok(Names {
            schema: schema.to_string(),
            table: table.to_string(),
            ledger: q(table),
            meta: q(&format!("{table}_meta")),
            guard_fn: q(&format!("{table}_append_guard")),
            reject_fn: q(&format!("{table}_reject_change")),
            field_fn: q(&format!("{table}_json_field")),
        })
    }
}

/// Identifiers are restricted so they never need escaping and never fold
/// case differently between Rust and SQL.
fn check_ident(param: &str, value: &str, max: usize) -> Result<()> {
    let mut chars = value.chars();
    let ok = matches!(chars.next(), Some('a'..='z' | '_'))
        && chars.all(|c| matches!(c, 'a'..='z' | '0'..='9' | '_'))
        && value.len() <= max
        && !value.starts_with("pg_");
    if ok {
        Ok(())
    } else {
        Err(ProvioError::Ledger(format!(
            "invalid {param} {value:?}: use 1-{max} characters of [a-z0-9_], starting with a \
             letter or underscore (not pg_)"
        )))
    }
}

fn decode(raw: &str) -> Result<String> {
    percent_encoding::percent_decode_str(raw)
        .decode_utf8()
        .map(|s| s.into_owned())
        .map_err(|_| ProvioError::Ledger("connection URL has an invalid percent-escape".into()))
}

fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn parse_target(url: &str) -> Result<Target> {
    let redacted = redact_postgres_url(url);
    let bad = |m: String| ProvioError::Ledger(format!("postgres ledger {redacted}: {m}"));
    if !is_postgres_url(url) {
        return Err(bad("not a postgres:// or postgresql:// URL".into()));
    }
    let (base, query) = url.split_once('?').unwrap_or((url, ""));
    let mut kept: Vec<&str> = Vec::new();
    let mut sslmode = None;
    let mut rootcert = None;
    let mut schema = DEFAULT_SCHEMA.to_string();
    let mut table = DEFAULT_TABLE.to_string();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        match decode(k).map_err(|e| bad(e.to_string()))?.as_str() {
            "sslmode" => sslmode = Some(decode(v)?),
            "sslrootcert" => rootcert = Some(decode(v)?),
            // writ_*: the parameter names before the rename (writ → provio).
            "provio_schema" | "writ_schema" => schema = decode(v)?,
            "provio_table" | "writ_table" => table = decode(v)?,
            key @ ("sslcert" | "sslkey" | "sslpassword" | "sslcrl" | "sslcrldir") => {
                return Err(bad(format!(
                    "connection parameter {key} is not supported by the PROVIO Postgres store"
                )))
            }
            _ => kept.push(pair),
        }
    }
    let names = Names::new(&schema, &table).map_err(|e| bad(e.to_string()))?;
    let sslmode = match sslmode.or_else(|| env_nonempty("PGSSLMODE")) {
        Some(m) => SslChoice::parse(&m).map_err(|e| bad(e.to_string()))?,
        None => SslChoice::Prefer,
    };
    let rootcert = rootcert.or_else(|| env_nonempty("PGSSLROOTCERT"));
    let conn = if kept.is_empty() {
        base.to_string()
    } else {
        format!("{base}?{}", kept.join("&"))
    };
    // tokio-postgres parse errors name the offending key, never its value.
    let mut config: Config = conn
        .parse()
        .map_err(|e: ::postgres::Error| bad(describe(&e)))?;
    config.ssl_mode(sslmode.driver_mode());
    if config.get_password().is_none() {
        if let Some(pw) = env_nonempty("PGPASSWORD") {
            config.password(pw);
        }
    }
    if config.get_connect_timeout().is_none() {
        config.connect_timeout(CONNECT_TIMEOUT);
    }
    if config.get_application_name().is_none() {
        config.application_name("provio-ledger");
    }
    let check = match sslmode {
        SslChoice::VerifyFull => CertCheck::ChainAndName,
        SslChoice::VerifyCa => CertCheck::Chain,
        _ if rootcert.is_some() => CertCheck::Chain,
        _ => CertCheck::None,
    };
    let tls = tls_connector(check, rootcert.as_deref()).map_err(|e| bad(e.to_string()))?;
    Ok(Target {
        config,
        tls,
        names,
        redacted,
    })
}

/// A `postgres::Error` with its cause chain (`Display` alone says only
/// "db error"). Never contains connection parameters.
fn describe(e: &::postgres::Error) -> String {
    if let Some(db) = e.as_db_error() {
        return format!(
            "{}: {} (SQLSTATE {})",
            db.severity(),
            db.message(),
            db.code().code()
        );
    }
    let mut out = e.to_string();
    let mut source = std::error::Error::source(e);
    while let Some(s) = source {
        out.push_str(": ");
        out.push_str(&s.to_string());
        source = s.source();
    }
    out
}

// ---------------------------------------------------------------------------
// TLS
// ---------------------------------------------------------------------------

fn tls_err(e: impl fmt::Display) -> ProvioError {
    ProvioError::Ledger(format!("TLS setup: {e}"))
}

fn load_roots(rootcert: Option<&str>) -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    match rootcert {
        Some(path) if path != "system" => {
            let certs = CertificateDer::pem_file_iter(path)
                .and_then(|it| it.collect::<std::result::Result<Vec<_>, _>>())
                .map_err(|e| tls_err(format!("sslrootcert {path:?}: {e}")))?;
            for cert in certs {
                roots
                    .add(cert)
                    .map_err(|e| tls_err(format!("sslrootcert {path:?}: {e}")))?;
            }
        }
        _ => {
            let native = rustls_native_certs::load_native_certs();
            roots.add_parsable_certificates(native.certs);
        }
    }
    if roots.is_empty() {
        return Err(tls_err(
            "no trusted root certificates (set sslrootcert to a PEM file)",
        ));
    }
    Ok(roots)
}

fn tls_connector(check: CertCheck, rootcert: Option<&str>) -> Result<MakeRustlsConnect> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .map_err(tls_err)?;
    let config = match check {
        CertCheck::None => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(EncryptOnly(provider)))
            .with_no_client_auth(),
        CertCheck::Chain | CertCheck::ChainAndName => {
            let roots = Arc::new(load_roots(rootcert)?);
            let webpki = WebPkiServerVerifier::builder_with_provider(roots, provider)
                .build()
                .map_err(tls_err)?;
            if check == CertCheck::Chain {
                builder
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(ChainOnly(webpki)))
                    .with_no_client_auth()
            } else {
                builder.with_webpki_verifier(webpki).with_no_client_auth()
            }
        }
    };
    Ok(MakeRustlsConnect::new(config))
}

/// libpq `sslmode=require` without a root certificate: encrypt, and check
/// handshake signatures, but do not authenticate the server.
#[derive(Debug)]
struct EncryptOnly(Arc<CryptoProvider>);

impl ServerCertVerifier for EncryptOnly {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// libpq `sslmode=verify-ca`: the chain must reach a trusted root; the
/// host name is not compared. rustls-webpki checks the chain before the
/// name, so a name mismatch means the chain already verified.
#[derive(Debug)]
struct ChainOnly(Arc<WebPkiServerVerifier>);

impl ServerCertVerifier for ChainOnly {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        match self
            .0
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
        {
            Err(rustls::Error::InvalidCertificate(
                CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. },
            )) => Ok(ServerCertVerified::assertion()),
            other => other,
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_verify_schemes()
    }
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

fn schema_sql(n: &Names) -> String {
    let Names {
        table,
        ledger,
        meta,
        guard_fn,
        reject_fn,
        field_fn,
        ..
    } = n;
    format!(
        r#"
-- One top-level field of a record, as text. Postgres' JSON operators
-- refuse the escape \u0000 anywhere in a document, and records embed
-- arbitrary tool arguments; it is mapped to \u0001 first. Only index and
-- hash fields (digits, hex) are ever extracted, so this cannot change a
-- compared value.
CREATE FUNCTION {field_fn}(record TEXT, key TEXT) RETURNS TEXT
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE SET search_path = pg_catalog, pg_temp
AS $provio$ SELECT (replace(record, E'\\u0000', E'\\u0001')::json) ->> key $provio$;

CREATE TABLE {meta} (
    singleton     BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    application   TEXT    NOT NULL,
    store_version INTEGER NOT NULL,
    ledger_table  TEXT    NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO {meta} (application, store_version, ledger_table)
    VALUES ('{APPLICATION}', {STORE_VERSION}, '{table}');

CREATE TABLE {ledger} (
    idx    BIGINT PRIMARY KEY CHECK (idx >= 0),
    record TEXT   NOT NULL,
    CONSTRAINT {table}_idx_is_record_index
        CHECK (idx = ({field_fn}(record, 'index'))::bigint)
);

CREATE FUNCTION {guard_fn}() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $provio$
DECLARE
    tip_idx  BIGINT;
    tip_hash TEXT;
BEGIN
    -- The append lock: every appender takes it before reading the tip.
    PERFORM 1 FROM {meta} WHERE singleton FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'provio ledger: marker row missing from {meta}';
    END IF;
    SELECT l.idx, {field_fn}(l.record, 'record_hash') INTO tip_idx, tip_hash
        FROM {ledger} l ORDER BY l.idx DESC LIMIT 1;
    IF NOT FOUND THEN
        tip_idx := -1;
        tip_hash := '{GENESIS_HASH}';
    END IF;
    IF NEW.idx IS DISTINCT FROM tip_idx + 1 THEN
        RAISE EXCEPTION 'provio ledger is append-only: index must equal the ledger length (got %, expected %)',
            NEW.idx, tip_idx + 1;
    END IF;
    IF {field_fn}(NEW.record, 'prev_hash') IS DISTINCT FROM tip_hash THEN
        RAISE EXCEPTION 'provio ledger is append-only: prev_hash must equal the chain tip';
    END IF;
    RETURN NEW;
END
$provio$;

CREATE FUNCTION {reject_fn}() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $provio$
BEGIN
    RAISE EXCEPTION 'provio ledger is append-only: % rejected on %.%',
        TG_OP, TG_TABLE_SCHEMA, TG_TABLE_NAME;
END
$provio$;

CREATE TRIGGER {table}_append_guard BEFORE INSERT ON {ledger}
    FOR EACH ROW EXECUTE FUNCTION {guard_fn}();
CREATE TRIGGER {table}_no_update BEFORE UPDATE ON {ledger}
    FOR EACH STATEMENT EXECUTE FUNCTION {reject_fn}();
CREATE TRIGGER {table}_no_delete BEFORE DELETE ON {ledger}
    FOR EACH STATEMENT EXECUTE FUNCTION {reject_fn}();
CREATE TRIGGER {table}_no_truncate BEFORE TRUNCATE ON {ledger}
    FOR EACH STATEMENT EXECUTE FUNCTION {reject_fn}();
CREATE TRIGGER {table}_meta_no_update BEFORE UPDATE ON {meta}
    FOR EACH STATEMENT EXECUTE FUNCTION {reject_fn}();
CREATE TRIGGER {table}_meta_no_delete BEFORE DELETE ON {meta}
    FOR EACH STATEMENT EXECUTE FUNCTION {reject_fn}();
CREATE TRIGGER {table}_meta_no_truncate BEFORE TRUNCATE ON {meta}
    FOR EACH STATEMENT EXECUTE FUNCTION {reject_fn}();
"#
    )
}

/// Result of looking for this ledger's marker table.
enum Marker {
    /// A PROVIO ledger of this store version.
    Present,
    /// Neither the marker nor the ledger table exists.
    Absent,
}

fn marker_state(c: &mut impl GenericClient, t: &Target) -> Result<Marker> {
    let n = &t.names;
    let row = c
        .query_one(
            "SELECT to_regclass($1) IS NOT NULL, to_regclass($2) IS NOT NULL",
            &[&n.meta, &n.ledger],
        )
        .map_err(|e| t.err("inspecting schema", e))?;
    let (has_meta, has_ledger): (bool, bool) = (row.get(0), row.get(1));
    let foreign = |why: &str| {
        ProvioError::Ledger(format!(
            "postgres ledger {}: {}.{} is not a PROVIO ledger ({why})",
            t.redacted, n.schema, n.table
        ))
    };
    if !has_meta {
        return if has_ledger {
            Err(foreign("table exists without a PROVIO marker table"))
        } else {
            Ok(Marker::Absent)
        };
    }
    let row = c
        .query_opt(
            &format!(
                "SELECT application, store_version, ledger_table FROM {} WHERE singleton",
                n.meta
            ),
            &[],
        )
        .map_err(|_| foreign("marker table has an unexpected layout"))?
        .ok_or_else(|| foreign("marker table is empty"))?;
    let application: String = row.try_get(0).map_err(|_| foreign("bad marker"))?;
    let version: i32 = row.try_get(1).map_err(|_| foreign("bad marker"))?;
    let ledger_table: String = row.try_get(2).map_err(|_| foreign("bad marker"))?;
    if application != APPLICATION || ledger_table != n.table {
        return Err(foreign("marker names another application"));
    }
    if version != STORE_VERSION {
        return Err(ProvioError::Ledger(format!(
            "postgres ledger {}: unsupported Postgres store version {version} \
             (this build reads {STORE_VERSION})",
            t.redacted
        )));
    }
    if !has_ledger {
        return Err(ProvioError::Ledger(format!(
            "postgres ledger {}: marker present but table {}.{} is missing",
            t.redacted, n.schema, n.table
        )));
    }
    Ok(Marker::Present)
}

/// Refuse to create tables in a schema that holds anything other than PROVIO
/// ledgers (tables `X` + `X_meta` with a valid marker).
fn check_schema_is_ours(tx: &mut ::postgres::Transaction<'_>, t: &Target) -> Result<bool> {
    let n = &t.names;
    let exists = tx
        .query_opt(
            "SELECT 1 FROM pg_namespace WHERE nspname = $1",
            &[&n.schema],
        )
        .map_err(|e| t.err("inspecting schema", e))?
        .is_some();
    if !exists {
        return Ok(false);
    }
    let rels: Vec<String> = tx
        .query(
            "SELECT c.relname::text FROM pg_class c \
             JOIN pg_namespace s ON s.oid = c.relnamespace \
             WHERE s.nspname = $1 AND c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')",
            &[&n.schema],
        )
        .map_err(|e| t.err("inspecting schema", e))?
        .iter()
        .map(|r| r.get(0))
        .collect();
    let mut ours: Vec<String> = Vec::new();
    for rel in &rels {
        let Some(ledger) = rel.strip_suffix("_meta") else {
            continue;
        };
        // Probe inside a savepoint: a foreign `*_meta` table may not have
        // these columns, and the error must not abort the transaction.
        let mut sp = tx
            .transaction()
            .map_err(|e| t.err("inspecting schema", e))?;
        let probe = sp.query_opt(
            &format!(
                "SELECT 1 FROM \"{}\".\"{rel}\" WHERE singleton AND application = $1 \
                 AND ledger_table = $2",
                n.schema
            ),
            &[&APPLICATION, &ledger],
        );
        drop(sp); // roll back to the savepoint
        if let Ok(Some(_)) = probe {
            ours.push(rel.clone());
            ours.push(ledger.to_string());
        }
    }
    if let Some(stranger) = rels.iter().find(|r| !ours.contains(r)) {
        return Err(ProvioError::Ledger(format!(
            "postgres ledger {}: schema {} is not a PROVIO ledger schema (it contains {stranger:?}); \
             use a dedicated schema (provio_schema=...)",
            t.redacted, n.schema
        )));
    }
    Ok(true)
}

/// Create the schema objects if absent, or confirm an existing ledger is
/// ours. Serialized across hosts by a transaction-scoped advisory lock.
fn init_or_check_schema(client: &mut Client, t: &Target) -> Result<()> {
    let n = &t.names;
    let mut tx = client
        .transaction()
        .map_err(|e| t.err("begin schema check", e))?;
    tx.execute(
        "SELECT pg_advisory_xact_lock(hashtext($1))",
        &[&format!("{APPLICATION}:{}.{}", n.schema, n.table)],
    )
    .map_err(|e| t.err("schema lock", e))?;
    if let Marker::Absent = marker_state(&mut tx, t)? {
        if !check_schema_is_ours(&mut tx, t)? {
            tx.batch_execute(&format!("CREATE SCHEMA \"{}\"", n.schema))
                .map_err(|e| t.err("creating schema", e))?;
        }
        tx.batch_execute(&schema_sql(n))
            .map_err(|e| t.err("creating ledger tables", e))?;
    }
    tx.commit().map_err(|e| t.err("commit schema", e))
}

/// Connect and apply the session settings every store connection needs.
fn connect_target(t: &Target) -> Result<Client> {
    let mut client = t
        .config
        .connect(t.tls.clone())
        .map_err(|e| t.err("connect", e))?;
    let row = client
        .query_one(
            "SELECT current_setting('server_encoding'), \
                    current_setting('server_version_num')::int, \
                    current_setting('synchronous_commit')",
            &[],
        )
        .map_err(|e| t.err("session setup", e))?;
    let (encoding, version, sync): (String, i32, String) = (row.get(0), row.get(1), row.get(2));
    if encoding != "UTF8" {
        return Err(ProvioError::Ledger(format!(
            "postgres ledger {}: server encoding is {encoding}, not UTF8; records would not be \
             stored byte-exact",
            t.redacted
        )));
    }
    if version < MIN_SERVER_VERSION {
        return Err(ProvioError::Ledger(format!(
            "postgres ledger {}: server version {version} is too old (need PostgreSQL 11+)",
            t.redacted
        )));
    }
    if sync == "off" {
        client
            .batch_execute("SET synchronous_commit TO on")
            .map_err(|e| t.err("session setup", e))?;
    }
    Ok(client)
}

/// A raw client to the ledger's database, with the same URL handling as
/// the store (TLS and `sslmode`, `PG*` environment fallbacks, PROVIO's own
/// parameters removed). For tooling and tests; appends must go through
/// [`PostgresLedgerStore`].
pub fn connect(url: &str) -> Result<Client> {
    connect_target(&parse_target(url)?)
}

// ---------------------------------------------------------------------------
// Rows
// ---------------------------------------------------------------------------

/// Parse one row. The row key must agree with the record's own index.
fn decode_row(row: &::postgres::Row) -> (i64, Result<LedgerRecord>) {
    let idx: i64 = match row.try_get(0) {
        Ok(i) => i,
        Err(e) => {
            return (
                -1,
                Err(ProvioError::Ledger(format!("row key unreadable: {e}"))),
            )
        }
    };
    let text: std::result::Result<String, _> = row.try_get(1);
    let rec = (|| {
        let text = text.map_err(|e| {
            ProvioError::Ledger(format!(
                "row {idx}: record column is not readable text: {e}"
            ))
        })?;
        let rec: LedgerRecord = serde_json::from_str(&text)?;
        if i64::try_from(rec.index).ok() != Some(idx) {
            return Err(ProvioError::Ledger(format!(
                "row key {idx} does not match record index {}",
                rec.index
            )));
        }
        Ok(rec)
    })();
    (idx, rec)
}

fn tip_record(c: &mut impl GenericClient, t: &Target) -> Result<Option<LedgerRecord>> {
    let row = c
        .query_opt(
            &format!(
                "SELECT idx, record FROM {} ORDER BY idx DESC LIMIT 1",
                t.names.ledger
            ),
            &[],
        )
        .map_err(|e| t.err("reading tip", e))?;
    row.map(|r| decode_row(&r).1).transpose()
}

/// Something a cursor can run one page query on.
trait ClientHandle {
    fn with_client<R>(&mut self, f: impl Fn(&mut Client) -> Result<R>) -> Result<R>;
}

impl ClientHandle for &PostgresLedgerStore {
    fn with_client<R>(&mut self, f: impl Fn(&mut Client) -> Result<R>) -> Result<R> {
        self.read(f)
    }
}

impl ClientHandle for &mut Client {
    fn with_client<R>(&mut self, f: impl Fn(&mut Client) -> Result<R>) -> Result<R> {
        f(self)
    }
}

/// Owns a connection with a read-only snapshot transaction open on it; the
/// transaction is rolled back when the connection closes on drop.
struct Snapshot(Client);

impl ClientHandle for Snapshot {
    fn with_client<R>(&mut self, f: impl Fn(&mut Client) -> Result<R>) -> Result<R> {
        f(&mut self.0)
    }
}

/// Lazy, keyset-paginated scan in ascending `idx` order. A row that fails
/// to decode yields an `Err` item and the scan continues.
struct RowCursor<H> {
    handle: H,
    target: Arc<Target>,
    next_idx: i64,
    buf: VecDeque<Result<LedgerRecord>>,
    done: bool,
}

impl<H: ClientHandle> RowCursor<H> {
    fn new(handle: H, target: Arc<Target>) -> Self {
        RowCursor {
            handle,
            target,
            next_idx: 0,
            buf: VecDeque::new(),
            done: false,
        }
    }

    fn fill(&mut self) {
        let t = Arc::clone(&self.target);
        let from = self.next_idx;
        let sql = format!(
            "SELECT idx, record FROM {} WHERE idx >= $1 ORDER BY idx LIMIT $2",
            t.names.ledger
        );
        let page = self.handle.with_client(|c| {
            c.query(&sql, &[&from, &PAGE_SIZE])
                .map_err(|e| t.err("reading records", e))
        });
        match page {
            Err(e) => {
                self.buf.push_back(Err(e));
                self.done = true;
            }
            Ok(rows) => {
                if (rows.len() as i64) < PAGE_SIZE {
                    self.done = true;
                }
                for row in &rows {
                    let (idx, rec) = decode_row(row);
                    match idx.checked_add(1) {
                        Some(n) if idx >= 0 => self.next_idx = n,
                        _ => self.done = true,
                    }
                    self.buf.push_back(rec);
                }
            }
        }
    }
}

impl<H: ClientHandle> Iterator for RowCursor<H> {
    type Item = Result<LedgerRecord>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.is_empty() && !self.done {
            self.fill();
        }
        self.buf.pop_front()
    }
}

// ---------------------------------------------------------------------------
// The store
// ---------------------------------------------------------------------------

/// Append-only Postgres ledger. See the [module docs](self) for schema,
/// TLS and concurrency guarantees.
pub struct PostgresLedgerStore {
    target: Arc<Target>,
    client: RefCell<Client>,
    /// Last length observed; only a fallback for the infallible `len()`.
    /// `append` never trusts it — it re-reads the tip under the lock.
    len: Cell<u64>,
}

impl fmt::Debug for PostgresLedgerStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PostgresLedgerStore")
            .field("url", &self.target.redacted)
            .field("schema", &self.target.names.schema)
            .field("table", &self.target.names.table)
            .finish_non_exhaustive()
    }
}

/// Outcome of one append attempt on one connection.
enum Attempt {
    Done,
    /// `BEGIN` failed on a connection the server had closed: nothing was
    /// sent that could have written, so reconnecting and retrying is safe.
    Reconnect(ProvioError),
}

impl PostgresLedgerStore {
    /// Connect to the ledger at `url`, creating its schema objects if
    /// absent, and validate the stored chain links. A schema that is not a
    /// PROVIO ledger, or whose chain is broken, is a `ProvioError::Ledger`.
    pub fn open(url: impl AsRef<str>) -> Result<Self> {
        let target = Arc::new(parse_target(url.as_ref())?);
        let mut client = connect_target(&target)?;
        init_or_check_schema(&mut client, &target)?;
        let store = PostgresLedgerStore {
            target,
            client: RefCell::new(client),
            len: Cell::new(0),
        };
        store.rescan()?;
        Ok(store)
    }

    /// The ledger URL with its password redacted.
    pub fn url(&self) -> &str {
        &self.target.redacted
    }

    /// Schema holding the ledger (`provio_schema`, default `provio`).
    pub fn schema(&self) -> &str {
        &self.target.names.schema
    }

    /// Ledger table name (`provio_table`, default `ledger`).
    pub fn table(&self) -> &str {
        &self.target.names.table
    }

    fn borrow(&self) -> Result<RefMut<'_, Client>> {
        self.client
            .try_borrow_mut()
            .map_err(|_| ProvioError::Ledger("postgres ledger: connection already in use".into()))
    }

    /// Run a read, reconnecting and retrying once if the server had closed
    /// the connection (a restart or failover must not wedge a long-lived
    /// reader). Reads are idempotent, so the retry is always safe.
    fn read<R>(&self, f: impl Fn(&mut Client) -> Result<R>) -> Result<R> {
        let mut c = self.borrow()?;
        match f(&mut c) {
            Err(_) if c.is_closed() => {
                *c = connect_target(&self.target)?;
                f(&mut c)
            }
            other => other,
        }
    }

    /// Cheap link checks only (index sequence + prev_hash chain + every row
    /// parses), mirroring the other stores' `open`; full hash verification
    /// is [`verify_postgres`].
    fn rescan(&self) -> Result<()> {
        let t = &*self.target;
        let mut guard = self.borrow()?;
        let client: &mut Client = &mut guard;
        client
            .batch_execute("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .map_err(|e| t.err("begin scan", e))?;
        let scanned = (|| {
            let mut expected = 0u64;
            let mut prev = GENESIS_HASH.to_string();
            for item in RowCursor::new(&mut *client, Arc::clone(&self.target)) {
                let rec = item.map_err(|e| {
                    ProvioError::Ledger(format!(
                        "postgres ledger {}: corrupt record at index {} (mid-ledger corruption): {}",
                        t.redacted, expected, e
                    ))
                })?;
                if rec.index != expected {
                    return Err(ProvioError::Ledger(format!(
                        "postgres ledger {}: record index {} out of sequence (expected {})",
                        t.redacted, rec.index, expected
                    )));
                }
                if rec.prev_hash != prev {
                    return Err(ProvioError::Ledger(format!(
                        "postgres ledger {}: record {} prev_hash does not match the chain tip",
                        t.redacted, rec.index
                    )));
                }
                prev = rec.record_hash;
                expected += 1;
            }
            Ok(expected)
        })();
        let end = if scanned.is_ok() {
            "COMMIT"
        } else {
            "ROLLBACK"
        };
        client
            .batch_execute(end)
            .map_err(|e| t.err("end scan", e))?;
        self.len.set(scanned?);
        Ok(())
    }

    /// One append transaction (see the module docs). Transaction control is
    /// plain SQL so a failed `BEGIN` can be told apart from a later failure.
    fn append_once(
        &self,
        client: &mut Client,
        record: &LedgerRecord,
        idx: i64,
        line: &str,
    ) -> Result<Attempt> {
        let t = &*self.target;
        let n = &t.names;
        // READ COMMITTED explicitly: each statement takes a fresh snapshot,
        // so the tip read after the lock sees every committed append (a
        // server default of REPEATABLE READ would pin a stale snapshot).
        if let Err(e) = client.batch_execute(&format!(
            "BEGIN ISOLATION LEVEL READ COMMITTED; SET LOCAL lock_timeout = '{}ms'",
            LOCK_TIMEOUT.as_millis()
        )) {
            let err = t.err("begin append", e);
            if client.is_closed() {
                return Ok(Attempt::Reconnect(err));
            }
            let _ = client.batch_execute("ROLLBACK");
            return Err(err);
        }
        let body = (|| -> Result<u64> {
            // The append lock. Also re-confirms the marker on every append.
            let version: Option<i32> = client
                .query_opt(
                    &format!(
                        "SELECT store_version FROM {} WHERE singleton FOR UPDATE",
                        n.meta
                    ),
                    &[],
                )
                .map_err(|e| t.err("taking the append lock", e))?
                .map(|r| r.get(0));
            if version != Some(STORE_VERSION) {
                return Err(ProvioError::Ledger(format!(
                    "postgres ledger {}: marker row missing or changed; refusing to append",
                    t.redacted
                )));
            }
            let (len, tip_hash) = match tip_record(&mut *client, t)? {
                Some(tip) => (tip.index + 1, tip.record_hash),
                None => (0, GENESIS_HASH.to_string()),
            };
            if record.index != len {
                return Err(ProvioError::Ledger(format!(
                    "append rejected: record index {} but ledger length is {} \
                     (records are append-only and sequential)",
                    record.index, len
                )));
            }
            if record.prev_hash != tip_hash {
                return Err(ProvioError::Ledger(format!(
                    "append rejected: record {} prev_hash does not match the ledger tip",
                    record.index
                )));
            }
            client
                .execute(
                    &format!("INSERT INTO {} (idx, record) VALUES ($1, $2)", n.ledger),
                    &[&idx, &line],
                )
                .map_err(|e| t.err("insert", e))?;
            // With synchronous_commit on, durable once COMMIT returns.
            client
                .batch_execute("COMMIT")
                .map_err(|e| t.err("commit append", e))?;
            Ok(len + 1)
        })();
        match body {
            Ok(len) => {
                self.len.set(len);
                Ok(Attempt::Done)
            }
            Err(e) => {
                // Best effort: a broken connection rolls back on its own.
                let _ = client.batch_execute("ROLLBACK");
                Err(e)
            }
        }
    }
}

impl LedgerStore for PostgresLedgerStore {
    fn append(&mut self, record: &LedgerRecord) -> Result<()> {
        let idx = i64::try_from(record.index).map_err(|_| {
            ProvioError::Ledger(format!(
                "append rejected: record index {} exceeds the Postgres key range",
                record.index
            ))
        })?;
        // Content check needs no lock: a record whose hash is not its own
        // would verify as broken the moment it landed.
        if record.compute_hash()? != record.record_hash {
            return Err(ProvioError::Ledger(format!(
                "append rejected: record {} record_hash does not match its contents",
                record.index
            )));
        }
        let line = serde_json::to_string(record)?;
        let mut client = self.borrow()?;
        match self.append_once(&mut client, record, idx, &line)? {
            Attempt::Done => Ok(()),
            Attempt::Reconnect(first) => {
                *client = connect_target(&self.target).map_err(|_| first)?;
                match self.append_once(&mut client, record, idx, &line)? {
                    Attempt::Done => Ok(()),
                    Attempt::Reconnect(e) => Err(e),
                }
            }
        }
    }

    fn tip(&self) -> Result<Option<LedgerRecord>> {
        self.read(|c| tip_record(c, &self.target))
    }

    fn get(&self, index: u64) -> Result<Option<LedgerRecord>> {
        let Ok(idx) = i64::try_from(index) else {
            return Ok(None);
        };
        let t = &*self.target;
        let sql = format!("SELECT idx, record FROM {} WHERE idx = $1", t.names.ledger);
        let row = self.read(|c| {
            c.query_opt(&sql, &[&idx])
                .map_err(|e| t.err("reading record", e))
        })?;
        row.map(|r| decode_row(&r).1).transpose()
    }

    /// Next index to append, read from the database (so appends by other
    /// hosts are visible). Falls back to the last observed value only if
    /// the query itself fails; `append` re-checks under the lock.
    fn len(&self) -> u64 {
        let t = &*self.target;
        let sql = format!("SELECT COALESCE(MAX(idx) + 1, 0) FROM {}", t.names.ledger);
        let n = self.read(|c| {
            c.query_one(&sql, &[])
                .and_then(|r| r.try_get::<_, i64>(0))
                .map_err(|e| t.err("reading length", e))
        });
        match n {
            Ok(n) => {
                let n = u64::try_from(n).unwrap_or(0);
                self.len.set(n);
                n
            }
            Err(_) => self.len.get(),
        }
    }

    fn iter(&self) -> Box<dyn Iterator<Item = Result<LedgerRecord>> + '_> {
        Box::new(RowCursor::new(self, Arc::clone(&self.target)))
    }
}

// ---------------------------------------------------------------------------
// Read-only access (verify, log, show)
// ---------------------------------------------------------------------------

/// Read-only record stream over the ledger at `url`, inside one
/// `REPEATABLE READ READ ONLY` transaction (a consistent snapshot for the
/// whole scan). Never creates anything; a missing ledger is an error.
pub(crate) fn read_only_records(
    url: &str,
) -> Result<Box<dyn Iterator<Item = Result<LedgerRecord>>>> {
    let target = Arc::new(parse_target(url)?);
    let mut client = connect_target(&target)?;
    client
        .batch_execute("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .map_err(|e| target.err("begin scan", e))?;
    if let Marker::Absent = marker_state(&mut client, &target)? {
        return Err(ProvioError::Ledger(format!(
            "postgres ledger {}: no PROVIO ledger at {}.{}",
            target.redacted, target.names.schema, target.names.table
        )));
    }
    Ok(Box::new(RowCursor::new(Snapshot(client), target)))
}

/// Verify the hash chain of the Postgres ledger at `url` without opening it
/// as a store (so a ledger too damaged to open can still be diagnosed).
///
/// Same contract as [`verify`](crate::verify()): a record that fails its
/// hash, its chain link, or cannot be decoded at all (including a row key
/// that disagrees with the record's index) is reported as
/// `broken_at: Some(i)`.
pub fn verify_postgres(url: impl AsRef<str>) -> Result<VerifyReport> {
    verify_records(read_only_records(url.as_ref())?)
}
