//! The pairing bootstrap: what a QR code carries.
//!
//! # Why the QR matters
//!
//! It is the only authenticated channel that exists before pairing. A phone
//! that has never met this desktop has no way to tell the desktop's handshake
//! key from an attacker's — except that the user physically pointed a camera
//! at this screen. Carrying a commitment to the verifier's identity key is
//! what converts that physical act into a cryptographic check.
//!
//! # What it does not carry
//!
//! No private key, no long-term secret, nothing that authorizes anything. The
//! nonce is single-use and the whole thing expires in minutes. Someone who
//! photographs the code learns which desktop it belongs to and can attempt to
//! connect; they cannot impersonate the desktop, and the verification code
//! shown after the handshake is what stops them from quietly pairing instead
//! of the user.

use phone_auth_protocol::encoding::{from_base64url, to_base64url};

use crate::identity::IdentityKey;
use crate::SessionError;

/// URL scheme and path the phone scans.
pub const BOOTSTRAP_PREFIX: &str = "phoneauth://pair/v1?";

/// Default lifetime of a bootstrap.
pub const DEFAULT_LIFETIME_MS: i64 = 120_000;

/// The contents of a pairing QR code. Both ends hold the same values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerBootstrap {
    pub session_id: String,
    /// 32 fresh bytes, tying one scan to one handshake.
    pub nonce: [u8; 32],
    pub verifier_id: String,
    /// SHA-256 of the verifier's handshake identity SPKI.
    pub verifier_identity_hash: [u8; 32],
    /// Where to connect, e.g. `192.168.1.10:8765`. Empty when the transport
    /// does not need an address, as with BLE.
    pub endpoint: String,
    /// Milliseconds since the Unix epoch, after which this must be refused.
    pub expires_at_ms: i64,
}

impl ServerBootstrap {
    /// Builds a fresh bootstrap for `identity`.
    pub fn new(
        session_id: impl Into<String>,
        verifier_id: impl Into<String>,
        endpoint: impl Into<String>,
        identity: &IdentityKey,
        now_ms: i64,
        lifetime_ms: i64,
    ) -> Result<Self, SessionError> {
        let mut nonce = [0u8; 32];
        getrandom::getrandom(&mut nonce).expect("operating system CSPRNG is unavailable");

        let bootstrap = Self {
            session_id: session_id.into(),
            nonce,
            verifier_id: verifier_id.into(),
            verifier_identity_hash: identity.public_key_hash()?,
            endpoint: endpoint.into(),
            expires_at_ms: now_ms.saturating_add(lifetime_ms.max(1)),
        };
        bootstrap.validate()?;
        Ok(bootstrap)
    }

    pub fn validate(&self) -> Result<(), SessionError> {
        if self.session_id.is_empty() || self.session_id.len() > 64 {
            return Err(SessionError::InvalidBootstrap("invalid session identifier"));
        }
        if self.verifier_id.is_empty() || self.verifier_id.len() > 64 {
            return Err(SessionError::InvalidBootstrap("invalid verifier identifier"));
        }
        if self.endpoint.len() > 128 {
            return Err(SessionError::InvalidBootstrap("endpoint is too long"));
        }
        // The separators used by the query encoding must not appear inside a
        // value, or a round trip would silently split a field in two.
        for field in [&self.session_id, &self.verifier_id, &self.endpoint] {
            if field.contains('&') || field.contains('=') {
                return Err(SessionError::InvalidBootstrap(
                    "bootstrap fields may not contain `&` or `=`",
                ));
            }
        }
        Ok(())
    }

    pub fn is_expired_at(&self, now_ms: i64) -> bool {
        now_ms >= self.expires_at_ms
    }

    /// Renders the scannable string.
    pub fn to_uri(&self) -> String {
        format!(
            "{BOOTSTRAP_PREFIX}vid={}&sid={}&n={}&k={}&ep={}&exp={}",
            self.verifier_id,
            self.session_id,
            to_base64url(&self.nonce),
            to_base64url(&self.verifier_identity_hash),
            self.endpoint,
            self.expires_at_ms
        )
    }

    /// Parses a scanned string.
    ///
    /// Every field is required. A bootstrap missing its identity hash would
    /// leave the phone with nothing to authenticate the desktop against, so an
    /// absent field fails rather than defaulting.
    pub fn from_uri(uri: &str) -> Result<Self, SessionError> {
        let query = uri
            .strip_prefix(BOOTSTRAP_PREFIX)
            .ok_or(SessionError::InvalidBootstrap(
                "not a PhoneAuth v1 pairing bootstrap",
            ))?;

        let mut verifier_id = None;
        let mut session_id = None;
        let mut nonce = None;
        let mut hash = None;
        let mut endpoint = None;
        let mut expires_at_ms = None;

        for pair in query.split('&') {
            let (key, value) = pair
                .split_once('=')
                .ok_or(SessionError::InvalidBootstrap("malformed bootstrap field"))?;
            match key {
                "vid" => verifier_id = Some(value.to_owned()),
                "sid" => session_id = Some(value.to_owned()),
                "n" => nonce = Some(fixed_b64(value, "invalid bootstrap nonce")?),
                "k" => hash = Some(fixed_b64(value, "invalid verifier identity hash")?),
                "ep" => endpoint = Some(value.to_owned()),
                "exp" => {
                    expires_at_ms = Some(value.parse::<i64>().map_err(|_| {
                        SessionError::InvalidBootstrap("invalid bootstrap expiry")
                    })?)
                }
                // Unknown keys fail closed. A future version that adds a
                // meaningful field must not be silently half-understood.
                _ => return Err(SessionError::InvalidBootstrap("unknown bootstrap field")),
            }
        }

        let missing = || SessionError::InvalidBootstrap("bootstrap is missing a required field");
        let bootstrap = Self {
            session_id: session_id.ok_or_else(missing)?,
            nonce: nonce.ok_or_else(missing)?,
            verifier_id: verifier_id.ok_or_else(missing)?,
            verifier_identity_hash: hash.ok_or_else(missing)?,
            endpoint: endpoint.ok_or_else(missing)?,
            expires_at_ms: expires_at_ms.ok_or_else(missing)?,
        };
        bootstrap.validate()?;
        Ok(bootstrap)
    }
}

fn fixed_b64(value: &str, message: &'static str) -> Result<[u8; 32], SessionError> {
    from_base64url(value)
        .map_err(|_| SessionError::InvalidBootstrap(message))?
        .try_into()
        .map_err(|_| SessionError::InvalidBootstrap(message))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_787_745_600_000;

    fn bootstrap() -> ServerBootstrap {
        ServerBootstrap::new(
            "session-1",
            "desktop-1",
            "192.168.1.10:8765",
            &IdentityKey::generate(),
            NOW,
            DEFAULT_LIFETIME_MS,
        )
        .expect("bootstrap")
    }

    #[test]
    fn round_trips_through_its_uri() {
        let original = bootstrap();
        let parsed = ServerBootstrap::from_uri(&original.to_uri()).expect("parse");
        assert_eq!(parsed, original);
    }

    #[test]
    fn the_uri_carries_the_identity_commitment() {
        let identity = IdentityKey::generate();
        let bootstrap = ServerBootstrap::new(
            "session-1",
            "desktop-1",
            "",
            &identity,
            NOW,
            DEFAULT_LIFETIME_MS,
        )
        .expect("bootstrap");

        assert_eq!(
            bootstrap.verifier_identity_hash,
            identity.public_key_hash().expect("hash"),
            "without this the phone cannot authenticate the desktop on first contact"
        );
        assert!(bootstrap.to_uri().starts_with(BOOTSTRAP_PREFIX));
    }

    #[test]
    fn the_uri_carries_no_private_material() {
        let identity = IdentityKey::generate();
        let uri = ServerBootstrap::new(
            "session-1",
            "desktop-1",
            "",
            &identity,
            NOW,
            DEFAULT_LIFETIME_MS,
        )
        .expect("bootstrap")
        .to_uri();

        let private = identity.to_pkcs8_der().expect("encode");
        assert!(
            !uri.contains(&to_base64url(&private)),
            "a bootstrap must never carry a private key"
        );
        // Nor should the full public key: only its hash belongs in the code.
        let spki = identity.public_key_spki().expect("spki");
        assert!(!uri.contains(&to_base64url(&spki)));
    }

    #[test]
    fn nonces_differ_between_bootstraps() {
        assert_ne!(bootstrap().nonce, bootstrap().nonce);
    }

    #[test]
    fn expiry_is_enforced_at_the_boundary() {
        let bootstrap = bootstrap();
        assert!(!bootstrap.is_expired_at(bootstrap.expires_at_ms - 1));
        assert!(bootstrap.is_expired_at(bootstrap.expires_at_ms));
        assert!(bootstrap.is_expired_at(bootstrap.expires_at_ms + 1));
    }

    #[test]
    fn a_foreign_scheme_is_refused() {
        for uri in [
            "https://example.com/pair?vid=a",
            "phoneauth://pair/v2?vid=a",
            "",
        ] {
            assert!(
                matches!(
                    ServerBootstrap::from_uri(uri),
                    Err(SessionError::InvalidBootstrap(_))
                ),
                "`{uri}` must be refused"
            );
        }
    }

    #[test]
    fn a_missing_field_is_refused() {
        let full = bootstrap().to_uri();
        for key in ["vid", "sid", "n", "k", "ep", "exp"] {
            let query = full
                .strip_prefix(BOOTSTRAP_PREFIX)
                .expect("prefix")
                .split('&')
                .filter(|pair| !pair.starts_with(&format!("{key}=")))
                .collect::<Vec<_>>()
                .join("&");

            assert!(
                ServerBootstrap::from_uri(&format!("{BOOTSTRAP_PREFIX}{query}")).is_err(),
                "a bootstrap without `{key}` must be refused"
            );
        }
    }

    #[test]
    fn an_unknown_field_is_refused() {
        let uri = format!("{}&surprise=1", bootstrap().to_uri());
        assert!(matches!(
            ServerBootstrap::from_uri(&uri),
            Err(SessionError::InvalidBootstrap(_))
        ));
    }

    #[test]
    fn wrong_length_nonces_and_hashes_are_refused() {
        // A 32-byte field decoded from a shorter string would leave the rest
        // of the buffer as zeroes, which is exactly the kind of quiet
        // truncation a fixed-size field exists to prevent.
        for (nonce, hash) in [
            (to_base64url(&[1u8; 16]), to_base64url(&[2u8; 32])),
            (to_base64url(&[1u8; 32]), to_base64url(&[2u8; 31])),
            ("not base64url!".to_owned(), to_base64url(&[2u8; 32])),
        ] {
            let uri = format!(
                "{BOOTSTRAP_PREFIX}vid=desktop-1&sid=session-1&n={nonce}&k={hash}&ep=&exp={NOW}"
            );
            assert!(
                matches!(
                    ServerBootstrap::from_uri(&uri),
                    Err(SessionError::InvalidBootstrap(_))
                ),
                "must refuse nonce `{nonce}` with hash `{hash}`"
            );
        }
    }

    #[test]
    fn separators_may_not_appear_inside_a_field() {
        // Otherwise `to_uri` and `from_uri` disagree about where a value ends.
        let mut bootstrap = bootstrap();
        bootstrap.endpoint = "host:1&vid=attacker".into();
        assert!(matches!(
            bootstrap.validate(),
            Err(SessionError::InvalidBootstrap(_))
        ));
    }

    #[test]
    fn an_empty_endpoint_is_allowed_for_transports_without_addresses() {
        let bootstrap = ServerBootstrap::new(
            "session-1",
            "desktop-1",
            "",
            &IdentityKey::generate(),
            NOW,
            DEFAULT_LIFETIME_MS,
        )
        .expect("BLE has no endpoint to publish");
        assert_eq!(
            ServerBootstrap::from_uri(&bootstrap.to_uri()).expect("parse"),
            bootstrap
        );
    }
}
