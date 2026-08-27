//! The boundary between the protocol and whatever moves its bytes.
//!
//! A session carries opaque frames and reports two things the verifier acts
//! on: whether the channel is confidential and peer-authenticated, and the
//! session binding folded into the signed request. Everything else about a
//! transport — addresses, signal strength, hostnames — is a hint and never
//! reaches the authorization decision.
//!
//! # Where the binding comes from
//!
//! Not from here. The verifier reads a binding; it does not derive one. The
//! single derivation lives in `phone_auth_session::keys::session_binding`,
//! next to the handshake that produces its inputs, because two copies of a
//! derivation that must match on two devices is exactly the kind of thing that
//! drifts and then fails as an unexplained mismatch on every request.

use std::io;
use std::time::Duration;

use phone_auth_protocol::SESSION_BINDING_LEN;

/// What a transport claims about the channel it established.
///
/// These are claims by the transport implementation about its own handshake,
/// not measurements. A transport that cannot honestly set `confidential` and
/// `peer_authenticated` must report `false` and will be refused for sensitive
/// authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportSecurity {
    pub transport_name: String,
    /// The channel encrypts frames end to end between verifier and phone.
    pub confidential: bool,
    /// The peer proved possession of the key this session is bound to.
    pub peer_authenticated: bool,
    pub requires_network: bool,
    /// Whether the transport implies physical proximity. Recorded for display
    /// and policy only. Proximity is never authorization.
    pub proximity_signal: bool,
    /// True for in-process fixtures that stand in for a real transport.
    ///
    /// A development transport never carries a boot-time flow, and every UI
    /// surface that shows a session shows this. It exists so that "it worked
    /// on my machine" cannot quietly mean "it worked against a simulator".
    pub is_development: bool,
}

impl TransportSecurity {
    /// Whether this channel may carry sensitive authorization at all.
    pub fn suitable_for_authorization(&self) -> bool {
        self.confidential && self.peer_authenticated
    }
}

/// An established, framed channel to an authenticator.
pub trait SecureSession {
    /// Human-readable description of where the session came from, shown to the
    /// user. Never used as identity.
    fn origin_label(&self) -> &str;

    /// Handshake-derived binding, echoed inside the signed request so a
    /// response captured on one session cannot be replayed on another.
    fn session_binding(&self) -> [u8; SESSION_BINDING_LEN];

    fn security(&self) -> &TransportSecurity;

    fn send(&mut self, frame: &[u8]) -> io::Result<()>;

    fn receive(&mut self, timeout: Duration) -> io::Result<Vec<u8>>;

    fn close(&mut self) -> io::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_channel_missing_either_property_is_unsuitable() {
        let mut security = TransportSecurity {
            transport_name: "test".into(),
            confidential: true,
            peer_authenticated: true,
            requires_network: false,
            proximity_signal: false,
            is_development: true,
        };
        assert!(security.suitable_for_authorization());

        security.confidential = false;
        assert!(!security.suitable_for_authorization());

        security.confidential = true;
        security.peer_authenticated = false;
        assert!(!security.suitable_for_authorization());

        security.confidential = false;
        assert!(!security.suitable_for_authorization());
    }
}
