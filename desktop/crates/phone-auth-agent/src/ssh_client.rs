//! Asking a paired phone to sign an SSH login.
//!
//! `SYS-02`. The mirror of `vault.rs`: one `ApplicationFrame` over an
//! authenticated session, one answer, and no path where a failure can be
//! mistaken for a signature.
//!
//! The frame carries the SSH blob itself, because a server accepts a signature
//! over exactly those bytes. What keeps that from being a blind signing oracle
//! is on the phone — it re-parses the blob and signs nothing it cannot name an
//! account for. This side's reading only draws the prompt.

use phone_auth_protocol::ssh::{SignRequest, SignResponse, OPERATION_SIGN};
use phone_auth_protocol::{
    ApplicationErrorCode, ApplicationFrame, ApplicationFrameKind, PROTOCOL_VERSION,
};
use phone_auth_verifier::verifier::now_ms;
use phone_auth_verifier::{random, SecureSession};
use zeroize::Zeroize;

use crate::vault::VaultError;

/// How long a request stays valid. Long enough for a person to read a prompt
/// and answer it, short enough that a captured frame is useless later.
const VALIDITY_MS: i64 = 90_000;

const RECEIVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(90);

/// The SSH half of a paired phone.
pub struct PhoneSsh<'a> {
    session: &'a mut Box<dyn SecureSession + Send>,
    verifier_name: String,
}

impl<'a> PhoneSsh<'a> {
    pub fn new(
        session: &'a mut Box<dyn SecureSession + Send>,
        verifier_name: impl Into<String>,
    ) -> Self {
        Self {
            session,
            verifier_name: verifier_name.into(),
        }
    }

    /// Asks the phone to sign one SSH authentication request.
    ///
    /// `destination` is what this computer believes the connection is going
    /// to, and is passed through as a claim: the phone cannot check it and
    /// shows it as something the computer said.
    pub fn sign(&mut self, data: &[u8], destination: &str) -> Result<Vec<u8>, VaultError> {
        let request = SignRequest {
            verifier_name: self.verifier_name.clone(),
            destination: destination.to_owned(),
            data: data.to_vec(),
        };
        request
            .validate()
            .map_err(|error| VaultError::protocol(error.to_string()))?;

        let payload = self.exchange(OPERATION_SIGN, request.encode())?;
        let response = SignResponse::decode(&payload)
            .map_err(|error| VaultError::protocol(error.to_string()))?;
        Ok(response.signature)
    }

    /// Sends one frame and returns the payload of the matching reply.
    ///
    /// The same shape as the vault's exchange, and for the same reasons: a
    /// decoded envelope is not an authorization, and the reply has to be the
    /// answer to the request still pending, in this session, unexpired.
    fn exchange(&mut self, operation: &str, payload: Vec<u8>) -> Result<Vec<u8>, VaultError> {
        if !self.session.security().suitable_for_authorization() {
            return Err(VaultError::protocol(
                "signing needs an authenticated confidential session",
            ));
        }
        let issued_at_ms = now_ms();
        let request = ApplicationFrame {
            protocol_version: PROTOCOL_VERSION,
            kind: ApplicationFrameKind::Request,
            request_id: random::request_id(),
            session_binding: self.session.session_binding(),
            operation: operation.to_owned(),
            issued_at_ms,
            expires_at_ms: issued_at_ms + VALIDITY_MS,
            payload,
        };
        request
            .validate()
            .map_err(|error| VaultError::protocol(error.to_string()))?;

        self.session
            .send(&request.encode())
            .map_err(|_| VaultError::Unavailable)?;
        let mut raw = self
            .session
            .receive(RECEIVE_TIMEOUT)
            .map_err(|_| VaultError::Unavailable)?;

        let reply = ApplicationFrame::decode(&raw);
        raw.zeroize();
        let reply = reply.map_err(|error| VaultError::protocol(error.to_string()))?;

        if !reply.is_reply_to(&request, now_ms()) {
            return Err(VaultError::protocol(
                "the phone answered a different request",
            ));
        }
        if reply.kind == ApplicationFrameKind::Error {
            // A refusal that will not decode is still a refusal. Falling back
            // to `Declined` keeps a malformed error from reading as anything
            // softer than a no.
            return Err(match ApplicationErrorCode::decode(&reply.payload) {
                Ok(ApplicationErrorCode::Unavailable) => VaultError::Unavailable,
                _ => VaultError::Declined,
            });
        }
        if reply.kind != ApplicationFrameKind::Response {
            return Err(VaultError::protocol("the phone sent an unexpected frame"));
        }
        Ok(reply.payload)
    }
}
