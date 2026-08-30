//! The agent's half of the File Locker: asking a phone to wrap or unwrap a
//! container's data key.
//!
//! The engine in `phone-auth-locker` knows nothing about transports, and this
//! module knows nothing about the container format. They meet at
//! [`phone_auth_locker::KeyCustodian`], which is the only place a data key
//! crosses between them.
//!
//! Two rules hold here. A data key travels only inside an authenticated,
//! confidential session, and it is never written to the audit log, an IPC
//! reply, an event, or an error message. Neither is a recovery code: it is
//! written to the file the caller named and nowhere else.

use std::time::Duration;

use phone_auth_locker::{
    KeyCustodian, LockerError, UnwrapRequest as EngineUnwrapRequest,
    WrapRequest as EngineWrapRequest, Wrapper, WrapperKind,
};
use phone_auth_protocol::locker::{
    UnwrapRequest, UnwrapResponse, WrapRequest, WrapResponse, OPERATION_CREATE, OPERATION_REKEY,
    OPERATION_UNLOCK,
};
use phone_auth_protocol::{ApplicationFrame, ApplicationFrameKind, PROTOCOL_VERSION};
use phone_auth_verifier::verifier::now_ms;
use phone_auth_verifier::{random, SecureSession};

/// How long to wait for the user to answer a locker prompt.
const RECEIVE_TIMEOUT: Duration = Duration::from_secs(90);

/// How long a locker request stays valid, matching the envelope's ceiling.
const VALIDITY_MS: i64 = 120_000;

/// A phone, reached by opening a session for each request put to it.
///
/// A session carries exactly one application request: the phone answers on it
/// and closes it on the way out. Holding a single session, a custodian could
/// serve a `wrap` or an `unwrap` but never both -- and a rekey is exactly
/// both, so `locker rekey` unwrapped the old key and then spoke its `wrap`
/// into a socket that was already gone.
pub struct PhoneCustodian<'a> {
    /// Dials the phone again. Answering a request is what spends a session, so
    /// this is called once per exchange rather than once per custodian.
    open: Box<dyn FnMut() -> Result<Box<dyn SecureSession + Send>, LockerError> + 'a>,
    verifier_name: String,
    /// Which credential the desktop believes it is talking to. The phone
    /// decides for itself, and a mismatch shows up as a failed unwrap rather
    /// than as a key handed to the wrong credential.
    credential_id: String,
    /// True when a `locker.rekey` prompt should be shown instead of an unlock.
    rekeying: bool,
}

impl<'a> PhoneCustodian<'a> {
    pub fn new(
        open: impl FnMut() -> Result<Box<dyn SecureSession + Send>, LockerError> + 'a,
        verifier_name: impl Into<String>,
        credential_id: impl Into<String>,
    ) -> Self {
        Self {
            open: Box::new(open),
            verifier_name: verifier_name.into(),
            credential_id: credential_id.into(),
            rekeying: false,
        }
    }

    /// Makes the next unwrap ask for re-keying authority rather than a plain
    /// unlock, so the phone tells the user what is really about to happen.
    pub fn rekeying(mut self) -> Self {
        self.rekeying = true;
        self
    }

    /// Opens a session, sends one application frame on it, and closes it.
    fn exchange(&mut self, operation: &str, payload: Vec<u8>) -> Result<Vec<u8>, LockerError> {
        let mut session = (self.open)()?;
        let answered = self.exchange_on(&mut session, operation, payload);
        let _ = session.close();
        answered
    }

    /// Sends one application frame and returns the payload of the matching
    /// reply, or an error nobody can mistake for a grant.
    fn exchange_on(
        &self,
        session: &mut Box<dyn SecureSession + Send>,
        operation: &str,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, LockerError> {
        if !session.security().suitable_for_authorization() {
            return Err(LockerError::Denied(
                "the locker needs an authenticated confidential session".into(),
            ));
        }
        let issued_at_ms = now_ms();
        let request = ApplicationFrame {
            protocol_version: PROTOCOL_VERSION,
            kind: ApplicationFrameKind::Request,
            request_id: random::request_id(),
            session_binding: session.session_binding(),
            operation: operation.to_owned(),
            issued_at_ms,
            expires_at_ms: issued_at_ms + VALIDITY_MS,
            payload,
        };
        request
            .validate()
            .map_err(|error| LockerError::Denied(error.to_string()))?;

        session
            .send(&request.encode())
            .map_err(|error| LockerError::Denied(error.to_string()))?;
        let raw = session
            .receive(RECEIVE_TIMEOUT)
            .map_err(|error| LockerError::Denied(error.to_string()))?;

        let reply = ApplicationFrame::decode(&raw)
            .map_err(|error| LockerError::Denied(error.to_string()))?;
        // Decoding an envelope is not authorization: the reply has to be the
        // answer to the request still pending, in this session, unexpired.
        if !reply.is_reply_to(&request, now_ms()) {
            return Err(LockerError::Denied(
                "the phone answered a different request".into(),
            ));
        }
        if reply.kind == ApplicationFrameKind::Error {
            return Err(LockerError::Denied(
                "the phone declined the locker request".into(),
            ));
        }
        Ok(reply.payload)
    }
}

impl KeyCustodian for PhoneCustodian<'_> {
    fn wrap(&mut self, request: &EngineWrapRequest<'_>) -> phone_auth_locker::Result<Wrapper> {
        let payload = WrapRequest {
            verifier_name: self.verifier_name.clone(),
            file_name: request.file_name.clone(),
            plaintext_len: request.plaintext_len,
            container_binding: request.binding,
            data_key: request.dek.expose().to_vec(),
        };
        payload
            .validate()
            .map_err(|error| LockerError::Denied(error.to_string()))?;

        let answer = self.exchange(OPERATION_CREATE, payload.encode())?;
        let decoded = WrapResponse::decode(&answer)
            .map_err(|error| LockerError::Denied(error.to_string()))?;
        Ok(Wrapper {
            kind: WrapperKind::Phone,
            id: decoded.credential_id,
            salt: Vec::new(),
            nonce: Vec::new(),
            ciphertext: decoded.wrapper,
        })
    }

    fn unwrap(
        &mut self,
        request: &EngineUnwrapRequest<'_>,
    ) -> phone_auth_locker::Result<phone_auth_locker::Dek> {
        if request.wrapper.kind != WrapperKind::Phone {
            return Err(LockerError::NoWrapper(WrapperKind::Phone));
        }
        let payload = UnwrapRequest {
            verifier_name: self.verifier_name.clone(),
            file_name: request.container_name.clone(),
            plaintext_len: request.plaintext_len,
            container_binding: request.binding,
            credential_id: self.credential_id.clone(),
            wrapper: request.wrapper.ciphertext.clone(),
        };
        payload
            .validate()
            .map_err(|error| LockerError::Denied(error.to_string()))?;

        let operation = if self.rekeying {
            OPERATION_REKEY
        } else {
            OPERATION_UNLOCK
        };
        let answer = self.exchange(operation, payload.encode())?;
        let decoded = UnwrapResponse::decode(&answer)
            .map_err(|error| LockerError::Denied(error.to_string()))?;
        phone_auth_locker::Dek::from_slice(&decoded.data_key).ok_or(LockerError::Corrupt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use phone_auth_locker::Dek;
    use phone_auth_verifier::session::TransportSecurity;
    use std::io;

    /// Builds the phone's answer to one request frame.
    type Answer = Box<dyn Fn(&ApplicationFrame) -> Vec<u8> + Send>;

    /// A session that answers with whatever the test queued.
    struct ScriptedSession {
        security: TransportSecurity,
        sent: Vec<Vec<u8>>,
        answer: Answer,
    }

    impl SecureSession for ScriptedSession {
        fn origin_label(&self) -> &str {
            "scripted"
        }

        fn session_binding(&self) -> [u8; 32] {
            [3; 32]
        }

        fn security(&self) -> &TransportSecurity {
            &self.security
        }

        fn send(&mut self, frame: &[u8]) -> io::Result<()> {
            self.sent.push(frame.to_vec());
            Ok(())
        }

        fn receive(&mut self, _timeout: Duration) -> io::Result<Vec<u8>> {
            let request = ApplicationFrame::decode(self.sent.last().expect("a sent frame"))
                .expect("the agent sends a valid frame");
            Ok((self.answer)(&request))
        }

        fn close(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn security(confidential: bool) -> TransportSecurity {
        TransportSecurity {
            transport_name: "scripted".into(),
            confidential,
            peer_authenticated: confidential,
            requires_network: false,
            proximity_signal: false,
            is_development: true,
        }
    }

    fn session(
        confidential: bool,
        answer: impl Fn(&ApplicationFrame) -> Vec<u8> + Send + 'static,
    ) -> Box<dyn SecureSession + Send> {
        Box::new(ScriptedSession {
            security: security(confidential),
            sent: Vec::new(),
            answer: Box::new(answer),
        })
    }

    fn reply(request: &ApplicationFrame, payload: Vec<u8>) -> Vec<u8> {
        ApplicationFrame {
            kind: ApplicationFrameKind::Response,
            payload,
            ..request.clone()
        }
        .encode()
    }

    #[test]
    fn a_wrap_asks_for_locker_create_and_returns_a_phone_wrapper() {
        let transport = || {
            session(true, |request| {
                assert_eq!(request.operation, OPERATION_CREATE);
                let asked = WrapRequest::decode(&request.payload).expect("payload decodes");
                assert_eq!(asked.file_name, "notes.txt");
                assert_eq!(asked.plaintext_len, 42);
                reply(
                    request,
                    WrapResponse {
                        credential_id: "locker-cred-1".into(),
                        wrapper: vec![8; 60],
                    }
                    .encode(),
                )
            })
        };
        let mut custodian = PhoneCustodian::new(|| Ok(transport()), "Workstation", "locker-cred-1");
        let dek = Dek::random();
        let wrapper = custodian
            .wrap(&EngineWrapRequest {
                binding: [1; 32],
                dek: &dek,
                file_name: "notes.txt".into(),
                plaintext_len: 42,
            })
            .expect("wrap");
        assert_eq!(wrapper.kind, WrapperKind::Phone);
        assert_eq!(wrapper.id, "locker-cred-1");
    }

    #[test]
    fn a_rekey_says_so_instead_of_looking_like_an_unlock() {
        let transport = || {
            session(true, |request| {
                assert_eq!(request.operation, OPERATION_REKEY);
                reply(
                    request,
                    UnwrapResponse {
                        data_key: vec![4; 32],
                    }
                    .encode(),
                )
            })
        };
        let mut custodian =
            PhoneCustodian::new(|| Ok(transport()), "Workstation", "locker-cred-1").rekeying();
        let wrapper = Wrapper {
            kind: WrapperKind::Phone,
            id: "locker-cred-1".into(),
            salt: Vec::new(),
            nonce: Vec::new(),
            ciphertext: vec![7; 60],
        };
        custodian
            .unwrap(&EngineUnwrapRequest {
                binding: [1; 32],
                wrapper: &wrapper,
                container_name: "notes.txt.balock".into(),
                plaintext_len: 42,
            })
            .expect("unwrap");
    }

    /// The regression this file was rewritten for.
    ///
    /// A rekey is an unwrap followed by a wrap, and a session carries exactly
    /// one request: the phone answers on it and closes it. Sharing one session
    /// between the two halves, the `wrap` spoke into a socket that was already
    /// gone, so a rekey against a real phone left a container the desktop had
    /// just unwrapped and could not seal again.
    ///
    /// Asserted as a count of sessions rather than by simulating a closed
    /// socket, because a double that answers a second request on the same
    /// session is exactly what hid this.
    #[test]
    fn each_half_of_a_rekey_gets_a_session_of_its_own() {
        let opened = std::cell::Cell::new(0usize);
        let mut custodian = PhoneCustodian::new(
            || {
                opened.set(opened.get() + 1);
                Ok(session(true, |request| match request.operation.as_str() {
                    OPERATION_REKEY => reply(
                        request,
                        UnwrapResponse {
                            data_key: vec![4; 32],
                        }
                        .encode(),
                    ),
                    OPERATION_CREATE => reply(
                        request,
                        WrapResponse {
                            credential_id: "locker-cred-1".into(),
                            wrapper: vec![8; 60],
                        }
                        .encode(),
                    ),
                    other => panic!("unexpected operation {other}"),
                }))
            },
            "Workstation",
            "locker-cred-1",
        )
        .rekeying();

        let wrapper = Wrapper {
            kind: WrapperKind::Phone,
            id: "locker-cred-1".into(),
            salt: Vec::new(),
            nonce: Vec::new(),
            ciphertext: vec![7; 60],
        };
        custodian
            .unwrap(&EngineUnwrapRequest {
                binding: [1; 32],
                wrapper: &wrapper,
                container_name: "notes.txt.balock".into(),
                plaintext_len: 42,
            })
            .expect("the old key comes back");
        let dek = Dek::random();
        custodian
            .wrap(&EngineWrapRequest {
                binding: [1; 32],
                dek: &dek,
                file_name: "notes.txt".into(),
                plaintext_len: 42,
            })
            .expect("the new key is sealed");

        assert_eq!(
            opened.get(),
            2,
            "one session per request, not one per rekey"
        );
    }

    #[test]
    fn a_reply_to_another_request_is_not_an_answer() {
        let transport = || {
            session(true, |request| {
                let mut forged = request.clone();
                forged.kind = ApplicationFrameKind::Response;
                forged.request_id = "some-other-request".into();
                forged.payload = WrapResponse {
                    credential_id: "locker-cred-1".into(),
                    wrapper: vec![8; 60],
                }
                .encode();
                forged.encode()
            })
        };
        let mut custodian = PhoneCustodian::new(|| Ok(transport()), "Workstation", "locker-cred-1");
        let dek = Dek::random();
        assert!(matches!(
            custodian.wrap(&EngineWrapRequest {
                binding: [1; 32],
                dek: &dek,
                file_name: "notes.txt".into(),
                plaintext_len: 42,
            }),
            Err(LockerError::Denied(_))
        ));
    }

    #[test]
    fn an_unauthenticated_channel_never_sees_a_data_key() {
        let transport = || session(false, |request| reply(request, Vec::new()));
        let mut custodian = PhoneCustodian::new(|| Ok(transport()), "Workstation", "locker-cred-1");
        let dek = Dek::random();
        assert!(matches!(
            custodian.wrap(&EngineWrapRequest {
                binding: [1; 32],
                dek: &dek,
                file_name: "notes.txt".into(),
                plaintext_len: 42,
            }),
            Err(LockerError::Denied(_))
        ));
    }

    #[test]
    fn an_error_frame_is_a_refusal_and_not_a_key() {
        let transport = || {
            session(true, |request| {
                let mut error = request.clone();
                error.kind = ApplicationFrameKind::Error;
                error.payload = vec![0];
                error.encode()
            })
        };
        let mut custodian = PhoneCustodian::new(|| Ok(transport()), "Workstation", "locker-cred-1");
        let wrapper = Wrapper {
            kind: WrapperKind::Phone,
            id: "locker-cred-1".into(),
            salt: Vec::new(),
            nonce: Vec::new(),
            ciphertext: vec![7; 60],
        };
        assert!(matches!(
            custodian.unwrap(&EngineUnwrapRequest {
                binding: [1; 32],
                wrapper: &wrapper,
                container_name: "notes.txt.balock".into(),
                plaintext_len: 42,
            }),
            Err(LockerError::Denied(_))
        ));
    }

    #[test]
    fn a_recovery_wrapper_is_never_sent_to_the_phone() {
        let transport = || session(true, |request| reply(request, Vec::new()));
        let mut custodian = PhoneCustodian::new(|| Ok(transport()), "Workstation", "locker-cred-1");
        let wrapper = Wrapper {
            kind: WrapperKind::Recovery,
            id: String::new(),
            salt: vec![1; 32],
            nonce: vec![2; 12],
            ciphertext: vec![7; 48],
        };
        assert!(matches!(
            custodian.unwrap(&EngineUnwrapRequest {
                binding: [1; 32],
                wrapper: &wrapper,
                container_name: "notes.txt.balock".into(),
                plaintext_len: 42,
            }),
            Err(LockerError::NoWrapper(WrapperKind::Phone))
        ));
    }
}
