//! The agent's half of boot enrollment: asking a phone to wrap a fresh volume
//! key.
//!
//! The volume key is random and it is generated here. It is not derived from a
//! signature, a biometric result or anything the phone says -- those authorize,
//! they do not produce key material. This module is the only place on the
//! desktop that ever holds it, it is wiped on the way out, and it reaches the
//! caller through a file the caller named rather than through an IPC reply,
//! for the same reason the locker's recovery code does: a reply is a value that
//! gets logged, retried and copied by code that has no idea what is in it.
//!
//! What the phone returns is public: a credential id and an opaque wrapper that
//! only that phone's hardware key can open. That is what the initrd carries.

use std::time::Duration;

use phone_auth_protocol::luks::{
    EnrollRequest, EnrollResponse, WrappedVolumeKey, DISK_KEY_LEN, OPERATION_ENROLL,
    VOLUME_BINDING_LEN,
};
use phone_auth_protocol::{ApplicationFrame, ApplicationFrameKind, PROTOCOL_VERSION};
use phone_auth_verifier::verifier::now_ms;
use phone_auth_verifier::{random, SecureSession};

/// How long an enrollment request stays valid. The user has to read a prompt
/// naming the machine and the volume, then present a fingerprint.
const VALIDITY_MS: i64 = 120_000;

/// How long to wait for the answer: the whole validity window, plus the margin
/// the agent allows for an answer to travel back.
const RECEIVE_TIMEOUT: Duration =
    Duration::from_millis(VALIDITY_MS as u64).saturating_add(crate::ANSWER_TRAVEL_MARGIN);

/// A freshly generated volume key, zeroed when it goes out of scope.
///
/// Deliberately not `Clone` and deliberately without a `Debug` that could put
/// it in a log line.
pub struct DiskKey([u8; DISK_KEY_LEN]);

impl DiskKey {
    pub fn random() -> Self {
        Self(random::bytes::<DISK_KEY_LEN>())
    }

    pub fn expose(&self) -> &[u8; DISK_KEY_LEN] {
        &self.0
    }
}

impl Drop for DiskKey {
    fn drop(&mut self) {
        for byte in self.0.iter_mut() {
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

/// What one enrollment produced: a public wrapper for the initrd, and the key
/// that has to reach `cryptsetup` and nothing else.
pub struct Enrollment {
    pub wrapped: WrappedVolumeKey,
    pub disk_key: DiskKey,
}

/// Asks the phone to wrap a new volume key for `volume_name`.
///
/// The binding is fresh per enrollment and is authenticated by the phone's
/// wrapper, so a wrapper lifted from one volume cannot be replayed onto
/// another. Any failure returns a message fit for a person to read and nothing
/// derived from the key.
pub fn enroll(
    session: &mut dyn SecureSession,
    verifier_name: &str,
    volume_name: &str,
) -> Result<Enrollment, String> {
    let disk_key = DiskKey::random();
    let volume_binding = random::bytes::<VOLUME_BINDING_LEN>();

    let payload = EnrollRequest {
        verifier_name: verifier_name.to_owned(),
        volume_name: volume_name.to_owned(),
        volume_binding,
        disk_key: disk_key.expose().to_vec(),
    };
    payload.validate().map_err(|error| error.to_string())?;

    let issued_at_ms = now_ms();
    let request = ApplicationFrame {
        protocol_version: PROTOCOL_VERSION,
        kind: ApplicationFrameKind::Request,
        request_id: random::request_id(),
        session_binding: session.session_binding(),
        operation: OPERATION_ENROLL.to_owned(),
        issued_at_ms,
        expires_at_ms: issued_at_ms + VALIDITY_MS,
        payload: payload.encode(),
    };
    request.validate().map_err(|error| error.to_string())?;

    session
        .send(&request.encode())
        .map_err(|error| error.to_string())?;
    let raw = session
        .receive(RECEIVE_TIMEOUT)
        .map_err(|error| error.to_string())?;

    let reply = ApplicationFrame::decode(&raw).map_err(|error| error.to_string())?;
    // Decoding an envelope is not authorization: the reply has to answer the
    // request still pending, in this session, unexpired.
    if !reply.is_reply_to(&request, now_ms()) {
        return Err("the phone answered a different request".to_owned());
    }
    if reply.kind == ApplicationFrameKind::Error {
        return Err("the phone declined the enrollment".to_owned());
    }

    let response = EnrollResponse::decode(&reply.payload).map_err(|error| error.to_string())?;
    let wrapped = WrappedVolumeKey {
        volume_binding,
        credential_id: response.credential_id,
        wrapper: response.wrapper,
    };
    wrapped.validate().map_err(|error| error.to_string())?;

    Ok(Enrollment { wrapped, disk_key })
}

#[cfg(test)]
mod tests {
    use super::*;
    use phone_auth_verifier::session::TransportSecurity;
    use std::io;

    /// A session that answers with whatever the test queued.
    struct ScriptedSession {
        security: TransportSecurity,
        sent: Vec<Vec<u8>>,
        answer: Box<dyn Fn(&ApplicationFrame) -> Vec<u8> + Send>,
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

    fn session(answer: impl Fn(&ApplicationFrame) -> Vec<u8> + Send + 'static) -> ScriptedSession {
        ScriptedSession {
            security: TransportSecurity {
                transport_name: "scripted".into(),
                confidential: true,
                peer_authenticated: true,
                requires_network: false,
                proximity_signal: false,
                is_development: true,
            },
            sent: Vec::new(),
            answer: Box::new(answer),
        }
    }

    fn wrapped(request: &ApplicationFrame) -> Vec<u8> {
        ApplicationFrame {
            kind: ApplicationFrameKind::Response,
            payload: EnrollResponse {
                credential_id: "cred-boot".into(),
                wrapper: vec![7; 60],
            }
            .encode(),
            ..request.clone()
        }
        .encode()
    }

    /// `Enrollment` has no `Debug` on purpose -- it holds a key -- so the
    /// usual `expect_err` cannot be used on it.
    fn refusal(outcome: Result<Enrollment, String>) -> String {
        match outcome {
            Err(error) => error,
            Ok(_) => panic!("the enrollment should have been refused"),
        }
    }

    #[test]
    fn the_key_the_phone_wraps_is_random_and_is_never_the_binding() {
        let mut first = session(wrapped);
        let mut second = session(wrapped);

        let one = enroll(&mut first, "Desktop", "cryptroot").expect("enrolled");
        let two = enroll(&mut second, "Desktop", "cryptroot").expect("enrolled");

        let sent = EnrollRequest::decode(
            &ApplicationFrame::decode(&first.sent[0])
                .expect("frame")
                .payload,
        )
        .expect("request");

        // The key is 32 fresh bytes, and the binding is 32 different fresh
        // bytes. Deriving one from the other would make a wrapper that its own
        // public file could be used to attack.
        assert_eq!(sent.disk_key.len(), DISK_KEY_LEN);
        assert_ne!(sent.disk_key.as_slice(), &sent.volume_binding[..]);
        assert_ne!(one.disk_key.expose(), two.disk_key.expose());
        assert_ne!(one.wrapped.volume_binding, two.wrapped.volume_binding);
    }

    #[test]
    fn the_binding_kept_is_the_binding_sent() {
        let mut phone = session(wrapped);
        let enrolled = enroll(&mut phone, "Desktop", "cryptroot").expect("enrolled");

        let sent = EnrollRequest::decode(
            &ApplicationFrame::decode(&phone.sent[0])
                .expect("frame")
                .payload,
        )
        .expect("request");

        // The initrd sends this binding back at unlock time, and the phone
        // authenticates it as part of the wrapper. A binding that does not
        // match what was wrapped is a volume that never opens.
        assert_eq!(enrolled.wrapped.volume_binding, sent.volume_binding);
        assert_eq!(enrolled.wrapped.credential_id, "cred-boot");
    }

    #[test]
    fn an_answer_to_another_request_is_not_an_enrollment() {
        let mut phone = session(|request| {
            ApplicationFrame {
                kind: ApplicationFrameKind::Response,
                request_id: "some-other-request".into(),
                payload: EnrollResponse {
                    credential_id: "cred-boot".into(),
                    wrapper: vec![7; 60],
                }
                .encode(),
                ..request.clone()
            }
            .encode()
        });

        let error = refusal(enroll(&mut phone, "Desktop", "cryptroot"));
        assert!(error.contains("different request"), "{error}");
    }

    #[test]
    fn a_refusal_is_a_refusal_not_a_wrapper() {
        let mut phone = session(|request| {
            ApplicationFrame {
                kind: ApplicationFrameKind::Error,
                payload: Vec::new(),
                ..request.clone()
            }
            .encode()
        });

        let error = refusal(enroll(&mut phone, "Desktop", "cryptroot"));
        assert!(error.contains("declined"), "{error}");
    }
}
