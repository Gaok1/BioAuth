//! The authorization response: the phone's answer, and its proof.

use crate::cbor::{Reader, Writer};
use crate::{
    bytes_equal, check_frame_size, check_text, ProtocolError, Result, MESSAGE_TYPE_RESPONSE,
    PROTOCOL_VERSION,
};

const RESPONSE_FRAME_LEN: u64 = 8;

/// The phone's verdict.
///
/// Wire values are the Dart `AuthorizationDecision` enum indices, so the
/// ordering is part of the protocol and must not be rearranged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Authorized = 0,
    Denied = 1,
}

impl Decision {
    fn from_wire(value: i64) -> Result<Self> {
        match value {
            0 => Ok(Self::Authorized),
            1 => Ok(Self::Denied),
            other => Err(ProtocolError::InvalidDecision(other)),
        }
    }
}

/// A response to exactly one [`crate::AuthRequest`].
///
/// A response is not authority on its own. `Authorized` only means the phone
/// says yes; the verifier still has to check the signature against a paired
/// public key over the request it actually issued.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthResponse {
    pub protocol_version: u64,
    pub request_id: String,
    pub verifier_id: String,
    pub credential_id: String,
    pub decision: Decision,
    /// Empty when denied. See [`crate::ALGORITHM_ECDSA_P256_SHA256`].
    pub algorithm: String,
    /// Empty when denied; otherwise a DER signature over the request frame.
    pub signature: Vec<u8>,
}

impl AuthResponse {
    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(self.protocol_version));
        }
        check_text("requestId", &self.request_id, 64)?;
        check_text("verifierId", &self.verifier_id, 64)?;
        check_text("credentialId", &self.credential_id, 64)?;

        if self.decision == Decision::Authorized
            && (self.algorithm.is_empty() || self.signature.is_empty())
        {
            return Err(ProtocolError::MissingProof);
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.array(RESPONSE_FRAME_LEN);
        writer.uint(MESSAGE_TYPE_RESPONSE);
        writer.uint(self.protocol_version);
        writer.text(&self.request_id);
        writer.text(&self.verifier_id);
        writer.text(&self.credential_id);
        writer.uint(self.decision as u64);
        writer.text(&self.algorithm);
        writer.bytes(&self.signature);
        writer.into_bytes()
    }

    pub fn decode(frame: &[u8]) -> Result<Self> {
        check_frame_size(frame)?;
        let mut reader = Reader::new(frame);

        let len = reader.array()?;
        if len != RESPONSE_FRAME_LEN {
            return Err(ProtocolError::FrameShape {
                expected: RESPONSE_FRAME_LEN,
                actual: len,
            });
        }
        let message_type = reader.uint()?;
        if message_type != MESSAGE_TYPE_RESPONSE {
            return Err(ProtocolError::UnexpectedMessageType(message_type));
        }

        let response = Self {
            protocol_version: reader.uint()?,
            request_id: reader.text()?.to_owned(),
            verifier_id: reader.text()?.to_owned(),
            credential_id: reader.text()?.to_owned(),
            decision: Decision::from_wire(reader.int()?)?,
            // The algorithm is allowed to be empty on a denial, so it skips
            // the non-blank rule the identifier fields get.
            algorithm: reader.text()?.to_owned(),
            signature: reader.bytes()?.to_vec(),
        };
        reader.finish()?;
        response.validate()?;

        if !bytes_equal(frame, &response.encode()) {
            return Err(ProtocolError::NotCanonical);
        }
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authorized() -> AuthResponse {
        AuthResponse {
            protocol_version: 1,
            request_id: "request-1".into(),
            verifier_id: "desktop-1".into(),
            credential_id: "desktop-1-sudo-v1".into(),
            decision: Decision::Authorized,
            algorithm: crate::ALGORITHM_ECDSA_P256_SHA256.into(),
            signature: vec![1, 2, 3],
        }
    }

    #[test]
    fn round_trips_an_authorized_response() {
        let response = authorized();
        assert_eq!(AuthResponse::decode(&response.encode()), Ok(response));
    }

    #[test]
    fn round_trips_a_denial_with_no_proof() {
        let response = AuthResponse {
            decision: Decision::Denied,
            algorithm: String::new(),
            signature: Vec::new(),
            ..authorized()
        };
        assert_eq!(AuthResponse::decode(&response.encode()), Ok(response));
    }

    #[test]
    fn rejects_an_authorization_without_a_signature() {
        let response = AuthResponse {
            signature: Vec::new(),
            ..authorized()
        };
        assert_eq!(response.validate(), Err(ProtocolError::MissingProof));
        assert_eq!(
            AuthResponse::decode(&response.encode()),
            Err(ProtocolError::MissingProof)
        );
    }

    #[test]
    fn rejects_an_authorization_without_an_algorithm() {
        let response = AuthResponse {
            algorithm: String::new(),
            ..authorized()
        };
        assert_eq!(response.validate(), Err(ProtocolError::MissingProof));
    }

    #[test]
    fn rejects_an_unknown_decision() {
        let mut writer = Writer::new();
        writer.array(RESPONSE_FRAME_LEN);
        writer.uint(MESSAGE_TYPE_RESPONSE);
        writer.uint(1);
        writer.text("request-1");
        writer.text("desktop-1");
        writer.text("desktop-1-sudo-v1");
        writer.uint(7);
        writer.text("SHA256withECDSA");
        writer.bytes(&[1, 2, 3]);

        assert_eq!(
            AuthResponse::decode(&writer.into_bytes()),
            Err(ProtocolError::InvalidDecision(7))
        );
    }

    #[test]
    fn rejects_a_request_frame_offered_as_a_response() {
        let request = crate::request::tests::fixture();
        assert!(matches!(
            AuthResponse::decode(&request.encode()),
            Err(ProtocolError::FrameShape { .. })
        ));
    }
}
