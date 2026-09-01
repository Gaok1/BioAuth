//! Asking a phone what a pairing's permissions should be, and storing the answer.
//!
//! The desktop is what enforces permissions, and until now it was also the only
//! place they could be written. Granting a phone a second set of powers meant
//! pairing it a second time, which is the thing this removes.
//!
//! The phone never initiates, so this is the desktop offering what it believes
//! and the phone answering with what stands. The reconciliation itself happens
//! on the phone, using the rule in [`phone_auth_protocol::permissions`]; this
//! side stores the answer.
//!
//! Storing it verbatim is deliberate, and so is the one thing this side still
//! checks. A reply that names a revision lower than either side's is not a
//! reconciliation any rule produces — it is a phone that lost track, or a
//! rollback of a revocation the user made minutes ago. Refused rather than
//! stored, because the failure mode of accepting it is a permission the user
//! took away coming back.

use phone_auth_protocol::permissions::{
    Permission as WirePermission, SyncRequest, SyncResponse, OPERATION_SYNC,
};
use phone_auth_protocol::{
    ApplicationErrorCode, ApplicationFrame, ApplicationFrameKind, PROTOCOL_VERSION,
};
use phone_auth_verifier::policy::Permission as StoredPermission;
use phone_auth_verifier::verifier::now_ms;
use phone_auth_verifier::{random, SecureSession};
use zeroize::Zeroize;

use crate::vault::VaultError;

/// How long the phone has to answer. The user may have to unlock it and read a
/// list, which is slower than approving a single prompt.
const RECEIVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);
/// How long the request stays answerable.
const VALIDITY_MS: i64 = 120_000;

/// One paired phone's permission set, reached over an established session.
pub struct PhonePermissions<'a> {
    session: &'a mut Box<dyn SecureSession + Send>,
    verifier_name: String,
}

impl<'a> PhonePermissions<'a> {
    pub fn new(
        session: &'a mut Box<dyn SecureSession + Send>,
        verifier_name: impl Into<String>,
    ) -> Self {
        Self {
            session,
            verifier_name: verifier_name.into(),
        }
    }

    /// Offers this side's set and returns the one that stands.
    ///
    /// `revision` is what this side believes it last wrote. The response is
    /// authoritative: whichever side won, the phone answers with the whole
    /// settled set rather than a diff, so a reply this side cannot understand
    /// is a refused call instead of a half-updated pairing.
    pub fn sync(
        &mut self,
        revision: u64,
        permissions: &[StoredPermission],
    ) -> Result<SyncResponse, VaultError> {
        let request = SyncRequest {
            verifier_name: self.verifier_name.clone(),
            revision,
            permissions: permissions.iter().map(to_wire).collect(),
        };
        request
            .validate()
            .map_err(|error| VaultError::protocol(error.to_string()))?;

        let payload = self.exchange(OPERATION_SYNC, request.encode())?;
        let response = SyncResponse::decode(&payload)
            .map_err(|error| VaultError::protocol(error.to_string()))?;

        // The one check this side keeps. Nothing the rule can produce is older
        // than both inputs, so a reply that is has either lost track or is
        // undoing a revocation the user just made.
        if response.revision < revision {
            return Err(VaultError::protocol(
                "the phone answered with an older permission revision than it was given",
            ));
        }
        Ok(response)
    }

    /// Sends one frame and returns the payload of the matching reply.
    ///
    /// The same shape as the vault's and the ssh client's, and for the same
    /// reasons: a decoded envelope is not an authorization, and the reply has
    /// to be the answer to the request still pending, in this session,
    /// unexpired.
    fn exchange(&mut self, operation: &str, payload: Vec<u8>) -> Result<Vec<u8>, VaultError> {
        if !self.session.security().suitable_for_authorization() {
            return Err(VaultError::protocol(
                "permissions need an authenticated confidential session",
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
            // A refusal that will not decode is still a refusal.
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

/// The stored shape on the wire.
pub fn to_wire(permission: &StoredPermission) -> WirePermission {
    WirePermission {
        service: permission.service.clone(),
        action: permission.action.clone(),
        resource: permission.resource.clone(),
        user: permission.user.clone(),
    }
}

/// The wire shape as stored.
pub fn from_wire(permission: &WirePermission) -> StoredPermission {
    StoredPermission {
        service: permission.service.clone(),
        action: permission.action.clone(),
        resource: permission.resource.clone(),
        user: permission.user.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use phone_auth_protocol::permissions::WILDCARD;

    fn stored(service: &str) -> StoredPermission {
        StoredPermission {
            service: service.to_owned(),
            action: WILDCARD.to_owned(),
            resource: WILDCARD.to_owned(),
            user: "gaok1".to_owned(),
        }
    }

    /// The wire and the enforcing side must spell "any" the same way, or a
    /// grant that matched everything before a sync matches nothing after it.
    /// The protocol crate cannot depend on the verifier, so the two constants
    /// are pinned together here.
    #[test]
    fn the_wire_and_the_verifier_agree_on_the_wildcard() {
        assert_eq!(WILDCARD, phone_auth_verifier::policy::WILDCARD);
    }

    #[test]
    fn a_permission_survives_the_round_trip_through_the_wire() {
        let permission = stored("sudo");
        assert_eq!(from_wire(&to_wire(&permission)), permission);
    }
}
