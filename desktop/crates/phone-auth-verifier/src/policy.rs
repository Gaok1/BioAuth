//! What a paired credential is permitted to authorize.
//!
//! Policy is default-deny: a credential authorizes nothing until a permission
//! explicitly covers the request. Both sides hold policy independently — the
//! phone decides what it is willing to be asked, the verifier decides what it
//! is willing to accept — and a grant needs both to agree.

use serde::{Deserialize, Serialize};

use phone_auth_protocol::AuthRequest;

/// Matches any value for a field.
pub const WILDCARD: &str = "*";

/// One grant of authority to a credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Permission {
    /// Exact match. Services are a small closed vocabulary (`sudo`, `login`,
    /// `luks`), so a wildcard here would be a grant of everything and is not
    /// accepted.
    pub service: String,
    /// The operation, or [`WILDCARD`] to allow any operation in the service.
    ///
    /// A wildcard action is a real delegation: for `sudo` it means the
    /// credential may authorize any command. It is offered because per-command
    /// enrolment is unusable in practice, but it is never the default.
    #[serde(default = "wildcard")]
    pub action: String,
    /// The target, or [`WILDCARD`] to allow any target.
    #[serde(default = "wildcard")]
    pub resource: String,
    /// Accounts this permission covers, or [`WILDCARD`].
    ///
    /// Without this a phone paired for one user's `sudo` would equally
    /// authorize another account's.
    #[serde(default = "wildcard")]
    pub user: String,
}

fn wildcard() -> String {
    WILDCARD.to_owned()
}

impl Permission {
    /// Builds a permission covering everything within one service.
    pub fn service(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            action: wildcard(),
            resource: wildcard(),
            user: wildcard(),
        }
    }

    pub fn with_action(mut self, action: impl Into<String>) -> Self {
        self.action = action.into();
        self
    }

    pub fn with_resource(mut self, resource: impl Into<String>) -> Self {
        self.resource = resource.into();
        self
    }

    pub fn with_user(mut self, user: impl Into<String>) -> Self {
        self.user = user.into();
        self
    }

    /// Whether this permission covers the request.
    pub fn allows(&self, request: &AuthRequest) -> bool {
        self.allows_fields(
            &request.service,
            &request.action,
            &request.resource,
            &request.user,
        )
    }

    /// Whether this permission covers a request with these fields.
    ///
    /// Separate from [`Self::allows`] so a caller can test coverage before
    /// building a request — the agent uses it to pick which paired credential
    /// to ask, without generating a challenge it may not need.
    pub fn allows_fields(&self, service: &str, action: &str, resource: &str, user: &str) -> bool {
        // A wildcard service is meaningless and would be a total grant, so it
        // is treated as matching nothing rather than everything.
        self.service != WILDCARD
            && self.service == service
            && matches(&self.action, action)
            && matches(&self.resource, resource)
            && matches(&self.user, user)
    }
}

/// Whether any permission covers a request with these fields.
pub fn permits_fields(
    permissions: &[Permission],
    service: &str,
    action: &str,
    resource: &str,
    user: &str,
) -> bool {
    permissions
        .iter()
        .any(|permission| permission.allows_fields(service, action, resource, user))
}

fn matches(pattern: &str, value: &str) -> bool {
    pattern == WILDCARD || pattern == value
}

/// Evaluates a set of permissions, default-deny.
pub fn permits(permissions: &[Permission], request: &AuthRequest) -> bool {
    permissions
        .iter()
        .any(|permission| permission.allows(request))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> AuthRequest {
        let issued_at_ms = 1_787_745_600_000;
        AuthRequest {
            protocol_version: 1,
            request_id: "request-1".into(),
            verifier_id: "desktop-1".into(),
            verifier_name: "Desktop-Casa".into(),
            credential_id: "cred-1".into(),
            challenge: [0; 32],
            service: "sudo".into(),
            action: "nixos-rebuild switch".into(),
            resource: "Desktop-NixOS".into(),
            user: "alice".into(),
            issued_at_ms,
            expires_at_ms: issued_at_ms + 60_000,
            session_binding: [0; 32],
        }
    }

    #[test]
    fn an_empty_policy_denies() {
        assert!(!permits(&[], &request()));
    }

    #[test]
    fn a_service_wide_permission_allows_any_action() {
        assert!(permits(&[Permission::service("sudo")], &request()));
    }

    #[test]
    fn a_permission_for_another_service_denies() {
        assert!(!permits(&[Permission::service("login")], &request()));
    }

    #[test]
    fn an_exact_action_must_match_exactly() {
        let exact = Permission::service("sudo").with_action("nixos-rebuild switch");
        assert!(permits(std::slice::from_ref(&exact), &request()));

        let mut other = request();
        other.action = "nixos-rebuild switch --upgrade".into();
        assert!(
            !permits(&[exact], &other),
            "a longer command must not match a prefix permission"
        );
    }

    #[test]
    fn user_is_scoped() {
        let alice_only = Permission::service("sudo").with_user("alice");
        assert!(permits(std::slice::from_ref(&alice_only), &request()));

        let mut as_root = request();
        as_root.user = "root".into();
        assert!(
            !permits(&[alice_only], &as_root),
            "a permission for one account must not cover another"
        );
    }

    #[test]
    fn resource_is_scoped() {
        let one_host = Permission::service("luks").with_resource("nvme0n1p2");
        let mut request = request();
        request.service = "luks".into();
        request.resource = "nvme0n1p2".into();
        assert!(permits(std::slice::from_ref(&one_host), &request));

        request.resource = "nvme0n1p3".into();
        assert!(!permits(&[one_host], &request));
    }

    #[test]
    fn a_wildcard_service_grants_nothing() {
        // Guards against a config typo turning into a grant of everything.
        let everything = Permission {
            service: WILDCARD.into(),
            action: WILDCARD.into(),
            resource: WILDCARD.into(),
            user: WILDCARD.into(),
        };
        assert!(!permits(&[everything], &request()));
    }

    #[test]
    fn permissions_default_to_wildcards_when_absent_from_json() {
        let parsed: Permission =
            serde_json::from_str(r#"{"service":"sudo"}"#).expect("minimal permission parses");
        assert_eq!(parsed, Permission::service("sudo"));
    }
}
