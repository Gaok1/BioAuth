//! End-to-end verifier behaviour, with real ECDSA on both sides.
//!
//! The authenticator here is a software fixture rather than a phone, so these
//! tests prove the verifier's decision procedure, not the biometric guarantee.
//! What they do establish is that every way a signature can fail to mean
//! "this user approved this request" is actually rejected.

use phone_auth_protocol::{AuthRequest, AuthResponse, Decision};
use phone_auth_verifier::pairing::{CredentialPurpose, KeyKind};
use phone_auth_verifier::testing::{
    AuthenticatorBehaviour, LoopbackSession, SoftwareAuthenticator,
};
use phone_auth_verifier::verifier::AuthorizationError;
use phone_auth_verifier::{
    PairingStore, Permission, RequestSpec, SecureSession, Verifier, VerifierIdentity,
};

const NOW_MS: i64 = 1_787_745_600_000;
const DEVICE_ID: &str = "phone-1";
const CREDENTIAL_ID: &str = "desktop-1-sudo-v1";

fn identity() -> VerifierIdentity {
    VerifierIdentity {
        verifier_id: "desktop-1".into(),
        verifier_name: "Desktop-Casa".into(),
    }
}

fn spec() -> RequestSpec {
    RequestSpec::new(
        CREDENTIAL_ID,
        "sudo",
        "nixos-rebuild switch",
        "Desktop-NixOS",
        "alice",
    )
}

/// A verifier with one paired software authenticator permitted to run sudo.
fn paired() -> (Verifier, SoftwareAuthenticator) {
    let authenticator = SoftwareAuthenticator::new(DEVICE_ID, CREDENTIAL_ID, 11);
    let mut store = PairingStore::in_memory();
    store
        .insert(authenticator.pairing_record(vec![Permission::service("sudo")]))
        .expect("pairing record is accepted");
    (Verifier::new(identity(), store), authenticator)
}

/// Runs the whole exchange and returns the verifier's verdict.
fn run(
    verifier: &mut Verifier,
    authenticator: &SoftwareAuthenticator,
    session: &mut LoopbackSession,
) -> Result<phone_auth_verifier::Grant, AuthorizationError> {
    let pending = verifier.issue(&spec(), session, NOW_MS)?;
    session
        .send(&pending.frame())
        .expect("session accepts the frame");
    let response = authenticator.answer(session.last_sent().expect("a frame was sent"));
    verifier.accept(pending, &response, session, NOW_MS)
}

#[test]
fn a_signed_authorization_produces_a_grant() {
    let (mut verifier, authenticator) = paired();
    let mut session = LoopbackSession::secure();

    let grant = run(&mut verifier, &authenticator, &mut session).expect("authorization succeeds");

    assert_eq!(grant.device_id, DEVICE_ID);
    assert_eq!(grant.credential_id, CREDENTIAL_ID);
    assert_eq!(grant.service, "sudo");
    assert_eq!(grant.action, "nixos-rebuild switch");
    assert_eq!(grant.user, "alice");
    assert_eq!(grant.granted_at_ms, NOW_MS);
    assert!(
        grant.origin.contains("Loopback"),
        "the grant records where it came from"
    );
}

#[test]
fn the_signed_payload_is_the_full_request_not_just_the_challenge() {
    // If the phone signed only the challenge, a signature collected for one
    // action would verify against any other. Confirm the payload carries the
    // whole context by checking the frame the verifier sent.
    let (mut verifier, _) = paired();
    let session = LoopbackSession::secure();
    let pending = verifier.issue(&spec(), &session, NOW_MS).expect("issue");
    let frame = pending.frame();
    let decoded = AuthRequest::decode(&frame).expect("frame decodes");
    assert_eq!(decoded.signing_payload(), frame);
    assert!(frame.windows(4).any(|w| w == b"sudo"));
    assert!(frame.windows(20).any(|w| w == b"nixos-rebuild switch"));
}

#[test]
fn a_declined_request_is_not_a_grant() {
    let (mut verifier, authenticator) = paired();
    let authenticator = authenticator.with_behaviour(AuthenticatorBehaviour::Decline);
    let mut session = LoopbackSession::secure();

    assert_eq!(
        run(&mut verifier, &authenticator, &mut session),
        Err(AuthorizationError::Declined)
    );
}

#[test]
fn a_signature_over_a_different_request_is_rejected() {
    let (mut verifier, authenticator) = paired();
    let authenticator = authenticator.with_behaviour(AuthenticatorBehaviour::SignMismatchedRequest);
    let mut session = LoopbackSession::secure();

    assert!(matches!(
        run(&mut verifier, &authenticator, &mut session),
        Err(AuthorizationError::Signature(_))
    ));
}

#[test]
fn a_signature_from_an_unpaired_key_is_rejected() {
    let (mut verifier, authenticator) = paired();
    let authenticator = authenticator.with_behaviour(AuthenticatorBehaviour::SignWithForeignKey);
    let mut session = LoopbackSession::secure();

    assert!(matches!(
        run(&mut verifier, &authenticator, &mut session),
        Err(AuthorizationError::Signature(_))
    ));
}

#[test]
fn a_valid_response_cannot_be_replayed() {
    let (mut verifier, authenticator) = paired();
    let session = LoopbackSession::secure();

    let pending = verifier.issue(&spec(), &session, NOW_MS).expect("issue");
    let frame = pending.frame();
    let response = authenticator.answer(&frame);

    verifier
        .accept(pending.clone(), &response, &session, NOW_MS)
        .expect("first use succeeds");

    // Replaying the identical request and response pair must fail, even though
    // the signature itself is still perfectly valid.
    assert_eq!(
        verifier.accept(pending, &response, &session, NOW_MS),
        Err(AuthorizationError::Replayed)
    );
}

#[test]
fn a_response_for_another_request_is_rejected() {
    let (mut verifier, authenticator) = paired();
    let session = LoopbackSession::secure();

    let first = verifier
        .issue(&spec(), &session, NOW_MS)
        .expect("issue first");
    let second = verifier
        .issue(&spec(), &session, NOW_MS)
        .expect("issue second");
    assert_ne!(
        first.request().request_id,
        second.request().request_id,
        "every request gets a fresh id"
    );
    assert_ne!(
        first.request().challenge,
        second.request().challenge,
        "every request gets a fresh challenge"
    );

    let answer_to_second = authenticator.answer(&second.frame());
    assert_eq!(
        verifier.accept(first, &answer_to_second, &session, NOW_MS),
        Err(AuthorizationError::ResponseMismatch { field: "requestId" })
    );
}

#[test]
fn an_expired_request_is_rejected() {
    let (mut verifier, authenticator) = paired();
    let session = LoopbackSession::secure();

    let pending = verifier
        .issue(&spec().with_validity_ms(30_000), &session, NOW_MS)
        .expect("issue");
    let response = authenticator.answer(&pending.frame());

    assert_eq!(
        verifier.accept(pending, &response, &session, NOW_MS + 30_000),
        Err(AuthorizationError::Expired)
    );
}

#[test]
fn a_channel_that_is_not_confidential_is_refused_before_the_user_is_asked() {
    let (mut verifier, _) = paired();
    let session = LoopbackSession::cleartext();

    assert!(matches!(
        verifier.issue(&spec(), &session, NOW_MS),
        Err(AuthorizationError::ChannelUnsuitable { .. })
    ));
}

#[test]
fn a_channel_with_an_unauthenticated_peer_is_refused() {
    let (mut verifier, _) = paired();
    let session = LoopbackSession::unauthenticated();

    assert!(matches!(
        verifier.issue(&spec(), &session, NOW_MS),
        Err(AuthorizationError::ChannelUnsuitable { .. })
    ));
}

#[test]
fn a_response_arriving_on_a_different_session_is_rejected() {
    // The signature is valid and fresh; it simply belongs to another session.
    let (mut verifier, authenticator) = paired();
    let issuing_session = LoopbackSession::secure().with_binding([0x11; 32]);
    let other_session = LoopbackSession::secure().with_binding([0x22; 32]);

    let pending = verifier
        .issue(&spec(), &issuing_session, NOW_MS)
        .expect("issue");
    let response = authenticator.answer(&pending.frame());

    assert_eq!(
        verifier.accept(pending, &response, &other_session, NOW_MS),
        Err(AuthorizationError::SessionBindingMismatch)
    );
}

#[test]
fn the_session_binding_is_inside_the_signed_request() {
    let (mut verifier, _) = paired();
    let session = LoopbackSession::secure().with_binding([0xa7; 32]);

    let pending = verifier.issue(&spec(), &session, NOW_MS).expect("issue");
    assert_eq!(pending.request().session_binding, [0xa7; 32]);
    assert!(
        pending.frame().windows(32).any(|w| w == [0xa7; 32]),
        "the binding must be part of the bytes that get signed"
    );
}

#[test]
fn an_unpaired_credential_is_refused() {
    let (mut verifier, _) = paired();
    let session = LoopbackSession::secure();
    let mut unknown = spec();
    unknown.credential_id = "not-paired".into();

    assert_eq!(
        verifier.issue(&unknown, &session, NOW_MS),
        Err(AuthorizationError::UnknownCredential("not-paired".into()))
    );
}

#[test]
fn policy_denies_a_service_the_credential_was_not_granted() {
    let (mut verifier, _) = paired();
    let session = LoopbackSession::secure();
    let mut other_service = spec();
    other_service.service = "login".into();
    other_service.action = "sign-in".into();

    assert_eq!(
        verifier.issue(&other_service, &session, NOW_MS),
        Err(AuthorizationError::PolicyDenied)
    );
}

#[test]
fn revoking_a_device_mid_flight_stops_the_grant() {
    // The phone has already been tapped; the pairing is removed before the
    // answer is processed. The signature is valid but the device is no longer
    // trusted, so no grant may be produced.
    let (mut verifier, authenticator) = paired();
    let session = LoopbackSession::secure();

    let pending = verifier.issue(&spec(), &session, NOW_MS).expect("issue");
    let response = authenticator.answer(&pending.frame());
    verifier.store_mut().remove(DEVICE_ID).expect("unpair");

    assert_eq!(
        verifier.accept(pending, &response, &session, NOW_MS),
        Err(AuthorizationError::UnknownCredential(CREDENTIAL_ID.into()))
    );
}

#[test]
fn narrowing_policy_mid_flight_stops_the_grant() {
    let (mut verifier, authenticator) = paired();
    let session = LoopbackSession::secure();

    let pending = verifier.issue(&spec(), &session, NOW_MS).expect("issue");
    let response = authenticator.answer(&pending.frame());

    // Re-pair the same device with a permission that no longer covers sudo.
    verifier
        .store_mut()
        .insert(authenticator.pairing_record(vec![Permission::service("login")]))
        .expect("re-pair with narrower permissions");

    assert_eq!(
        verifier.accept(pending, &response, &session, NOW_MS),
        Err(AuthorizationError::PolicyDenied)
    );
}

#[test]
fn a_software_key_cannot_be_used_for_disk_unlock() {
    // The boot gate is what keeps the development simulator from ever standing
    // in for a phone on the one flow with no fallback.
    let authenticator = SoftwareAuthenticator::new(DEVICE_ID, "luks-v1", 11);
    let mut store = PairingStore::in_memory();
    store
        .insert(authenticator.pairing_record_with(
            vec![Permission::service("luks")],
            CredentialPurpose::DiskUnlock,
            KeyKind::Software,
        ))
        .expect("pair");
    let mut verifier = Verifier::new(identity(), store);
    let session = LoopbackSession::secure();

    let unlock = RequestSpec::new("luks-v1", "luks", "unlock", "nvme0n1p2", "root");

    assert_eq!(
        verifier.issue(&unlock, &session, NOW_MS),
        Err(AuthorizationError::KeyKindUnsuitableForBoot {
            credential_id: "luks-v1".into()
        })
    );
}

#[test]
fn a_hardware_key_registered_for_disk_unlock_is_accepted() {
    let authenticator = SoftwareAuthenticator::new(DEVICE_ID, "luks-v1", 11);
    let mut store = PairingStore::in_memory();
    store
        .insert(authenticator.pairing_record_with(
            vec![Permission::service("luks")],
            CredentialPurpose::DiskUnlock,
            KeyKind::StrongBox,
        ))
        .expect("pair");
    let mut verifier = Verifier::new(identity(), store);
    let mut session = LoopbackSession::posing_as_production();

    let unlock = RequestSpec::new("luks-v1", "luks", "unlock", "nvme0n1p2", "root");

    let pending = verifier.issue(&unlock, &session, NOW_MS).expect("issue");
    session.send(&pending.frame()).expect("send");
    let response = authenticator.answer(&pending.frame());
    let grant = verifier
        .accept(pending, &response, &session, NOW_MS)
        .expect("unlock is granted");

    assert_eq!(grant.service, "luks");
    assert_eq!(grant.resource, "nvme0n1p2");
}

#[test]
fn a_development_transport_cannot_unlock_a_disk() {
    // Even with a hardware-backed credential, the simulator must not be able
    // to stand in for a phone on the one flow that has no second chance.
    let authenticator = SoftwareAuthenticator::new(DEVICE_ID, "luks-v1", 11);
    let mut store = PairingStore::in_memory();
    store
        .insert(authenticator.pairing_record_with(
            vec![Permission::service("luks")],
            CredentialPurpose::DiskUnlock,
            KeyKind::StrongBox,
        ))
        .expect("pair");
    let mut verifier = Verifier::new(identity(), store);
    let session = LoopbackSession::secure();
    assert!(session.security().is_development);

    let unlock = RequestSpec::new("luks-v1", "luks", "unlock", "nvme0n1p2", "root");

    assert!(matches!(
        verifier.issue(&unlock, &session, NOW_MS),
        Err(AuthorizationError::DevelopmentTransportRefused { .. })
    ));
}

#[test]
fn an_authorization_credential_cannot_be_borrowed_for_disk_unlock() {
    // Key separation: the sudo credential must not double as the LUKS one.
    let (mut verifier, _) = paired();
    let session = LoopbackSession::secure();

    let unlock = RequestSpec::new(CREDENTIAL_ID, "luks", "unlock", "nvme0n1p2", "root");

    assert!(matches!(
        verifier.issue(&unlock, &session, NOW_MS),
        Err(AuthorizationError::PurposeMismatch { .. })
    ));
}

#[test]
fn vault_and_locker_refuse_every_foreign_credential_purpose() {
    let all_purposes = [
        CredentialPurpose::Authorization,
        CredentialPurpose::DiskUnlock,
        CredentialPurpose::WebAuthn,
        CredentialPurpose::Vault,
        CredentialPurpose::FileLocker,
    ];

    for (service, required) in [
        ("vault", CredentialPurpose::Vault),
        ("locker", CredentialPurpose::FileLocker),
    ] {
        for purpose in all_purposes
            .into_iter()
            .filter(|purpose| *purpose != required)
        {
            let authenticator = SoftwareAuthenticator::new(DEVICE_ID, CREDENTIAL_ID, 11);
            let mut store = PairingStore::in_memory();
            store
                .insert(authenticator.pairing_record_with(
                    vec![Permission::service(service)],
                    purpose,
                    KeyKind::StrongBox,
                ))
                .expect("pair");
            let mut verifier = Verifier::new(identity(), store);

            assert!(matches!(
                verifier.issue(
                    &RequestSpec::new(CREDENTIAL_ID, service, "unlock", "item", "alice"),
                    &LoopbackSession::secure(),
                    NOW_MS,
                ),
                Err(AuthorizationError::PurposeMismatch { requested, .. })
                    if requested == required
            ));
        }
    }
}

#[test]
fn a_garbled_response_frame_is_rejected() {
    let (mut verifier, authenticator) = paired();
    let session = LoopbackSession::secure();

    let pending = verifier.issue(&spec(), &session, NOW_MS).expect("issue");
    let mut response = authenticator.answer(&pending.frame());
    response[0] ^= 0xff;

    assert!(matches!(
        verifier.accept(pending, &response, &session, NOW_MS),
        Err(AuthorizationError::Protocol(_))
    ));
}

#[test]
fn a_forged_authorization_over_a_denied_response_is_rejected() {
    // Flip a denial into an authorization without touching the signature.
    let (mut verifier, authenticator) = paired();
    let declining = SoftwareAuthenticator::new(DEVICE_ID, CREDENTIAL_ID, 11)
        .with_behaviour(AuthenticatorBehaviour::Decline);
    let session = LoopbackSession::secure();

    let pending = verifier.issue(&spec(), &session, NOW_MS).expect("issue");
    let denial = AuthResponse::decode(&declining.answer(&pending.frame())).expect("denial decodes");
    assert_eq!(denial.decision, Decision::Denied);

    let forged = AuthResponse {
        decision: Decision::Authorized,
        algorithm: phone_auth_protocol::ALGORITHM_ECDSA_P256_SHA256.into(),
        // Borrow a signature the authenticator made for a *different* request.
        signature: AuthResponse::decode(
            &authenticator.answer(
                &verifier
                    .issue(&spec(), &session, NOW_MS)
                    .expect("issue another")
                    .frame(),
            ),
        )
        .expect("decode")
        .signature,
        ..denial
    };

    assert!(matches!(
        verifier.accept(pending, &forged.encode(), &session, NOW_MS),
        Err(AuthorizationError::Signature(_))
    ));
}
