//! Payloads for keeping a pairing's permissions the same on both sides.
//!
//! What a paired phone is allowed to authorise -- `sudo` on this account,
//! `login`, the file locker, the vault -- has always been the desktop's to
//! know, because the desktop is what enforces it. The phone carried the
//! credential and no opinion about what it was for. So changing what a pairing
//! could do meant walking to the computer, and granting a phone a second set
//! of powers meant pairing it a second time.
//!
//! One operation fixes that, and its shape is decided by something the
//! transport already settled: **the phone never initiates.** Every operation in
//! this crate is the desktop asking and the phone answering. A phone that
//! edited its own permissions has no channel to announce it.
//!
//! So this is not two writes. It is one reconciliation, carried by a call the
//! desktop already makes: the desktop sends what it believes, the phone answers
//! with what stands, and both end the call agreeing. Edit on either side; the
//! next session settles it.
//!
//! The rule is deliberately two lines long, because it is implemented twice --
//! once here and once in Dart -- and a rule that needs a paragraph is a rule
//! the two copies will eventually disagree about:
//!
//!   1. The higher revision wins.
//!   2. On a tie, the phone's set stands.
//!
//! Rule 2 is not a coin toss. A tie means both sides edited without seeing each
//! other, and of the two screens involved only one asked for a fingerprint
//! before it let anybody change what a device may authorise. Deciding for the
//! device that verified a human is the same instinct as the rest of this
//! product.
//!
//! Revisions start at 1 and only ever climb, so a side that has never been
//! edited sends 0 and loses to any real revision.
//!
//! Zero against zero is the exception, and it is the case every pairing alive
//! today hits on its first sync. The two zeroes do not mean the same thing:
//! the desktop's set is whatever was granted from the tray over the life of the
//! pairing, and the phone's is empty because the phone has never had a
//! permission store. Sent through the tie-break, the phone would win with
//! nothing and a working pairing would be revoked by the act of syncing it. So
//! a double zero goes to the desktop, and only then does rule 2 apply.

use crate::cbor::{Reader, Writer};
use crate::{bytes_equal, check_text, ProtocolError, Result, MAX_APPLICATION_PAYLOAD_BYTES};

/// Exchange permissions and settle on one set.
pub const OPERATION_SYNC: &str = "permissions.sync";

/// How every field but `service` spells "any value".
///
/// Repeated here rather than imported from the verifier, because this crate is
/// the wire and must not depend on the thing that enforces it. The two are
/// pinned together by a test on the enforcing side.
pub const WILDCARD: &str = "*";

/// Schema marker, first field of every payload here.
pub const PERMISSIONS_SCHEMA: u64 = 1;

const SYNC_REQUEST_FIELDS: u64 = 4;
const SYNC_RESPONSE_FIELDS: u64 = 3;

/// How many grants one credential may carry.
///
/// A person granting sixty-four distinct powers to one phone has stopped
/// describing a pairing and started describing an account, and the bound is
/// what keeps a malformed reply from becoming an allocation.
pub const MAX_PERMISSIONS: usize = 64;

const MAX_NAME_UNITS: usize = 255;
const MAX_FIELD_UNITS: usize = 255;

/// One grant: who may do what, to what, as whom.
///
/// The four fields mirror the agent's own `Permission` exactly. They are
/// matched, not interpreted, on the way through here.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Permission {
    pub service: String,
    pub action: String,
    pub resource: String,
    pub user: String,
}

impl Permission {
    pub fn validate(&self) -> Result<()> {
        // All four required, none of them empty. "Any resource" is spelled
        // `*` on the enforcing side, and an empty string there is not a
        // wildcard -- it is a value nothing ever matches. Letting one across
        // would turn a grant the user wrote into one that silently never
        // applies, which is a permission system that lies about itself.
        check_text("service", &self.service, MAX_FIELD_UNITS)?;
        check_text("action", &self.action, MAX_FIELD_UNITS)?;
        check_text("resource", &self.resource, MAX_FIELD_UNITS)?;
        check_text("user", &self.user, MAX_FIELD_UNITS)
    }

    fn write(&self, writer: &mut Writer) {
        writer.array(4);
        writer.text(&self.service);
        writer.text(&self.action);
        writer.text(&self.resource);
        writer.text(&self.user);
    }

    fn read(reader: &mut Reader<'_>) -> Result<Self> {
        let len = reader.array()?;
        if len != 4 {
            return Err(ProtocolError::FrameShape {
                expected: 4,
                actual: len,
            });
        }
        Ok(Self {
            service: reader.text()?.to_owned(),
            action: reader.text()?.to_owned(),
            resource: reader.text()?.to_owned(),
            user: reader.text()?.to_owned(),
        })
    }
}

/// Which side's set is the one that stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Winner {
    /// The caller's own set is newer, or the tie went its way.
    Mine,
    /// The other side's set is newer, or the tie went against.
    Theirs,
}

/// The whole reconciliation rule, in the one place both callers can reach.
///
/// `phone_wins_ties` is what makes this the same function on both sides: the
/// phone calls it with `true` about its own set, the desktop calls it with
/// `false` about its own. Neither has a second rule of its own to drift from.
pub fn reconcile(mine: u64, theirs: u64, phone_wins_ties: bool) -> Winner {
    // Neither side has ever been edited. This is the first sync of a pairing
    // that predates the feature, and the two zeroes do not mean the same
    // thing: the desktop's set is whatever was granted from the tray over the
    // life of the pairing, and the phone's is empty because the phone has
    // never had a permission store at all. Handing this to the tie-break
    // would revoke a working pairing on contact.
    if mine == 0 && theirs == 0 {
        return if phone_wins_ties {
            Winner::Theirs
        } else {
            Winner::Mine
        };
    }
    if mine > theirs {
        return Winner::Mine;
    }
    if theirs > mine {
        return Winner::Theirs;
    }
    if phone_wins_ties {
        Winner::Mine
    } else {
        Winner::Theirs
    }
}

/// `permissions.sync`: the desktop offers what it believes and asks what stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncRequest {
    /// Shown on the phone beside the set, so a person approving a change knows
    /// which computer's powers they are looking at.
    pub verifier_name: String,
    /// The desktop's revision. Zero means it has never been edited.
    pub revision: u64,
    pub permissions: Vec<Permission>,
}

impl SyncRequest {
    pub fn validate(&self) -> Result<()> {
        check_text("verifierName", &self.verifier_name, MAX_NAME_UNITS)?;
        check_set(&self.permissions)?;
        check_size(self.encode().len())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.array(SYNC_REQUEST_FIELDS);
        writer.uint(PERMISSIONS_SCHEMA);
        writer.text(&self.verifier_name);
        writer.uint(self.revision);
        write_set(&mut writer, &self.permissions);
        writer.into_bytes()
    }

    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut reader = open(payload, SYNC_REQUEST_FIELDS)?;
        let decoded = Self {
            verifier_name: reader.text()?.to_owned(),
            revision: reader.uint()?,
            permissions: read_set(&mut reader)?,
        };
        finish(reader, &decoded.encode(), payload)?;
        decoded.validate()?;
        Ok(decoded)
    }
}

/// The phone's answer: the set that stands, and the revision it stands at.
///
/// Always the settled set, never a diff and never "no change". The desktop
/// stores what comes back verbatim, so a reply it fails to understand can only
/// ever be a refused call rather than a pairing left half-updated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncResponse {
    pub revision: u64,
    pub permissions: Vec<Permission>,
}

impl SyncResponse {
    pub fn validate(&self) -> Result<()> {
        check_set(&self.permissions)?;
        check_size(self.encode().len())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.array(SYNC_RESPONSE_FIELDS);
        writer.uint(PERMISSIONS_SCHEMA);
        writer.uint(self.revision);
        write_set(&mut writer, &self.permissions);
        writer.into_bytes()
    }

    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut reader = open(payload, SYNC_RESPONSE_FIELDS)?;
        let decoded = Self {
            revision: reader.uint()?,
            permissions: read_set(&mut reader)?,
        };
        finish(reader, &decoded.encode(), payload)?;
        decoded.validate()?;
        Ok(decoded)
    }
}

fn write_set(writer: &mut Writer, permissions: &[Permission]) {
    writer.array(permissions.len() as u64);
    for permission in permissions {
        permission.write(writer);
    }
}

fn read_set(reader: &mut Reader<'_>) -> Result<Vec<Permission>> {
    let count = reader.array()?;
    // Checked before allocating: the length prefix is attacker-controlled and
    // `with_capacity` on it would be the whole denial of service.
    if count > MAX_PERMISSIONS as u64 {
        return Err(ProtocolError::PayloadSize(count as usize));
    }
    let mut permissions = Vec::with_capacity(count as usize);
    for _ in 0..count {
        permissions.push(Permission::read(reader)?);
    }
    Ok(permissions)
}

fn check_set(permissions: &[Permission]) -> Result<()> {
    if permissions.len() > MAX_PERMISSIONS {
        return Err(ProtocolError::PayloadSize(permissions.len()));
    }
    for permission in permissions {
        permission.validate()?;
    }
    Ok(())
}

fn check_size(encoded: usize) -> Result<()> {
    if encoded > MAX_APPLICATION_PAYLOAD_BYTES {
        return Err(ProtocolError::PayloadSize(encoded));
    }
    Ok(())
}

/// Shared front of every decode: bounds, shape and schema.
fn open(payload: &[u8], fields: u64) -> Result<Reader<'_>> {
    if payload.is_empty() || payload.len() > MAX_APPLICATION_PAYLOAD_BYTES {
        return Err(ProtocolError::PayloadSize(payload.len()));
    }
    let mut reader = Reader::new(payload);
    let len = reader.array()?;
    if len != fields {
        return Err(ProtocolError::FrameShape {
            expected: fields,
            actual: len,
        });
    }
    let schema = reader.uint()?;
    if schema != PERMISSIONS_SCHEMA {
        return Err(ProtocolError::UnsupportedVersion(schema));
    }
    Ok(reader)
}

fn finish(reader: Reader<'_>, reencoded: &[u8], payload: &[u8]) -> Result<()> {
    reader.finish()?;
    if !bytes_equal(reencoded, payload) {
        return Err(ProtocolError::NotCanonical);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant(service: &str, action: &str) -> Permission {
        Permission {
            service: service.to_owned(),
            action: action.to_owned(),
            resource: WILDCARD.to_owned(),
            user: "gaok1".to_owned(),
        }
    }

    #[test]
    fn a_request_survives_the_round_trip() {
        let request = SyncRequest {
            verifier_name: "Workstation".to_owned(),
            revision: 7,
            permissions: vec![grant("sudo", "run"), grant("login", "unlock")],
        };

        assert_eq!(
            SyncRequest::decode(&request.encode()).expect("decodes"),
            request
        );
    }

    #[test]
    fn a_response_survives_the_round_trip() {
        let response = SyncResponse {
            revision: 9,
            permissions: vec![grant("vault", "read")],
        };

        assert_eq!(
            SyncResponse::decode(&response.encode()).expect("decodes"),
            response
        );
    }

    /// An empty set is a real answer, and the one a revocation produces. It
    /// must not be mistaken for a malformed payload.
    #[test]
    fn granting_nothing_is_a_set_like_any_other() {
        let response = SyncResponse {
            revision: 3,
            permissions: Vec::new(),
        };

        let decoded = SyncResponse::decode(&response.encode()).expect("decodes");
        assert!(decoded.permissions.is_empty());
        assert_eq!(decoded.revision, 3);
    }

    #[test]
    fn the_higher_revision_wins_from_either_seat() {
        assert_eq!(reconcile(5, 4, true), Winner::Mine);
        assert_eq!(reconcile(5, 4, false), Winner::Mine);
        assert_eq!(reconcile(4, 5, true), Winner::Theirs);
        assert_eq!(reconcile(4, 5, false), Winner::Theirs);
    }

    /// The two seats must reach the same conclusion about the same pair of
    /// revisions, or a sync leaves the sides further apart than it found them.
    #[test]
    fn a_tie_settles_on_the_phone_from_both_seats() {
        // The phone, asked about its own set, keeps it.
        assert_eq!(reconcile(6, 6, true), Winner::Mine);
        // The desktop, asked about its own, yields -- to the same set.
        assert_eq!(reconcile(6, 6, false), Winner::Theirs);
    }

    /// Zero is what a side that has never been edited sends, and it loses to
    /// any real revision from either seat.
    #[test]
    fn a_side_that_was_never_edited_loses() {
        assert_eq!(reconcile(0, 1, false), Winner::Theirs);
        assert_eq!(reconcile(0, 1, true), Winner::Theirs);
        assert_eq!(reconcile(1, 0, false), Winner::Mine);
        assert_eq!(reconcile(1, 0, true), Winner::Mine);
    }

    /// The first sync of a pairing older than this feature, which is every
    /// pairing that exists today. Both sides send zero, and the tie-break must
    /// not run: the desktop's zero means "granted from the tray and never
    /// touched since", the phone's means "has never had a permission store".
    /// Treating them as equal claims revokes a working pairing on contact --
    /// the phone answers with its empty set and the desktop stores it.
    #[test]
    fn a_first_sync_keeps_the_grants_the_desktop_already_had() {
        // Asked from the phone's seat about the phone's own empty set.
        assert_eq!(reconcile(0, 0, true), Winner::Theirs);
        // Asked from the desktop's seat about the desktop's set.
        assert_eq!(reconcile(0, 0, false), Winner::Mine);
    }

    /// The bound is checked before the allocation, not after it: the count is
    /// a number the peer chose.
    #[test]
    fn a_set_larger_than_the_bound_is_refused() {
        let response = SyncResponse {
            revision: 1,
            permissions: vec![grant("sudo", "run"); MAX_PERMISSIONS + 1],
        };

        assert!(matches!(
            response.validate(),
            Err(ProtocolError::PayloadSize(_))
        ));
        assert!(matches!(
            SyncResponse::decode(&response.encode()),
            Err(ProtocolError::PayloadSize(_))
        ));
    }

    /// Two encodings of one meaning is two things to compare, and every
    /// decoder here refuses the one it did not produce.
    #[test]
    fn a_non_canonical_encoding_is_refused() {
        let response = SyncResponse {
            revision: 1,
            permissions: vec![grant("sudo", "run")],
        };
        let mut payload = response.encode();
        // Same array, longer length encoding: valid CBOR, not what we write.
        payload.push(0);

        assert!(SyncResponse::decode(&payload).is_err());
    }

    /// The bytes, pinned. `mobile/test/permission_payloads_test.dart` asserts
    /// the same two strings.
    ///
    /// Two encoders, two languages, one meaning. Reorder a field here or write
    /// an integer at a different width and everything still compiles, every
    /// round-trip test on each side still passes, and the pair only finds out
    /// in the field -- as "the phone answered a different request", which names
    /// neither the cause nor the file.
    #[test]
    fn the_bytes_are_the_ones_the_phone_expects() {
        let request = SyncRequest {
            verifier_name: "Workstation".to_owned(),
            revision: 7,
            permissions: vec![
                grant("sudo", WILDCARD),
                Permission {
                    service: "login".to_owned(),
                    action: "unlock".to_owned(),
                    resource: WILDCARD.to_owned(),
                    user: "gaok1".to_owned(),
                },
            ],
        };
        let response = SyncResponse {
            revision: 9,
            permissions: vec![Permission {
                service: "vault".to_owned(),
                action: "read".to_owned(),
                resource: WILDCARD.to_owned(),
                user: "gaok1".to_owned(),
            }],
        };

        assert_eq!(
            hex(&request.encode()),
            concat!(
                "84016b576f726b73746174696f6e078284647375646f612a612a6567616f",
                "6b3184656c6f67696e66756e6c6f636b612a6567616f6b31",
            )
        );
        assert_eq!(
            hex(&response.encode()),
            "8301098184657661756c746472656164612a6567616f6b31"
        );
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn a_payload_from_another_schema_is_refused() {
        let mut writer = Writer::new();
        writer.array(SYNC_RESPONSE_FIELDS);
        writer.uint(PERMISSIONS_SCHEMA + 1);
        writer.uint(1);
        writer.array(0);

        assert!(matches!(
            SyncResponse::decode(&writer.into_bytes()),
            Err(ProtocolError::UnsupportedVersion(_))
        ));
    }

    /// Every field, not just the obvious one. An empty `resource` reaching the
    /// enforcing side is not "any resource" -- it is a grant that matches
    /// nothing, written by a user who believes it matches something.
    #[test]
    fn a_grant_with_an_empty_field_is_refused() {
        for empty in ["service", "action", "resource", "user"] {
            let mut permission = grant("sudo", "run");
            match empty {
                "service" => permission.service.clear(),
                "action" => permission.action.clear(),
                "resource" => permission.resource.clear(),
                _ => permission.user.clear(),
            }
            let response = SyncResponse {
                revision: 1,
                permissions: vec![permission],
            };
            assert!(
                response.validate().is_err(),
                "an empty `{empty}` was accepted"
            );
        }
    }
}
