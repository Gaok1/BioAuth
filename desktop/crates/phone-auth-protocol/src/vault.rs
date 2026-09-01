//! Payloads for the personal vault operations.
//!
//! Like the File Locker payloads, these ride inside an [`crate::ApplicationFrame`]
//! within the authenticated encrypted session. The phone is the authoritative
//! store: it holds the ciphertext, and the desktop never sees an item's secret
//! until it asks for that one item and the user approves it with a fingerprint.
//!
//! Two rules shape every type here.
//!
//! The first is that listing and reading are different operations. A list is
//! metadata the user already agreed to show on the desktop; a fetch is one
//! secret, released once. Collapsing them would mean the desktop holding the
//! whole vault in memory to render a search box, which is exactly what the
//! phone-as-vault design exists to avoid.
//!
//! The second is optimistic revision. Every item carries a revision, and an
//! update or delete must name the revision it believes it is replacing. Two
//! desktops editing the same login is not a hypothetical once a phone can be
//! paired with more than one computer, and a last-writer-wins vault silently
//! eats a password change.
//!
//! Nothing here that can carry a secret implements `Debug`, and the secret
//! carriers wipe on drop.

use crate::cbor::{Reader, Writer};
use crate::{
    bytes_equal, check_text, utf16_len, ProtocolError, Result, MAX_APPLICATION_PAYLOAD_BYTES,
};

/// Ask the phone for a page of item metadata. No secret crosses.
pub const OPERATION_LIST: &str = "vault.list";
/// Ask the phone to release one item's secret. Gated by biometrics.
pub const OPERATION_FETCH: &str = "vault.fetch";
/// Store a new item.
pub const OPERATION_CREATE: &str = "vault.create";
/// Replace an existing item, naming the revision being replaced.
pub const OPERATION_UPDATE: &str = "vault.update";
/// Remove an item, naming the revision being removed.
pub const OPERATION_DELETE: &str = "vault.delete";

/// Only schema this build speaks. Unknown schemas fail closed.
pub const VAULT_SCHEMA: u64 = 1;

/// Most summaries one `vault.list` page may carry.
///
/// The real bound is [`MAX_APPLICATION_PAYLOAD_BYTES`], which every response
/// checks after encoding. This count exists so a phone can stop building a page
/// before it wastes work on summaries it will have to drop, and so a hostile
/// response cannot make the desktop allocate an unbounded vector before the
/// size check runs.
pub const MAX_PAGE_ITEMS: usize = 32;

const MAX_ID_UNITS: usize = 64;
const MAX_NAME_UNITS: usize = 255;
const MAX_USERNAME_UNITS: usize = 255;
const MAX_URI_UNITS: usize = 1024;
const MAX_CURSOR_UNITS: usize = 128;
/// Bounds a login password or a secure note's body.
///
/// Generous enough for a recovery-code blob pasted into a note, and still far
/// inside the frame budget so a single item can never fail to come back.
const MAX_SECRET_UNITS: usize = 4096;

const SUMMARY_FIELDS: u64 = 7;
const LIST_REQUEST_FIELDS: u64 = 3;
const LIST_RESPONSE_FIELDS: u64 = 3;
const FETCH_REQUEST_FIELDS: u64 = 3;
const FETCH_RESPONSE_FIELDS: u64 = 4;
const CREATE_REQUEST_FIELDS: u64 = 7;
const UPDATE_REQUEST_FIELDS: u64 = 9;
const DELETE_REQUEST_FIELDS: u64 = 4;
const WRITE_RESPONSE_FIELDS: u64 = 3;
const DELETE_RESPONSE_FIELDS: u64 = 2;

/// Wipes a secret that is about to be dropped.
///
/// Same limited promise as the locker's: enough that freed memory is not still
/// a password, and deliberately not a claim about pages, cores or optimisers.
/// The agent is where a secret gets `VirtualLock`/`mlock` treatment.
fn wipe(buffer: &mut [u8]) {
    for byte in buffer.iter_mut() {
        // `write_volatile` is what stops this being optimised away as a store
        // to memory nothing reads again.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Zeroes a secret string in place.
///
/// Overwriting every byte with zero leaves the buffer valid UTF-8, which is the
/// invariant `as_bytes_mut` requires the caller to uphold.
fn wipe_text(value: &mut str) {
    unsafe { wipe(value.as_bytes_mut()) };
}

/// What kind of thing an item is.
///
/// Two variants, matching `DEC-05`: logins and secure notes. Cards, identities
/// and attachments stay out until the threat model is revisited, and adding a
/// variant is a schema change on both sides rather than a new free-text field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ItemKind {
    Login,
    Note,
    /// A TOTP seed. The stored secret is the base32 key; the six digits are
    /// derived on the phone and never stored, because a stored code is a code
    /// that outlives its window.
    Totp,
}

impl ItemKind {
    fn wire(self) -> u64 {
        match self {
            Self::Login => 0,
            Self::Note => 1,
            Self::Totp => 2,
        }
    }

    fn from_wire(value: u64) -> Result<Self> {
        match value {
            0 => Ok(Self::Login),
            1 => Ok(Self::Note),
            2 => Ok(Self::Totp),
            _ => Err(ProtocolError::InvalidItemKind(value)),
        }
    }
}

/// One row of the desktop's list. Carries no secret.
///
/// `username` and `uri` are empty for a note, and empty is a legitimate value
/// for a login too: plenty of logins have no URL worth recording. That is why
/// they use [`check_optional_text`] rather than the non-blank rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ItemSummary {
    /// Opaque and stable. The desktop never derives meaning from it.
    pub id: String,
    pub revision: u64,
    pub kind: ItemKind,
    pub name: String,
    pub username: String,
    pub uri: String,
    pub updated_at_ms: i64,
}

impl ItemSummary {
    pub fn validate(&self) -> Result<()> {
        check_text("itemId", &self.id, MAX_ID_UNITS)?;
        check_text("name", &self.name, MAX_NAME_UNITS)?;
        check_optional_text("username", &self.username, MAX_USERNAME_UNITS)?;
        check_optional_text("uri", &self.uri, MAX_URI_UNITS)?;
        check_revision(self.revision)
    }

    fn write(&self, writer: &mut Writer) {
        writer.array(SUMMARY_FIELDS);
        writer.text(&self.id);
        writer.uint(self.revision);
        writer.uint(self.kind.wire());
        writer.text(&self.name);
        writer.text(&self.username);
        writer.text(&self.uri);
        writer.int(self.updated_at_ms);
    }

    fn read(reader: &mut Reader<'_>) -> Result<Self> {
        let len = reader.array()?;
        if len != SUMMARY_FIELDS {
            return Err(ProtocolError::FrameShape {
                expected: SUMMARY_FIELDS,
                actual: len,
            });
        }
        Ok(Self {
            id: reader.text()?.to_owned(),
            revision: reader.uint()?,
            kind: ItemKind::from_wire(reader.uint()?)?,
            name: reader.text()?.to_owned(),
            username: reader.text()?.to_owned(),
            uri: reader.text()?.to_owned(),
            updated_at_ms: reader.int()?,
        })
    }
}

/// `vault.list`: the desktop asks for a page of metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListRequest {
    /// The computer asking, as the user named it.
    pub verifier_name: String,
    /// Empty starts at the first page; otherwise the cursor a previous
    /// [`ListResponse`] handed back.
    pub cursor: String,
}

impl ListRequest {
    pub fn validate(&self) -> Result<()> {
        check_text("verifierName", &self.verifier_name, MAX_NAME_UNITS)?;
        check_optional_text("cursor", &self.cursor, MAX_CURSOR_UNITS)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.array(LIST_REQUEST_FIELDS);
        writer.uint(VAULT_SCHEMA);
        writer.text(&self.verifier_name);
        writer.text(&self.cursor);
        writer.into_bytes()
    }

    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut reader = open(payload, LIST_REQUEST_FIELDS)?;
        let decoded = Self {
            verifier_name: reader.text()?.to_owned(),
            cursor: reader.text()?.to_owned(),
        };
        finish(reader, &decoded.encode(), payload)?;
        decoded.validate()?;
        Ok(decoded)
    }
}

/// The phone's answer to `vault.list`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListResponse {
    pub items: Vec<ItemSummary>,
    /// Empty means this was the last page. Anything else is opaque to the
    /// desktop and must be echoed back verbatim.
    pub next_cursor: String,
}

impl ListResponse {
    pub fn validate(&self) -> Result<()> {
        if self.items.len() > MAX_PAGE_ITEMS {
            return Err(ProtocolError::PayloadSize(self.items.len()));
        }
        for item in &self.items {
            item.validate()?;
        }
        check_optional_text("nextCursor", &self.next_cursor, MAX_CURSOR_UNITS)?;
        // A page that does not fit is the phone's bug, and catching it here
        // means it surfaces as a refusal instead of a frame the session layer
        // drops for being oversized.
        let encoded = self.encode().len();
        if encoded > MAX_APPLICATION_PAYLOAD_BYTES {
            return Err(ProtocolError::PayloadSize(encoded));
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.array(LIST_RESPONSE_FIELDS);
        writer.uint(VAULT_SCHEMA);
        writer.array(self.items.len() as u64);
        for item in &self.items {
            item.write(&mut writer);
        }
        writer.text(&self.next_cursor);
        writer.into_bytes()
    }

    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut reader = open(payload, LIST_RESPONSE_FIELDS)?;
        let count = reader.array()?;
        // Checked before allocating: the length prefix is attacker-controlled
        // and `with_capacity` on it would be the whole denial of service.
        if count > MAX_PAGE_ITEMS as u64 {
            return Err(ProtocolError::PayloadSize(count as usize));
        }
        let mut items = Vec::with_capacity(count as usize);
        for _ in 0..count {
            items.push(ItemSummary::read(&mut reader)?);
        }
        let decoded = Self {
            items,
            next_cursor: reader.text()?.to_owned(),
        };
        finish(reader, &decoded.encode(), payload)?;
        decoded.validate()?;
        Ok(decoded)
    }
}

/// `vault.fetch`: the desktop asks for exactly one item's secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchRequest {
    pub verifier_name: String,
    pub item_id: String,
}

impl FetchRequest {
    pub fn validate(&self) -> Result<()> {
        check_text("verifierName", &self.verifier_name, MAX_NAME_UNITS)?;
        check_text("itemId", &self.item_id, MAX_ID_UNITS)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.array(FETCH_REQUEST_FIELDS);
        writer.uint(VAULT_SCHEMA);
        writer.text(&self.verifier_name);
        writer.text(&self.item_id);
        writer.into_bytes()
    }

    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut reader = open(payload, FETCH_REQUEST_FIELDS)?;
        let decoded = Self {
            verifier_name: reader.text()?.to_owned(),
            item_id: reader.text()?.to_owned(),
        };
        finish(reader, &decoded.encode(), payload)?;
        decoded.validate()?;
        Ok(decoded)
    }
}

/// The phone's answer to `vault.fetch`: the one secret that was approved.
///
/// The revision travels with it so the desktop can tell that the value it is
/// about to put on the clipboard belongs to the row the user clicked, and not
/// to a version edited on another device in between.
#[derive(Clone, PartialEq, Eq)]
pub struct FetchResponse {
    pub item_id: String,
    pub revision: u64,
    /// A login's password or a note's body.
    pub secret: String,
}

impl Drop for FetchResponse {
    fn drop(&mut self) {
        wipe_text(&mut self.secret);
    }
}

impl FetchResponse {
    pub fn validate(&self) -> Result<()> {
        check_text("itemId", &self.item_id, MAX_ID_UNITS)?;
        check_revision(self.revision)?;
        check_secret(&self.secret)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.array(FETCH_RESPONSE_FIELDS);
        writer.uint(VAULT_SCHEMA);
        writer.text(&self.item_id);
        writer.uint(self.revision);
        writer.text(&self.secret);
        writer.into_bytes()
    }

    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut reader = open(payload, FETCH_RESPONSE_FIELDS)?;
        let decoded = Self {
            item_id: reader.text()?.to_owned(),
            revision: reader.uint()?,
            secret: reader.text()?.to_owned(),
        };
        finish(reader, &decoded.encode(), payload)?;
        decoded.validate()?;
        Ok(decoded)
    }
}

/// `vault.create`: the desktop asks the phone to store a new item.
#[derive(Clone, PartialEq, Eq)]
pub struct CreateRequest {
    pub verifier_name: String,
    pub kind: ItemKind,
    /// Shown on the phone before the biometric prompt, so the user approves a
    /// named thing rather than an opaque write.
    pub name: String,
    pub username: String,
    pub uri: String,
    pub secret: String,
}

impl Drop for CreateRequest {
    fn drop(&mut self) {
        wipe_text(&mut self.secret);
    }
}

impl CreateRequest {
    pub fn validate(&self) -> Result<()> {
        check_text("verifierName", &self.verifier_name, MAX_NAME_UNITS)?;
        check_text("name", &self.name, MAX_NAME_UNITS)?;
        check_optional_text("username", &self.username, MAX_USERNAME_UNITS)?;
        check_optional_text("uri", &self.uri, MAX_URI_UNITS)?;
        check_secret(&self.secret)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.array(CREATE_REQUEST_FIELDS);
        writer.uint(VAULT_SCHEMA);
        writer.text(&self.verifier_name);
        writer.uint(self.kind.wire());
        writer.text(&self.name);
        writer.text(&self.username);
        writer.text(&self.uri);
        writer.text(&self.secret);
        writer.into_bytes()
    }

    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut reader = open(payload, CREATE_REQUEST_FIELDS)?;
        let decoded = Self {
            verifier_name: reader.text()?.to_owned(),
            kind: ItemKind::from_wire(reader.uint()?)?,
            name: reader.text()?.to_owned(),
            username: reader.text()?.to_owned(),
            uri: reader.text()?.to_owned(),
            secret: reader.text()?.to_owned(),
        };
        finish(reader, &decoded.encode(), payload)?;
        decoded.validate()?;
        Ok(decoded)
    }
}

/// `vault.update`: replace an item, naming the revision being replaced.
///
/// Carries the whole item rather than a patch. A patch would need the desktop
/// to hold the previous secret to know what it is not changing, and the point
/// of the design is that it does not hold secrets between operations.
#[derive(Clone, PartialEq, Eq)]
pub struct UpdateRequest {
    pub verifier_name: String,
    pub item_id: String,
    /// The revision the desktop believes it is replacing. A phone that holds a
    /// different one refuses, and the desktop re-reads instead of overwriting
    /// an edit it never saw.
    pub expected_revision: u64,
    pub kind: ItemKind,
    pub name: String,
    pub username: String,
    pub uri: String,
    pub secret: String,
}

impl Drop for UpdateRequest {
    fn drop(&mut self) {
        wipe_text(&mut self.secret);
    }
}

impl UpdateRequest {
    pub fn validate(&self) -> Result<()> {
        check_text("verifierName", &self.verifier_name, MAX_NAME_UNITS)?;
        check_text("itemId", &self.item_id, MAX_ID_UNITS)?;
        check_revision(self.expected_revision)?;
        check_text("name", &self.name, MAX_NAME_UNITS)?;
        check_optional_text("username", &self.username, MAX_USERNAME_UNITS)?;
        check_optional_text("uri", &self.uri, MAX_URI_UNITS)?;
        check_secret(&self.secret)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.array(UPDATE_REQUEST_FIELDS);
        writer.uint(VAULT_SCHEMA);
        writer.text(&self.verifier_name);
        writer.text(&self.item_id);
        writer.uint(self.expected_revision);
        writer.uint(self.kind.wire());
        writer.text(&self.name);
        writer.text(&self.username);
        writer.text(&self.uri);
        writer.text(&self.secret);
        writer.into_bytes()
    }

    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut reader = open(payload, UPDATE_REQUEST_FIELDS)?;
        let decoded = Self {
            verifier_name: reader.text()?.to_owned(),
            item_id: reader.text()?.to_owned(),
            expected_revision: reader.uint()?,
            kind: ItemKind::from_wire(reader.uint()?)?,
            name: reader.text()?.to_owned(),
            username: reader.text()?.to_owned(),
            uri: reader.text()?.to_owned(),
            secret: reader.text()?.to_owned(),
        };
        finish(reader, &decoded.encode(), payload)?;
        decoded.validate()?;
        Ok(decoded)
    }
}

/// The phone's answer to `vault.create` and `vault.update`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WriteResponse {
    pub item_id: String,
    /// The revision now stored. Always greater than the one replaced.
    pub revision: u64,
}

impl WriteResponse {
    pub fn validate(&self) -> Result<()> {
        check_text("itemId", &self.item_id, MAX_ID_UNITS)?;
        check_revision(self.revision)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.array(WRITE_RESPONSE_FIELDS);
        writer.uint(VAULT_SCHEMA);
        writer.text(&self.item_id);
        writer.uint(self.revision);
        writer.into_bytes()
    }

    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut reader = open(payload, WRITE_RESPONSE_FIELDS)?;
        let decoded = Self {
            item_id: reader.text()?.to_owned(),
            revision: reader.uint()?,
        };
        finish(reader, &decoded.encode(), payload)?;
        decoded.validate()?;
        Ok(decoded)
    }
}

/// `vault.delete`: remove an item, naming the revision being removed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeleteRequest {
    pub verifier_name: String,
    pub item_id: String,
    pub expected_revision: u64,
}

impl DeleteRequest {
    pub fn validate(&self) -> Result<()> {
        check_text("verifierName", &self.verifier_name, MAX_NAME_UNITS)?;
        check_text("itemId", &self.item_id, MAX_ID_UNITS)?;
        check_revision(self.expected_revision)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.array(DELETE_REQUEST_FIELDS);
        writer.uint(VAULT_SCHEMA);
        writer.text(&self.verifier_name);
        writer.text(&self.item_id);
        writer.uint(self.expected_revision);
        writer.into_bytes()
    }

    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut reader = open(payload, DELETE_REQUEST_FIELDS)?;
        let decoded = Self {
            verifier_name: reader.text()?.to_owned(),
            item_id: reader.text()?.to_owned(),
            expected_revision: reader.uint()?,
        };
        finish(reader, &decoded.encode(), payload)?;
        decoded.validate()?;
        Ok(decoded)
    }
}

/// The phone's answer to `vault.delete`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeleteResponse {
    pub item_id: String,
}

impl DeleteResponse {
    pub fn validate(&self) -> Result<()> {
        check_text("itemId", &self.item_id, MAX_ID_UNITS)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.array(DELETE_RESPONSE_FIELDS);
        writer.uint(VAULT_SCHEMA);
        writer.text(&self.item_id);
        writer.into_bytes()
    }

    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut reader = open(payload, DELETE_RESPONSE_FIELDS)?;
        let decoded = Self {
            item_id: reader.text()?.to_owned(),
        };
        finish(reader, &decoded.encode(), payload)?;
        decoded.validate()?;
        Ok(decoded)
    }
}

/// Bounded, but allowed to be empty.
///
/// Distinct from [`check_text`] because a login with no URL and a note with no
/// username are ordinary, and rejecting them would push callers into writing a
/// placeholder that then shows up in the UI.
fn check_optional_text(field: &'static str, value: &str, max: usize) -> Result<()> {
    let actual = utf16_len(value);
    if actual > max {
        return Err(ProtocolError::FieldTooLong { field, max, actual });
    }
    Ok(())
}

/// A secret may not be blank, and is bounded well inside the frame budget.
fn check_secret(value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(ProtocolError::FieldEmpty("secret"));
    }
    let actual = utf16_len(value);
    if actual > MAX_SECRET_UNITS {
        return Err(ProtocolError::FieldTooLong {
            field: "secret",
            max: MAX_SECRET_UNITS,
            actual,
        });
    }
    Ok(())
}

/// Revisions start at one, so zero is always a caller that forgot to set it.
fn check_revision(revision: u64) -> Result<()> {
    if revision == 0 {
        return Err(ProtocolError::InvalidRevision);
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
    if schema != VAULT_SCHEMA {
        return Err(ProtocolError::UnsupportedVersion(schema));
    }
    Ok(reader)
}

/// Shared tail: nothing left over, and one spelling per value.
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
    use crate::encoding::to_hex;

    fn summary() -> ItemSummary {
        ItemSummary {
            id: "item-1".into(),
            revision: 3,
            kind: ItemKind::Login,
            name: "GitHub".into(),
            username: "luis".into(),
            uri: "https://github.com".into(),
            updated_at_ms: 1_700_000_000_000,
        }
    }

    fn fetch_response() -> FetchResponse {
        FetchResponse {
            item_id: "item-1".into(),
            revision: 3,
            secret: "correct horse battery staple".into(),
        }
    }

    /// Pins the bytes the Dart side has to reproduce. A change here is a
    /// protocol change and must move `mobile/` in the same commit.
    const CREATE_REQUEST_HEX: &str = concat!(
        "87",                             // array(7)
        "01",                             // schema 1
        "6b", "576f726b73746174696f6e",   // "Workstation"
        "01",                             // kind: note
        "6e", "5265636f7665727920636f646573", // "Recovery codes"
        "60",                             // username: ""
        "60",                             // uri: ""
        "69", "313131312d32323232",       // "1111-2222"
    );

    #[test]
    fn a_fetch_response_pins_its_bytes() {
        assert_eq!(
            to_hex(&fetch_response().encode()),
            concat!(
                "8401666974656d2d3103781c636f727265637420686f7273652062617474657279",
                "20737461706c65"
            )
        );
    }

    /// The request that carries a password, pinned the way the fetch reply is.
    ///
    /// `vault.create` was the one vault payload with no cross-language vector:
    /// the Dart side only decoded what it had just encoded, which proves the
    /// two halves of one implementation agree and nothing about whether the
    /// other language does. It is also the payload where disagreement is worst
    /// -- a field read at the wrong offset here is a password stored under the
    /// wrong name, or a name stored as the password.
    ///
    /// The same fixture is asserted from the phone in
    /// `mobile/test/vault_payloads_test.dart`.
    #[test]
    fn a_create_request_pins_its_bytes() {
        let request = CreateRequest {
            verifier_name: "Workstation".into(),
            kind: ItemKind::Note,
            name: "Recovery codes".into(),
            username: String::new(),
            uri: String::new(),
            secret: "1111-2222".into(),
        };
        assert_eq!(to_hex(&request.encode()), CREATE_REQUEST_HEX);
    }

    #[test]
    fn every_payload_round_trips() {
        let list_request = ListRequest {
            verifier_name: "Workstation".into(),
            cursor: String::new(),
        };
        assert_eq!(
            ListRequest::decode(&list_request.encode()).expect("list request"),
            list_request
        );

        let list_response = ListResponse {
            items: vec![summary()],
            next_cursor: "page-2".into(),
        };
        assert_eq!(
            ListResponse::decode(&list_response.encode()).expect("list response"),
            list_response
        );

        let fetch_request = FetchRequest {
            verifier_name: "Workstation".into(),
            item_id: "item-1".into(),
        };
        assert_eq!(
            FetchRequest::decode(&fetch_request.encode()).expect("fetch request"),
            fetch_request
        );
        assert!(
            FetchResponse::decode(&fetch_response().encode()).expect("fetch") == fetch_response()
        );

        let create = CreateRequest {
            verifier_name: "Workstation".into(),
            kind: ItemKind::Note,
            name: "Recovery codes".into(),
            username: String::new(),
            uri: String::new(),
            secret: "1111-2222".into(),
        };
        assert!(CreateRequest::decode(&create.encode()).expect("create") == create);

        let update = UpdateRequest {
            verifier_name: "Workstation".into(),
            item_id: "item-1".into(),
            expected_revision: 3,
            kind: ItemKind::Login,
            name: "GitHub".into(),
            username: "luis".into(),
            uri: "https://github.com".into(),
            secret: "new-password".into(),
        };
        assert!(UpdateRequest::decode(&update.encode()).expect("update") == update);

        let write = WriteResponse {
            item_id: "item-1".into(),
            revision: 4,
        };
        assert_eq!(
            WriteResponse::decode(&write.encode()).expect("write response"),
            write
        );

        let delete = DeleteRequest {
            verifier_name: "Workstation".into(),
            item_id: "item-1".into(),
            expected_revision: 4,
        };
        assert_eq!(
            DeleteRequest::decode(&delete.encode()).expect("delete request"),
            delete
        );

        let deleted = DeleteResponse {
            item_id: "item-1".into(),
        };
        assert_eq!(
            DeleteResponse::decode(&deleted.encode()).expect("delete response"),
            deleted
        );
    }

    /// An empty page is how the desktop learns the vault is empty, and it must
    /// not be confused with a truncated frame.
    #[test]
    fn an_empty_page_is_a_legitimate_answer() {
        let empty = ListResponse {
            items: Vec::new(),
            next_cursor: String::new(),
        };
        let decoded = ListResponse::decode(&empty.encode()).expect("empty page");
        assert!(decoded.items.is_empty());
        assert!(decoded.next_cursor.is_empty());
    }

    /// A note has no username and no URL. Rejecting that would force callers to
    /// invent a placeholder that the UI would then display.
    #[test]
    fn optional_fields_may_be_empty_but_the_name_may_not() {
        let mut note = summary();
        note.kind = ItemKind::Note;
        note.username = String::new();
        note.uri = String::new();
        assert!(note.validate().is_ok());

        note.name = "   ".into();
        assert_eq!(note.validate(), Err(ProtocolError::FieldEmpty("name")));
    }

    /// Revision zero means a caller built the request without reading the item
    /// first, which is exactly the overwrite optimistic concurrency exists to
    /// stop. It fails closed rather than being treated as "any revision".
    #[test]
    fn revision_zero_is_refused_on_every_message_that_carries_one() {
        let delete = DeleteRequest {
            verifier_name: "Workstation".into(),
            item_id: "item-1".into(),
            expected_revision: 0,
        };
        assert_eq!(delete.validate(), Err(ProtocolError::InvalidRevision));

        let write = WriteResponse {
            item_id: "item-1".into(),
            revision: 0,
        };
        assert_eq!(write.validate(), Err(ProtocolError::InvalidRevision));

        let mut stale = summary();
        stale.revision = 0;
        assert_eq!(stale.validate(), Err(ProtocolError::InvalidRevision));
    }

    /// The length prefix arrives before the items do. Trusting it would let a
    /// three-byte payload ask for a gigabyte of `Vec`.
    #[test]
    fn a_lying_length_prefix_never_reaches_an_allocation() {
        let mut writer = Writer::new();
        writer.array(LIST_RESPONSE_FIELDS);
        writer.uint(VAULT_SCHEMA);
        writer.array(u32::MAX as u64);
        let hostile = writer.into_bytes();

        assert_eq!(
            ListResponse::decode(&hostile),
            Err(ProtocolError::PayloadSize(u32::MAX as usize))
        );
    }

    /// A page the phone built too large must be refused by the phone, not sent
    /// and dropped by the session layer as an oversized frame.
    #[test]
    fn a_page_past_the_payload_budget_is_refused() {
        let items = (0..MAX_PAGE_ITEMS)
            .map(|index| ItemSummary {
                id: format!("item-{index}"),
                name: "x".repeat(MAX_NAME_UNITS),
                uri: "u".repeat(MAX_URI_UNITS),
                ..summary()
            })
            .collect();
        let overflowing = ListResponse {
            items,
            next_cursor: String::new(),
        };
        assert!(matches!(
            overflowing.validate(),
            Err(ProtocolError::PayloadSize(_))
        ));
    }

    #[test]
    fn more_items_than_a_page_allows_is_refused() {
        let response = ListResponse {
            items: vec![summary(); MAX_PAGE_ITEMS + 1],
            next_cursor: String::new(),
        };
        assert_eq!(
            response.validate(),
            Err(ProtocolError::PayloadSize(MAX_PAGE_ITEMS + 1))
        );
    }

    #[test]
    fn an_unknown_item_kind_fails_closed() {
        // Every kind this build knows round-trips, and the first one past them
        // does not. Written as a walk rather than a literal: this test used to
        // assert on `2`, and adding `Totp` as 2 turned it into a test that a
        // valid kind is rejected.
        let known = [ItemKind::Login, ItemKind::Note, ItemKind::Totp];
        for kind in known {
            assert_eq!(ItemKind::from_wire(kind.wire()), Ok(kind));
        }
        let unknown = known.len() as u64;
        assert_eq!(
            ItemKind::from_wire(unknown),
            Err(ProtocolError::InvalidItemKind(unknown))
        );
        assert!(ItemKind::from_wire(u64::MAX).is_err());
    }

    #[test]
    fn an_unknown_schema_fails_closed() {
        let mut writer = Writer::new();
        writer.array(DELETE_RESPONSE_FIELDS);
        writer.uint(VAULT_SCHEMA + 1);
        writer.text("item-1");
        assert_eq!(
            DeleteResponse::decode(&writer.into_bytes()),
            Err(ProtocolError::UnsupportedVersion(VAULT_SCHEMA + 1))
        );
    }

    /// Two spellings of the same value must not both decode, or an audit line
    /// over the bytes would not mean what it appears to.
    ///
    /// The reader rejects the padded integer before the re-encode comparison
    /// ever runs, which is why this asserts the CBOR error rather than
    /// [`ProtocolError::NotCanonical`]. That check stays as the backstop for
    /// anything the reader cannot see, such as a field whose canonical spelling
    /// is decided by the struct rather than by the encoding.
    #[test]
    fn a_non_canonical_encoding_is_refused() {
        // `revision` written as a two-byte uint where one byte would do.
        let canonical = WriteResponse {
            item_id: "item-1".into(),
            revision: 4,
        }
        .encode();
        let mut padded = canonical.clone();
        let last = padded.pop().expect("revision byte");
        padded.extend_from_slice(&[0x18, last]);

        assert_eq!(
            WriteResponse::decode(&padded),
            Err(ProtocolError::Cbor(
                crate::cbor::CborError::NonCanonicalInteger
            ))
        );
        assert!(WriteResponse::decode(&canonical).is_ok());
    }

    /// An empty secret is a caller bug: it would put an empty clipboard in
    /// front of the user and look like a successful copy.
    #[test]
    fn an_empty_secret_is_refused() {
        let empty = FetchResponse {
            item_id: "item-1".into(),
            revision: 1,
            secret: String::new(),
        };
        assert_eq!(empty.validate(), Err(ProtocolError::FieldEmpty("secret")));
    }

    /// The whole point of the type. If this regresses, a freed password stays
    /// readable in the allocator's memory.
    #[test]
    fn dropping_a_secret_zeroes_it() {
        let mut response = fetch_response();
        let address = response.secret.as_ptr();
        let len = response.secret.len();
        wipe_text(&mut response.secret);

        // Safe: the buffer is still owned by `response`, still `len` bytes, and
        // still valid UTF-8 because every byte is now zero.
        let after = unsafe { core::slice::from_raw_parts(address, len) };
        assert!(after.iter().all(|byte| *byte == 0));
    }
}
