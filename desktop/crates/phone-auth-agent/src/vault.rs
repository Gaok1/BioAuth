//! The agent's half of the personal vault: asking a phone for a page of
//! metadata, or for exactly one secret.
//!
//! The storage lives on the phone, in the Android Keystore, and nothing here
//! caches it. Every `fetch` costs the user a biometric prompt on the device,
//! which is the point: the desktop cannot decide on its own that a secret may
//! be released.
//!
//! Two rules hold in this file. A secret travels only inside an authenticated,
//! confidential session, and it never reaches an IPC reply, an event, the audit
//! log, or an error message — the buffers it passed through are wiped on the
//! way out. What the caller gets back is a description of what happened.

use std::collections::HashSet;
use std::time::Duration;

use phone_auth_protocol::vault::{
    CreateRequest, FetchRequest, FetchResponse, ItemKind, ItemSummary, ListRequest, ListResponse,
    WriteResponse, OPERATION_CREATE, OPERATION_FETCH, OPERATION_LIST,
};
use phone_auth_protocol::{
    ApplicationErrorCode, ApplicationFrame, ApplicationFrameKind, PROTOCOL_VERSION,
};
use phone_auth_verifier::verifier::now_ms;
use phone_auth_verifier::{random, SecureSession};
use zeroize::Zeroize;

/// How long to wait for the user to answer a vault prompt.
///
/// As long as the request stays valid, plus [`crate::ANSWER_TRAVEL_MARGIN`].
const RECEIVE_TIMEOUT: Duration =
    Duration::from_millis(VALIDITY_MS as u64).saturating_add(crate::ANSWER_TRAVEL_MARGIN);

/// How long a vault request stays valid, matching the envelope's ceiling.
const VALIDITY_MS: i64 = 120_000;

/// How many items one listing may carry before the agent gives up.
///
/// The cursor is chosen by the phone, so without a ceiling a buggy or hostile
/// peer could keep the desktop paging forever. The ceiling used to be
/// thirty-two *pages*, described here as "over a thousand items, a larger
/// vault than the schema was designed for" -- but the phone lets a vault hold
/// four thousand and lets a restore fill it, so a vault of any real size read
/// back on the desktop stopped at "the vault listing did not end". This is
/// the number the phone's own store enforces, counted the way the phone
/// counts it: in items, not in pages of them.
pub(crate) const MAX_ITEMS: usize = 4096;

/// Why a vault exchange did not produce an answer.
///
/// [`Declined`](VaultError::Declined) is deliberately coarse and stays that
/// way as it travels outward. The phone answers a missing item, a stale
/// revision and a refused biometric with the same code on purpose, so that a
/// desktop that is not entitled to a secret cannot learn whether it exists.
/// Widening this enum to explain the difference would undo that on this side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultError {
    /// The phone said no, and did not say why.
    Declined,
    /// The vault could not be served right now — locked, storage error, no
    /// biometric enrolled. Retrying later is meaningful; retrying immediately
    /// is not.
    Unavailable,
    /// The phone rejected the frame, or answered with something that is not a
    /// valid reply. Either way it is a bug on one side, not a decision.
    Protocol(String),
}

impl VaultError {
    /// Visible to the crate because the SSH client reports the same three
    /// outcomes over the same frames. One error type rather than two that
    /// would have to be kept in step by hand.
    pub(crate) fn protocol(reason: impl Into<String>) -> Self {
        Self::Protocol(reason.into())
    }
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Declined => f.write_str("the phone declined the vault request"),
            Self::Unavailable => f.write_str("the vault is not available on the phone"),
            Self::Protocol(reason) => write!(f, "vault protocol error: {reason}"),
        }
    }
}

/// What the desktop wants stored, on its way to the phone.
///
/// Deliberately without a `Drop` of its own: its fields are moved straight
/// into a `CreateRequest`, which wipes the secret when it goes, and a type
/// that wipes cannot have its fields moved out. Callers hold the password in
/// locked memory and build one of these at the last moment.
pub struct NewItem {
    pub kind: ItemKind,
    pub name: String,
    pub username: String,
    pub uri: String,
    pub secret: String,
}

/// A phone's vault, reached over one already established session.
pub struct PhoneVault<'a> {
    session: &'a mut Box<dyn SecureSession + Send>,
    verifier_name: String,
}

impl<'a> PhoneVault<'a> {
    pub fn new(
        session: &'a mut Box<dyn SecureSession + Send>,
        verifier_name: impl Into<String>,
    ) -> Self {
        Self {
            session,
            verifier_name: verifier_name.into(),
        }
    }

    /// One page of the listing, starting a walk when `cursor` is empty.
    ///
    /// Carries no secrets: a listing is what the desktop is allowed to know
    /// without a prompt. One page per session, because that is all a session
    /// carries -- see [`list_all`], which is what a caller wants.
    pub fn list_page(&mut self, cursor: &str) -> Result<ListResponse, VaultError> {
        let request = ListRequest {
            verifier_name: self.verifier_name.clone(),
            cursor: cursor.to_owned(),
        };
        request
            .validate()
            .map_err(|error| VaultError::protocol(error.to_string()))?;

        let answer = self.exchange(OPERATION_LIST, request.encode())?;
        ListResponse::decode(&answer).map_err(|error| VaultError::protocol(error.to_string()))
    }

    /// One item's secret, after the user approves it on the phone.
    ///
    /// The returned [`FetchResponse`] wipes its secret when dropped, so hold it
    /// for as short a time as the copy takes.
    pub fn fetch(&mut self, item_id: &str) -> Result<FetchResponse, VaultError> {
        let request = FetchRequest {
            verifier_name: self.verifier_name.clone(),
            item_id: item_id.to_owned(),
        };
        request
            .validate()
            .map_err(|error| VaultError::protocol(error.to_string()))?;

        // This payload is the one place a secret exists as loose bytes on this
        // side, so it is wiped whether or not it decoded.
        let mut answer = self.exchange(OPERATION_FETCH, request.encode())?;
        let decoded = FetchResponse::decode(&answer);
        answer.zeroize();

        decoded.map_err(|error| VaultError::protocol(error.to_string()))
    }

    /// Stores a new item on the phone, after the user approves it there.
    ///
    /// The secret travels and is never kept. `CreateRequest` wipes its own on
    /// drop, and the caller's copy should live in locked memory until this
    /// returns -- this side of the product does not have a place to put a
    /// password, and that is the point of it.
    ///
    /// `create` is the one operation whose approval sheet is worded from the
    /// frame rather than from the phone's own store, because the item does not
    /// exist there yet. So the name sent here is the name the person reads
    /// before deciding.
    pub fn create(&mut self, item: NewItem) -> Result<WriteResponse, VaultError> {
        let request = CreateRequest {
            verifier_name: self.verifier_name.clone(),
            kind: item.kind,
            name: item.name,
            username: item.username,
            uri: item.uri,
            secret: item.secret,
        };
        request
            .validate()
            .map_err(|error| VaultError::protocol(error.to_string()))?;

        // `exchange` wipes the bytes it sends, which is what matters here:
        // this is the one request payload in the product that carries a
        // secret, the mirror of the reply `fetch` already wipes.
        let mut answer = self.exchange(OPERATION_CREATE, request.encode())?;
        let decoded = WriteResponse::decode(&answer);
        answer.zeroize();

        decoded.map_err(|error| VaultError::protocol(error.to_string()))
    }

    /// Whether this request may be sent at all.
    ///
    /// Separated from [`exchange`](Self::exchange) so that both ways of saying
    /// no leave through one door, which is where the payload is wiped.
    fn check(&self, request: &ApplicationFrame) -> Result<(), VaultError> {
        if !self.session.security().suitable_for_authorization() {
            return Err(VaultError::protocol(
                "the vault needs an authenticated confidential session",
            ));
        }
        request
            .validate()
            .map_err(|error| VaultError::protocol(error.to_string()))
    }

    /// Sends one application frame and returns the payload of the matching
    /// reply, or an error nobody can mistake for a grant.
    fn exchange(&mut self, operation: &str, payload: Vec<u8>) -> Result<Vec<u8>, VaultError> {
        let issued_at_ms = now_ms();
        let mut request = ApplicationFrame {
            protocol_version: PROTOCOL_VERSION,
            kind: ApplicationFrameKind::Request,
            request_id: random::request_id(),
            session_binding: self.session.session_binding(),
            operation: operation.to_owned(),
            issued_at_ms,
            expires_at_ms: issued_at_ms + VALIDITY_MS,
            payload,
        };
        // Both refusals happen with the password already in `request.payload`,
        // and both used to return with it still there. The success path below
        // goes out of its way to keep that payload out of freed heap; a
        // session that turned out not to be confidential, or a frame a size
        // bound refuses, took the same password to the same place by the
        // shorter route. Checked here, after the frame exists, so there is one
        // buffer to wipe and one place that wipes it.
        if let Err(error) = self.check(&request) {
            request.payload.zeroize();
            return Err(error);
        }

        // Bound and wiped rather than sent from a temporary. Every other
        // operation's payload is an id or a cursor, but `vault.create` carries
        // a password, and it would otherwise sit in freed heap on the one side
        // of this product whose whole promise is that it never keeps one.
        let mut encoded = request.encode();
        let sent = self.session.send(&encoded);
        encoded.zeroize();
        request.payload.zeroize();
        sent.map_err(|_| VaultError::Unavailable)?;
        let mut raw = self
            .session
            .receive(RECEIVE_TIMEOUT)
            .map_err(|_| VaultError::Unavailable)?;

        let reply = ApplicationFrame::decode(&raw);
        raw.zeroize();
        let reply = reply.map_err(|error| VaultError::protocol(error.to_string()))?;

        // Decoding an envelope is not authorization: the reply has to be the
        // answer to the request still pending, in this session, unexpired.
        if !reply.is_reply_to(&request, now_ms()) {
            return Err(VaultError::protocol(
                "the phone answered a different request",
            ));
        }
        if reply.kind == ApplicationFrameKind::Error {
            // An error payload that will not decode is still an error. Falling
            // back to `Declined` keeps a malformed refusal from being read as
            // anything softer.
            return Err(match ApplicationErrorCode::decode(&reply.payload) {
                Ok(ApplicationErrorCode::Rejected) | Err(_) => VaultError::Declined,
                Ok(ApplicationErrorCode::Unavailable) => VaultError::Unavailable,
                Ok(ApplicationErrorCode::InvalidRequest) => {
                    VaultError::protocol("the phone rejected the request as malformed")
                }
            });
        }
        Ok(reply.payload)
    }
}

/// Every item's metadata, walked page by page, opening one session per page.
///
/// A session carries exactly one application request and the phone closes it
/// on the way out -- that is what keeps a phone which walked out of range from
/// looking available until the first timeout. So a walk that reuses its
/// session gets one page and then a socket nobody is listening on, and the
/// desktop reports the phone as unavailable partway through a listing it had
/// already half received.
///
/// The phone has always expected this: it keeps the snapshot a walk started
/// from for thirty seconds precisely so the pages of one walk agree with each
/// other across the several sessions it takes to fetch them, and its own
/// comment says each page of the desktop's walk is a new session. This side
/// simply never did it.
///
/// It held up for so long because a vault of thirty-two items or fewer is one
/// page and never asks for a second. The failure starts at item thirty-three.
pub fn list_all(
    verifier_name: &str,
    mut open: impl FnMut() -> Result<Box<dyn SecureSession + Send>, VaultError>,
) -> Result<Vec<ItemSummary>, VaultError> {
    let mut items = Vec::new();
    let mut cursor = String::new();
    // The phone picks the cursors, so a repeat is how an endless walk starts.
    // Refusing on the second sighting stops it a page early instead of after
    // `MAX_ITEMS` have been read.
    let mut seen: HashSet<String> = HashSet::new();

    loop {
        let mut session = open()?;
        let page = PhoneVault::new(&mut session, verifier_name).list_page(&cursor);
        let _ = session.close();
        let page = page?;

        let carried = page.items.len();
        items.extend(page.items);
        if page.next_cursor.is_empty() {
            return Ok(items);
        }
        if !seen.insert(page.next_cursor.clone()) {
            return Err(VaultError::protocol("the phone repeated a page cursor"));
        }
        // A page that carried nothing and still asks for another walks forever
        // without ever reaching the item ceiling below.
        if carried == 0 || items.len() > MAX_ITEMS {
            return Err(VaultError::protocol("the vault listing did not end"));
        }
        cursor = page.next_cursor;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use phone_auth_protocol::vault::{ItemKind, MAX_PAGE_ITEMS};
    use phone_auth_verifier::session::TransportSecurity;
    use std::io;

    /// Builds the phone's answer to one request frame.
    type Answer = Box<dyn FnMut(&ApplicationFrame) -> Vec<u8> + Send>;

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
        answer: impl FnMut(&ApplicationFrame) -> Vec<u8> + Send + 'static,
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

    fn refusal(request: &ApplicationFrame, code: ApplicationErrorCode) -> Vec<u8> {
        ApplicationFrame {
            kind: ApplicationFrameKind::Error,
            payload: code.encode(),
            ..request.clone()
        }
        .encode()
    }

    /// `FetchResponse` has no `Debug` on purpose — it holds a secret — so
    /// `expect_err` cannot be used on a fetch. Unwrapping the error by hand is
    /// the price of that, and a cheaper one than deriving `Debug` on a secret.
    fn refused(result: Result<FetchResponse, VaultError>) -> VaultError {
        match result {
            Ok(_) => panic!("the fetch should not have succeeded"),
            Err(error) => error,
        }
    }

    fn summary(id: &str) -> ItemSummary {
        ItemSummary {
            id: id.to_owned(),
            revision: 1,
            kind: ItemKind::Login,
            name: format!("Item {id}"),
            username: "someone@example.com".into(),
            uri: "https://example.com".into(),
            updated_at_ms: 1_700_000_000_000,
        }
    }

    #[test]
    fn a_listing_walks_every_page_and_stops_on_the_empty_cursor() {
        let transport = || {
            session(true, |request| {
                assert_eq!(request.operation, OPERATION_LIST);
                let asked = ListRequest::decode(&request.payload).expect("payload decodes");
                let (items, next_cursor) = match asked.cursor.as_str() {
                    "" => (vec![summary("a"), summary("b")], "page-2"),
                    "page-2" => (vec![summary("c")], ""),
                    other => panic!("unexpected cursor {other}"),
                };
                reply(
                    request,
                    ListResponse {
                        items,
                        next_cursor: next_cursor.into(),
                    }
                    .encode(),
                )
            })
        };

        let items = list_all("Workstation", || Ok(transport())).expect("the listing completes");

        let ids: Vec<&str> = items.iter().map(|item| item.id.as_str()).collect();
        assert_eq!(ids, ["a", "b", "c"]);
    }

    #[test]
    fn a_phone_that_repeats_a_cursor_does_not_page_forever() {
        let transport = || {
            session(true, |request| {
                reply(
                    request,
                    ListResponse {
                        items: vec![summary("a")],
                        next_cursor: "same".into(),
                    }
                    .encode(),
                )
            })
        };

        let error =
            list_all("Workstation", || Ok(transport())).expect_err("an endless listing is refused");
        assert!(matches!(error, VaultError::Protocol(_)));
    }

    /// A full vault is four thousand items and the phone hands them out
    /// thirty-two at a time, so the walk is a hundred and twenty-eight pages
    /// long. Bounded by pages instead, the desktop gave up on page
    /// thirty-three and the user's answer was that the vault would not open.
    #[test]
    fn a_vault_as_large_as_the_phone_allows_is_listed_whole() {
        let transport = || {
            session(true, |request| {
                let asked = ListRequest::decode(&request.payload).expect("payload decodes");
                let offset: usize = if asked.cursor.is_empty() {
                    0
                } else {
                    asked.cursor.parse().expect("the cursor is the offset")
                };
                let next = offset + MAX_PAGE_ITEMS;
                reply(
                    request,
                    ListResponse {
                        items: (offset..next)
                            .map(|index| summary(&index.to_string()))
                            .collect(),
                        next_cursor: if next < MAX_ITEMS {
                            next.to_string()
                        } else {
                            String::new()
                        },
                    }
                    .encode(),
                )
            })
        };

        let items = list_all("Workstation", || Ok(transport())).expect("the listing completes");

        assert_eq!(items.len(), MAX_ITEMS);
        assert_eq!(items[MAX_ITEMS - 1].id, (MAX_ITEMS - 1).to_string());
    }

    #[test]
    fn a_listing_that_never_ends_stops_at_the_item_ceiling() {
        // The counter lives outside the session, because each page of the walk
        // arrives on a session of its own.
        let page = std::cell::Cell::new(0usize);
        let transport = || {
            let asked = page.get() + 1;
            page.set(asked);
            session(true, move |request| {
                reply(
                    request,
                    ListResponse {
                        items: vec![summary("a")],
                        next_cursor: format!("page-{asked}"),
                    }
                    .encode(),
                )
            })
        };

        let error =
            list_all("Workstation", || Ok(transport())).expect_err("an endless listing is refused");
        assert_eq!(
            error,
            VaultError::Protocol("the vault listing did not end".into())
        );
    }

    #[test]
    fn a_create_carries_the_new_item_and_comes_back_with_its_id() {
        // The name matters more here than anywhere else: `create` is the only
        // vault operation whose approval sheet is worded from the frame,
        // because the item does not exist on the phone yet. What is sent is
        // what the person reads before deciding.
        let mut transport = session(true, |request| {
            assert_eq!(request.operation, OPERATION_CREATE);
            let asked = CreateRequest::decode(&request.payload).expect("payload decodes");
            assert_eq!(asked.verifier_name, "Workstation");
            assert_eq!(asked.name, "Banco");
            assert_eq!(asked.username, "alice");
            assert_eq!(asked.uri, "https://banco.example.com");
            assert_eq!(asked.secret, "correct horse battery staple");
            reply(
                request,
                WriteResponse {
                    item_id: "item-9".into(),
                    revision: 1,
                }
                .encode(),
            )
        });

        let written = PhoneVault::new(&mut transport, "Workstation")
            .create(NewItem {
                kind: ItemKind::Login,
                name: "Banco".into(),
                username: "alice".into(),
                uri: "https://banco.example.com".into(),
                secret: "correct horse battery staple".into(),
            })
            .expect("the create succeeds");
        assert_eq!(written.item_id, "item-9");
        assert_eq!(written.revision, 1);
    }

    #[test]
    fn a_create_over_an_unauthenticated_session_never_sends_the_secret() {
        // The check that stops it is the same one guarding every other
        // operation, but this is the one whose payload is a password: a
        // session that is not both authenticated and confidential must be
        // refused before the frame is built, not after.
        let mut transport = session(false, |_| unreachable!("nothing may be sent"));
        let error = PhoneVault::new(&mut transport, "Workstation")
            .create(NewItem {
                kind: ItemKind::Login,
                name: "Banco".into(),
                username: String::new(),
                uri: String::new(),
                secret: "correct horse battery staple".into(),
            })
            .expect_err("an unsuitable session is refused");
        assert!(matches!(error, VaultError::Protocol(_)), "{error:?}");
    }

    #[test]
    fn a_fetch_returns_the_secret_for_the_item_that_was_asked_for() {
        let mut transport = session(true, |request| {
            assert_eq!(request.operation, OPERATION_FETCH);
            let asked = FetchRequest::decode(&request.payload).expect("payload decodes");
            assert_eq!(asked.item_id, "item-7");
            assert_eq!(asked.verifier_name, "Workstation");
            reply(
                request,
                FetchResponse {
                    item_id: "item-7".into(),
                    revision: 4,
                    secret: "correct horse battery staple".into(),
                }
                .encode(),
            )
        });

        let fetched = PhoneVault::new(&mut transport, "Workstation")
            .fetch("item-7")
            .expect("the fetch succeeds");
        assert_eq!(fetched.item_id, "item-7");
        assert_eq!(fetched.revision, 4);
        assert_eq!(fetched.secret, "correct horse battery staple");
    }

    /// The whole point of the coarse taxonomy: a desktop that is refused
    /// learns nothing about why, so it cannot use `fetch` to probe which item
    /// IDs exist.
    #[test]
    fn a_missing_item_and_a_refused_prompt_are_the_same_error() {
        for item in ["item-that-exists", "item-that-does-not"] {
            let mut transport = session(true, |request| {
                refusal(request, ApplicationErrorCode::Rejected)
            });
            let error = refused(PhoneVault::new(&mut transport, "Workstation").fetch(item));
            assert_eq!(error, VaultError::Declined);
        }
    }

    #[test]
    fn the_error_codes_survive_the_round_trip_without_becoming_a_grant() {
        for (code, expected) in [
            (ApplicationErrorCode::Rejected, VaultError::Declined),
            (ApplicationErrorCode::Unavailable, VaultError::Unavailable),
        ] {
            let mut transport = session(true, move |request| refusal(request, code));
            let error = refused(PhoneVault::new(&mut transport, "Workstation").fetch("item-1"));
            assert_eq!(error, expected);
        }
    }

    /// A refusal whose payload is nonsense is still a refusal.
    #[test]
    fn an_undecodable_error_payload_is_treated_as_a_refusal() {
        let mut transport = session(true, |request| {
            ApplicationFrame {
                kind: ApplicationFrameKind::Error,
                payload: vec![0xff, 0xff, 0xff],
                ..request.clone()
            }
            .encode()
        });

        let error = refused(PhoneVault::new(&mut transport, "Workstation").fetch("item-1"));
        assert_eq!(error, VaultError::Declined);
    }

    #[test]
    fn a_reply_to_another_request_is_not_an_answer() {
        let mut transport = session(true, |request| {
            let mut forged = request.clone();
            forged.kind = ApplicationFrameKind::Response;
            forged.request_id = random::request_id();
            forged.payload = FetchResponse {
                item_id: "item-1".into(),
                revision: 1,
                secret: "attacker supplied".into(),
            }
            .encode();
            forged.encode()
        });

        let error = refused(PhoneVault::new(&mut transport, "Workstation").fetch("item-1"));
        assert_eq!(
            error,
            VaultError::Protocol("the phone answered a different request".into())
        );
    }

    #[test]
    fn a_session_that_is_not_confidential_never_asks_for_a_secret() {
        let mut transport = session(false, |_| panic!("nothing may be sent"));
        let error = refused(PhoneVault::new(&mut transport, "Workstation").fetch("item-1"));
        assert!(matches!(error, VaultError::Protocol(_)));
    }

    /// The phone cannot make the desktop allocate on its say-so: an oversized
    /// page is refused by the decoder before the items are read.
    #[test]
    fn an_oversized_page_is_refused() {
        let mut transport = session(true, |request| {
            let items: Vec<ItemSummary> = (0..MAX_PAGE_ITEMS + 1)
                .map(|index| summary(&format!("item-{index}")))
                .collect();
            reply(
                request,
                ListResponse {
                    items,
                    next_cursor: String::new(),
                }
                .encode(),
            )
        });

        let error = PhoneVault::new(&mut transport, "Workstation")
            .list_page("")
            .expect_err("an oversized page is refused");
        assert!(matches!(error, VaultError::Protocol(_)));
    }

    /// The other half of the same mistake.
    ///
    /// A request says how long it is good for, and the answer is refused once
    /// that has passed. Waiting for less than that is this side hanging up
    /// before its own deadline: the person answers inside the window they were
    /// given, the phone unlocks the secret, and it goes into a socket that has
    /// already been closed. Pinned here because the two numbers sat thirty
    /// seconds apart for as long as they were written independently.
    #[test]
    fn the_wait_outlasts_the_request_it_is_waiting_on() {
        assert!(RECEIVE_TIMEOUT > Duration::from_millis(VALIDITY_MS as u64));
    }

    /// The regression this file was rewritten for.
    ///
    /// A session carries one request. Walking the pages of a listing on a
    /// single session got page one and then talked into a socket the phone had
    /// already closed, so every vault above thirty-two items answered the
    /// desktop's panel with "the vault is not available on the phone" -- after
    /// the phone's owner had unlocked it.
    ///
    /// Asserted as a count of sessions rather than by simulating a closed
    /// socket, because a double that answered a second request on the same
    /// session is exactly the too-tolerant peer that hid this in the first
    /// place.
    #[test]
    fn each_page_of_a_walk_arrives_on_a_session_of_its_own() {
        let opened = std::cell::Cell::new(0usize);
        let items = list_all("Workstation", || {
            opened.set(opened.get() + 1);
            Ok(session(true, |request| {
                let asked = ListRequest::decode(&request.payload).expect("payload decodes");
                let (items, next_cursor) = match asked.cursor.as_str() {
                    "" => (vec![summary("a")], "page-2"),
                    "page-2" => (vec![summary("b")], "page-3"),
                    "page-3" => (vec![summary("c")], ""),
                    other => panic!("unexpected cursor {other}"),
                };
                reply(
                    request,
                    ListResponse {
                        items,
                        next_cursor: next_cursor.into(),
                    }
                    .encode(),
                )
            }))
        })
        .expect("the listing completes");

        assert_eq!(items.len(), 3);
        assert_eq!(opened.get(), 3, "one session per page, not one per walk");
    }
}
