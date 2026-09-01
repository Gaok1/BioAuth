/// The desktop's paged walk through the vault, as one look rather than many.
///
/// Two bugs live in the same place. Each page was its own trip into the
/// Keystore, and the key is auth-per-use, so a hundred-item vault asked the
/// phone's owner for four biometric prompts for one click on the desktop —
/// none of them behind a sheet, because listing raises none. And the cursor is
/// an offset into a list sorted by when each item last changed, so an item
/// touched between two pages sorted back to the front, shifted everything
/// behind it, and the desktop silently skipped one.
library;

import 'dart:async';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/protocol/application_frame.dart';
import 'package:phone_auth/core/protocol/vault_payloads.dart' as wire;
import 'package:phone_auth/core/vault/vault_listing.dart';
import 'package:phone_auth/core/vault/vault_service.dart';
import 'package:phone_auth/features/vault/vault_store.dart' as store;

void main() {
  final binding = Uint8List(32);
  final now = DateTime.utc(2026, 8, 29, 12);

  Uint8List listRequest(String cursor) => ApplicationFrame(
    protocolVersion: 1,
    kind: ApplicationFrameKind.request,
    requestId: 'request-$cursor',
    sessionBinding: binding,
    operation: wire.vaultListOperation,
    issuedAt: now,
    expiresAt: now.add(const Duration(seconds: 60)),
    payload: wire.VaultListRequest(
      verifierName: 'Desktop',
      cursor: cursor,
    ).encode(),
  ).encode();

  /// Walks the whole vault the way the desktop does, one page per request.
  Future<List<String>> walk(VaultService service) async {
    final ids = <String>[];
    var cursor = '';
    do {
      final answer = ApplicationFrame.decode(
        await service.handle(
          listRequest(cursor),
          sessionBinding: binding,
          authorized: true,
          now: now,
        ),
      );
      expect(answer.kind, ApplicationFrameKind.response);
      final page = wire.VaultListResponse.decode(answer.payload);
      ids.addAll(page.items.map((item) => item.id));
      cursor = page.nextCursor;
    } while (cursor.isNotEmpty);
    return ids;
  }

  test('a whole walk costs one look at the vault', () async {
    final repository = _Store(70);
    final service = VaultService(
      repository: repository,
      listing: VaultListing(store: repository),
    );

    final ids = await walk(service);

    expect(ids, hasLength(70));
    expect(ids.first, 'item-0');
    expect(ids.last, 'item-69');
    // Three pages of thirty-two, one read. It used to be one read per page,
    // and a read is a fingerprint the desktop never explained.
    expect(repository.reads, 1);
  });

  test('an item touched mid-walk does not push another off the walk', () async {
    final repository = _Store(40);
    final service = VaultService(
      repository: repository,
      listing: VaultListing(store: repository),
    );

    final first = wire.VaultListResponse.decode(
      ApplicationFrame.decode(
        await service.handle(
          listRequest(''),
          sessionBinding: binding,
          authorized: true,
          now: now,
        ),
      ).payload,
    );
    expect(first.items, hasLength(32));

    // The user edits something on the phone between the two pages. Sorted
    // newest first, it moves to the front and everything behind it slides by
    // one — which, read from an offset, drops whatever was at the boundary.
    repository.touch('item-39');

    final second = wire.VaultListResponse.decode(
      ApplicationFrame.decode(
        await service.handle(
          listRequest(first.nextCursor),
          sessionBinding: binding,
          authorized: true,
          now: now,
        ),
      ).payload,
    );

    expect([...first.items, ...second.items].map((item) => item.id), [
      for (var index = 0; index < 40; index++) 'item-$index',
    ], reason: 'a walk pages through the vault as it was when it started');
  });

  test('a walk that outlives its snapshot reads again', () async {
    final repository = _Store(40);
    var moment = now;
    final service = VaultService(
      repository: repository,
      listing: VaultListing(
        store: repository,
        clock: () => moment,
        ttl: const Duration(seconds: 30),
      ),
    );

    final first = wire.VaultListResponse.decode(
      ApplicationFrame.decode(
        await service.handle(
          listRequest(''),
          sessionBinding: binding,
          authorized: true,
          now: now,
        ),
      ).payload,
    );
    moment = moment.add(const Duration(seconds: 31));

    await service.handle(
      listRequest(first.nextCursor),
      sessionBinding: binding,
      authorized: true,
      now: now,
    );

    // Paying for an unlock beats serving a listing from something stale. This
    // is the unusual case now rather than every page.
    expect(repository.reads, 2);
  });

  test('a walk that just stops loses its snapshot anyway', () async {
    // The TTL check in `items` is consulted when the next page arrives, and a
    // walk that simply stopped never sends one. The snapshot used to sit there
    // until the app left the foreground -- and it is the vault's metadata,
    // every item's name, username and address, decrypted.
    final repository = _Store(40);
    final listing = VaultListing(
      store: repository,
      // Frozen, so the check inside `items` cannot be what drops the
      // snapshot: by that clock no time passes at all between the two pages.
      // What is under test is the bound happening on its own.
      clock: () => now,
      ttl: const Duration(milliseconds: 20),
    );
    final service = VaultService(repository: repository, listing: listing);

    final first = wire.VaultListResponse.decode(
      ApplicationFrame.decode(
        await service.handle(
          listRequest(''),
          sessionBinding: binding,
          authorized: true,
          now: now,
        ),
      ).payload,
    );
    expect(first.nextCursor, isNotEmpty, reason: 'the walk has more to go');
    expect(repository.reads, 1);

    await Future<void>.delayed(const Duration(milliseconds: 120));

    // Nothing asked for anything in between and the listing's own clock has
    // not moved, so a second read here is the snapshot having been dropped on
    // its own rather than having been found stale or replaced.
    await service.handle(
      listRequest(first.nextCursor),
      sessionBinding: binding,
      authorized: true,
      now: now,
    );
    expect(repository.reads, 2);
  });

  test('a walk that keeps walking keeps its snapshot', () async {
    final repository = _Store(120);
    var moment = now;
    final service = VaultService(
      repository: repository,
      listing: VaultListing(
        store: repository,
        clock: () => moment,
        ttl: const Duration(seconds: 30),
      ),
    );

    // Every page is a session: the desktop dials, asks once, and the phone
    // closes. A full vault is a hundred and twenty-eight of those, so a
    // snapshot timed from the start of the walk is one the longest walk can
    // never finish inside -- and re-reading mid-listing costs a fingerprint
    // that no sheet explains, because listing raises none.
    var cursor = '';
    var pages = 0;
    do {
      final page = wire.VaultListResponse.decode(
        ApplicationFrame.decode(
          await service.handle(
            listRequest(cursor),
            sessionBinding: binding,
            authorized: true,
            now: now,
          ),
        ).payload,
      );
      cursor = page.nextCursor;
      pages++;
      moment = moment.add(const Duration(seconds: 20));
    } while (cursor.isNotEmpty);

    expect(pages, 4);
    expect(
      repository.reads,
      1,
      reason: 'the gap between pages is what expires, not the walk',
    );
  });

  /// `VaultService` calls `forget` after every create, update and delete, and
  /// says why: the approval sheet's wording comes from this snapshot, so a
  /// write has to invalidate it or the next request for that item names it
  /// whatever it was called before.
  ///
  /// A read in flight across that write put the pre-write snapshot back when
  /// it landed, and armed a fresh timer while doing it — so the invalidation
  /// held for as long as nothing was reading, which is the case it was not
  /// written for.
  test(
    'a read that lands after a write does not put the snapshot back',
    () async {
      final held = _HeldStore();
      final listing = VaultListing(store: held);

      final walking = listing.items(restart: true);
      // The write arrives while the owner still has a fingerprint prompt open.
      listing.forget();
      held.answer(0, ['before-the-write']);
      // The caller that asked is still served: it asked before the write, and an
      // answer is what it is owed. What it does not get is to leave it behind.
      expect((await walking).single.id, 'before-the-write');

      // The next page has to read again. If the landed read had been kept, this
      // would be served from it and the sheet would still say the old name.
      final next = listing.items(restart: false);
      expect(
        held.reads,
        2,
        reason: 'the invalidated snapshot was served again',
      );
      held.answer(1, ['after-the-write']);
      expect((await next).single.id, 'after-the-write');
    },
  );

  /// Sessions share one listing, so two pages can be in the air at once — a
  /// desktop re-dialling after a timeout is the ordinary way. Each read is a
  /// fingerprint prompt, and a second one seconds after the first, explaining
  /// nothing, is what this class exists to remove.
  test('overlapping pages share one read', () async {
    final held = _HeldStore();
    final listing = VaultListing(store: held);

    final first = listing.items(restart: true);
    final second = listing.items(restart: false);
    final third = listing.items(restart: true);
    expect(
      held.reads,
      1,
      reason: 'an overlapping page asked for its own unlock',
    );

    held.answer(0, ['item-0']);
    for (final answer in [first, second, third]) {
      expect((await answer).single.id, 'item-0');
    }

    // And the shared read is not held past its completion: the snapshot serves
    // the next page, rather than a stale future doing it.
    await listing.items(restart: false);
    expect(held.reads, 1);
  });

  test('a cursor pointing outside the vault is refused', () async {
    final repository = _Store(4);
    final service = VaultService(
      repository: repository,
      listing: VaultListing(store: repository),
    );

    for (final cursor in ['99', '-1', 'nope']) {
      final answer = ApplicationFrame.decode(
        await service.handle(
          listRequest(cursor),
          sessionBinding: binding,
          authorized: true,
          now: now,
        ),
      );
      expect(answer.kind, ApplicationFrameKind.error, reason: cursor);
    }
  });
}

/// A store whose reads do not finish until the test says so.
///
/// The interleavings below are the ones a phone actually produces: a read is a
/// Keystore unlock behind a fingerprint prompt, so it is open for as long as
/// the owner takes to answer, and anything can arrive in that window.
class _HeldStore extends store.VaultStore {
  final List<Completer<List<store.VaultItemSummary>>> pending = [];
  int reads = 0;

  @override
  Future<List<store.VaultItemSummary>> listAll() {
    reads++;
    final completer = Completer<List<store.VaultItemSummary>>();
    pending.add(completer);
    return completer.future;
  }

  void answer(int index, List<String> ids) {
    pending[index].complete([
      for (final id in ids)
        store.VaultItemSummary(
          id: id,
          revision: 1,
          kind: store.VaultItemKind.login,
          name: id,
          username: '',
          uri: '',
          updatedAt: DateTime.utc(2026),
        ),
    ]);
  }

  @override
  Future<store.VaultPage> listPage([String? cursor]) =>
      throw UnimplementedError();

  @override
  Future<store.VaultSecret> fetch(String id) => throw UnimplementedError();

  @override
  Future<store.VaultWrite> create(store.VaultItemInput item) =>
      throw UnimplementedError();

  @override
  Future<store.VaultWrite> update(
    store.VaultItemSummary current,
    store.VaultItemInput item,
  ) => throw UnimplementedError();

  @override
  Future<List<store.VaultItemSummary>?> delete(store.VaultItemSummary item) =>
      throw UnimplementedError();
}

/// Counts how many times the vault was actually read, which on a real phone is
/// how many times the user was asked for a fingerprint.
class _Store extends store.VaultStore {
  _Store(int count)
    : _items = [
        for (var index = 0; index < count; index++)
          store.VaultItemSummary(
            id: 'item-$index',
            revision: 1,
            kind: store.VaultItemKind.login,
            name: 'Item $index',
            username: 'alice',
            uri: 'https://example.com',
            // Newest first is the order the store hands out, so the ids come
            // back in ascending order.
            updatedAt: DateTime.utc(2026).subtract(Duration(minutes: index)),
          ),
      ];

  final List<store.VaultItemSummary> _items;
  int reads = 0;

  /// Moves an item to the front of the order, the way an edit does.
  void touch(String id) {
    final item = _items.firstWhere((each) => each.id == id);
    _items
      ..remove(item)
      ..insert(
        0,
        store.VaultItemSummary(
          id: item.id,
          revision: item.revision + 1,
          kind: item.kind,
          name: item.name,
          username: item.username,
          uri: item.uri,
          updatedAt: DateTime.utc(2026, 2),
        ),
      );
  }

  @override
  Future<List<store.VaultItemSummary>> listAll() async {
    reads++;
    return List.of(_items);
  }

  @override
  Future<store.VaultPage> listPage([String? cursor]) =>
      throw UnimplementedError('the service lists through listAll');

  @override
  Future<store.VaultSecret> fetch(String id) => throw UnimplementedError();

  @override
  Future<store.VaultWrite> create(store.VaultItemInput item) =>
      throw UnimplementedError();

  @override
  Future<store.VaultWrite> update(
    store.VaultItemSummary current,
    store.VaultItemInput item,
  ) => throw UnimplementedError();

  @override
  Future<List<store.VaultItemSummary>?> delete(store.VaultItemSummary item) =>
      throw UnimplementedError();
}
