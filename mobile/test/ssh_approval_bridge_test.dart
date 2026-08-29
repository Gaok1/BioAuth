/// The object between the SSH service and the sheet.
///
/// Everything here is about answers that never arrive: a phone with no
/// activity on screen, a session torn down while the sheet is still up, a
/// retry of a request already being asked about. Each of those has exactly one
/// safe outcome, and it is `false`.
library;

import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/ssh/ssh_service.dart';

void main() {
  const request = SshApprovalRequest(
    id: 'r1',
    verifierName: 'PC',
    user: 'deploy',
    destination: 'SHA256:x',
  );

  test('an approval is the answer the sheet gave', () async {
    late InteractiveSshApproval approval;
    approval = InteractiveSshApproval(
      onRequest: (r) => approval.settle(r.id, approved: true),
    );

    expect(await approval.confirm(request), isTrue);
    expect(approval.pendingRequestIds, isEmpty);
  });

  test('a refusal is too', () async {
    late InteractiveSshApproval approval;
    approval = InteractiveSshApproval(
      onRequest: (r) => approval.settle(r.id, approved: false),
    );

    expect(await approval.confirm(request), isFalse);
  });

  /// A desktop that retries — a dropped session, a second dial — must not put a
  /// second sheet on top of the first. Two stacked sheets is how someone
  /// approves the one they were not reading.
  test('a repeat of a live request shows one sheet and shares its answer', () {
    final shown = <String>[];
    late InteractiveSshApproval approval;
    approval = InteractiveSshApproval(onRequest: (r) => shown.add(r.id));

    final first = approval.confirm(request);
    final second = approval.confirm(request);

    expect(shown, ['r1'], reason: 'the retry opened a second sheet');
    approval.settle('r1', approved: true);

    expect(first, completion(isTrue));
    expect(second, completion(isTrue));
  });

  /// The session is gone. Whatever is on screen can no longer be answered, and
  /// a caller left awaiting forever holds the loop open.
  test('abandoning what is outstanding refuses it', () async {
    final approval = InteractiveSshApproval(onRequest: (_) {});
    final pending = approval.confirm(request);

    approval.abandonAll();

    expect(await pending, isFalse);
    expect(approval.pendingRequestIds, isEmpty);
  });

  test('settling something already settled is not an error', () {
    late InteractiveSshApproval approval;
    approval = InteractiveSshApproval(
      onRequest: (r) => approval.settle(r.id, approved: true),
    );

    expect(approval.confirm(request), completion(isTrue));
    expect(() => approval.settle('r1', approved: false), returnsNormally);
    expect(
      () => approval.settle('never-asked', approved: true),
      returnsNormally,
    );
  });
}
