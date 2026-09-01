/// The object between the vault service and the sheet the user taps.
///
/// One question decides everything here: what does an answer cover? The sheet
/// names a computer, an operation and an item, and the tap answers *that*. The
/// request id cannot stand in for it -- the id is chosen by the computer
/// asking, and one map of pending answers is shared by every session, so two
/// in flight at once are two desktops, or one desktop on two credentials.
library;

import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/vault/vault_approval.dart';

void main() {
  const create = VaultApprovalRequest(
    id: 'r1',
    verifierName: 'Workstation',
    operation: VaultOperation.create,
    itemName: 'Roteador',
  );

  test('a repeat of the same request waits on the one answer', () async {
    final shown = <VaultApprovalRequest>[];
    final approval = InteractiveVaultApproval(onRequest: shown.add);

    final first = approval.confirm(create);
    final retry = approval.confirm(create);
    // The desktop retrying must not turn one approval into two: a second sheet
    // is how a user approves the one they were not reading.
    expect(shown, hasLength(1));

    approval.settle('r1', approved: true);
    expect(await first, isTrue);
    expect(await retry, isTrue);
  });

  test('an answer does not carry over to a different request', () async {
    final shown = <VaultApprovalRequest>[];
    final approval = InteractiveVaultApproval(onRequest: shown.add);

    final storing = approval.confirm(create);
    // The same id, now asking to hand a password to the computer. Sharing the
    // first one's answer would let a tap on "Guardar um item novo" release a
    // secret under "Copiar a senha de", with nothing on screen to read.
    final reading = await approval.confirm(
      const VaultApprovalRequest(
        id: 'r1',
        verifierName: 'Workstation',
        operation: VaultOperation.read,
        itemName: 'Banco',
      ),
    );

    expect(reading, isFalse);
    expect(shown, hasLength(1), reason: 'the second never reached a sheet');

    approval.settle('r1', approved: true);
    expect(
      await storing,
      isTrue,
      reason: 'the one the user read still gets its answer',
    );
  });

  test('the item named is part of what was answered', () async {
    final approval = InteractiveVaultApproval(onRequest: (_) {});

    approval.confirm(create);
    // Same computer, same operation, another item. The sheet would have read
    // differently, so the answer to it does not reach here.
    expect(
      await approval.confirm(
        const VaultApprovalRequest(
          id: 'r1',
          verifierName: 'Workstation',
          operation: VaultOperation.create,
          itemName: 'Banco',
        ),
      ),
      isFalse,
    );
  });

  test('a name cannot be shaped to look like another sheet', () async {
    final approval = InteractiveVaultApproval(onRequest: (_) {});

    approval.confirm(
      const VaultApprovalRequest(
        id: 'r1',
        verifierName: 'Workstation',
        operation: VaultOperation.create,
        itemName: 'Banco',
        username: 'alice',
      ),
    );
    // Every field is a string the computer chose, so the fields are
    // length-prefixed rather than joined on a separator it could type inside
    // one of them.
    expect(
      await approval.confirm(
        const VaultApprovalRequest(
          id: 'r1',
          verifierName: 'Workstation',
          operation: VaultOperation.create,
          itemName: 'Banc',
          username: 'oalice',
        ),
      ),
      isFalse,
    );
  });

  test('abandoning refuses what is still waiting', () async {
    final approval = InteractiveVaultApproval(onRequest: (_) {});
    final pending = approval.confirm(create);

    approval.abandonAll();

    expect(await pending, isFalse);
    expect(approval.pendingRequestIds, isEmpty);
  });
}
