import '../core/pairing/pairing_service.dart';
import '../core/protocol/enrolment.dart';
import '../core/vault/vault_approval.dart';
import '../core/vault/totp.dart';
import '../core/vault/vault_export.dart';
import '../core/vault/vault_import.dart';
import '../features/vault/vault_controller.dart';
import '../features/vault/vault_store.dart';
import '../domain/audit_entry.dart';
import '../domain/connection_phase.dart';
import 'app_strings.dart';

/// English. The fallback for any language the app does not ship.
class EnglishStrings extends AppStrings {
  const EnglishStrings();

  @override
  String get languageName => 'English';

  @override
  String get appTitle => 'PhoneAuth';
  @override
  String get tabDevices => 'Devices';
  @override
  String get tabPair => 'Pair';
  @override
  String get tabVault => 'Vault';
  @override
  String get tabHistory => 'History';
  @override
  String get tabSettings => 'Settings';
  @override
  String requestsWaiting(int count) =>
      count == 1 ? '1 request waiting' : '$count requests waiting';

  @override
  String get onboardingTitle => 'Approve logins with your phone';
  @override
  String get onboardingBody => 'Works offline. Keys stay on this phone.';
  @override
  String get onboardingPasskeyWarningTitle => 'Passkeys have no backup';
  @override
  String get onboardingPasskeyWarningBody =>
      'Keep another sign-in method on every site.';
  @override
  String get onboardingStart => 'Start';

  @override
  String get devicesRequests => 'Requests';
  @override
  String get devicesPaired => 'Devices';
  @override
  String get devicesEmpty => 'No paired computers.';
  @override
  String get devicesFloodTitle => 'Possible attack';
  @override
  String devicesFloodBody(String device, int requests, int seconds) =>
      '$device sent $requests requests in $seconds seconds.';
  @override
  String get devicesBlockForFifteenMinutes => 'Block for 15 min';

  @override
  String get historyTitle => 'History';
  @override
  String get historyEmpty => 'Nothing recorded yet.';

  @override
  String get settingsTitle => 'Settings';
  @override
  String get settingsSecurity => 'Security';
  @override
  String get settingsSecuritySubtitle => 'Biometrics and key protection';
  @override
  String get settingsPasskeys => 'Passkeys';
  @override
  String get settingsPasskeysSubtitle => 'Sites, accounts and keys';
  @override
  String get settingsRecovery => 'Recovery';
  @override
  String get settingsRecoverySubtitle => 'Revoke and pair again';
  @override
  String get settingsLanguage => 'Language';
  @override
  String get settingsLanguageSystem => 'System';

  @override
  String get recoveryTitle => 'Recovery';
  @override
  String get recoveryLostPhone => 'Lost your phone?';
  @override
  String get recoveryBody =>
      'Remove this phone on every paired computer. A new phone needs its own '
      'key and a new pairing.';
  @override
  String get recoveryKeysNotExported =>
      'Private keys are never exported or backed up.';

  @override
  String get passkeysTitle => 'Passkeys';
  @override
  String get passkeysEmpty => 'No passkeys on this phone.';
  @override
  String get passkeysOrphan => 'Orphan key';
  @override
  String get passkeysDelete => 'Delete passkey';
  @override
  String get passkeysDeleteTitle => 'Delete passkey?';
  @override
  String get passkeysDeleteOrphanBody => 'This key has no metadata to show.';
  @override
  String passkeysDeleteBody(String user, String site) =>
      'Removes $user at $site from this phone.';
  @override
  String get passkeysDeleteFailed => 'Could not delete the passkey.';
  @override
  String passkeysCreatedOn(String user, String date) => '$user · created $date';
  @override
  String get passkeyStatusAvailable => 'Available';
  @override
  String get passkeyStatusMissingKey => 'Metadata without a key';
  @override
  String get passkeyStatusInvalidKey => 'Key invalidated by biometrics';
  @override
  String get passkeyStatusOrphanKey => 'Key without metadata';

  @override
  String connectionPhase(ConnectionPhase phase) => switch (phase) {
    ConnectionPhase.disconnected => 'Offline',
    ConnectionPhase.scanning => 'Looking',
    ConnectionPhase.connecting => 'Connecting',
    ConnectionPhase.secureHandshake => 'Checking the connection',
    ConnectionPhase.connected => 'Connected',
    ConnectionPhase.authenticationPending => 'Request pending',
    ConnectionPhase.awaitingBiometric => 'Waiting for your fingerprint',
    ConnectionPhase.signing => 'Signing',
    ConnectionPhase.approved => 'Approved',
    ConnectionPhase.denied => 'Denied',
    ConnectionPhase.expired => 'Expired',
    ConnectionPhase.error => 'Error',
    ConnectionPhase.revoking => 'Revoking',
  };

  @override
  String auditOutcome(AuditOutcome outcome) => switch (outcome) {
    AuditOutcome.approved => 'Approved',
    AuditOutcome.denied => 'Denied',
    AuditOutcome.expired => 'Expired',
    AuditOutcome.blocked => 'Blocked',
  };

  @override
  String credentialPurpose(CredentialPurpose purpose) => switch (purpose) {
    CredentialPurpose.authorization => 'Login',
    CredentialPurpose.diskUnlock => 'Disk',
    CredentialPurpose.webAuthn => 'Sites',
    CredentialPurpose.vault => 'Vault',
    CredentialPurpose.fileLocker => 'Files',
    CredentialPurpose.ssh => 'SSH',
  };

  @override
  String credentialPurposeNote(CredentialPurpose purpose) => switch (purpose) {
    CredentialPurpose.authorization =>
      'Approves logins and actions such as `sudo` on this computer.',
    CredentialPurpose.diskUnlock => "Unlocks this computer's disk at boot.",
    CredentialPurpose.webAuthn => 'Answers for passkeys on websites.',
    CredentialPurpose.vault => 'Releases vault passwords to this computer.',
    CredentialPurpose.fileLocker => 'Opens locked files on this computer.',
    CredentialPurpose.ssh =>
      'Signs SSH logins. Every login still asks for your fingerprint.',
  };

  @override
  String get deviceBlocked => 'Blocked for now';
  @override
  String deviceLastSeen(String elapsed) => 'Seen $elapsed';
  @override
  String get deviceJustNow => 'just now';
  @override
  String deviceMinutesAgo(int minutes) => '$minutes min ago';
  @override
  String deviceHoursAgo(int hours) => '$hours h ago';
  @override
  String deviceDaysAgo(int days) => '$days d ago';
  @override
  String get deviceMenu => 'Device options';
  @override
  String get devicePermissions => 'Permissions';
  @override
  String get deviceRevoke => 'Revoke device';
  @override
  String get revoke => 'Revoke';
  @override
  String get deviceRevokeTitle => 'Revoke this computer?';
  @override
  String deviceRevokeBody(String device) =>
      'Removes $device and closes the session. The computer keeps your public '
      'key until you unpair there too. Pair again to reconnect.';

  @override
  String get requestTitle => 'Access request';
  @override
  String get requestUnavailable => 'Request no longer available';
  @override
  String get requestOrigin => 'Origin';
  @override
  String get requestService => 'Service';
  @override
  String get requestAction => 'Action';
  @override
  String get requestTarget => 'Target';
  @override
  String get requestUser => 'User';
  @override
  String get requestTime => 'Time';
  @override
  String requestGrouped(int count) => '$count identical requests grouped.';
  @override
  String requestGroupedShort(int count) => '$count identical requests grouped';
  @override
  String get requestDeny => 'Deny';
  @override
  String get requestApprove => 'Approve';

  @override
  String verificationCheckOn(String verifier) => 'Check the code on $verifier';
  @override
  String verificationCodeSpoken(String spacedDigits) =>
      'Verification code $spacedDigits';
  @override
  String get verificationWarning =>
      'Confirm only if the computer shows these same six digits.';
  @override
  String get verificationDiffer => 'They differ';
  @override
  String get verificationMatch => 'They match';

  @override
  String get scannerLabel => 'Pairing QR code scanner';
  @override
  String get scannerPermissionDenied => 'Allow camera access to scan the code.';
  @override
  String get scannerUnsupported => 'This device has no usable camera.';
  @override
  String get scannerUnavailable => 'The camera could not be opened.';

  @override
  String get cancel => 'Cancel';
  @override
  String get continueLabel => 'Continue';
  @override
  String get retry => 'Try again';

  @override
  String get pairingTitle => 'Pair a computer';
  @override
  String get pairingSubtitle => 'Scan the QR code on its screen';
  @override
  String get pairingConnecting => 'Connecting…';
  @override
  String pairingDone(String verifier) => 'Paired with $verifier';
  @override
  String get pairingFinishOnComputer =>
      'Finish the authorization on the computer.';
  @override
  String get pairingFailed => 'Pairing did not finish';
  @override
  String pairingProblem(PairingProblem problem) => switch (problem) {
    PairingProblem.notAPairingCode => 'This is not a pairing code.',
    PairingProblem.codeExpired => 'This code expired. Generate a new one.',
    PairingProblem.noAddress => 'This code carries no address to connect to.',
    PairingProblem.notPairing => 'The computer was not pairing.',
    PairingProblem.unreachable =>
      'Could not reach the computer. Check that it is on the same network.',
    PairingProblem.timedOut => 'The computer did not answer in time.',
    PairingProblem.failed => 'Pairing failed. Generate a new code.',
  };
  @override
  String get done => 'Done';

  @override
  String permissionsTitle(String verifier) => 'Permissions · $verifier';
  @override
  String get permissionsAppliesOnNextConnection =>
      'Applies the next time this computer connects.';
  @override
  String get permissionsSaveFailed => 'Could not save.';
  @override
  String get permissionsNoCredentials => 'No credentials for this computer.';
  @override
  String permissionService(String service) => switch (service) {
    'vault' => 'vault',
    'locker' => 'files',
    'luks' => 'disk',
    _ => service,
  };

  @override
  String get securityTitle => 'Security';
  @override
  String get securityChecking => 'Checking…';
  @override
  String get securityKey => 'Device key';
  @override
  String get securityKeyMissing => 'Not created yet';
  @override
  String get securityKeyStrongBox => 'Held in StrongBox';
  @override
  String get securityKeyHardware => 'Hardware-backed, no StrongBox';
  @override
  String get securityKeySoftware => 'No hardware protection';
  @override
  String get securityKeyUnknown => 'Could not read the keystore';
  @override
  String get securityBiometrics => 'Strong biometrics';
  @override
  String get securityBiometricsStrong => 'Available';
  @override
  String get securityBiometricsWeak => 'Present, but not strong';
  @override
  String get securityBiometricsNoneEnrolled => 'None enrolled';
  @override
  String get securityBiometricsTemporarilyUnavailable =>
      'Temporarily unavailable';
  @override
  String get securityBiometricsUnavailable => 'Unavailable';
  @override
  String get securityBiometricsUnsupported => 'Not supported on this device';
  @override
  String get securityBiometricsUnknown => 'Unknown';
  @override
  String get securityBackground => 'Background sessions';
  @override
  String get securityBackgroundRunning => 'Running';
  @override
  String get securityBackgroundIdle => 'Idle; pair a computer to start';
  @override
  String get securityBackgroundUnknown => 'Could not check';

  @override
  String get sshTitle => 'SSH login';
  @override
  String get sshComputer => 'Computer';
  @override
  String get sshSignInAs => 'Sign in as';
  @override
  String get sshServer => 'Server';
  @override
  String get sshServerUnnamed => 'not named by this computer';
  @override
  String get sshSessionLasts =>
      'The session stays open until the terminal closes.';
  @override
  String get sshNoServerNamed =>
      'This computer did not name the server. Approve only if you just ran '
      '`ssh` and know where to.';
  @override
  String get sshApprove => 'Approve login';
  @override
  String get refuse => 'Refuse';

  @override
  String get vaultRequestTitle => 'Request from a computer';
  @override
  String get vaultOperationLabel => 'Operation';
  @override
  String vaultOperation(VaultOperation operation) => switch (operation) {
    VaultOperation.read => 'Copy the password of',
    VaultOperation.create => 'Store a new item:',
    VaultOperation.update => 'Change',
    VaultOperation.delete => 'Delete',
  };
  @override
  String get vaultItemLabel => 'Item';
  @override
  String get vaultDomainLabel => 'Domain';
  @override
  String get vaultApprovalCopyNote =>
      "The password goes to that computer's clipboard.";
  @override
  String get vaultApprovalWriteNote => 'The item stored on this phone changes.';
  @override
  String get vaultApproveCopy => 'Approve copy';
  @override
  String get approve => 'Approve';

  @override
  String vaultFailure(VaultFailure failure) => switch (failure) {
    VaultSeedFailure(:final problem) => totpProblem(problem),
    VaultBackupFailure(:final problem) => backupProblem(problem),
    VaultStoreFailure(:final code) => switch (code) {
      'authentication_cancelled' => 'Authentication cancelled.',
      'authentication_failed' =>
        'Could not read your fingerprint. Try again in a moment.',
      'authentication_required' =>
        'Confirm your fingerprint to open the vault.',
      'biometric_unavailable' => 'Enrol a strong biometric to use the vault.',
      'activity_unavailable' =>
        'The confirmation could not be shown. Come back to the app and try '
            'again.',
      'unsupported_android' => 'The vault needs Android 11 or newer.',
      'revision_conflict' => 'This item changed. Refresh the vault and retry.',
      'operation_in_progress' =>
        'Another vault operation is running. Try again in a moment.',
      'vault_full' =>
        'The vault holds its limit of $maxVaultItems items. Delete one first.',
      'clipboard_unavailable' =>
        'This device has no clipboard, so nothing was copied. Use Reveal to '
            'read the value on screen.',
      'clipboard_failed' =>
        'The clipboard refused the value; nothing was '
            'copied.',
      'key_invalidated' =>
        'A new fingerprint invalidated this vault\'s key. The contents cannot '
            'be opened any more. Restore from a backup.',
      'store_corrupt' =>
        'The vault file failed its integrity check. Restore from a backup.',
      'store_version_unsupported' =>
        'This vault was written by a newer version. Update before opening it '
            '-- do not delete anything.',
      _ => 'Could not finish the vault operation.',
    },
  };

  @override
  String vaultNotice(VaultNotice notice) => switch (notice) {
    VaultPasswordCopied() => 'Password for ${notice.itemName} copied.',
    VaultCodeCopied() => 'Code for ${notice.itemName} copied -- not the seed.',
  };

  @override
  String totpProblem(TotpProblem problem) => switch (problem) {
    TotpProblem.digitsOutOfRange => 'A TOTP code has 6 to 8 digits.',
    TotpProblem.windowOutOfRange => 'The TOTP window is out of range.',
    TotpProblem.emptyKey => 'The TOTP key is empty.',
    TotpProblem.invalidCharacter => 'The TOTP key has an invalid character.',
    TotpProblem.keyTooShort => 'The TOTP key is too short.',
    TotpProblem.notOtpauth => 'This is not an otpauth://totp link.',
    TotpProblem.noKeyInUri => 'That otpauth link carries no key.',
    TotpProblem.unsupportedAlgorithm => 'Unsupported TOTP algorithm.',
  };

  @override
  String backupProblem(BackupProblem problem) => switch (problem) {
    BackupProblem.notABackupCode => 'This is not a vault backup code.',
    BackupProblem.codeHasInvalidCharacter =>
      'The code has an invalid character.',
    BackupProblem.codeIncomplete => 'The code is incomplete.',
    BackupProblem.vaultTooLarge => 'This vault is too large to export.',
    BackupProblem.fileTruncated => 'The backup file is truncated.',
    BackupProblem.wrongCodeOrEdited =>
      'The code does not open this file, or the file was changed.',
    BackupProblem.contradictsItself =>
      'The backup contradicts itself about its contents.',
    BackupProblem.badHeader => 'Invalid backup header.',
    BackupProblem.schemaTooNew => 'This backup was written by a newer version.',
    BackupProblem.backupTooLarge => 'This backup is too large to restore.',
    BackupProblem.notABackupFile => 'This is not a vault backup.',
    BackupProblem.badItem => 'Invalid item in the backup.',
    BackupProblem.unknownItemKind => 'Unknown item kind in the backup.',
    BackupProblem.corruptContent => 'The backup contents are corrupt.',
  };

  @override
  String get vaultRefresh => 'Refresh';
  @override
  String get vaultRefreshAction => 'Refresh';
  @override
  String get vaultBackup => 'Back up';
  @override
  String get vaultLock => 'Lock';
  @override
  String get vaultUnlock => 'Unlock';
  @override
  String get vaultLocked => 'The vault is locked';
  @override
  String get vaultNewItem => 'New item';
  @override
  String get vaultEditItem => 'Edit item';
  @override
  String get vaultDiscardNote =>
      'Discarding empties this vault. Only do it if you have a backup.';
  @override
  String get vaultDiscardAndRestart => 'Discard and start over';
  @override
  String get vaultDiscardTitle => 'Discard the vault?';
  @override
  String get vaultDiscardBody =>
      'Every item on this phone is deleted along with the key. There is no '
      'undo. If you have a backup, you can restore it afterwards.';
  @override
  String get vaultDiscard => 'Discard';
  @override
  String get vaultSearchHint => 'Search name, user or address';
  @override
  String get vaultStale => 'A computer wrote to the vault since it opened.';
  @override
  String get vaultEmpty => 'The vault is empty. Tap + to store an item.';
  @override
  String get vaultNoMatch => 'No item matches the search.';
  @override
  String get vaultReveal => 'Reveal';
  @override
  String get vaultHide => 'Hide';
  @override
  String get vaultFavourite => 'Add to favourites';
  @override
  String get vaultUnfavourite => 'Remove from favourites';
  @override
  String get vaultCopy => 'Copy';
  @override
  String get vaultEdit => 'Edit';
  @override
  String get vaultDelete => 'Delete';
  @override
  String get vaultDeleteTitle => 'Delete item?';
  @override
  String vaultDeleteBody(String item) => '“$item” is removed from the vault.';
  @override
  String get vaultKind => 'Kind';
  @override
  String get vaultKindLogin => 'Login';
  @override
  String get vaultKindNote => 'Secure note';
  @override
  String get vaultKindTotp => 'TOTP code';
  @override
  String get vaultName => 'Name';
  @override
  String get vaultNameRequired => 'Enter a name';
  @override
  String get vaultAddress => 'Address';
  @override
  String get vaultSecret => 'Secret';
  @override
  String get vaultNewSecret => 'New secret';
  @override
  String get vaultSecretRequired => 'Enter the secret';
  @override
  String get vaultTotpKey => 'TOTP key or otpauth://';
  @override
  String get vaultTotpHint => 'Paste the key the site showed, or the QR link.';
  @override
  String get save => 'Save';

  @override
  String get backupTitle => 'Vault backup';
  @override
  String get backupExport => 'Export';
  @override
  String get backupExportNote =>
      'Writes an encrypted file and a code shown only once. Without the code '
      'the file opens for nobody, you included.';
  @override
  String get backupCreate => 'Create backup';
  @override
  String get backupRestore => 'Restore';
  @override
  String get backupRestoreNote =>
      'Adds what the file holds. Nothing is deleted, and items already here '
      'are skipped.';
  @override
  String get backupRestoreAction => 'Restore';
  @override
  String get backupChooseFile => 'Choose a file…';
  @override
  String get backupImport => 'Import from another manager';
  @override
  String get backupImportNote =>
      'Reads a Bitwarden export (JSON) or a CSV with a header. You see what '
      'would be added before anything is stored.';
  @override
  String get backupImportWarning =>
      "The other manager's file is plain text. Delete it from the phone when "
      'you are done.';
  @override
  String get backupChooseExport => 'Choose an export…';
  @override
  String get backupCodeCopied => 'Code copied.';
  @override
  String get backupCodeCopyFailed =>
      'Could not copy. Write the code down exactly as shown above.';
  @override
  String get backupSaved => 'Backup saved. Keep the code somewhere else.';
  @override
  String get backupSaveFailed => 'Could not save the file.';
  @override
  String get backupReadFailed => 'Could not read the file.';
  @override
  String backupRestored(int added, int skipped) {
    if (added == 0 && skipped == 0) return 'The backup was empty.';
    final restored = added == 1 ? '1 item restored' : '$added items restored';
    if (skipped == 0) return '$restored.';
    final already = skipped == 1
        ? '1 was already here'
        : '$skipped were already here';
    return '$restored; $already.';
  }

  @override
  String get backupWriteCodeDown => 'Write this code down now';
  @override
  String get backupCodeShownOnce =>
      'It is not shown again and it is stored nowhere.';
  @override
  String get backupCopyCode => 'Copy code';
  @override
  String backupItemCount(int items) =>
      items == 1 ? '1 item in this backup.' : '$items items in this backup.';
  @override
  String get backupSaveFile => 'Save file…';
  @override
  String get backupKeepApart =>
      'Keep the file and the code apart. Together they are the whole vault in '
      'plain text.';
  @override
  String get backupCodeTitle => 'Backup code';
  @override
  String get backupCodeLabel => 'Code';
  @override
  String backupFileSummary(int items, String date) =>
      items == 1 ? '1 item, from $date.' : '$items items, from $date.';
  @override
  String get importReviewTitle => 'Review the import';
  @override
  String importWillAdd(int items) =>
      items == 1 ? '1 item will be added.' : '$items items will be added.';
  @override
  String get importNothingDeleted =>
      'Nothing is deleted. Items already here are skipped.';
  @override
  String importRejectedCount(int rows) => rows == 1
      ? '1 row will not be imported:'
      : '$rows rows will not be imported:';
  @override
  String importRejectedRow(int row, String name, String reason) =>
      'row $row${name.isEmpty ? '' : ' ($name)'} — $reason';
  @override
  String importAndMore(int rows) => '…and $rows more.';
  @override
  String get importAction => 'Import';
  @override
  String importProblem(ImportProblem problem) => switch (problem) {
    ImportProblem.notUtf8 => 'The file is not UTF-8 text. Export it again.',
    ImportProblem.malformedJson => 'The JSON in this file is malformed.',
    ImportProblem.notBitwarden =>
      'This JSON does not look like a Bitwarden export.',
    ImportProblem.bitwardenEncrypted =>
      'This Bitwarden export is encrypted. Export it again unencrypted.',
    ImportProblem.noItemsList => 'This JSON has no `items` list.',
    ImportProblem.tooManyRows => 'The file has too many rows.',
    ImportProblem.unreadableCsv => 'This CSV could not be read.',
    ImportProblem.emptyFile => 'The file is empty.',
    ImportProblem.csvNeedsNameColumn =>
      'The CSV needs a name column (name, title or account).',
    ImportProblem.csvNeedsSecretColumn =>
      'The CSV needs a password or a note column.',
  };

  @override
  String rowProblem(RowProblem problem) => switch (problem) {
    RowProblem.notAnItem => 'not an item',
    RowProblem.unsupportedType => 'not a login or a note',
    RowProblem.noName => 'no name',
    RowProblem.noSecret => 'no password or content',
    RowProblem.nameTooLong => 'name too long',
    RowProblem.usernameTooLong => 'user too long',
    RowProblem.uriTooLong => 'address too long',
    RowProblem.secretTooLong => 'content too long',
  };
}
