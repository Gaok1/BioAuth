/// Every word the interface says, in each language the app ships.
///
/// A plain abstract class rather than generated code: the compiler is then the
/// thing that guarantees a new string exists in every language, and adding a
/// language is adding one file that implements this and one entry in
/// [supportedLocales]. Nothing has to be generated before the app builds, and
/// nothing here can drift out of date without the build failing.
///
/// The house rule for the copy itself: say what a thing is or what a button
/// does. No sentence explains how the app works, reassures the reader, or
/// describes what happens underneath -- a person opening a screen wants the
/// label, not the design notes.
library;

import 'package:flutter/foundation.dart';
import 'package:flutter/widgets.dart';

import '../core/pairing/pairing_service.dart';
import '../core/protocol/enrolment.dart';
import '../core/vault/vault_approval.dart';
import '../core/vault/totp.dart';
import '../core/vault/vault_export.dart';
import '../core/vault/vault_import.dart';
import '../features/vault/vault_controller.dart';
import '../domain/audit_entry.dart';
import '../domain/connection_phase.dart';
import 'app_strings_en.dart';
import 'app_strings_pt.dart';

abstract class AppStrings {
  const AppStrings();

  /// The languages the app ships, best first.
  ///
  /// English leads because it is the fallback: a phone set to a language
  /// nothing here speaks resolves to the first entry.
  static const List<Locale> supportedLocales = <Locale>[
    Locale('en'),
    Locale('pt', 'BR'),
  ];

  static const LocalizationsDelegate<AppStrings> delegate =
      _AppStringsDelegate();

  /// The pack for [locale], falling back to English.
  ///
  /// Matched on the language alone. A phone set to `pt_PT` gets the Brazilian
  /// pack, which is far closer to right than English would be.
  static AppStrings forLocale(Locale locale) => switch (locale.languageCode) {
    'pt' => const PortugueseStrings(),
    _ => const EnglishStrings(),
  };

  static AppStrings of(BuildContext context) =>
      Localizations.of<AppStrings>(context, AppStrings) ??
      const EnglishStrings();

  /// This language's own name, for the picker. Never translated.
  String get languageName;

  // ---------------------------------------------------------------- app shell

  String get appTitle;
  String get tabDevices;
  String get tabPair;
  String get tabVault;
  String get tabHistory;
  String get tabSettings;

  /// Read out over the tab badge, which is drawn and never spoken.
  String requestsWaiting(int count);

  // --------------------------------------------------------------- onboarding

  String get onboardingTitle;
  String get onboardingBody;
  String get onboardingPasskeyWarningTitle;
  String get onboardingPasskeyWarningBody;
  String get onboardingStart;

  // ------------------------------------------------------------------ devices

  String get devicesRequests;
  String get devicesPaired;
  String get devicesEmpty;
  String get devicesFloodTitle;
  String devicesFloodBody(String device, int requests, int seconds);
  String get devicesBlockForFifteenMinutes;

  // ------------------------------------------------------------------ history

  String get historyTitle;
  String get historyEmpty;

  // ----------------------------------------------------------------- settings

  String get settingsTitle;
  String get settingsSecurity;
  String get settingsSecuritySubtitle;
  String get settingsPasskeys;
  String get settingsPasskeysSubtitle;
  String get settingsRecovery;
  String get settingsRecoverySubtitle;
  String get settingsLanguage;
  String get settingsLanguageSystem;

  // ----------------------------------------------------------------- recovery

  String get recoveryTitle;
  String get recoveryLostPhone;
  String get recoveryBody;
  String get recoveryKeysNotExported;

  // ----------------------------------------------------------------- passkeys

  String get passkeysTitle;
  String get passkeysEmpty;
  String get passkeysOrphan;
  String get passkeysDelete;
  String get passkeysDeleteTitle;
  String get passkeysDeleteOrphanBody;
  String passkeysDeleteBody(String user, String site);
  String get passkeysDeleteFailed;
  String passkeysCreatedOn(String user, String date);
  String get passkeyStatusAvailable;
  String get passkeyStatusMissingKey;
  String get passkeyStatusInvalidKey;
  String get passkeyStatusOrphanKey;

  // -------------------------------------------------------------------- common

  String get cancel;
  String get continueLabel;
  String get retry;

  // ------------------------------------------------------------------- labels

  String connectionPhase(ConnectionPhase phase);
  String auditOutcome(AuditOutcome outcome);

  /// The short chip on a device card: what one credential is for.
  String credentialPurpose(CredentialPurpose purpose);

  /// The sentence under the verification code: what confirming grants.
  String credentialPurposeNote(CredentialPurpose purpose);

  // -------------------------------------------------------------- device card

  String get deviceBlocked;
  String deviceLastSeen(String elapsed);
  String get deviceJustNow;
  String deviceMinutesAgo(int minutes);
  String deviceHoursAgo(int hours);
  String deviceDaysAgo(int days);
  String get deviceMenu;
  String get devicePermissions;
  String get deviceRevoke;
  String get revoke;
  String get deviceRevokeTitle;
  String deviceRevokeBody(String device);

  // ------------------------------------------------------------------ request

  String get requestTitle;
  String get requestUnavailable;
  String get requestOrigin;
  String get requestService;
  String get requestAction;
  String get requestTarget;
  String get requestUser;
  String get requestTime;
  String requestGrouped(int count);
  String requestGroupedShort(int count);
  String get requestDeny;
  String get requestApprove;

  // -------------------------------------------------------- verification code

  String verificationCheckOn(String verifier);
  String verificationCodeSpoken(String spacedDigits);
  String get verificationWarning;
  String get verificationDiffer;
  String get verificationMatch;

  // ------------------------------------------------------------------ scanner

  String get scannerLabel;
  String get scannerPermissionDenied;
  String get scannerUnsupported;
  String get scannerUnavailable;

  // ------------------------------------------------------------------ pairing

  String get pairingTitle;
  String get pairingSubtitle;
  String get pairingConnecting;
  String pairingDone(String verifier);
  String get pairingFinishOnComputer;
  String get pairingFailed;
  String pairingProblem(PairingProblem problem);
  String get done;

  // -------------------------------------------------------------- permissions

  String permissionsTitle(String verifier);
  String get permissionsAppliesOnNextConnection;
  String get permissionsSaveFailed;
  String get permissionsNoCredentials;

  /// The word for one grantable service, keyed as the wire names it.
  String permissionService(String service);

  // ----------------------------------------------------------------- security

  String get securityTitle;
  String get securityChecking;
  String get securityKey;
  String get securityKeyMissing;
  String get securityKeyStrongBox;
  String get securityKeyHardware;
  String get securityKeySoftware;
  String get securityKeyUnknown;
  String get securityBiometrics;
  String get securityBiometricsStrong;
  String get securityBiometricsWeak;
  String get securityBiometricsNoneEnrolled;
  String get securityBiometricsTemporarilyUnavailable;
  String get securityBiometricsUnavailable;
  String get securityBiometricsUnsupported;
  String get securityBiometricsUnknown;
  String get securityBackground;
  String get securityBackgroundRunning;
  String get securityBackgroundIdle;
  String get securityBackgroundUnknown;

  // ---------------------------------------------------------------------- ssh

  String get sshTitle;
  String get sshComputer;
  String get sshSignInAs;
  String get sshServer;
  String get sshServerUnnamed;
  String get sshSessionLasts;
  String get sshNoServerNamed;
  String get sshApprove;
  String get refuse;

  // ------------------------------------------------------------ vault request

  String get vaultRequestTitle;
  String get vaultOperationLabel;
  String vaultOperation(VaultOperation operation);
  String get vaultItemLabel;
  String get vaultDomainLabel;
  String get vaultApprovalCopyNote;
  String get vaultApprovalWriteNote;
  String get vaultApproveCopy;
  String get approve;

  // ---------------------------------------------------------------- the vault

  String vaultFailure(VaultFailure failure);
  String vaultNotice(VaultNotice notice);
  String totpProblem(TotpProblem problem);
  String backupProblem(BackupProblem problem);

  // ----------------------------------------------------------- vault screen

  String get vaultRefresh;
  String get vaultRefreshAction;
  String get vaultBackup;
  String get vaultLock;
  String get vaultUnlock;
  String get vaultLocked;
  String get vaultNewItem;
  String get vaultEditItem;
  String get vaultDiscardNote;
  String get vaultDiscardAndRestart;
  String get vaultDiscardTitle;
  String get vaultDiscardBody;
  String get vaultDiscard;
  String get vaultSearchHint;
  String get vaultStale;
  String get vaultEmpty;
  String get vaultNoMatch;
  String get vaultReveal;
  String get vaultHide;
  String get vaultFavourite;
  String get vaultUnfavourite;
  String get vaultCopy;
  String get vaultEdit;
  String get vaultDelete;
  String get vaultDeleteTitle;
  String vaultDeleteBody(String item);
  String get vaultKind;
  String get vaultKindLogin;
  String get vaultKindNote;
  String get vaultKindTotp;
  String get vaultName;
  String get vaultNameRequired;
  String get vaultAddress;
  String get vaultSecret;
  String get vaultNewSecret;
  String get vaultSecretRequired;
  String get vaultTotpKey;
  String get vaultTotpHint;
  String get save;

  // ------------------------------------------------------- backup and import

  String get backupTitle;
  String get backupExport;
  String get backupExportNote;
  String get backupCreate;
  String get backupRestore;
  String get backupRestoreNote;
  String get backupRestoreAction;
  String get backupChooseFile;
  String get backupImport;
  String get backupImportNote;
  String get backupImportWarning;
  String get backupChooseExport;
  String get backupCodeCopied;
  String get backupCodeCopyFailed;
  String get backupSaved;
  String get backupSaveFailed;
  String get backupReadFailed;
  String backupRestored(int added, int skipped);
  String get backupWriteCodeDown;
  String get backupCodeShownOnce;
  String get backupCopyCode;
  String backupItemCount(int items);
  String get backupSaveFile;
  String get backupKeepApart;
  String get backupCodeTitle;
  String get backupCodeLabel;
  String backupFileSummary(int items, String date);
  String get importReviewTitle;
  String importWillAdd(int items);
  String get importNothingDeleted;
  String importRejectedCount(int rows);
  String importRejectedRow(int row, String name, String reason);
  String importAndMore(int rows);
  String get importAction;

  /// The kind of file the picker offers, drawn by the platform's own dialog.
  ///
  /// It reached the file dialog in Portuguese on an English phone: the label
  /// sat inside a `const` list, which is exactly where a string hides from a
  /// language pack.
  String get importFileType;
  String importProblem(ImportProblem problem);
  String rowProblem(RowProblem problem);
}

class _AppStringsDelegate extends LocalizationsDelegate<AppStrings> {
  const _AppStringsDelegate();

  @override
  bool isSupported(Locale locale) => AppStrings.supportedLocales.any(
    (supported) => supported.languageCode == locale.languageCode,
  );

  /// Synchronous on purpose.
  ///
  /// `Localizations` renders nothing at all until every delegate's future
  /// resolves, so an `async` load here costs a frame with an empty app in it
  /// -- on launch, and again on every language change.
  @override
  Future<AppStrings> load(Locale locale) =>
      SynchronousFuture<AppStrings>(AppStrings.forLocale(locale));

  @override
  bool shouldReload(_AppStringsDelegate old) => false;
}
