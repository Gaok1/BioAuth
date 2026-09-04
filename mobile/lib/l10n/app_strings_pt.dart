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

/// Português do Brasil.
class PortugueseStrings extends AppStrings {
  const PortugueseStrings();

  @override
  String get languageName => 'Português (Brasil)';

  @override
  String get appTitle => 'PhoneAuth';
  @override
  String get tabDevices => 'Dispositivos';
  @override
  String get tabPair => 'Parear';
  @override
  String get tabVault => 'Cofre';
  @override
  String get tabHistory => 'Histórico';
  @override
  String get tabSettings => 'Ajustes';
  @override
  String requestsWaiting(int count) => count == 1
      ? '1 solicitação aguardando'
      : '$count solicitações aguardando';

  @override
  String get onboardingTitle => 'Aprove acessos pelo telefone';
  @override
  String get onboardingBody =>
      'Funciona offline. As chaves ficam neste aparelho.';
  @override
  String get onboardingPasskeyWarningTitle => 'Passkeys não têm backup';
  @override
  String get onboardingPasskeyWarningBody =>
      'Mantenha outro método de acesso em cada site.';
  @override
  String get onboardingStart => 'Começar';

  @override
  String get devicesRequests => 'Solicitações';
  @override
  String get devicesPaired => 'Dispositivos';
  @override
  String get devicesEmpty => 'Nenhum computador pareado.';
  @override
  String get devicesFloodTitle => 'Possível ataque';
  @override
  String devicesFloodBody(String device, int requests, int seconds) =>
      '$device enviou $requests solicitações em $seconds segundos.';
  @override
  String get devicesBlockForFifteenMinutes => 'Bloquear por 15 min';

  @override
  String get historyTitle => 'Histórico';
  @override
  String get historyEmpty => 'Nada registrado ainda.';

  @override
  String get settingsTitle => 'Ajustes';
  @override
  String get settingsSecurity => 'Segurança';
  @override
  String get settingsSecuritySubtitle => 'Biometria e proteção de chaves';
  @override
  String get settingsPasskeys => 'Passkeys';
  @override
  String get settingsPasskeysSubtitle => 'Sites, contas e chaves';
  @override
  String get settingsRecovery => 'Recuperação';
  @override
  String get settingsRecoverySubtitle => 'Revogar e parear de novo';
  @override
  String get settingsLanguage => 'Idioma';
  @override
  String get settingsLanguageSystem => 'Do sistema';

  @override
  String get recoveryTitle => 'Recuperação';
  @override
  String get recoveryLostPhone => 'Perdeu o telefone?';
  @override
  String get recoveryBody =>
      'Remova este telefone em cada computador pareado. Um aparelho novo '
      'precisa da própria chave e de um novo pareamento.';
  @override
  String get recoveryKeysNotExported =>
      'Chaves privadas não são exportadas nem incluídas em backup.';

  @override
  String get passkeysTitle => 'Passkeys';
  @override
  String get passkeysEmpty => 'Nenhuma passkey neste telefone.';
  @override
  String get passkeysOrphan => 'Chave órfã';
  @override
  String get passkeysDelete => 'Excluir passkey';
  @override
  String get passkeysDeleteTitle => 'Excluir passkey?';
  @override
  String get passkeysDeleteOrphanBody => 'Esta chave não tem metadados.';
  @override
  String passkeysDeleteBody(String user, String site) =>
      'Remove $user em $site deste telefone.';
  @override
  String get passkeysDeleteFailed => 'Não foi possível excluir a passkey.';
  @override
  String passkeysCreatedOn(String user, String date) =>
      '$user · criada em $date';
  @override
  String get passkeyStatusAvailable => 'Disponível';
  @override
  String get passkeyStatusMissingKey => 'Metadados sem chave';
  @override
  String get passkeyStatusInvalidKey => 'Chave invalidada pela biometria';
  @override
  String get passkeyStatusOrphanKey => 'Chave sem metadados';

  @override
  String connectionPhase(ConnectionPhase phase) => switch (phase) {
    ConnectionPhase.disconnected => 'Offline',
    ConnectionPhase.scanning => 'Procurando',
    ConnectionPhase.connecting => 'Conectando',
    ConnectionPhase.secureHandshake => 'Validando conexão',
    ConnectionPhase.connected => 'Conectado',
    ConnectionPhase.authenticationPending => 'Solicitação pendente',
    ConnectionPhase.awaitingBiometric => 'Aguardando biometria',
    ConnectionPhase.signing => 'Autenticando',
    ConnectionPhase.approved => 'Aprovado',
    ConnectionPhase.denied => 'Negado',
    ConnectionPhase.expired => 'Expirado',
    ConnectionPhase.error => 'Erro',
    ConnectionPhase.revoking => 'Revogando',
  };

  @override
  String auditOutcome(AuditOutcome outcome) => switch (outcome) {
    AuditOutcome.approved => 'Aprovado',
    AuditOutcome.denied => 'Negado',
    AuditOutcome.expired => 'Expirado',
    AuditOutcome.blocked => 'Bloqueado',
  };

  @override
  String credentialPurpose(CredentialPurpose purpose) => switch (purpose) {
    CredentialPurpose.authorization => 'Login',
    CredentialPurpose.diskUnlock => 'Disco',
    CredentialPurpose.webAuthn => 'Sites',
    CredentialPurpose.vault => 'Cofre',
    CredentialPurpose.fileLocker => 'Arquivos',
    CredentialPurpose.ssh => 'SSH',
  };

  @override
  String credentialPurposeNote(CredentialPurpose purpose) => switch (purpose) {
    CredentialPurpose.authorization =>
      'Aprova logins e ações como `sudo` neste computador.',
    CredentialPurpose.diskUnlock => 'Destrava o disco deste computador.',
    CredentialPurpose.webAuthn => 'Responde por passkeys em sites.',
    CredentialPurpose.vault => 'Libera senhas do cofre para este computador.',
    CredentialPurpose.fileLocker => 'Abre arquivos trancados neste computador.',
    CredentialPurpose.ssh =>
      'Assina logins SSH. Cada login ainda pede sua digital.',
  };

  @override
  String get deviceBlocked => 'Bloqueado por ora';
  @override
  String deviceLastSeen(String elapsed) => 'Visto $elapsed';
  @override
  String get deviceJustNow => 'agora';
  @override
  String deviceMinutesAgo(int minutes) => 'há $minutes min';
  @override
  String deviceHoursAgo(int hours) => 'há $hours h';
  @override
  String deviceDaysAgo(int days) => 'há $days d';
  @override
  String get deviceMenu => 'Opções do dispositivo';
  @override
  String get devicePermissions => 'Permissões';
  @override
  String get deviceRevoke => 'Revogar dispositivo';
  @override
  String get revoke => 'Revogar';
  @override
  String get deviceRevokeTitle => 'Revogar este computador?';
  @override
  String deviceRevokeBody(String device) =>
      'Remove $device e encerra a sessão. O computador guarda sua chave '
      'pública até você desfazer o pareamento lá também. Pareie de novo para '
      'reconectar.';

  @override
  String get requestTitle => 'Solicitação de acesso';
  @override
  String get requestUnavailable => 'Solicitação indisponível';
  @override
  String get requestOrigin => 'Origem';
  @override
  String get requestService => 'Serviço';
  @override
  String get requestAction => 'Ação';
  @override
  String get requestTarget => 'Destino';
  @override
  String get requestUser => 'Usuário';
  @override
  String get requestTime => 'Horário';
  @override
  String requestGrouped(int count) =>
      '$count solicitações idênticas agrupadas.';
  @override
  String requestGroupedShort(int count) =>
      '$count solicitações idênticas agrupadas';
  @override
  String get requestDeny => 'Negar';
  @override
  String get requestApprove => 'Autorizar';

  @override
  String verificationCheckOn(String verifier) =>
      'Confira o código em $verifier';
  @override
  String verificationCodeSpoken(String spacedDigits) =>
      'Código de verificação $spacedDigits';
  @override
  String get verificationWarning =>
      'Só confirme se o computador mostrar estes mesmos seis dígitos.';
  @override
  String get verificationDiffer => 'São diferentes';
  @override
  String get verificationMatch => 'Conferem';

  @override
  String get scannerLabel => 'Leitor de QR Code para pareamento';
  @override
  String get scannerPermissionDenied =>
      'Permita o acesso à câmera para escanear o código.';
  @override
  String get scannerUnsupported =>
      'Este dispositivo não tem câmera compatível.';
  @override
  String get scannerUnavailable => 'A câmera não pôde ser aberta.';

  @override
  String get cancel => 'Cancelar';
  @override
  String get continueLabel => 'Continuar';
  @override
  String get retry => 'Tentar novamente';

  @override
  String get pairingTitle => 'Parear computador';
  @override
  String get pairingSubtitle => 'Escaneie o QR na tela dele';
  @override
  String get pairingConnecting => 'Conectando…';
  @override
  String pairingDone(String verifier) => 'Pareado com $verifier';
  @override
  String get pairingFinishOnComputer => 'Conclua a autorização no computador.';
  @override
  String get pairingFailed => 'Pareamento não concluído';
  @override
  String pairingProblem(PairingProblem problem) => switch (problem) {
    PairingProblem.notAPairingCode => 'Isto não é um código de pareamento.',
    PairingProblem.codeExpired => 'Este código expirou. Gere um novo.',
    PairingProblem.noAddress => 'Este código não traz endereço para conectar.',
    PairingProblem.notPairing => 'O computador não estava em pareamento.',
    PairingProblem.unreachable =>
      'Não foi possível alcançar o computador. Confira se está na mesma rede.',
    PairingProblem.timedOut => 'O computador não respondeu a tempo.',
    PairingProblem.failed => 'O pareamento falhou. Gere um novo código.',
  };
  @override
  String get done => 'Concluir';

  @override
  String permissionsTitle(String verifier) => 'Permissões · $verifier';
  @override
  String get permissionsAppliesOnNextConnection =>
      'Vale a partir da próxima conexão deste computador.';
  @override
  String get permissionsSaveFailed => 'Não foi possível salvar.';
  @override
  String get permissionsNoCredentials =>
      'Nenhuma credencial para este computador.';
  @override
  String permissionService(String service) => switch (service) {
    'vault' => 'cofre',
    'locker' => 'arquivos',
    'luks' => 'disco',
    _ => service,
  };

  @override
  String get securityTitle => 'Segurança';
  @override
  String get securityChecking => 'Verificando…';
  @override
  String get securityKey => 'Chave do aparelho';
  @override
  String get securityKeyMissing => 'Ainda não criada';
  @override
  String get securityKeyStrongBox => 'Guardada no StrongBox';
  @override
  String get securityKeyHardware => 'Protegida por hardware, sem StrongBox';
  @override
  String get securityKeySoftware => 'Sem proteção de hardware';
  @override
  String get securityKeyUnknown => 'Não foi possível ler o keystore';
  @override
  String get securityBiometrics => 'Biometria forte';
  @override
  String get securityBiometricsStrong => 'Disponível';
  @override
  String get securityBiometricsWeak => 'Existe, mas não é forte';
  @override
  String get securityBiometricsNoneEnrolled => 'Nenhuma cadastrada';
  @override
  String get securityBiometricsTemporarilyUnavailable =>
      'Temporariamente indisponível';
  @override
  String get securityBiometricsUnavailable => 'Indisponível';
  @override
  String get securityBiometricsUnsupported => 'Sem suporte neste aparelho';
  @override
  String get securityBiometricsUnknown => 'Desconhecida';
  @override
  String get securityBackground => 'Sessões em segundo plano';
  @override
  String get securityBackgroundRunning => 'Ativas';
  @override
  String get securityBackgroundIdle => 'Inativas; pareie um computador';
  @override
  String get securityBackgroundUnknown => 'Não foi possível verificar';

  @override
  String get sshTitle => 'Login SSH';
  @override
  String get sshComputer => 'Computador';
  @override
  String get sshSignInAs => 'Entrar como';
  @override
  String get sshServer => 'Servidor';
  @override
  String get sshServerUnnamed => 'não informado por este computador';
  @override
  String get sshSessionLasts =>
      'A sessão fica aberta enquanto o terminal estiver aberto.';
  @override
  String get sshNoServerNamed =>
      'Este computador não disse qual é o servidor. Só aprove se você acabou '
      'de rodar um `ssh` e sabe para onde.';
  @override
  String get sshApprove => 'Aprovar login';
  @override
  String get refuse => 'Recusar';

  @override
  String get vaultRequestTitle => 'Pedido de um computador';
  @override
  String get vaultOperationLabel => 'Operação';
  @override
  String vaultOperation(VaultOperation operation) => switch (operation) {
    VaultOperation.read => 'Copiar a senha de',
    VaultOperation.create => 'Guardar um item novo:',
    VaultOperation.update => 'Alterar',
    VaultOperation.delete => 'Apagar',
  };
  @override
  String get vaultItemLabel => 'Item';
  @override
  String get vaultDomainLabel => 'Domínio';
  @override
  String get vaultApprovalCopyNote =>
      'A senha vai para a área de transferência daquele computador.';
  @override
  String get vaultApprovalWriteNote => 'O item guardado neste telefone muda.';
  @override
  String get vaultApproveCopy => 'Aprovar cópia';
  @override
  String get approve => 'Aprovar';

  @override
  String vaultFailure(VaultFailure failure) => switch (failure) {
    VaultSeedFailure(:final problem) => totpProblem(problem),
    VaultBackupFailure(:final problem) => backupProblem(problem),
    VaultStoreFailure(:final code) => switch (code) {
      'authentication_cancelled' => 'Autenticação cancelada.',
      'authentication_failed' =>
        'Não foi possível ler sua digital. Tente de novo em instantes.',
      'authentication_required' => 'Confirme sua digital para abrir o cofre.',
      'biometric_unavailable' => 'Cadastre uma biometria forte para o cofre.',
      'activity_unavailable' =>
        'A confirmação não pôde ser aberta. Volte ao aplicativo e tente de '
            'novo.',
      'unsupported_android' => 'O cofre precisa do Android 11 ou mais novo.',
      'revision_conflict' =>
        'Este item mudou. Atualize o cofre e tente de novo.',
      'operation_in_progress' =>
        'Outra operação do cofre está em andamento. Tente de novo em '
            'instantes.',
      'vault_full' =>
        'O cofre já guarda o máximo de $maxVaultItems itens. Apague algum '
            'antes.',
      'clipboard_unavailable' =>
        'Este aparelho não tem área de transferência, então nada foi copiado. '
            'Use Revelar para ler o valor na tela.',
      'clipboard_failed' =>
        'A área de transferência recusou o valor; nada foi copiado.',
      'key_invalidated' =>
        'Um novo cadastro de biometria invalidou a chave deste cofre. O '
            'conteúdo não pode mais ser aberto. Restaure a partir de um '
            'backup.',
      'store_corrupt' =>
        'O arquivo do cofre não passou na verificação de integridade. '
            'Restaure a partir de um backup.',
      'store_version_unsupported' =>
        'Este cofre foi gravado por uma versão mais nova. Atualize antes de '
            'abri-lo -- não apague nada.',
      _ => 'Não foi possível concluir a operação do cofre.',
    },
  };

  @override
  String vaultNotice(VaultNotice notice) => switch (notice) {
    VaultPasswordCopied() => 'Senha de ${notice.itemName} copiada.',
    VaultCodeCopied() =>
      'Código de ${notice.itemName} copiado -- não a semente.',
  };

  @override
  String totpProblem(TotpProblem problem) => switch (problem) {
    TotpProblem.digitsOutOfRange => 'Um código TOTP tem de 6 a 8 dígitos.',
    TotpProblem.windowOutOfRange => 'A janela TOTP está fora do intervalo.',
    TotpProblem.emptyKey => 'A chave TOTP está vazia.',
    TotpProblem.invalidCharacter => 'A chave TOTP tem um caractere inválido.',
    TotpProblem.keyTooShort => 'A chave TOTP é curta demais.',
    TotpProblem.notOtpauth => 'Isto não é um link otpauth://totp.',
    TotpProblem.noKeyInUri => 'Esse link otpauth não traz uma chave.',
    TotpProblem.unsupportedAlgorithm => 'Algoritmo TOTP não suportado.',
  };

  @override
  String backupProblem(BackupProblem problem) => switch (problem) {
    BackupProblem.notABackupCode => 'Este não é um código de backup do cofre.',
    BackupProblem.codeHasInvalidCharacter =>
      'O código tem um caractere inválido.',
    BackupProblem.codeIncomplete => 'O código está incompleto.',
    BackupProblem.vaultTooLarge => 'Este cofre é grande demais para exportar.',
    BackupProblem.fileTruncated => 'O arquivo de backup está truncado.',
    BackupProblem.wrongCodeOrEdited =>
      'O código não abre este arquivo, ou o arquivo foi alterado.',
    BackupProblem.contradictsItself =>
      'O backup se contradiz sobre o conteúdo.',
    BackupProblem.badHeader => 'Cabeçalho de backup inválido.',
    BackupProblem.schemaTooNew =>
      'Este backup foi gravado por uma versão mais nova.',
    BackupProblem.backupTooLarge =>
      'Este backup é grande demais para restaurar.',
    BackupProblem.notABackupFile => 'Isto não é um backup de cofre.',
    BackupProblem.badItem => 'Item inválido no backup.',
    BackupProblem.unknownItemKind => 'Tipo de item desconhecido no backup.',
    BackupProblem.corruptContent => 'O conteúdo do backup está corrompido.',
  };

  @override
  String get vaultRefresh => 'Atualizar';
  @override
  String get vaultRefreshAction => 'Atualizar';
  @override
  String get vaultBackup => 'Backup';
  @override
  String get vaultLock => 'Bloquear';
  @override
  String get vaultUnlock => 'Desbloquear';
  @override
  String get vaultLocked => 'O cofre está bloqueado';
  @override
  String get vaultNewItem => 'Novo item';
  @override
  String get vaultEditItem => 'Editar item';
  @override
  String get vaultDiscardNote =>
      'Descartar esvazia este cofre. Só faça isso se tiver um backup.';
  @override
  String get vaultDiscardAndRestart => 'Descartar e começar de novo';
  @override
  String get vaultDiscardTitle => 'Descartar o cofre?';
  @override
  String get vaultDiscardBody =>
      'Todos os itens deste telefone são apagados junto com a chave. Não tem '
      'volta. Se você tem um backup, poderá restaurá-lo depois.';
  @override
  String get vaultDiscard => 'Descartar';
  @override
  String get vaultSearchHint => 'Buscar nome, usuário ou endereço';
  @override
  String get vaultStale =>
      'Um computador gravou no cofre desde que ele foi aberto.';
  @override
  String get vaultEmpty =>
      'O cofre está vazio. Toque em + para guardar um '
      'item.';
  @override
  String get vaultNoMatch => 'Nenhum item corresponde à busca.';
  @override
  String get vaultReveal => 'Revelar';
  @override
  String get vaultHide => 'Ocultar';
  @override
  String get vaultFavourite => 'Marcar como favorito';
  @override
  String get vaultUnfavourite => 'Tirar dos favoritos';
  @override
  String get vaultCopy => 'Copiar';
  @override
  String get vaultEdit => 'Editar';
  @override
  String get vaultDelete => 'Excluir';
  @override
  String get vaultDeleteTitle => 'Excluir item?';
  @override
  String vaultDeleteBody(String item) => '“$item” sai do cofre.';
  @override
  String get vaultKind => 'Tipo';
  @override
  String get vaultKindLogin => 'Login';
  @override
  String get vaultKindNote => 'Nota segura';
  @override
  String get vaultKindTotp => 'Código TOTP';
  @override
  String get vaultName => 'Nome';
  @override
  String get vaultNameRequired => 'Informe um nome';
  @override
  String get vaultAddress => 'Endereço';
  @override
  String get vaultSecret => 'Segredo';
  @override
  String get vaultNewSecret => 'Novo segredo';
  @override
  String get vaultSecretRequired => 'Informe o segredo';
  @override
  String get vaultTotpKey => 'Chave TOTP ou otpauth://';
  @override
  String get vaultTotpHint =>
      'Cole a chave que o site mostrou, ou o link do QR code.';
  @override
  String get save => 'Salvar';

  @override
  String get backupTitle => 'Backup do cofre';
  @override
  String get backupExport => 'Exportar';
  @override
  String get backupExportNote =>
      'Gera um arquivo criptografado e um código que aparece uma vez só. Sem '
      'o código o arquivo não abre para ninguém, nem para você.';
  @override
  String get backupCreate => 'Gerar backup';
  @override
  String get backupRestore => 'Restaurar';
  @override
  String get backupRestoreNote =>
      'Acrescenta o que o arquivo tiver. Nada é apagado, e itens que já estão '
      'aqui são ignorados.';
  @override
  String get backupRestoreAction => 'Restaurar';
  @override
  String get backupChooseFile => 'Escolher arquivo…';
  @override
  String get backupImport => 'Importar de outro gerenciador';
  @override
  String get backupImportNote =>
      'Lê uma exportação do Bitwarden (JSON) ou um CSV com cabeçalho. Você vê '
      'o que seria adicionado antes de qualquer coisa ser guardada.';
  @override
  String get backupImportWarning =>
      'O arquivo do outro gerenciador está em texto claro. Apague-o do '
      'telefone quando terminar.';
  @override
  String get backupChooseExport => 'Escolher exportação…';
  @override
  String get backupCodeCopied => 'Código copiado.';
  @override
  String get backupCodeCopyFailed =>
      'Não foi possível copiar. Anote o código exatamente como está acima.';
  @override
  String get backupSaved => 'Backup salvo. Guarde o código em outro lugar.';
  @override
  String get backupSaveFailed => 'Não foi possível salvar o arquivo.';
  @override
  String get backupReadFailed => 'Não foi possível ler o arquivo.';
  @override
  String backupRestored(int added, int skipped) {
    if (added == 0 && skipped == 0) return 'O backup estava vazio.';
    final restored = added == 1
        ? '1 item restaurado'
        : '$added itens restaurados';
    if (skipped == 0) return '$restored.';
    final already = skipped == 1
        ? '1 já estava aqui'
        : '$skipped já estavam aqui';
    return '$restored; $already.';
  }

  @override
  String get backupWriteCodeDown => 'Anote este código agora';
  @override
  String get backupCodeShownOnce =>
      'Ele não aparece de novo e não fica guardado em lugar nenhum.';
  @override
  String get backupCopyCode => 'Copiar código';
  @override
  String backupItemCount(int items) =>
      items == 1 ? '1 item neste backup.' : '$items itens neste backup.';
  @override
  String get backupSaveFile => 'Salvar arquivo…';
  @override
  String get backupKeepApart =>
      'Guarde o arquivo e o código em lugares diferentes. Juntos, os dois são '
      'o cofre inteiro em texto claro.';
  @override
  String get backupCodeTitle => 'Código do backup';
  @override
  String get backupCodeLabel => 'Código';
  @override
  String backupFileSummary(int items, String date) =>
      items == 1 ? '1 item, de $date.' : '$items itens, de $date.';
  @override
  String get importReviewTitle => 'Conferir a importação';
  @override
  String importWillAdd(int items) => items == 1
      ? '1 item será adicionado.'
      : '$items itens serão adicionados.';
  @override
  String get importNothingDeleted =>
      'Nada é apagado. Itens que já estão aqui são ignorados.';
  @override
  String importRejectedCount(int rows) => rows == 1
      ? '1 linha não será importada:'
      : '$rows linhas não serão importadas:';
  @override
  String importRejectedRow(int row, String name, String reason) =>
      'linha $row${name.isEmpty ? '' : ' ($name)'} — $reason';
  @override
  String importAndMore(int rows) => '…e mais $rows.';
  @override
  String get importAction => 'Importar';
  @override
  String get importFileType => 'Exportação de gerenciador';
  @override
  String importProblem(ImportProblem problem) => switch (problem) {
    ImportProblem.notUtf8 =>
      'O arquivo não é texto UTF-8. Exporte de novo em UTF-8.',
    ImportProblem.malformedJson => 'O JSON deste arquivo está malformado.',
    ImportProblem.notBitwarden =>
      'Este JSON não parece uma exportação do Bitwarden.',
    ImportProblem.bitwardenEncrypted =>
      'Esta exportação do Bitwarden está criptografada. Exporte de novo sem '
          'criptografia.',
    ImportProblem.noItemsList => 'Este JSON não tem uma lista `items`.',
    ImportProblem.tooManyRows => 'O arquivo tem linhas demais.',
    ImportProblem.unreadableCsv => 'Não foi possível ler este CSV.',
    ImportProblem.emptyFile => 'O arquivo está vazio.',
    ImportProblem.csvNeedsNameColumn =>
      'O CSV precisa de uma coluna de nome (name, title ou account).',
    ImportProblem.csvNeedsSecretColumn =>
      'O CSV precisa de uma coluna de senha ou de nota.',
  };

  @override
  String rowProblem(RowProblem problem) => switch (problem) {
    RowProblem.notAnItem => 'não é um item',
    RowProblem.unsupportedType => 'não é login nem nota',
    RowProblem.noName => 'sem nome',
    RowProblem.noSecret => 'sem senha nem conteúdo',
    RowProblem.nameTooLong => 'nome longo demais',
    RowProblem.usernameTooLong => 'usuário longo demais',
    RowProblem.uriTooLong => 'endereço longo demais',
    RowProblem.secretTooLong => 'conteúdo longo demais',
  };
}
