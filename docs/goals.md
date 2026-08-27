# BioAuth — estado e metas

Inventário do app inteiro. Cada item foi verificado no código, não herdado de
memória; onde há uma pendência, ela aponta o arquivo.

## Legenda

| | |
|---|---|
| `[x]` | feito e coberto por teste |
| `[.]` | em andamento ou parcial — funciona, falta pedaço |
| `[-]` | **pendência encontrada** — verificada, com localização |
| `[ ]` | não começado |

Última verificação: commit `bb600ed`.

---

## 0. Estado do release — resolver primeiro

- [-] **A versão pública é a v0.1.4 e tem duas falhas já corrigidas na `main`.**
      A v0.1.4 saiu de `427568d`, antes de `dc197ca`. Ela aceita um RP ID que é
      sufixo público (uma página em `evil.com.br` reivindica `com.br`) e leva a
      extensão que não funciona no Chrome. Cortar a **0.1.5** é um bump em
      quatro arquivos: `desktop/Cargo.toml`, `mobile/pubspec.yaml`,
      `desktop/ui/package.json`, `desktop/nixos/package.nix`.
- [-] **O APK sai assinado com a chave de debug.** O workflow já trata o caso e
      diz nas notas, mas enquanto os quatro secrets não existirem
      (`ANDROID_KEYSTORE_BASE64`, `ANDROID_KEYSTORE_PASSWORD`,
      `ANDROID_KEY_ALIAS`, `ANDROID_KEY_PASSWORD`) todo release sai assim. Ação
      do dono do repositório, não de agente.
- [-] **Não existe `flake.lock`.** O nixpkgs está solto: dois builds da mesma
      tag podem não produzir o mesmo binário. `nix flake lock` e commitar.

---

## 1. Protocolo e sessão

- [x] `AuthRequest`/`AuthResponse` canônicos, independentes de transporte, com
      golden vector compartilhado Dart/Rust
- [x] Handshake de duas mensagens, X25519 assinado, HKDF salgado pelo hash do
      transcript
- [x] `SecureChannel` ChaCha20-Poly1305 com contador de records
- [x] Session binding de 32 bytes como associated data
- [x] Intenção `pair`/`resume` no ClientHello (v2), aceitando v1 por
      compatibilidade — `docs/protocol-handshake.md`
- [ ] **Commit retomável** (`prepare`/`commit`/`commit-ack` com
      `pairingAttemptId` compartilhado). Decisão tomada de **não fazer**: se o
      commit não fechar, um QR novo repara e nada se perde, porque os dados
      vivem no celular. Reabrir só se aparecer um caso real de assimetria que o
      repareamento não conserte.

## 2. Pareamento, revogação e reconexão

- [x] Pareamento criptográfico com código de verificação nos dois lados
- [x] Revogação no celular remove o registro, derruba a sessão daquele verifier
      e só então atualiza a tela
- [x] `connected` emitido no fim do handshake, não na chegada de uma requisição
- [x] `Service::forget` republica a tabela de peers e descarta sessões
      estacionadas
- [x] Proposta pendente idempotente — consultar não consome
- [x] `attemptId` por tentativa, citado no `pair.confirm`
- [x] Backoff de reconexão de 1s dobrando até 15s, com as três primeiras
      falhas ainda lidas como "conectando"
- [-] **`PairingService.begin` vaza a sessão se preparar a credencial falhar.**
      `mobile/lib/core/pairing/pairing_service.dart:174` — o
      `_credential.describe()` está fora de qualquer `try` que feche o socket.
      Um Keystore que recusa (biometria reinscrita, por exemplo) deixa o
      pareamento aberto no desktop.
- [-] **`PairingController.reject` pode travar na tela do código.**
      `mobile/lib/features/pairing/pairing_controller.dart:84` — `await
      session?.reject()` propaga a exceção e o `state` nunca vira `idle`. Um
      `close` que falha prende o usuário numa tela sem saída.
- [-] **`PairingController.reset` descarta a sessão sem fechá-la.**
      Mesmo arquivo, linha 91. Sai da tela e deixa o socket aberto.
- [-] **Resultado de tentativa antiga pode sobrescrever a nova, no celular.**
      O `attemptId` que resolvi é do lado desktop. No celular não há nada
      equivalente: uma operação assíncrona da tentativa A ainda pode atualizar
      a UI depois que B começou.
- [ ] Revogação bilateral. Revogar o PC no celular não apaga a chave pública
      que o PC guarda — está documentado no plano, mas a UI não deixa esse
      limite claro para o usuário.

## 3. Transportes

- [x] `QrNetworkTransport` — TCP na LAN, endpoint vindo do QR
- [x] `BleTransport` no Android — GATT client, MTU, notificações, permissões,
      framing limitado
- [x] Servidor GATT BlueZ no desktop Linux (`ble.rs`)
- [x] `FallbackAuthTransport` — LAN primeiro, BLE depois, e **nunca** faz
      fallback durante pareamento
- [x] Ordem no `TransportRegistry`: rede antes de BLE, para que a espera de 10s
      do BLE não entre no caminho comum
- [-] **`ble.rs` tem 551 linhas e zero testes.** É `cfg(target_os = "linux")`,
      então nem compila no Windows; o CI compila e roda clippy, mas nada
      exercita. Um teste de unidade sobre um duplo de BlueZ daria pouca
      garantia pelo custo — o que falta de verdade é o item abaixo.
- [ ] **Teste de autorização BLE em hardware real.** Roadmap desmarcado. Não é
      tarefa de agente: precisa de um celular e um Linux com Bluetooth.
- [-] **O `ble.rs` não serve para o initrd.** Usa o crate `bluer` com a feature
      `bluetoothd`, ou seja, fala com o daemon por D-Bus. Um caminho BLE no
      boot precisaria de outra implementação, em socket HCI cru.

## 4. App mobile

- [x] Shell Material 3, estado Riverpod, aprovação contextual, auditoria
- [x] Chave de autorização no Keystore com `BIOMETRIC_STRONG` +
      `CryptoObject(Signature)`
- [x] Agrupamento de duplicatas, aviso de enxurrada, bloqueio temporário
- [x] Foreground service com notificação persistente, sessões vivas com o app
      fora da tela
- [x] `inactive` tratado como em tela — o prompt biométrico não derruba a
      sessão que espera por ele
- [ ] Política de background por OEM. Xiaomi, Samsung e Huawei matam foreground
      services de formas diferentes; nada disso foi verificado.
- [ ] **Matriz de background e task-removal em aparelho real.** Roadmap
      desmarcado.

## 5. Agente desktop e tray

- [x] Agente com IPC em `127.0.0.1` autenticado por token de 32 bytes em
      arquivo só do dono
- [x] CLI `phone-auth` com códigos de saída estáveis
- [x] Tray Electron, geração de QR no processo main
- [x] Log de auditoria
- [x] Permissões por verifier e por credencial
- [ ] Um segundo cliente IPC concorrente (tray + CLI ao mesmo tempo) nunca foi
      exercitado; o `attemptId` cobre a confirmação de pareamento, mas não há
      teste de duas UIs vivas.

## 6. WebAuthn / passkeys

- [x] `CredentialProviderService` no Android
- [x] Encoding CTAP2 — `authenticatorData`, COSE_Key, `attestationObject`,
      attestation `none`, AAGUID zerado
- [x] Chaves por RP em alias próprio (`bioauth_webauthn_v1_`), separadas das
      credenciais PhoneAuth
- [x] Validação de origem: assetlinks para apps, allowlist do Google para
      navegadores privilegiados (70 apps, lista canônica)
- [x] Public Suffix List embutida — RP ID precisa ser domínio registrável
- [x] Extensão de navegador funcionando em Chrome **e** Firefox
- [x] Permissions Policy reconferida, iframe de terceiro bloqueado
- [x] Native messaging host + relay pela sessão pareada
- [-] **A matriz manual do webauthn.io nunca foi executada.** Roadmap
      desmarcado, e é o único jeito de saber se registro e login funcionam de
      ponta a ponta. Precisa de aparelho e navegador reais.
- [ ] `getPublicKey()` devolve a chave, mas nenhum relying party real foi
      testado consumindo ela.
- [ ] Atualizar as duas listas embutidas periodicamente
      (`public_suffix_list.dat`, `privileged_browsers.json`). Não há lembrete
      nem verificação de idade — só o teste que confere que a lista não está
      truncada.

## 7. Empacotamento e release

- [x] Workflow único: push na main com versão nova corta o release
- [x] Windows NSIS, Linux AppImage + deb, tarball headless, pacote Nix
- [x] Gate que recusa build se os quatro arquivos de versão discordarem
- [x] Ícones reais a partir de `assets/`, adaptive icons no Android, iOS sem
      canal alfa
- [-] Ver a seção 0 — APK debug-signed, sem `flake.lock`, 0.1.5 não cortada.

## 8. Criptografia de disco (LUKS)

- [x] `phone-auth-initrd` com seleção de credencial, separação de propósito e
      exigência de chave em hardware
- [x] Contrato com o boot script: chave no stdout e saída 0, diagnóstico no
      stderr para o log nunca capturar material de chave
- [-] **Não tem transporte: sempre sai com código 3 e cai na senha.** É o
      comportamento correto hoje, não uma falha.
- [ ] Transporte que funcione no initrd, **depois** da revisão de superfície de
      ataque que o roadmap exige. Ethernet é o caminho realista; Wi-Fi
      exigiria a PSK em claro no `/boot`, que é trocar um segredo por outro.
- [ ] Credencial dedicada de wrapping LUKS e keyslot próprio. Assinatura não é
      chave: ECDSA não é determinístico, então precisa de um esquema de
      embrulho (AES-GCM no Keystore travado por biometria é o desenho que se
      encaixa no resto).
- [ ] Módulo NixOS não tem **nenhuma** linha de initrd hoje.
- [ ] Keyslot de recuperação offline obrigatório, com ensaio de recuperação.

## 9. Integração com o sistema

- [x] PAM via `pam_exec` para `sudo` e `login`, com módulo NixOS
- [ ] **Windows Credential Provider.** É o que permitiria aprovar UAC pela
      digital. Só entra no caso de usuário padrão — para quem é admin, o UAC é
      só "Sim" e não chama credential provider nenhum. Duas saídas, ambas
      caras: guardar a senha do Windows (contradiz o objetivo) ou ir de
      certificado/smart card virtual (projeto grande). Risco alto: a DLL é
      carregada pelo `LogonUI`, e um defeito ali tranca o usuário para fora da
      máquina.
- [ ] SSH e agente forwarding
- [ ] iOS: `ASCredentialProviderExtension`, mais toda a metade nativa

## 10. Vault de segredos no celular (Fase 3A)

- [.] **Destravado pelo foreground service, ainda não começado.** Estava
      bloqueado pela Fase 3B, que o Codex entregou.
- [ ] Ciphertext no celular, desktop navega e copia para o clipboard
- [ ] O clipboard é o furo, não o swap: no Windows ele é global, o Win+V grava
      histórico e o clipboard da nuvem sincroniza para fora da máquina.
      Precisa de `ExcludeClipboardContentFromMonitorProcessing`,
      `CanIncludeInClipboardHistory` e limpeza por timer.
- [ ] O segredo não pode entrar no processo Electron: strings JS são imutáveis
      e coletadas, não dá para zerar. Fica no agente, em buffer `Zeroize` sob
      `VirtualLock`/`mlock`, e o agente escreve o clipboard. A UI vê só nomes.
- [ ] Caminho de export, senão perder o celular é perder o vault.

## 11. Testes e CI

- [x] Rust 214, mobile 115, Kotlin 20, tray 7 — todos no CI
- [x] `fmt`, `clippy -D warnings`, `analyze`, `dart format` no CI
- [x] Testes Kotlin do plugin agora rodam no CI
      (`:phone_auth_native:testDebugUnitTest`)
- [x] Golden vectors do handshake pinados nos dois lados, com o v1 guardado
      como prova de compatibilidade
- [-] **Nenhum teste de integração real PC↔celular.** Todo o fluxo é exercitado
      contra duplos. As matrizes de queda que o
      `pairing-reliability-plan.md` lista — derrubar a conexão em cada
      fronteira — não existem.
- [ ] Teste de fumaça do release: instalar o artefato e parear, em vez de só
      construir.

---

## Ordem sugerida

1. **Cortar a 0.1.5.** A versão pública tem falha de segurança já corrigida.
   Tudo o mais é menos urgente que isso.
2. **Os quatro P1 de pareamento** (seção 2). São pequenos, verificados, com
   arquivo e linha, e cada um é um jeito de o usuário ficar preso numa tela ou
   vazar um socket.
3. **`flake.lock`.** Um comando.
4. **Matrizes em hardware real** (webauthn.io, BLE, background por OEM). Não
   são tarefa de agente — precisam de aparelho — mas são o que separa
   "implementado" de "funciona".
5. **Vault (seção 10)**, se o objetivo é produto. Está destravado e é a coisa
   que o usuário mais encosta no dia a dia.
6. **Windows Credential Provider**, se o objetivo é substituir senha no PC.
   Leia a seção 9 antes de começar: o risco de trancar a própria máquina para
   fora é real e a recuperação é modo de segurança.

## Regras que valem para qualquer item

- Commits direto na `main`, sem PR e sem trailer `Co-Authored-By`.
- Nunca reusar os aliases `bioauth_authorization_v1` nem
  `bioauth_session_identity_v1` para outra finalidade.
- Sem `BIOMETRIC_WEAK`, sem fallback de credencial de sistema, sem período de
  graça: cada assinatura passa por uma biometria.
- Nada de chave, challenge, assinatura ou material LUKS em log.
- A versão vive em quatro arquivos e o gate recusa o release se discordarem.
- Marcar item como feito só depois de verificado. Um `[x]` que não roda em
  teste é pior que um `[ ]`.
