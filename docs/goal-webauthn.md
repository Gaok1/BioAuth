# Goal: BioAuth como autenticador reconhecido no celular, no PC e na web

Especificação de trabalho para a Fase 1C do `roadmap.md`.

## Objetivo

Uma passkey criada no BioAuth deve ser utilizável em três lugares, com a chave
privada existindo em um único lugar — o Keystore do celular:

1. Apps Android, via Credential Manager.
2. Navegadores no PC (Chrome, Edge, Firefox), via extensão + agente já existente.
3. Sites, que é consequência de (1) e (2).

O desktop nunca guarda chave. Ele monta a requisição, pede ao celular pela
sessão pareada que já existe, o celular pede a digital e assina, a resposta
volta. É exatamente o fluxo `AuthRequest`/`AuthResponse` de hoje, com um
conteúdo novo.

## Sequência (a ordem importa)

### Etapa 1 — Núcleo WebAuthn no celular

Construir uma vez, consumir nas duas portas. Uma passkey criada pelo Credential
Manager tem que funcionar depois a partir do PC, e vice-versa: é o mesmo store.

- Geração de credencial por RP: alias próprio no Keystore, P-256,
  `setUserAuthenticationRequired(true)`, StrongBox com fallback — o padrão que
  `DeviceKeyStore.kt` já usa.
- Store de credenciais (credentialId, rpId, userHandle, signCount) fora do
  Keystore. O Keystore guarda chave, não blob.
- Encoding CTAP2: `authenticatorData` (flags UP/UV/AT/BE/BS, AAGUID, signCount,
  attestedCredentialData), COSE_Key P-256 com labels inteiros negativos,
  `attestationObject`. Attestation `none` nesta etapa; documente a escolha.
- **Verifique** se o CBOR canônico que já existe no repo (com golden vector
  Dart/Rust) satisfaz as regras do CTAP2. Não assuma que sim.

Novo valor em `CredentialPurpose`
(`desktop/crates/phone-auth-verifier/src/pairing.rs`): hoje são `Authorization`
e `DiskUnlock`. Passkey é um terceiro propósito e o modelo de separação de
chaves do projeto já existe para isso — a credencial que autoriza sudo não pode
assinar uma asserção WebAuthn.

### Etapa 2 — Android: `CredentialProviderService`

Registrar o serviço no manifesto para que o BioAuth apareça na lista de
autenticadores do sistema. `BeginCreatePublicKeyCredentialRequest` e
`BeginGetPublicKeyCredentialOption` sobre o núcleo da Etapa 1.

Validação de origem é a parte crítica: o RP ID pedido tem que ser validado
contra o app chamador (assetlinks.json para apps; lista de navegadores
privilegiados quando vem `origin` explícito). Errar isso deixa um site de
phishing reivindicar qualquer RP ID. Se não der para validar direito, **recuse a
requisição** em vez de aceitar sem validar.

### Etapa 3 — Sessão que sobrevive ao app em segundo plano (Fase 3B)

**Dependência dura da Etapa 4, não item opcional.** Hoje o celular só mantém
sessão enquanto um widget observa `pairedSessionRunnerProvider`. Se o usuário
está no PC com o app fechado, o desktop não alcança o celular — e o caminho do
PC inteiro não funciona.

Precisa de foreground service Android com notificação persistente. É a troca
honesta: a conexão fica de pé e você consegue ver que ela está de pé.

A Etapa 2 não depende disso — o Credential Manager acorda o app sozinho.

### Etapa 4 — PC: extensão de navegador + relay no agente

O caminho que o Bitwarden usa, e o único que funciona hoje em Windows 10, Linux
e macOS ao mesmo tempo.

- Extensão sobrescreve `navigator.credentials.create/get`.
- Native messaging host conversa com o agente. O agente já expõe IPC em
  `127.0.0.1` com token de 32 bytes em arquivo legível só pelo dono
  (`desktop/crates/phone-auth-agent/src/ipc.rs`) — reuse esse mecanismo, não
  invente outro.
- Agente traduz a chamada WebAuthn em `AuthRequest` e usa a sessão pareada.
- Celular mostra o que está sendo pedido — *"PC-DO-LUIS quer entrar em:
  github.com"* — e libera pela digital.

**Assimetria de confiança, para documentar e não maquiar:** no Android dá para
verificar o chamador via assetlinks. No PC, a origem é o que a extensão afirma
ser. A defesa real é o celular exibir a origem e o usuário ser o último
conferente. É o mesmo modelo do Bitwarden, mas tem que estar escrito no
`threat-model.md`, não implícito.

## Fora de escopo

- **caBLE / hybrid transport.** O Android já é autenticador cross-device pelo
  Play Services. Reimplementar o túnel não ganha nada.
- **Windows Plugin Authenticator API.** É a integração nativa certa a longo
  prazo — aparece na UI de passkey do próprio Windows, sem extensão — mas exige
  Windows 11 24H2+. A máquina de desenvolvimento é Windows 10; anote como item
  futuro e siga pela extensão.
- iOS (`ASCredentialProviderExtension`).
- Sincronizar passkeys entre celulares.
- Qualquer mudança em transporte, pareamento ou handshake de sessão. Esse
  caminho está funcionando; não mexa.

## Definição de pronto

- `flutter test`, `flutter analyze`, `dart format --set-exit-if-changed`,
  `./gradlew lintDevDebug testDevDebugUnitTest`, `cargo fmt`,
  `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace` — os gates que o CI já roda.
- Testes de unidade do encoding CTAP2 contra vetores fixos, no espírito do
  golden vector Dart/Rust que já existe: um `authenticatorData` e um COSE_Key
  conhecidos, byte a byte.
- Um teste provando que RP ID não validado é **recusado**.
- Uma passkey registrada pelo Credential Manager no celular autentica depois
  pelo navegador do PC — mesma credencial, duas portas.
- Verificação manual descrita no commit: registrar e logar em webauthn.io pelo
  Chrome do aparelho, e pelo Chrome do PC.
- Roadmap (Fase 1C) marcado só no que foi de fato verificado.

## Restrições do repositório

- Commits direto na `main`, sem PR e sem trailer `Co-Authored-By`.
- Não reusar os aliases `bioauth_authorization_v1` nem
  `bioauth_session_identity_v1`. `architecture.md` proíbe explicitamente reusar
  o alias de autorização para WebAuthn.
- Sem `BIOMETRIC_WEAK`, sem fallback de credencial de sistema, sem período de
  graça. Cada assinatura passa por uma biometria.
- Nada de chave, challenge ou assinatura em log.
- A versão vive em quatro arquivos e o job `gate` recusa o release se
  discordarem: `desktop/Cargo.toml`, `mobile/pubspec.yaml`,
  `desktop/ui/package.json`, `desktop/nixos/package.nix`.

## Recuperação

Fora do escopo de implementação, registrado aqui porque decide se o resultado é
usável: se o celular vira o único acesso, um celular perdido ou quebrado é
perder tudo de uma vez. O projeto já trata isso como regra no LUKS — keyslot de
recuperação offline obrigatório, o celular nunca é o único caminho. A mesma
regra precisa valer para passkeys: segundo fator ou caminho de recuperação em
cada serviço, ou um caminho de export. É decisão de produto, não de código.
