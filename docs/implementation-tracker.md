# BioAuth — tracking para produto completo

Auditoria do repositório em **2026-08-28**, no commit `4026d92` e atualizada
depois da integração da onda 1 de tracks paralelos, consolidada com
o inventário que antes vivia em `docs/goals.md`. Este arquivo é a única fonte de
verdade para requisitos concluídos, pendências verificadas e o que falta até o
BioAuth ser utilizável por uma pessoa comum em três cenários:

1. passkeys/WebAuthn na web;
2. cofre de arquivos no computador;
3. cofre pessoal de senhas, no escopo de um gerenciador como o Bitwarden.

O `roadmap.md` continua registrando a visão de longo prazo. Aqui, "pronto"
significa instalável, recuperável e validado em dispositivos reais — não apenas
compilando ou passando em testes unitários.

## Legenda

| Estado | Significado |
|---|---|
| ✅ | Implementado e coberto por teste automatizado no repositório |
| 🧪 | Implementado, mas falta validação real, integração ou distribuição |
| ⬜ | Não implementado |
| ⛔ | Decisão de produto/segurança que bloqueia implementação correta |

Prioridades: **P0** bloqueia o primeiro produto seguro; **P1** é necessária
para uso diário; **P2** amplia compatibilidade ou conveniência.

## Resumo honesto do estado atual

| Área | Estado | Evidência / principal lacuna |
|---|---:|---|
| Protocolo, handshake, canal seguro e verificador | ✅ | Vetores Dart/Rust e testes em `desktop/crates/` e `mobile/test/` |
| Assinatura biométrica Android | 🧪 | Keystore e `BIOMETRIC_STRONG` existem; falta a matriz física telefone ↔ Rust |
| Pareamento e transporte LAN/QR | 🧪 | Código dos dois lados existe; falta certificar dispositivos/redes reais |
| BLE Android ↔ Linux | 🧪 | Cliente GATT e servidor BlueZ existem; falta teste físico e de OEM |
| Sessões Android em background | 🧪 | Foreground service existe; falta matriz de fabricantes/task removal |
| Passkeys Android | 🧪 | Credential Provider + Keystore implementados; instrumentação API 35 cobre registro e fronteiras, mas falta cerimônia completa e matriz real |
| Passkeys no desktop/web | 🧪 | Extensão, native host e relay existem; a instalação virou script com teste próprio, mas nenhum navegador real leu os manifests |
| Gestão/backup de passkeys | 🧪 | Tela Android lista/exclui e detecta chaves inválidas/órfãs; passkeys são explicitamente device-bound e ainda não têm backup/sync |
| File Locker | 🧪 | Formato, engine, wrappers, protocolo, CLI e recuperação existem e passam em teste, inclusive um round-trip real de 4 GiB; falta o telefone físico, disco cheio/kill e revisão externa |
| Cofre de senhas | 🧪 | Schema, as cinco operações `vault.*`, store no Keystore Android, memória travada, clipboard com prazo e geradores de senha e passphrase existem e passam em teste; faltam o CRUD mobile, o handler que liga os dois lados, export/restore e autofill |
| Recuperação do cofre/locker | 🧪 | O locker já tem wrapper offline e drill executado pelo binário; o cofre ainda não tem export/wrapper |
| Distribuição de produção | 🧪 | Pipeline recusa publicar sem assinatura Android e o native host já tem instalador; faltam secrets reais, empacotamento da extensão e smoke test |

**Conclusão:** a fundação de autenticação é substancial. WebAuthn é um protótipo
integrado, ainda não um recurso instalável. O File Locker deixou de ser um
projeto novo: o formato, a engine, os dois caminhos de recuperação e a CLI
existem e são testados de ponta a ponta com um telefone simulado. O que falta
nele é aparelho real, escala e revisão externa. O cofre de senhas deixou de ser
uma pasta vazia: o schema e as cinco operações `vault.*` concordam byte a byte
nos dois lados, o Android já tem onde guardar os itens sob biometria forte, e o
desktop já sabe gerar um segredo, mantê-lo fora do pagefile e entregá-lo pelo
clipboard sem passar pelo Electron. Ainda não é um produto: **falta o meio** —
o CRUD na tela do telefone e o handler que responde às operações. As duas
pontas existem e não se falam.

A onda 1 também deixou claro o limite do que este repositório consegue provar
sozinho. Quase tudo que ela entregou está em 🧪 pelo mesmo motivo, não por
qualidade: o Keystore nunca rodou em aparelho, o caminho Linux de `mlock` e
clipboard nunca executou, e nenhum navegador leu os manifests do native host.
Sair de 🧪 daqui em diante depende de hardware, não de mais código.

## Baseline já implementada

Estes requisitos vieram do inventário original de `goals.md` e precisam
continuar passando enquanto os produtos novos são construídos.

| ID | Estado | Requisito já atendido |
|---|---:|---|
| BAS-01 | ✅ | `AuthRequest`/`AuthResponse` canônicos, golden vector Dart/Rust, validação estrita de versão, tamanho, validade e payload assinado completo. |
| BAS-02 | ✅ | Handshake X25519 assinado, ClientHello v2 com intenção `pair`/`resume` e leitura compatível do v1, HKDF pelo transcript, ChaCha20-Poly1305, contador e session binding. |
| BAS-03 | ✅ | Pareamento com código nos dois lados, proposta idempotente, `attemptId` no desktop, revogação local, publicação de peers, descarte de sessão e backoff de reconnect de 1s a 15s. |
| BAS-04 | ✅ | `QrNetworkTransport`, cliente BLE Android, servidor GATT BlueZ Linux, framing limitado e fallback LAN → BLE que não atua durante pareamento. |
| BAS-05 | ✅ | App Material 3/Riverpod, aprovação contextual, auditoria, agrupamento de duplicatas, flood guard, Keystore com `BIOMETRIC_STRONG` e foreground service. |
| BAS-06 | ✅ | Agent com IPC local autenticado, CLI com exit codes, tray Electron, QR no main process, audit log e permissões por verifier/credencial. |
| BAS-07 | ✅ | Credential Provider Android, CTAP2/ES256, alias por passkey, validação de caller/origin/RP/PSL, extensão Chrome/Firefox, Permissions Policy e native relay. |
| BAS-08 | ✅ | Builds NSIS, AppImage, deb, tarball e Nix; gate que exige a mesma versão nos quatro manifests; ícones de produção. |
| BAS-09 | ✅ | `phone-auth-initrd` seleciona somente credencial hardware de propósito LUKS e preserva contrato stdout/stderr seguro; ainda não desbloqueia disco. |
| BAS-10 | ✅ | PAM via `pam_exec` para `sudo`/`login`, com separação entre agent de sistema e de usuário no módulo NixOS. |
| BAS-11 | ✅ | CI executa formatação, análise, Clippy, Rust, Flutter, Kotlin e tray; vetores v1/v2 preservam compatibilidade. |

## Bloqueadores imediatos do release atual

| ID | Pri. | Estado | Trabalho e critério de aceite |
|---|---:|---:|---|
| HOT-01 | P0 | 🧪 | Versão **0.1.5** sincronizada em `desktop/Cargo.toml`, `mobile/pubspec.yaml`, `desktop/ui/package.json` e `desktop/nixos/package.nix`; locks Cargo/npm atualizados e gate local aprovado. Falta publicar a tag/release para concluir o corte. |
| HOT-02 | P0 | 🧪 | O workflow agora exige os quatro secrets de assinatura Android em qualquer publicação, falha com configuração parcial e só permite APK debug-signed, com nome distinto, em `workflow_dispatch` não publicável. Ainda cabe ao dono configurar `ANDROID_KEYSTORE_BASE64`, `ANDROID_KEYSTORE_PASSWORD`, `ANDROID_KEY_ALIAS` e `ANDROID_KEY_PASSWORD`. |
| HOT-03 | P0 | ✅ | `flake.lock` foi gerado com Nix, fixa `nixpkgs`, `flake-utils` e `systems`, passa validação estrutural e **está versionado**. O texto anterior dizia que faltava commitar; estava desatualizado. |

## Decisões que precisam ser fechadas primeiro

| ID | Pri. | Estado | Decisão / aceite |
|---|---:|---:|---|
| DEC-01 | P0 | ✅ | Matriz fixada em `docs/product-decisions.md`: Android 14+, Windows 11 x64, Linux x64 e Chrome/Edge/Firefox estáveis; iOS, macOS, Safari, Windows 10 e ARM64 ficam explicitamente fora do primeiro release. |
| DEC-02 | P0 | ✅ | Telefone é o cofre autoritativo; cópia/autofill entrega plaintext ao agent/browser somente após gesto e aprovação. Electron nunca recebe segredos. Documentado em `docs/product-decisions.md`. |
| DEC-03 | P0 | ✅ | Recuperação usa ambos: export criptografado com chave guardada separadamente e segundo telefone confiável; drill em aparelho novo integra o gate. |
| DEC-04 | P0 | ✅ | Locker mantém ciphertext/header no PC, DEK aleatória por locker, wrapper biométrico com credencial Android exclusiva e wrapper offline de recovery. |
| DEC-05 | P0 | ✅ | MVP pessoal fixado: logins, notas, busca, gerador, import/export/restore e autofill por gesto; organizações, sharing, cartões, identidades e anexos ficam fora. |
| DEC-06 | P0 | ✅ | Nomes, sites, usuários, caminhos, timestamps sensíveis e índices ficam cifrados; somente framing mínimo e IDs opacos podem ficar claros. |

## Fundação comum

Esses itens bloqueiam web, locker e cofre; resolvê-los uma vez evita três
implementações de segurança divergentes.

| ID | Pri. | Estado | Trabalho e critério de aceite |
|---|---:|---:|---|
| FND-01 | P0 | 🧪 | Executar pareamento, autorização, rejeição, expiração, revogação e reconnect em Android físico contra agente Rust em Windows e Linux. Guardar apenas resultado e versões, nunca material criptográfico. |
| FND-02 | P0 | 🧪 | Executar a mesma suíte por LAN e BLE; testar Bluetooth desligado, perda de alcance, mudança de IP, Wi-Fi cliente-isolado e fallback sem downgrade silencioso. |
| FND-03 | P0 | 🧪 | Validar background em Pixel/Samsung/Motorola/Xiaomi, tela bloqueada, Doze, activity removida e processo recriado. Force-stop deve ser comunicado como indisponível, nunca como conectado. |
| FND-04 | P0 | ✅ | `security_screen.dart` consulta `SecurityCapabilities` real e o estado do foreground service, exibindo Keystore/hardware/StrongBox, `BIOMETRIC_STRONG` e sessões em background; coberto por widget test. |
| FND-05 | P0 | ✅ | Frames CBOR v1 separados de `AuthRequest` para `vault.*`/`locker.*` existem em Rust e Dart, com kind request/response/cancel/error, request ID, binding de 32 bytes, operação, limite de 6144 bytes e expiração; `isReplyTo` falha fechado e o payload não implementa debug/toString. Golden vector compartilhado e especificação em `docs/protocol-application.md`. |
| FND-06 | P0 | ✅ | `CredentialPurpose` ganhou valores wire estáveis e aliases distintos para `Vault` e `FileLocker`. O verifier deriva o propósito dos serviços reservados `vault`/`locker` (também `luks`/`webauthn`), sem aceitar override por IPC; teste cobre todos os propósitos estrangeiros mesmo quando a permissão de serviço foi concedida. |
| FND-07 | P0 | 🧪 | Pareamentos e passkeys usam envelopes v2 com migração, snapshot anterior, rollback reportado e recusa de versão futura. O locker usa container v1 estrito e publicação atômica; o store do cofre ainda não existe. |
| FND-08 | P0 | 🧪 | Passkeys agora carregam o mesmo request ID browser→host→agent→Android. Abort, timeout de browser, timeout do agent e desconexão enviam/cumprem cancelamento; notificação e `BiometricPrompt` são removidos, conclusão é once-only e testes cobrem bridge, registry Rust, frame Dart e coordinator Kotlin. Idempotência específica de vault/locker e o race de create WebAuthn já commitado ainda impedem ✅ global. |
| FND-09 | P1 | ✅ | iOS foi removido da matriz do primeiro release e está explicitamente marcado como não suportado; a implementação futura permanece em `SYS-03`/`WEB-13`. |
| FND-10 | P1 | ✅ | `docs/desktop.md` agora descreve os transportes LAN/BLE, handshake Dart, scanner, `KeyKind` e limitação iOS atuais; o README documenta corretamente que publicação sem os quatro secrets falha. |
| FND-11 | P0 | ✅ | `PairingService.begin` fecha a sessão se `_credential.describe()` ou o envio do enrolment falhar, preservando o erro original; coberto por `mobile/test/pairing_controller_test.dart`. |
| FND-12 | P0 | ✅ | `PairingController.reject` cancela localmente antes do close e sempre retorna a `idle`, inclusive quando o transporte falha; coberto por teste. |
| FND-13 | P0 | ✅ | `PairingController.reset` invalida a tentativa e rejeita/fecha qualquer sessão pendente antes de permitir novo scan; coberto por teste. |
| FND-14 | P0 | ✅ | O controller mobile usa `attemptId` monotônico: resultado cancelado é fechado e nunca sobrescreve a tentativa atual; coberto por teste de duas futures fora de ordem. |
| FND-15 | P1 | ✅ | A revogação no telefone agora exige confirmação que explica que o PC retém a chave pública até o usuário remover o pareamento também nele e que reconexão exige novo QR/códigos; coberto por widget test. |
| FND-16 | P1 | 🧪 | `ipc::concurrent_client_tests` sobe um listener real em loopback e liga dois `AgentClient`: cada um recebe a própria resposta, evento chega aos dois inscritos, evento no meio de um request não vira resposta, saída de um cliente não derruba o outro nem deixa o subscriber pendurado, e token errado desconecta só o impostor. Rodado 12x seguidas sem flake. Falta cobrir pareamento e autorização concorrentes, que precisam de telefone ou simulador nos dois clientes. |

O commit retomável de pareamento (`prepare/commit/commit-ack`) continua
deliberadamente fora do escopo: QR novo repara um commit incompleto sem perder
dados. Reabrir somente com evidência de assimetria que o reparing não resolva.

## Web, WebAuthn e passkeys

### Para sair de "protótipo integrado"

| ID | Pri. | Estado | Trabalho e critério de aceite |
|---|---:|---:|---|
| WEB-01 | P0 | 🧪 | Completar a matriz documentada em `docs/webauthn.md`: criação e login cruzados entre Android Credential Manager e Chrome/Edge/Firefox desktop, inclusive app em background. |
| WEB-02 | P0 | 🧪 | `install.ps1` registra e remove o host por usuário em HKCU para Chrome, Edge e Firefox; `install.sh` faz o mesmo nos três caminhos Linux. Cada navegador recebe manifest próprio, com caminho absoluto do executável e allowlist da chave certa — `allowed_origins` no Chromium, `allowed_extensions` no Firefox. ID Chromium é exigido no formato real de 32 caracteres `a`–`p`, então um placeholder é recusado em vez de virar allowlist frouxa. Recusa executável com nome diferente de `phone-auth-webauthn-host(.exe)`. Testes próprios instalam em `HOME`, diretório de manifests e raiz HKCU temporários, conferem caminho e allowlists, desinstalam e provam remoção; o do Windows foi verificado como não-vazio. **Não é ✅ porque nenhum navegador leu esses manifests** — os testes provam o contrato de filesystem e registro, não que a conexão nativa sobe. Entregue por `T4`. |
| WEB-03 | P0 | ⬜ | Empacotar e assinar a extensão para Chrome Web Store/Edge Add-ons/Firefox AMO, ou documentar explicitamente um canal corporativo. "Load unpacked" e extensão temporária não servem para usuário final. |
| WEB-04 | P0 | ✅ | `browser-extension.test.js` executa a extensão real em contextos isolados e cobre serialização de BufferSource, reconstrução dos objetos WebAuthn, abort/timeout, iframe/Permissions Policy, erro do native host e fallback nativo. A suíte Node do CI soma 11 testes. |
| WEB-05 | P0 | ✅ | O parser Android valida `authenticatorSelection`, `residentKey`, `userVerification` e `attestation`; rejeita attachment/attestation/valores incompatíveis antes da cerimônia. Criação suporta somente `credProps` e responde `rk: true`; demais extensions e extensions de assertion falham explicitamente. Coberto por teste Kotlin. |
| WEB-06 | P1 | ✅ | `Ajustes → Passkeys` lista RP/conta/data e saúde da chave. O inventário Android cruza metadata com aliases `bioauth_webauthn_v1_`, sinaliza chave ausente/inválida e alias órfão; exclusão exige `BIOMETRIC_STRONG` e remove primeiro o alias, depois a metadata retryable. Coberto por testes de channel/widget e build Kotlin. |
| WEB-07 | P1 | ✅ | Credential Manager publica uma entry por conta discoverable; o relay desktop agora mostra seletor no telefone quando mais de uma passkey combina e só então inicializa a assinatura da escolhida. `mediation: "conditional"` permanece decisão explícita de fallback ao autenticador nativo do browser. |
| WEB-08 | P1 | 🧪 | Instrumentação API 35 verifica registro/habilitação pelo Credential Manager real, permissão de bind, capability, activity privada, `PendingIntent` mutável explícito, política `BIOMETRIC_STRONG`, caller privilegiado com certificado instalado e asset links com package/certificado reais. O job de emulador está no CI; ainda faltam seleção do sistema + prompt biométrico concluído e fetch HTTPS real, portanto não é ✅. |
| WEB-09 | P1 | ✅ | Passkeys permanecem device-bound/sem sync neste corte. O onboarding avisa “sem backup” e exige manter outro método de acesso em cada RP; os prompts `BIOMETRIC_STRONG` de criação via Credential Manager e relay desktop repetem o aviso antes de criar a chave. |
| WEB-10 | P1 | ✅ | `scripts/update_android_trust_snapshots.py` baixa apenas as fontes HTTPS canônicas, limita/valida conteúdo, registra SHA-256 e idade em `trust-snapshots.json` e grava atomicamente. Workflow semanal testa a fronteira Android e abre PR com o diff; CI alerta após 45 dias. Nada é buscado em runtime. |
| WEB-11 | P1 | ✅ | A revisão em `docs/webauthn.md` enumera cada fronteira, confiança e risco residual. O bridge isolado agora repete Permissions Policy contra evento DOM forjado; worker deriva origin de `sender.url` e revalida shape; manifests limitam IDs; host rejeita >128 KiB antes de alocar e agent limita options a 6.000 bytes. Testes Node/Rust cobrem os gates. |
| WEB-12 | P2 | ⬜ | Avaliar Windows Plugin Authenticator API para dispensar extensão em Windows 11 24H2+, mantendo a extensão enquanto houver plataformas sem API equivalente. |
| WEB-13 | P2 | ⬜ | Implementar iOS credential provider/Safari apenas depois de `FND-09`; caBLE/hybrid continua fora até existir caso de uso e revisão próprios. |
| WEB-14 | P1 | ⬜ | Validar em um RP real que `AuthenticatorAttestationResponse.getPublicKey()` e `getPublicKeyAlgorithm()` são consumidos corretamente, além do teste em `webauthn.io`. |

### Gate de conclusão web

- instalação e remoção sem passos manuais em cada plataforma declarada;
- cadastro e login passam na matriz real e em pelo menos dois RPs além do
  `webauthn.io`;
- origem/RP/iframe inválidos falham fechados;
- usuário consegue ver e excluir uma passkey;
- perda do telefone tem comportamento e mensagem de recuperação definidos;
- atualização da extensão, app ou agent preserva credenciais existentes.

## File Locker

O locker deve criptografar arquivos no computador. O telefone autoriza o
unwrap da chave; ele não substitui um formato de arquivo, atomicidade nem uma
chave offline de recuperação.

O formato está especificado em `docs/locker-format.md`, a engine vive em
`desktop/crates/phone-auth-locker` e o protocolo em `docs/protocol-application.md`.

| ID | Pri. | Estado | Trabalho e critério de aceite |
|---|---:|---:|---|
| FLK-01 | P0 | ✅ | Container versionado especificado em `docs/locker-format.md` e implementado: magic com versão, header CBOR canônico, ChaCha20-Poly1305 por chunk com contador e flag de último chunk, salt/nonces por container, metadata cifrada, wrappers de chave e todos os limites conferidos antes de qualquer alocação. Revisão externa continua sendo `REL-04`. |
| FLK-02 | P0 | 🧪 | DEK aleatória por container, nunca reutilizada, e chave AES-GCM dedicada `bioauth_file_locker_v1` no Keystore, com auth-per-use, `BIOMETRIC_STRONG`, `setInvalidatedByBiometricEnrollment` e tentativa de StrongBox. O AAD do wrapper é derivado igual nos dois lados e o vetor está fixado em Rust e Kotlin. Falta rodar em aparelho físico e a matriz de fabricantes. |
| FLK-03 | P0 | 🧪 | `locker.create`, `locker.unlock` e `locker.rekey` implementados em Rust e Dart dentro do envelope de aplicação, ligados à sessão e ao binding do container, com nome de arquivo e nome do computador mostrados ao usuário. Vetores passam em Rust, Dart e Kotlin; falta a cerimônia em aparelho físico. |
| FLK-04 | P0 | ✅ | Engine em streaming por chunks de 64 KiB nos dois sentidos: nenhum arquivo é carregado inteiro em RAM. Chaves ficam em buffers zerados no drop (`Dek`, `Zeroizing`). Páginas **não** são travadas em memória: a decisão está registrada em `secret.rs` — o caminho realista de vazamento é um processo que já lê a RAM, e swap é problema de criptografia de disco. |
| FLK-05 | P0 | ✅ | Toda escrita vai para um temporário no mesmo diretório, com `fsync`, rename e `fsync` do diretório onde a plataforma suporta; o container é reaberto e verificado inteiro antes de o original ser removido, e o destino nunca é sobrescrito. Coberto por testes de recusa, falha e arquivo que cresce durante a leitura. |
| FLK-06 | P0 | ✅ | Wrapper offline com código de recuperação de 256 bits em base32 agrupado. O drill roda pelo binário publicado em `locker_recovery_drill.rs`: sem agent, sem sessão, sem telefone. O código é escrito no arquivo que o usuário escolher e nunca atravessa o IPC. |
| FLK-07 | P1 | ✅ | `phone-auth locker lock/unlock/status/rekey`, com `status` e recuperação rodando no próprio processo da CLI. `lock` exige `--recovery-out` e o agent devolve apenas o caminho, nunca o código: nenhuma UI recebe chave, código ou plaintext. Ainda não existe UI gráfica de locker — quando existir, ela chama os mesmos métodos IPC. |
| FLK-08 | P1 | 🧪 | Diretórios e não-arquivos são recusados em vez de seguidos; nomes com separador, `..`, controle ou nome reservado do Windows são recusados na leitura da metadata; modo Unix e mtime são restaurados quando a plataforma permite. Symlink e hardlink agora têm comportamento decidido e implementado em `docs/locker-format.md`: um caminho é recusado antes de qualquer biometria quando é link simbólico/diretório/dispositivo, ou quando tem um segundo hardlink **e** a operação apagaria ou renomearia o nome; rekey é sempre estrito; destino usa `symlink_metadata` para não consumir um symlink pendurado. O agent também faz a checagem porque ele mesmo apaga o plaintext. Faltam: contagem de hardlink no Windows (exige `windows-sys`), aviso de que ACL/ADS/xattr não são carregados, e os quatro testes novos são `cfg(unix)` — compilam cruzado mas só executam no CI Ubuntu. |
| FLK-09 | P1 | ⬜ | Não há operação em lote, e cada unlock exige biometria por uso, então não existe caminho automático hoje. Falta o trabalho real: limites, confirmação por lote e o detalhe de quantidade/tamanho/origem quando o lote existir. |
| FLK-10 | P1 | 🧪 | Cobertos: round-trip byte a byte, arquivo vazio, chunk exato, cauda parcial, corrupção amostrada em todo o container, truncamento, bytes sobrando, troca de chunks, splice entre containers, chave errada, recusa em cada fase, destino ocupado e arquivo que cresce durante a leitura. Multi-GB **foi executado**: 4 GiB + 3 bytes (comprimento além de `u32`, índice de chunk passando de 65536, cauda de 3 bytes) fazem round-trip com SHA-256 idêntico e 65 537 chunks, em 136,88 s no perfil release. O teste é `#[ignore]` porque move ~28 GiB de disco, então é evidência sob demanda e não cobertura contínua: `cargo test -p phone-auth-locker --release -- --ignored`. Faltam disco cheio e kill do processo por sinal — os dois exigem uma costura de injeção de erro ou um binário de teste separado, que ainda não existem. |
| FLK-11 | P2 | ⬜ | Integração com Explorer/Nautilus e drag-and-drop depois da CLI estar estável. Montagem de drive virtual/FUSE fica fora do MVP. |

### Gate de conclusão File Locker

- `lock → unlock` preserva bytes e metadata suportada de arquivos pequenos e
  multi-GB;
- qualquer alteração no ciphertext falha antes de publicar plaintext;
- cancelar, matar o processo ou encher o disco não perde o original;
- telefone perdido e rotação de telefone funcionam pelo recovery wrapper;
- agent/UI/log/clipboard nunca persistem chave ou conteúdo claro.

Estado do gate: os itens de integridade, recuperação e não-vazamento passam em
teste automatizado. Faltam disco cheio, kill por sinal, contagem de hardlinks
no Windows e a matriz com aparelho físico.
## Cofre de senhas pessoal

O primeiro corte deve ser um cofre pessoal sólido, não uma cópia de toda a
plataforma Bitwarden. Compartilhamento e organizações aumentariam muito o
modelo de confiança e ficam fora do MVP.

| ID | Pri. | Estado | Trabalho e critério de aceite |
|---|---:|---:|---|
| VLT-01 | P0 | ✅ | Schema v1 de login e nota segura em `phone-auth-protocol::vault` e `mobile/lib/core/protocol/vault_payloads.dart`: ID opaco, revisão, kind, nome, usuário, URI e data. `DEC-06` decide o que fica cifrado em repouso; `docs/protocol-application.md` registra que metadado viaja claro apenas dentro do canal já cifrado. Campos extras e múltiplas URLs ficaram fora, em `VLT-15`. |
| VLT-02 | P0 | 🧪 | Store Android no canal `bioauth/vault_store`: AES-256-GCM no Keystore, auth-per-use com `BIOMETRIC_STRONG` apenas, invalidação em novo enrollment, tentativa de StrongBox com fallback só para outra implementação do Keystore, blob cifrado em storage privado e CRUD paginado com revisão otimista. Nada sensível passa por `shared_preferences`. Testes JVM passam; a suíte instrumentada API 35 compila mas **nunca rodou** — não havia device nem emulador. Teto é 🧪 até rodar em hardware. Entregue por `T3`. |
| VLT-03 | P0 | 🧪 | CRUD mobile na aba Cofre: busca local, biometria por uso para revelar e copiar, auto-lock ao sair do foreground e `SensitiveContent` nas telas com segredo. Entregue por `T5`. Teto é 🧪 pelo mesmo motivo de `VLT-02`: o store nunca rodou em Keystore de verdade. |
| VLT-04 | P0 | 🧪 | As cinco operações têm handler dos dois lados. No telefone `VaultService` confere kind/binding/expiração, exige credencial de propósito `vault` e serve pelo store do Keystore; no desktop `phone-auth-agent::vault` pagina `vault.list` e busca por `vault.fetch`, com teto de páginas e recusa de cursor repetido. `ApplicationErrorCode` fixa três códigos byte a byte em Rust e Dart, e item ausente, revisão vencida e biometria recusada respondem o mesmo. Entregue por `T6`; `T6b` deu chamador ao caminho de leitura com `phone-auth vault list/copy/generate`. Teto é 🧪: os dois handlers só foram exercidos contra duplos — nenhum frame Rust chegou a um telefone real. |
| VLT-05 | P0 | 🧪 | Backup criptografado em `docs/vault-export-format.md`: 32 bytes do CSPRNG renderizados como código `BAV1`, HKDF-SHA256 e ChaCha20-Poly1305 sobre os itens com o cabeçalho como AAD — a mesma construção do locker. Contagem e data ficam fora do ciphertext para a tela dizer o que vai fazer antes de pedir o código, e são cobertas pelo AEAD. Export e restore são uma biometria cada, via `export`/`restore` nativos sobre o único blob. Restore **acrescenta e nunca substitui**; item já presente é contado, não duplicado. Nunca há caminho para JSON/CSV claro. 19 testes Dart + 5 JVM. Teto é 🧪: o drill de aparelho novo rodou contra store em memória, não contra dois telefones. |
| VLT-06 | P0 | 🧪 | `phone-auth-agent::secret_memory` aloca alinhado a página, trava com `VirtualLock` (Windows) ou `mlock` (Unix), exclui de dump com `WerRegisterExcludedMemoryBlock` / `MADV_DONTDUMP`, e faz wipe volátil **antes** de destravar — entre unlock e free as páginas voltariam a ser elegíveis para o pagefile. `is_locked()` reporta recusa do SO em vez de fingir sucesso. 7 testes. Hibernação continua fora de alcance; `docs/dependencies.md` registra por quê. **Não é ✅ porque o caminho Linux nunca foi executado**, só compilado e verificado com clippy para `x86_64-unknown-linux-gnu`. Entregue por `T1`. |
| VLT-07 | P0 | 🧪 | `phone-auth-agent::clipboard` copia com prazo e marca `CanIncludeInClipboardHistory`, `CanUploadToCloudClipboard` e `ExcludeClipboardContentFromMonitorProcessing`. A limpeza só dispara se o número de sequência ainda for o nosso — sem isso o timer apagaria o que o usuário copiou depois, que é perda de dado vestida de segurança. No Unix o segredo vai por **stdin**, nunca por argv, porque linha de comando é visível a qualquer usuário via `/proc`. O IPC expõe `vault.generate-copy` e o resultado não carrega a senha: um teste vai pelo socket real, lê o clipboard e procura esse texto nos bytes crus da resposta. 5 testes de módulo + 2 de IPC. **Mesma razão para 🧪**: o caminho X11/Wayland é compilado, não exercido. Entregue por `T1`. |
| VLT-08 | P1 | 🧪 | Aba Cofre na bandeja: lista ao abrir o painel (nunca no poll de status), filtra local, copia mandando a revisão da linha exibida e mostra o que o clipboard não protegeu. No telefone, toda operação que não seja `list` passa por uma folha que nomeia computador, operação, item, usuário e domínio antes do Keystore ser tocado; recusar ali significa que o store nunca é chamado. O nome do item vem do store do telefone, não do frame, e um id inexistente também recebe folha — responder mais rápido para item ausente é como se enumera um cofre. Serviço sem folha anexada recusa tudo além de `list`. 5 testes Dart + 5 na bandeja. Teto é 🧪: a folha nunca apareceu num aparelho. |
| VLT-09 | P1 | ⬜ | Criar extensão de autofill separada do relay de passkeys: correspondência exata de origem, seleção com gesto do usuário, bloqueio de iframe inesperado e nenhuma injeção automática. Documentar que o navegador recebe o plaintext. |
| VLT-10 | P1 | ⬜ | Integrar Android Autofill/Credential Manager para senhas; iOS Password AutoFill depende de `FND-09` e não bloqueia o primeiro corte Android. |
| VLT-11 | P1 | ⬜ | Importar Bitwarden JSON e CSV genérico com preview, relatório de rejeições e limpeza segura do arquivo temporário. Importadores de outros formatos entram só com fixtures reais. |
| VLT-12 | P1 | 🧪 | Gerador de **senha** em `phone-auth-agent::password`: alfabeto de 89 caracteres, amostragem uniforme por rejeição (nunca `%`), classes exigidas garantidas por redraw e não por posicionamento, saída em `Zeroizing` e nenhum histórico. Um teste de controle roda o amostrador enviesado pela mesma métrica para provar que o teste de viés não é vazio. O gerador de **passphrase** usa a wordlist da EFF (7776 palavras, CC-BY, SHA-256 conferido na integração), separador configurável e declara `log2(7776) × palavras` bits; `index_below` passou a amostrar 64 bits por rejeição para cobrir um alfabeto maior que 256. Entregue por `T2`. **Ressalva aberta**: `generate_passphrase` monta a saída num `String` que cresce, então cada realocação deixa um fragmento da passphrase no heap sem wipe — o `Zeroizing` só limpa o buffer final. `generate` já evita isso com `String::with_capacity`. Contabilizado em `VLT-14`. |
| VLT-13 | P1 | ⬜ | Resolver conflitos, migrações, corrupção parcial e operação concorrente entre mobile, desktop e browser. Toda escrita precisa de revisão e commit atômico. |
| VLT-14 | P1 | ⬜ | Testes de vazamento: logs, stack traces, notificações, screenshots, recents, audit log, IPC, crash dumps, clipboard, arquivos temporários e **fragmentos deixados no heap por realocação** — o caso concreto conhecido é `generate_passphrase` em `VLT-12`. |
| VLT-15 | P2 | ⬜ | TOTP local, favoritos e múltiplas URLs. Compartilhamento, organizações, anexos, cartões e identidades permanecem fora até nova threat model. |

### Gate de conclusão do cofre

- CRUD, busca, gerador, import, export e restore passam em aparelho físico;
- nenhum segredo aparece em storage claro, logs, Electron, histórico de
  clipboard, notificações ou crash reports controlados pelo projeto;
- autofill só ocorre após gesto e para origem compatível;
- migração de versão preserva todos os itens ou aborta sem modificar o cofre;
- perda/troca de telefone e chave invalidada têm fluxo de recuperação testado.

## Criptografia de disco (LUKS)

LUKS e File Locker compartilham ideias de envelope/recovery, mas não formato,
credencial ou chave. O scaffold atual sempre retorna código 3 e cai na senha;
isso é o comportamento seguro enquanto os itens abaixo não existem.

| ID | Pri. | Estado | Trabalho e critério de aceite |
|---|---:|---:|---|
| LUK-01 | P1 | ⛔ | Revisar a superfície de ataque do initrd e escolher o transporte. Ethernet é o primeiro candidato; Wi-Fi não pode exigir PSK em claro no `/boot`. |
| LUK-02 | P1 | ⬜ | Implementar transporte mínimo no initrd sem reutilizar `ble.rs`: ele depende de `bluetoothd`/D-Bus e não funciona antes do sistema subir. BLE exigiria caminho HCI próprio e revisão adicional. |
| LUK-03 | P1 | ⬜ | Criar credencial e esquema de wrapping dedicados a LUKS. ECDSA é assinatura, não chave determinística; nunca derivar chave de disco de uma assinatura. |
| LUK-04 | P1 | ⬜ | Criar keyslot PhoneAuth e unidade/configuração initrd no módulo NixOS. Hoje o módulo não instala nenhum serviço no initrd. |
| LUK-05 | P0 | ⬜ | Manter keyslot offline de recuperação obrigatório e executar drill antes de habilitar PhoneAuth no boot. Falha do telefone nunca pode tornar a máquina não inicializável. |
| LUK-06 | P1 | ⬜ | Testar boot real: sucesso, timeout, telefone ausente, resposta inválida, troca de keyslot e fallback. Chave somente no stdout do consumidor; diagnóstico somente no stderr sem material sensível. |

## Integrações do sistema e plataformas

| ID | Pri. | Estado | Trabalho e critério de aceite |
|---|---:|---:|---|
| SYS-01 | P2 | ⬜ | Windows Credential Provider para login/UAC somente após threat model e recovery em modo de segurança. Não guardar senha do Windows; avaliar certificado/smart card virtual. Uma DLL defeituosa no `LogonUI` não pode trancar o usuário para fora. |
| SYS-02 | P2 | ⬜ | SSH e agent forwarding com credencial própria, confirmação contextual e limites de destino/comando; nunca reutilizar `sudo` ou vault. |
| SYS-03 | P1 | ⬜ | Implementar a metade nativa iOS, incluindo Secure Enclave/Keychain, biometria e background; `ASCredentialProviderExtension` vem depois da base. Relacionado a `FND-09`. |
| SYS-04 | P2 | ⬜ | Validar PAM em `sudo`, login e display manager reais com recovery por senha antes de documentar suporte amplo. |

## Segurança, qualidade e distribuição

| ID | Pri. | Estado | Trabalho e critério de aceite |
|---|---:|---:|---|
| REL-01 | P0 | ✅ | Licença MIT completa adicionada em `LICENSE` e em `packages/phone_auth_native/LICENSE`; o `TODO` foi removido. |
| REL-02 | P0 | 🧪 | A publicação falha se qualquer um dos quatro secrets Android estiver ausente; APK debug-signed só pode sair de dispatch não publicável e tem nome explícito. Falta configurar a chave real e validar um release production-signed. |
| REL-03 | P0 | ✅ | `SECURITY.md` define disclosure privado, escopo, prazos e resposta a incidentes; `PRIVACY.md` documenta armazenamento local, tráfego LAN/BLE/asset links, logs, retenção e contato. Ambos estão ligados no README. |
| REL-04 | P0 | ⬜ | Revisão externa do protocolo novo de vault/locker, container, recovery e fronteiras de autofill antes de declarar produção. A revisão existente do código pelo próprio projeto não substitui isso. O container do locker (`docs/locker-format.md`) é o primeiro item da fila. |
| REL-05 | P0 | 🧪 | Três suítes de propriedade: `decoder_properties.rs` sobre todo `decode` do protocolo, `framing_properties.rs` sobre o enquadramento de socket e a remontagem BLE, e `container_properties.rs` sobre o container do locker. Provam que nenhum par pode causar pânico nem alocação escolhida por ele, e que nenhuma sequência de bytes decodifica para valor cuja forma canônica difira — sem isso uma assinatura cobre dois frames. O CI eleva `PROPTEST_CASES` a 4096 sob timeout que também é o limite de memória. 25 testes novos. Continua 🧪: faltam os importadores (`VLT-11`, ainda ⬜) e o handshake, que não tem decoder isolável hoje. |
| REL-06 | P1 | 🧪 | CI ganhou instrumentação Android em emulador Google APIs/API 35. Ainda falta CI Windows; job iOS entra apenas quando iOS voltar ao escopo. |
| REL-07 | P1 | ⬜ | Code signing do instalador Windows, assinatura/verificação de updates e checksums dos artefatos Linux. |
| REL-08 | P1 | ⬜ | SBOM, auditoria automática de dependências/licenças e processo de atualização de Flutter/Rust/Electron sem quebrar stores. |
| REL-09 | P1 | ⬜ | Testes de acessibilidade, leitor de tela, teclado, contraste e localização consistente. Operações críticas não podem depender só de cor/ícone. |
| REL-10 | P1 | ⬜ | Backups e restore drill em toda release que mude schema/crypto; fixtures antigas ficam versionadas no repositório. |
| REL-11 | P1 | ⬜ | Hardening de IPC e arquivos locais por plataforma, incluindo ACL no Windows, permissões Unix, múltiplas sessões de usuário e prevenção de symlink/race. |
| REL-12 | P2 | ⬜ | Auto-update seguro e rollback depois que assinatura e migrações estiverem resolvidos. |
| REL-13 | P0 | ⬜ | Criar integração física PC ↔ celular com injeção de queda em cada fronteira de `pairing-reliability-plan.md`; os testes atuais usam duplos. |
| REL-14 | P0 | ⬜ | Smoke test do release: instalar APK + desktop a partir dos artefatos, iniciar agent, parear, autorizar e desinstalar. Apenas construir o pacote não prova que ele funciona. |
| REL-15 | P1 | ⬜ | Registrar uma matriz versionada para BLE real; `desktop/crates/phone-auth-agent/src/ble.rs` compila no CI Linux, mas não possui teste que exerça BlueZ/hardware. |

## Ordem de entrega recomendada

1. **Hotfix de release:** `HOT-01..03`, começando pela 0.1.5 para não deixar a
   versão pública atrás das correções WebAuthn já presentes na `main`.
2. **Release 0 — estabilizar a base:** `FND-11..14`, decisões `DEC-*`, matriz
   física, background, permissões separadas, frames e recovery design.
3. **Release 1 — passkeys instaláveis:** `WEB-01..14`, gestão de credenciais e
   instaladores reais. Isso transforma o recurso mais avançado atual em produto.
4. **Release 2 — File Locker mínimo:** formato, CLI, recovery, testes de falha,
   comportamento de links e o round-trip de 4 GiB estão feitos; o que resta é
   `FLK-02` em aparelho físico, `FLK-09` em lote, o disco cheio e o kill do
   `FLK-10`, a contagem de hardlink no Windows do `FLK-08` e a revisão externa
   de `REL-04`.
5. **Release 3 — cofre pessoal:** schema e formato de fio (`VLT-01`, `VLT-04`)
   estão fixados nos dois lados; o que resta é storage/CRUD/recovery no telefone
   e cópia segura via agent.
6. **Release 4 — autofill/import:** extensão de senhas, Android Autofill,
   importadores e TOTP opcional.
7. **Release 5 — integrações extras:** LUKS, Windows Credential Provider, SSH,
   iOS/macOS/Safari, ARM64 e APIs nativas conforme demanda e recovery testado.

File Locker e vault podem compartilhar transporte, autorização, versionamento
e recovery, mas **não** a mesma chave. WebAuthn também permanece com aliases
próprios.

### Execução em paralelo

`docs/parallel-work-plan.md` fatia o trabalho desbloqueado em tracks que rodam
em worktrees separados sem colidir, e define o que o agente integrador faz no
fim. Regra que vale aqui: **nenhum track edita este arquivo**. Cada um deixa
`docs/handoff/<TRACK-ID>.md` e o integrador dobra tudo aqui num commit só.

**Onda 1, integrada em 2026-08-28.** `T3` (`VLT-02`), `T1` (`VLT-06`, `VLT-07`)
e `T2` (`VLT-12`) foram mergeados nesta ordem, sem conflito textual nem
semântico, e os três toolchains passaram depois do merge. `T4` (`WEB-02`) entrou
logo em seguida, também sem conflito. Com isso a **onda 1 está fechada**. Os
handoffs foram dobrados neste arquivo e em `docs/dependencies.md`, e
`docs/handoff/` foi removido; a onda 2 recria o diretório. Os quatro worktrees e
suas branches foram apagados depois de `git branch --no-merged main` voltar
vazio — a onda 2 começa de worktrees novos, a partir da `main` já integrada.

`T4` não é coberto por nenhum dos três toolchains — são scripts de shell, com
suíte própria em `install.test.ps1` e `install.test.sh`, que precisam ser
rodadas à mão. Se a instalação do native host regredir, nada no gate atual
avisa.

**Onda 2, integrada em 2026-08-28.** `T5` (`VLT-03`) e `T6` (`VLT-04`) foram
mergeados; `T6b` deu chamador ao caminho de leitura do cofre no CLI. `T7`
(`REL-05`) foi feito em sequência, na mesma branch, junto com `VLT-08` e
`VLT-05` — a partir daqui o trabalho deixou de ser paralelizável em worktrees,
porque `VLT-08` toca telefone, bandeja e docs ao mesmo tempo. Os handoffs foram
dobrados aqui e `docs/handoff/` foi removido de novo.

Três coisas que a onda 1 deixou para quem pegar a onda 2:

- **`T1` desviou do contrato do plano.** `vault.copy` com `item_id`/`revision`
  **não existe**: não há store do cofre deste lado, então o comando só saberia
  responder "não implementado". Entrou `vault.generate-copy`, documentado em
  `docs/desktop.md`. `T6`/`VLT-04` deve acrescentar `vault.copy` chamando
  `clipboard::copy_secret(&SecretBuffer, Duration) -> Result<CopyOutcome, ClipboardError>`
  com o segredo vindo do telefone.
- **`T3` fixou o canal `bioauth/vault_store`** com `list`/`fetch`/`create`/
  `update`/`delete`; revisão começa em 1 e revisão 0 é sempre recusada. `T5`
  (`VLT-03`) consome esse contrato do lado Dart.
- **`T2` deixou um vazamento pequeno em aberto**: `generate_passphrase` monta a
  saída num `String` que cresce, e cada realocação abandona um fragmento da
  passphrase no heap sem wipe. `generate` ao lado já evita isso com
  `String::with_capacity`. É inconsistência dentro do mesmo arquivo, não
  limitação inerente, e contradiz a `VLT-06` que entrou no mesmo merge.
  Contabilizado em `VLT-14`.

A suíte Rust ficou ~11s mais lenta: `MIN_TTL` do clipboard é 5s e dois testes
esperam a expiração real, em série. Encurtar `MIN_TTL` só para o teste deixaria
o teste rápido e o produto pior. Rodar a suíte **apaga o clipboard do
desenvolvedor** — não há como testar a coisa que importa sem tocar no recurso
real, e ele é um só por sessão.

## Evidência desta auditoria

<!-- Contagens atualizadas pelos gates após o merge. -->
- `cargo test --workspace`: **362 testes aprovados** no Windows; um teste
  multi-GB permanece ignorado por padrão. `cargo fmt --all -- --check` e
  `cargo clippy --workspace --all-targets -- -D warnings`: limpos.
- O teste multi-GB de `FLK-10` rodou no Windows antes do merge: round-trip de
  4 GiB + 3 bytes com SHA-256 idêntico. Ele permanece `#[ignore]` porque move
  aproximadamente 28 GiB; é evidência datada, não cobertura contínua.
- Os quatro testes de link do `FLK-08` são `cfg(unix)` e ficam a cargo do CI
  Ubuntu; a verificação Windows apenas prova compilação cruzada.
- `desktop/ui/npm test`: **11 testes aprovados**.
- `flutter analyze`: limpo. A suíte mobile soma **183 testes Flutter**, o
  package nativo soma **10**, e `:phone_auth_native:testDebugUnitTest` soma
  **36 testes Kotlin**.
- `:phone_auth_native:lintDebug` e `assembleDebugAndroidTest`: limpos; os
  **7 testes instrumentados** são executados pelo job API 35, não contados como
  aprovados localmente sem emulador.
- O drill de recuperação (`FLK-06`) roda pelo binário, sem agent e sem telefone.
- O vetor compartilhado do cofre está fixado em
  `phone-auth-protocol::vault::tests::a_fetch_response_pins_its_bytes` e em
  `mobile/test/vault_payloads_test.dart`. Os dois encoders foram escritos
  separadamente contra o mesmo hex, então um bug comum ao writer e ao reader de
  um dos lados não faz o par passar sozinho.
- Limitações confirmadas em código: plugin iOS é scaffold, native host depende
  de instalação por script sem smoke test de navegador, conditional mediation
  usa o autenticador nativo,
  passkeys são device-bound sem backup/sync e o locker não trava páginas.
- Pendências preservadas: LUKS/initrd, Windows Credential
  Provider, SSH, smoke test dos artefatos, testes destrutivos do locker e
  matrizes com hardware físico.

## Como manter este tracking

- Um item só vira ✅ quando código, teste automatizado e documentação estão no
  mesmo PR.
- Teste exclusivamente manual permanece 🧪 e deve apontar para uma matriz de
  resultados versionada.
- Toda mudança de crypto/schema adiciona fixture antiga e teste de migração.
- Nenhum release é chamado de "completo" enquanto existir P0 ⛔ ou ⬜ na área
  correspondente.

## Regras invariantes do projeto

- O fluxo definido pelo projeto usa commits diretos na `main`, sem PR e sem
  trailer `Co-Authored-By`; mudar essa regra exige decisão explícita do dono.
- Nunca reutilizar `bioauth_authorization_v1` ou
  `bioauth_session_identity_v1`; WebAuthn, vault, locker, LUKS e SSH usam
  credenciais separadas.
- Sem `BIOMETRIC_WEAK`, fallback para credencial do sistema ou período de
  graça. Cada operação sensível exige biometria forte por uso.
- Nunca registrar chave, challenge, assinatura, senha, TOTP seed, plaintext de
  arquivo ou material LUKS.
- A versão do produto permanece sincronizada nos quatro manifests e o release
  falha se divergirem.
- Marcar ✅ somente depois de código, teste executável e documentação. Sem
  evidência em hardware, o máximo é 🧪.
