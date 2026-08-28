# Plano de trabalho paralelo em worktrees

Este documento fatia o trabalho aprovado em **tracks independentes**, cada um
executável por um agente próprio, em um worktree próprio, sem coordenação com os
outros durante a execução. Um agente integrador faz o merge no fim.

O objetivo não é só dividir tarefas: é dividi-las de forma que os diffs **não se
sobreponham**. Duas tarefas boas que editam a mesma linha custam mais na
integração do que teriam custado em série.

Referência de estado: `docs/implementation-tracker.md`. Este arquivo é o plano
de execução; o tracker continua sendo a fonte de verdade sobre o que existe.

---

## 1. Regras que todo track obedece

Sem exceção, e antes de qualquer código.

### Propriedade de arquivo

Cada track tem uma lista de arquivos que **possui** e pode editar livremente.
Arquivos fora dela são proibidos, mesmo que a mudança pareça óbvia e pequena.

Três arquivos são compartilhados por quase todos e por isso têm regra especial:

| Arquivo | Regra |
|---|---|
| `docs/implementation-tracker.md` | **Nenhum track edita.** Só o integrador. |
| `docs/dependencies.md` | **Nenhum track edita.** Só o integrador. |
| `Cargo.lock` / `pubspec.lock` | Commite o que o build gerar; o integrador regenera. Conflito aqui não se resolve à mão. |

Em vez de editar o tracker, cada track cria **um arquivo só seu**:

```
docs/handoff/<TRACK-ID>.md
```

com exatamente três seções: `## Status` (a linha de tracker que o track acha que
merece, com o ícone justificado), `## Dependências` (qualquer crate/pacote novo,
com licença e justificativa, no formato de `docs/dependencies.md`) e
`## Ressalvas` (o que ficou de fora e por quê). O integrador dobra esses
arquivos no tracker e em `dependencies.md`, e depois apaga o diretório.

Isso troca um conflito garantido em arquivo grande por zero conflito.

### Contratos entre tracks

Onde dois tracks se encontram, a interface está **fixada neste documento**. O
track codifica contra a assinatura escrita aqui, mesmo que o outro lado ainda
não exista.

Se um track concluir que o contrato está errado, ele **para e reporta** em
`## Ressalvas` em vez de mudar a assinatura sozinho. Um contrato alterado de um
lado só é descoberto na integração, que é o pior momento possível.

### Portão verde

Nenhum track entrega sem, no seu próprio worktree:

```bash
# Rust — de desktop/
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings

# Dart — de mobile/  (Flutter NÃO está no PATH)
#   G:\.codex-tools\flutter-3.47.1\flutter\bin
flutter analyze
flutter test

# Kotlin — de packages/phone_auth_native/example/android  (NÃO mobile/android)
#   ANDROID_HOME e ANDROID_SDK_ROOT = C:\Users\gaok1\.codex\cache\android-sdk
.\gradlew.bat :phone_auth_native:testDebugUnitTest
```

Rodar só o gate da linguagem que o track tocou é suficiente. Entregar vermelho,
ou entregar helper `#[cfg(test)]` sem chamador (que quebra `-D warnings`), é
retrabalho garantido para o integrador.

### Invariantes do projeto

Valem em todo track, e estão em `docs/implementation-tracker.md` § *Regras
invariantes*. As que mais aparecem neste lote:

- Commits vão **direto na branch do track, sem `Co-Authored-By` e sem PR**.
- Nunca logar chave, challenge, assinatura, senha, seed TOTP ou plaintext.
- Nunca reutilizar credencial entre propósitos: vault, locker, WebAuthn, LUKS e
  SSH têm aliases próprios.
- Sem `BIOMETRIC_WEAK`, sem fallback para credencial do sistema, sem período de
  carência.
- `✅` só com código + teste automatizado + documentação. Sem evidência de
  hardware, o teto é `🧪`.
- Dado de terceiro que entra no repositório entra **verbatim da fonte
  canônica**, com licença registrada — convenção já usada por
  `public_suffix_list.dat` e `privileged_browsers.json`.

### Mecânica do worktree

```bash
git worktree add ../BioAuth-<TRACK-ID> -b <branch-do-track>
```

O track trabalha só ali, commita quantas vezes quiser, e não faz merge de nada.

---

## 2. Os tracks

### Onda 1 — sem dependência entre si, podem rodar todos ao mesmo tempo

#### T1 — Memória travada e clipboard seguro  (`VLT-06`, `VLT-07`)

Branch `feat/vault-clipboard`. **O item de maior valor do lote.**

Dois itens no mesmo track de propósito: compartilham a dependência
`windows-sys`, e o clipboard consome o buffer travado. Separá-los criaria um
contrato onde não precisa haver um.

**Escopo:**

1. `secret_memory.rs` — um buffer que não sai do processo:

   | Sistema | Medida |
   |---|---|
   | Windows | `VirtualLock` + `WerRegisterExcludedMemoryBlock` |
   | Linux | `mlock` + `madvise(MADV_DONTDUMP)` |
   | Ambos | wipe volátil no drop, tempo de vida mínimo |

   API pública, fixada:

   ```rust
   pub struct SecretBuffer { /* … */ }
   impl SecretBuffer {
       pub fn new(len: usize) -> Self;
       pub fn from_slice(bytes: &[u8]) -> Self;
       pub fn expose(&self) -> &[u8];
       pub fn expose_mut(&mut self) -> &mut [u8];
       /// Falso quando o SO recusou o lock (cota de working set, por exemplo).
       pub fn is_locked(&self) -> bool;
   }
   ```

   `is_locked()` não é enfeite: `VirtualLock` **falha** sob cota, e o desenho
   honesto reporta isso em vez de fingir que travou. Sem `Debug`, sem `Display`,
   sem `Serialize`.

2. `clipboard.rs` — copiar com prazo de validade. Limpar por timer, e no Windows
   marcar o item com `CanIncludeInClipboardHistory`,
   `CanUploadToCloudClipboard` e `ExcludeClipboardContentFromMonitorProcessing`
   para não entrar no Win+V nem subir para a conta Microsoft.

   No X11/Wayland as garantias **são outras**. Reportar o que de fato foi
   conseguido; não prometer exclusão que o sistema não oferece.

3. Comando IPC novo, no padrão de `LockerLockParams`/`LockerLockResult` em
   `api.rs`:

   ```
   vault.copy
     params: { item_id, revision, clear_after_ms }
     result: { clears_at_ms, history_excluded: bool, cloud_excluded: bool }
   ```

   Os dois booleanos são o mecanismo de honestidade: é assim que a UI descobre
   que no Wayland não deu para excluir do histórico, em vez de exibir um cadeado
   que mente.

**Regra dura:** plaintext **nunca** entra no processo Electron. O agent copia; a
UI pede e recebe só o resultado acima.

**Possui:** `desktop/crates/phone-auth-agent/src/secret_memory.rs`,
`clipboard.rs`, `api.rs`, `ipc.rs`, `Cargo.toml` do crate;
`docs/handoff/T1.md`.

**Testes:** o buffer zera no drop; `is_locked()` reflete a falha real (injete-a);
limpeza no prazo; limpeza acontece mesmo se o cliente cair antes do timer; nada
sensível em `Debug`.

---

#### T2 — Gerador de passphrase  (`VLT-12`, metade restante)

Branch `feat/passphrase`.

O gerador de **senha** já existe em `phone-auth-agent::password` e está fechado.
Falta o de **frase**.

**Escopo:** baixar a wordlist grande da EFF de
`https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt`, conferir que tem
**7776 linhas**, registrar o SHA-256, e embutir como recurso seguindo a
convenção de dados empacotados de `docs/dependencies.md`. Licença **CC-BY**,
atribuição registrada — aprovada pelo dono.

Reusar `index_below()` de `password.rs`: a amostragem por rejeição já está
correta e testada, e uma segunda implementação é uma segunda chance de errar.

**Se o download não for possível no ambiente, pare e reporte.** Não invente
palavras, não gere uma lista "equivalente", não reduza para 2048. A entropia por
palavra depende do tamanho exato da lista, e uma lista inventada quebra a conta
sem quebrar nenhum teste.

**Possui:** `desktop/crates/phone-auth-agent/src/password.rs`, o recurso da
wordlist, `docs/handoff/T2.md`.

**Testes:** a lista tem 7776 entradas únicas e ordenadas; nenhuma palavra
repetida (repetição enviesa); entropia declarada bate com
`log2(7776) × palavras`; separador configurável não altera a contagem.

---

#### T3 — Store do cofre no Android Keystore  (`VLT-02`)

Branch `feat/vault-store-android`. **Kotlin puro — o track mais isolado do lote.**

**Escopo:** chave AES-256-GCM no Keystore com `setUserAuthenticationRequired(true)`,
`setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG)` (por uso, sem
carência), `setInvalidatedByBiometricEnrollment(true)`, StrongBox primeiro com
fallback para outra implementação do Keystore — **nunca** fallback de força
biométrica. Blobs cifrados em storage privado do app, jamais em
`shared_preferences`.

**Contrato com T5, fixado aqui.** MethodChannel `bioauth/vault_store`:

| Método | Argumentos | Retorno |
|---|---|---|
| `list` | `cursor: String?` | `{ items: List<Map>, nextCursor: String? }` |
| `fetch` | `id: String` | `{ id, revision, secret }` |
| `create` | `item: Map` | `{ id, revision }` |
| `update` | `item: Map, expectedRevision: Int` | `{ id, revision }` |
| `delete` | `id: String, expectedRevision: Int` | `{ id }` |

Revisão começa em **1**; revisão 0 é sempre recusada. Conflito de revisão volta
como erro tipado, não como sucesso silencioso.

**Limite honesto:** os testes JVM locais só cobrem função pura. Tudo que toca
Keystore precisa da suíte instrumentada e de um emulador, que **não existe
localmente** — o job de CI em API 35 é quem roda. Portanto este track entrega no
máximo `🧪`, e deve dizer isso em `## Ressalvas`. Cubra por teste JVM o que for
device-independent (AAD, serialização, validação de revisão) e não escreva
helper sem chamador só para ter o que testar.

**Possui:** `packages/phone_auth_native/android/**`, `docs/handoff/T3.md`.

---

#### T4 — Instalador do native host  (`WEB-02`)

Branch `feat/native-host-installer`. Isolado dos outros quatro.

**Escopo:** instalar e **desinstalar** o native host. No Windows, registrar e
remover as chaves em HKCU. No Linux, instalar manifests nos caminhos suportados
com o caminho absoluto correto. Desinstalar tem que limpar de verdade — meio
registro órfão apontando para binário que sumiu é pior que nenhum.

**Possui:** scripts de instalação, `docs/handoff/T4.md`.

---

### Onda 2 — começa depois que a onda 1 integrou

#### T5 — CRUD e telas do cofre no mobile  (`VLT-03`)

Branch `feat/vault-ui`. Dart puro.

Busca, confirmação biométrica para revelar ou copiar, auto-lock ao ir para
background, e proteção de screenshot/recents nas telas sensíveis. Consome o
contrato `bioauth/vault_store` de **T3**, que precisa existir primeiro.

**Possui:** `mobile/lib/features/vault/**`, `mobile/test/**` do cofre.

#### T6 — Handler e taxonomia de erro do cofre  (`VLT-04`, metade restante)

Branch `feat/vault-handler`.

O formato de fio já existe e os encoders Rust e Dart batem byte a byte. Falta o
handler dos dois lados e a taxonomia de erro genérica — erro que não vaze se o
item existe, para quem não devia saber.

Fica na onda 2 porque edita `api.rs` e `ipc.rs`, os mesmos arquivos de **T1**.

#### T7 — Fuzz e property tests  (`REL-05`)

Branch `feat/protocol-fuzz`.

CBOR, handshake, native messaging, frames de vault/locker e container de
arquivos, com limite de CPU e memória. Precisa de um dev-dependency
(`proptest` ou `arbitrary`) — registre em `## Dependências`.

Fica na onda 2 porque só faz sentido depois que o handler de T6 existe.

---

## 3. Mapa de colisão

O que os tracks da onda 1 disputam, e como já está resolvido:

| Arquivo | Quem toca | Resolução |
|---|---|---|
| `docs/implementation-tracker.md` | ninguém | handoff |
| `docs/dependencies.md` | ninguém | handoff |
| `desktop/Cargo.toml` | só T1 | T2 não adiciona crate nenhum |
| `phone-auth-agent/src/lib.rs` | T1, T2 | uma linha `pub mod` cada, **em ordem alfabética** |
| `phone-auth-agent/Cargo.toml` | só T1 | T2 reusa `getrandom`, já declarado |
| `Cargo.lock` | T1, T2 | integrador regenera |

T3 e T4 não colidem com ninguém: um é Kotlin, o outro é script.

Sobra um único ponto de atrito real — duas linhas `pub mod` adjacentes em
`lib.rs`. Mantidas em ordem alfabética, o git resolve sozinho na maioria dos
casos e à mão em segundos no resto.

---

## 4. Antes de abrir os worktrees

Um commit de preparação na `main`, feito **uma vez**, que remove a maior fonte
de conflito:

1. Registrar em `docs/dependencies.md` que a decisão de `VLT-06`/`VLT-07` foi
   **resolvida e aprovada** — hoje aquela seção diz o contrário, e um agente
   que a leia em worktree vai achar que está proibido de continuar.
2. Criar `docs/handoff/.gitkeep`.

O item 1 não é burocracia: é a única coisa que impede T1 de parar no primeiro
parágrafo que ler.

Nenhuma dependência é pré-declarada. Só T1 adiciona crate, então ele mesmo
declara as suas (`windows-sys = "0.61"` sob `cfg(windows)`, `libc = "0.2"` sob
`cfg(unix)` — a linha 1.0 do `libc` ainda é pré-release e não entra).

---

## 5. O integrador

Um agente, depois que os tracks da onda terminarem.

**Ordem de merge:** T3 e T4 primeiro (isolados, merge trivial), depois T1,
depois T2. T1 antes de T2 porque T1 é maior e vale resolver conflito contra a
árvore mais limpa.

**Trabalho:**

1. Merge na ordem acima, resolvendo `lib.rs` mantendo as duas linhas.
2. `cargo check --workspace` para regenerar `Cargo.lock`; commitar o resultado
   em vez de resolver conflito de lock à mão.
3. Dobrar cada `docs/handoff/*.md` em `docs/implementation-tracker.md` e
   `docs/dependencies.md`. Rebaixar status quando a `## Ressalvas` do track
   contradisser o `## Status` que ele pediu — o track é parte interessada na
   própria nota.
4. Apagar `docs/handoff/`.
5. Rodar o portão verde **completo**, nos três toolchains, na árvore integrada.
   Cada track passou no seu; a combinação dos três nunca foi executada por
   ninguém, e é exatamente aí que mora o que escapou.
6. Atualizar o carimbo de data/commit no topo do tracker e as contagens de
   teste, num commit único de integração.

**O integrador não implementa feature.** Se um track chegou incompleto, isso
vira uma linha no tracker e um track novo — não um remendo no merge, onde não
tem teste nem revisão.
