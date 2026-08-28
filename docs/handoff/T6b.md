## Status

| VLT-04 | P0 | 🧪 | Os handlers do T6 agora têm chamador. `phone-auth vault list`, `vault copy <ITEM>` e `vault generate` entraram no CLI, cobrindo `vault.list`, `vault.copy` e `vault.generate-copy` — os três métodos IPC que existiam sem nada que os invocasse. `copy` aceita id, nome ou fragmento único de nome/URI, e a resolução é também de onde sai o `expectedRevision`: o agent recusa uma cópia que não nomeie revisão, e quem digita um comando não tem como saber uma, então o CLI lista e depois copia, os mesmos dois passos da bandeja. Fragmento ambíguo é recusado com os candidatos e seus ids. Os três comandos partilham um mapa de saída (`vault_exit`), documentado em `docs/desktop.md`. Continua 🧪: nada disto tocou num telefone real. |

## Dependências

Nenhuma. Só `serde_json` e o `AgentClient`, ambos já usados pelo CLI.

## O que isto muda no T6

A ressalva **"o desktop só lê"** continua verdadeira e continua deliberada — não
há `vault create`, `vault edit` nem `vault delete`, porque escrever do
computador precisa de uma tela no telefone que nomeie o que está a ser mudado.
O que deixa de ser verdade é a parte tácita dela: o caminho de leitura já não é
código sem chamador. `vault.list` e `vault.copy` podem ser exercidos por uma
pessoa, de um terminal, contra um telefone.

A ressalva **"o prompt que o usuário vê ainda é o do Keystore"** não mudou nada.
`vault copy` dispara a biometria genérica exigida por uso pela chave; o telefone
continua sem mostrar qual computador pediu, qual item ou qual domínio. `VLT-08`
segue ⬜ e segue sendo a lacuna mais importante do cofre.

## Ressalvas

**Um empate que estava escondido.** `vault list` saía 3 e `vault copy` saía 1
para exatamente o mesmo erro — `policy-denied`, "nenhuma credencial de cofre
enrolada" — porque `list` passava pelo `simple()`, que reporta qualquer falha
como indisponibilidade. Só apareceu no smoke test contra o agent, não nos
testes. Agora os três comandos passam por `vault_call`, e é por isso que ele
existe em vez de reusar `simple()`.

**`bad-params` sai 2, não 3.** Todo parâmetro que estes comandos enviam vem da
linha de comando, então o agent recusar um é erro de digitação — `--clear-after
1` — e não um cofre que não respondeu.

**A checagem de revisão é mais fraca sem `--revision`.** Quando o CLI lista e
copia em seguida, a janela que a checagem fecha é só a que existe entre essa
listagem e o fetch. `--revision N` fixa uma revisão lida antes, que é o uso
forte, e é o que um script deve passar.

**Ambiguidade é recusada, nunca adivinhada.** Copiar o segredo errado é
silencioso: nada a jusante mostra o que foi copiado, então o erro só aparece
quando é colado em algum lugar.

**O que foi exercido de verdade.** Contra o `--dev-simulator`: `vault list` e
`vault copy` recusam com mensagem limpa e saída 1 (o simulador só enrola
credencial de Authorization), `vault generate` copiou 24 caracteres para a área
de transferência com `memoryLocked`, `historyExcluded` e `cloudExcluded` todos
verdadeiros nesta máquina Windows, e `--clear-after 1` saiu 2. O par
`vault.list`/`vault.copy` contra um cofre povoado continua sem execução real —
depende de aparelho.

## Testes

Seis testes novos em `phone-auth-cli` (workspace: 331 → 337). Cobrem a
resolução de item — id vence item *chamado* como um id, nome exato vence nome
mais longo que o contém, fragmento de URI resolve, ambíguo lista candidatos,
nada não resolve — e o mapa de saída.
