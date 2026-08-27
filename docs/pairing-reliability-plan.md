# Plano de correção: pareamento, revogação e reconexão

## Objetivo

Fazer o pareamento ser **recuperável** em vez de depender de uma execução
perfeita. Queda de rede, fechamento de uma tela, recusa, revogação unilateral,
reinício de um processo ou perda de uma resposta IPC não podem deixar celular
e PC presos em estados incompatíveis.

Este documento é um diagnóstico do código atual e um roteiro de implementação.
Ele não afirma que os cenários abaixo foram reproduzidos em dispositivos reais.

## Sintomas relatados

1. O pareamento passa por QR e código de verificação, mas o celular continua
   mostrando **Conectando**.
2. Depois de revogar o PC no celular e tentar parear novamente, o código aparece
   no celular, enquanto o PC permanece no QR.
3. Recusa, queda ou nova tentativa podem deixar uma tentativa antiga interferir
   na seguinte.

## Causas encontradas

### P0. O estado `connected` do celular não chega corretamente à interface

- `mobile/lib/app/providers.dart` cria `PairedSessionRunner` sem fornecer
  `onStatus`.
- `mobile/lib/app/app_controller.dart::syncPairedDevices` cria todo dispositivo
  novo em `ConnectionPhase.connecting`.
- Mesmo depois de ligar o callback, `mobile/lib/core/session/paired_session_runner.dart`
  publica `connected` somente **depois** de `serveOne` terminar.
- `serveOne` pode ficar quatro minutos esperando uma solicitação. Uma conexão
  autenticada e ociosa, portanto, continua parecendo `connecting`.

Isso explica diretamente o primeiro sintoma.

**Correção:** publicar `connected` imediatamente depois que o handshake
autenticado terminar e antes de esperar uma solicitação. Ligar `onStatus` ao
`AppController.setDevicePhase`, com o mapeamento:

| Sessão | Interface |
| --- | --- |
| tentativa iniciada | `connecting` |
| handshake autenticado | `connected` |
| socket/handshake falhou | `disconnected` ou `unreachable` |
| registro revogado | remover o dispositivo |

`connected` deve descrever a conexão atual, não a conclusão de uma futura
autorização.

### P0. A revogação no celular remove apenas a linha da tela

`mobile/lib/app/app_controller.dart::revokeDevice` altera apenas `AppState`.
Ele não chama `PairingStore.remove`, não invalida
`pairedVerifiersProvider` e não encerra imediatamente a sessão daquele
verificador.

Consequências:

- o registro continua persistido;
- o loop de reconexão continua ativo;
- uma sincronização posterior pode recolocar o PC na tela;
- a nova tentativa parte de um estado diferente daquele que a interface
  prometeu ao usuário.

**Correção:** a operação de revogação deve ter um único caminho assíncrono:

1. marcar o dispositivo como `revoking` e desabilitar o botão;
2. remover o registro do `PairingStore`;
3. invalidar/recarregar `pairedVerifiersProvider`;
4. parar o loop e fechar a sessão ativa apenas daquele `verifierId`;
5. retirar solicitações pendentes dele;
6. somente então confirmar a remoção na interface.

Falha de persistência deve ser exibida e não pode fingir que a revogação
funcionou.

### P0. Um telefone conhecido impede o novo pareamento armado

Em `desktop/crates/phone-auth-agent/src/qr_network.rs::serve_connection`, a
decisão atual prioriza um `device_id` presente em `known_peers`, mesmo quando
existe um QR de pareamento armado:

```text
(telefone conhecido, qualquer estado) -> sessão já pareada
(telefone desconhecido, QR armado)     -> pareamento
```

Depois de uma revogação somente no celular, o PC ainda conhece o `device_id`.
O celular, que escaneou o QR, entra no caminho de primeiro pareamento, deriva e
mostra o código e envia o enrolment. O PC pode classificar a mesma conexão como
já pareada, não produzir `PairingProposal` e continuar mostrando o QR. Isso
explica o segundo sintoma.

**Correção imediata, compatível com o wire atual:** quando houver um QR
explicitamente armado, aceitar re-enrolment do mesmo `device_id` e substituir o
registro somente depois da confirmação do novo código. Sem QR armado, continuar
exigindo exatamente a identidade já armazenada.

**Correção definitiva:** incluir no ClientHello uma intenção autenticada
`pair`/`resume`. Assim, um loop normal de reconexão não pode ser confundido com
um re-pareamento enquanto outro QR estiver aberto. Isso exige nova versão do
handshake e compatibilidade explícita; não deve ser inserido silenciosamente no
protocolo v1.

### P0. O estado pendente no PC não é idempotente

`Service::pending_pairing` retira a proposta do transporte e a guarda em
`held_proposal`. A segunda consulta retorna `None`, em vez de retornar a mesma
proposta. Se o agente processar `pair.pending`, mas a resposta se perder antes
de chegar ao renderer, o código deixa de ser recuperável pela interface.

Além disso:

- `Service::cancel_pairing` limpa o transporte, mas não `held_proposal`;
- `Service::begin_pairing` não limpa uma proposta antiga antes de armar a nova;
- a confirmação usa apenas seis dígitos, sem identificar inequivocamente a
  tentativa.

**Correção:** tratar a proposta como estado consultável, não como fila:

- chamadas repetidas a `pair.pending` retornam a mesma proposta;
- `pair.begin` cancela e limpa atomicamente qualquer tentativa anterior;
- `pair.cancel` limpa QR, proposta no transporte e proposta retida;
- `pair.confirm` recebe `pairingAttemptId` mais o código e rejeita tentativa
  antiga;
- a chegada de uma proposta gera um evento `pairing-ready`; polling permanece
  apenas como recuperação caso o evento se perca.

### P0. Esquecer no PC não atualiza os peers do listener

`Service::forget` remove o registro do `PairingStore`, mas não chama
`publish_known_peers`. O listener pode continuar autenticando o peer removido
até outra publicação ou reinício.

**Correção:** depois de uma remoção persistida, publicar imediatamente o novo
mapa de peers e descartar sessões estacionadas daquele dispositivo antes de
emitir `DevicesChanged`.

### P1. Cancelamento e falhas deixam recursos ou estado antigo vivos

- `PairingService.begin` fecha a sessão se `send` falhar, mas não cobre todas
  as falhas posteriores ao `connect`, como falha ao preparar a credencial.
- `PairingController.reject` pode permanecer na tela de código se `close`
  falhar.
- `PairingController.reset` descarta `_pending` sem fechar a sessão.
- remover um registro de `_Loop` marca apenas `_stopped`; uma chamada
  `serveOne` já bloqueada pode continuar viva até o timeout.
- uma operação assíncrona antiga pode atualizar a UI depois que uma tentativa
  mais nova começar.

**Correção:** todo intento deve ter `attemptId` e cancelamento. Todo recurso
aberto deve ser fechado em `finally`. Resultado cujo `attemptId` não seja mais
o atual deve ser ignorado. Rejeitar/cancelar deve voltar a um estado utilizável
mesmo se o fechamento best-effort do socket falhar.

### P1. As confirmações atuais permitem pareamento unilateral

Depois do enrolment, celular e PC confirmam e persistem independentemente. Não
existe confirmação autenticada de commit entre os lados. Uma queda na hora
errada pode produzir:

- celular pareado e PC não pareado; ou
- PC pareado e celular não pareado.

Nenhum protocolo distribuído consegue prometer commit simultâneo sob uma
partição de rede. A garantia correta é: **commit idempotente, estado detectável
e re-pareamento sempre recuperável**.

Para uma versão futura do wire:

1. manter a sessão cifrada viva durante as confirmações;
2. associar tudo a um `pairingAttemptId` aleatório;
3. trocar mensagens autenticadas `prepare`, `reject`, `commit` e `commit-ack`;
4. persistir preparações/commits de forma idempotente;
5. ao reconectar, consultar o resultado pelo `pairingAttemptId`;
6. expirar e limpar preparações incompletas;
7. ainda permitir que um novo QR substitua um estado unilateral antigo.

## Ordem recomendada de implementação

1. **Persistência e limpeza:** corrigir revogação no celular,
   `Service::forget`, cancelamento e fechamento por dispositivo.
2. **Estado visual correto:** emitir `connected` ao fim do handshake e ligar
   `onStatus` ao controller.
3. **Estado de pareamento idempotente no PC:** tornar `pending` repetível e
   limpar corretamente em `begin`/`cancel`/`confirm`.
4. **Recuperação de assimetria:** permitir re-pareamento explicitamente
   armado de um `device_id` conhecido.
5. **Identidade da tentativa:** propagar `pairingAttemptId` por IPC e UI.
6. **Wire v2, se necessário:** intenção `pair`/`resume` e commit retomável.

Os itens 1 a 4 corrigem os sintomas relatados sem esperar uma reformulação
completa do protocolo.

## Invariantes que o código deve impor

1. No máximo uma tentativa de pareamento ativa por verifier.
2. Toda tentativa tem identidade própria; resposta antiga não altera tentativa
   nova.
3. `cancel` e `reject` são idempotentes.
4. Consultar estado pendente não consome esse estado.
5. Revogação só aparece concluída depois de persistir.
6. Registro removido não continua em `known_peers` nem com sessão estacionada.
7. `connected` significa handshake autenticado concluído.
8. Falha ou timeout sempre termina em um estado com ação clara de tentar de
   novo.
9. Um novo QR pode reparar qualquer pareamento unilateral anterior.
10. Confirmação de tentativa antiga nunca confirma tentativa nova, mesmo que o
    código de seis dígitos coincida.

## Testes de regressão obrigatórios

### Mobile (Dart/Flutter)

- handshake concluído muda `connecting -> connected` antes de chegar request;
- falha ao conectar muda para `unreachable`, tenta novamente e chega a
  `connected`;
- revogar remove do store, atualiza provider, para o loop e não reaparece;
- revogar com sessão ociosa fecha aquela sessão sem esperar quatro minutos;
- falha ao gerar credencial ou enviar enrolment fecha a sessão;
- falha em `close` durante recusa ainda devolve a UI a `idle`;
- resultado atrasado da tentativa A não sobrescreve a tentativa B.

### Desktop (Rust/IPC/UI)

- duas chamadas a `pair.pending` retornam a mesma proposta;
- perder a primeira resposta de `pair.pending` não perde o código;
- `pair.cancel` limpa QR e propostas do transporte e do service;
- `pair.begin` depois de recusa não reutiliza proposta/código anterior;
- `forget` remove imediatamente o peer conhecido e sessões estacionadas;
- telefone conhecido + QR armado consegue produzir nova proposta;
- telefone conhecido sem QR armado continua exigindo a chave armazenada;
- confirmação com `pairingAttemptId` antigo é recusada.

### Integração PC/celular

Executar o fluxo feliz e derrubar a conexão em cada fronteira:

1. antes do ServerHello;
2. depois do handshake;
3. antes e depois do enrolment;
4. durante cada confirmação;
5. depois de persistir em apenas um lado;
6. enquanto a sessão pareada está ociosa;
7. durante uma autorização;
8. durante revogação;
9. depois de recusa, seguido imediatamente por novo QR;
10. depois de reiniciar app, agente e UI separadamente.

Matrizes indispensáveis:

- revogar no celular -> novo QR -> parear novamente;
- esquecer no PC -> novo QR -> parear novamente;
- revogar/recusar com PC offline -> PC volta -> parear novamente;
- resposta IPC perdida -> reabrir janela -> mesmo código aparece;
- Wi-Fi cai e volta -> celular sai de `unreachable` para `connected` sozinho.

## Critérios de aceite

- Nenhum spinner de conexão permanece indefinidamente: cada etapa tem timeout,
  estado final e ação de tentar novamente.
- Após handshake autenticado, o celular mostra `connected` em até um ciclo de
  renderização.
- Revogar no celular sobrevive a restart e o dispositivo não reaparece.
- Um PC que ainda guarda o registro antigo não impede um novo pareamento
  explicitamente armado.
- Recusar/cancelar e iniciar novamente funciona sem reiniciar nenhum processo.
- Perder evento, poll ou resposta IPC não perde a proposta pendente.
- Todos os cenários de queda acima terminam em `connected`, `idle`, `rejected`,
  `revoked` ou erro recuperável; nunca em estado zumbi.

## Observação de produto sobre revogação

Revogar o **PC no celular** remove a confiança local do celular naquele PC; isso
não apaga magicamente, sobretudo offline, a chave pública que o PC guardou do
telefone. A interface deve deixar esse limite claro. Se o produto prometer
revogação bilateral, será necessário um pedido de revogação autenticado,
confirmação do PC e uma fila persistente para entrega posterior. Mesmo sem
essa extensão, o novo pareamento armado deve sempre reparar a assimetria.
