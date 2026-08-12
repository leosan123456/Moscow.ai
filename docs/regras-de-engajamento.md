# Regras de engajamento

Este documento é normativo para o código. Toda contribuição que o contrarie deve ser
rejeitada em revisão, mesmo que os testes passem.

## 1. Autorização é aplicada em código

O escopo contratado vive em `Engagement.scope` e é reavaliado a cada alvo, a cada
chamada. Não existe caminho em que um operador "declara" que um alvo é válido.

**Como isso se manifesta no código:** módulos de varredura recebem um `ScopeGuard`, não
uma lista de alvos. Se um módulo aceita `list[str]` de alvos e chama a ferramenta direto,
é bug de arquitetura, não detalhe de implementação.

```python
# certo
with guard.touch(alvo, ActionClass.ACTIVE_NON_INTRUSIVE, tool="nmap") as target:
    executar_scan(target)

# errado — nunca passa pelo gate, nunca audita
executar_scan(alvo)
```

## 2. Não destrutivo por padrão

| Classe | O que é | Exige |
|--------|---------|-------|
| `PASSIVE` | Não toca o ativo: OSINT, CVE/NVD, SBOM, API do provedor de nuvem | token |
| `ACTIVE_NON_INTRUSIVE` | Toca sem alterar estado: TCP connect, banner, header, versão TLS | token com teto ≥ |
| `INTRUSIVE` | Pode alterar estado ou degradar o serviço | opt-in contratual + aprovação humana vigente + plano que inclua `intrusive_checks` |

Confirmação de achado é feita por **observação** — banner, versão, header, configuração.
Nunca por exploração real que possa derrubar o serviço do cliente.

**Proibido no repositório, sem exceção:** payload destrutivo, negação de serviço, técnica
de evasão de detecção, exploração de terceiros fora do escopo, movimentação lateral.

## 3. Humano no circuito

Toda ação intrusiva exige um `HumanApproval` vigente, nomeado e com referência ao
documento de autorização. A aprovação:

- tem janela própria, mais curta que a da engagement;
- pode ser limitada a alvos específicos (`IntrusiveAuthorization.limited_to`);
- **nunca** é concedida por delegação da plataforma para si mesma.

## 4. Alvos que a plataforma recusa por política

Independentemente do que o contrato diga, `SafetyPolicy` bloqueia por padrão:

- loopback (`127.0.0.0/8`, `::1`) e os nomes que resolvem para ele;
- link-local (`169.254.0.0/16`, `fe80::/10`);
- **endpoint de metadados de nuvem** (`169.254.169.254`, `metadata.google.internal`);
- multicast e reservados.

Ranges privados (RFC1918) **não** são bloqueados — engajamento interno é caso de uso
legítimo. Liberar qualquer um dos bloqueados exige `SafetyPolicy.with_allowed()`, que é
uma decisão explícita e revisável.

## 5. Intensidade

Limite por `(engagement, alvo)`, via token bucket. Dois engajamentos do mesmo cliente não
somam pressão sobre o mesmo host. Os valores vêm de `Engagement.limits` e são parte do
contrato, não configuração de infraestrutura.

Pré-filtragem (`ScopeGuard.partition`) não consome cota: descoberta gera muito candidato
fora de escopo, e gastar a cota do alvo legítimo com eles seria perverso.

## 6. Trilha de auditoria

Toda operação que toca um ativo emite `AuditEvent`. Isso inclui **as negações** — o alvo
negado é registrado em sua forma bruta, porque o valor original é a prova.

## 7. Encerramento

Ao fim da janela contratada, os tokens expiram junto (`not_after` limita o TTL). Não
existe execução "só para terminar". Se precisar de mais tempo, precisa de nova janela.

## 8. Dados

Dados de vulnerabilidade são altamente sensíveis. Retenção mínima conforme
`Quota.DATA_RETENTION_DAYS` do plano. Toda entidade persistida carrega `client_id`;
consulta sem filtro por tenant é bug de isolamento.
