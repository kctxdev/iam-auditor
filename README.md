# IAM Permission Auditor

Auditor de permissoes IAM para contas AWS: encontra **acesso excessivo**, credenciais antigas/ociosas e gera um
**relatorio com correcoes** e politicas de **menor privilegio** sugeridas. Somente leitura.

Stack: Python 3.10+, boto3, IAM APIs, IAM Access Analyzer e IAM Access Advisor.

## O que ele verifica

| Area | Checks |
|---|---|
| Politicas (gerenciadas e inline) | `Action: *`, wildcard de servico (`s3:*`, `iam:*`), `NotAction`/`NotResource` com Allow, acoes de escalada de privilegio (`iam:PassRole`, `iam:PutRolePolicy`...) com `Resource: *` |
| Trust policies das roles | `Principal: *`, conta externa sem `sts:ExternalId` / `aws:PrincipalOrgID` |
| Credenciais (credential report) | root sem MFA ou com access key, usuario com console sem MFA, access keys antigas / nunca usadas / ociosas, senha de console ociosa, duas keys ativas |
| Acessos sem uso | roles nunca usadas ou ociosas (`RoleLastUsed`) |
| Higiene | politicas anexadas direto em usuarios (use grupos/roles/SSO) |
| Access Analyzer | findings de acesso publico/externo (S3, KMS, roles, etc.) |
| Menor privilegio | com `--advisor`, cruza com o Access Advisor e propoe uma politica so com os servicos realmente usados (janela de 365 dias) |

Cada finding traz severidade (CRITICAL/HIGH/MEDIUM/LOW), evidencia, recursos afetados e correcao sugerida.

## Inicio rapido (interface + launchers)

| Sistema | Comando |
|---|---|
| Linux / macOS | `./iniciar.sh` (se necessario: `chmod +x iniciar.sh`) |
| Windows | duplo clique em `iniciar.bat` |

O launcher cria o `.venv`, instala as dependencias e abre a **interface local** no navegador
(`http://127.0.0.1:8765`, acessivel so desta maquina): painel com o resumo do projeto, risk score, filtros por severidade,
busca, detalhes de cada finding, politica sugerida com botao copiar e exportacao em HTML/JSON/Markdown.
A tela inicial e o painel de conexao: escolha um **perfil do AWS CLI** (inclusive SSO) ou informe **chaves de acesso**
(ficam so na memoria da sessao local, nunca em disco). Apos conectar, a interface mostra o resultado da sua conta;
antes disso exibe apenas um exemplo ilustrativo. Os dados ficticios continuam disponiveis no terminal com `--demo`.

Com argumentos, o launcher roda o modo terminal: `./iniciar.sh --demo`, `./iniciar.sh --profile meu-perfil --advisor -v`.

## Modo terminal

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python -m iam_auditor --demo                 # dados ficticios, sem AWS
python -m iam_auditor                        # sua conta (usa as credenciais do AWS CLI)
python -m iam_auditor --profile meu-perfil   # perfil especifico
python -m iam_auditor --advisor -v           # + sugestoes de menor privilegio e detalhes
```

O resultado aparece direto no terminal, colorido por severidade, com resumo e risk score.
Para tambem salvar relatorios: `--format terminal,html,json,md` (ou `--format all`), gravados em `reports/`.

Opcoes uteis: `-v` (detalhes), `--no-color`, `--stale-days 90`, `--key-max-age 90`, `--fail-on HIGH` (exit code 1 para CI),
`--snapshot-out snap.json` / `--snapshot-in snap.json` (analise offline; o snapshot contem dados sensiveis, nao versione).

## Permissoes necessarias

Use `examples/auditor-readonly-policy.json` em uma role/usuario dedicado. Nenhuma acao de escrita e executada.

## IAM Access Analyzer

O auditor le findings de um analyzer existente. Para habilitar (uma vez, por regiao):

```bash
aws accessanalyzer create-analyzer --analyzer-name account-analyzer --type ACCOUNT
```

Sem analyzer ativo, a parte de Access Analyzer e ignorada. Para acesso nao utilizado no nivel de organizacao existe o tipo
`ACCOUNT_UNUSED_ACCESS` (recurso pago); basta cria-lo que seus findings tambem sao lidos se estiverem ativos.

## Arquitetura

```
collector.py  -> boto3 (IAM, STS, Access Analyzer, Access Advisor) -> snapshot (dict/JSON)
analyzer.py   -> regras puras sobre o snapshot -> lista de Finding
recommender.py-> cruza com Access Advisor -> politica de menor privilegio sugerida
report.py     -> HTML autocontido, JSON e Markdown
terminal.py   -> saida colorida no terminal
web.py + ui/  -> interface local (http.server, so 127.0.0.1, token por sessao)
cli.py        -> orquestracao, --fail-on para CI
```

A analise nao depende de rede, entao e totalmente testavel (`tests/`, dados em `demo_data.py`).

## Testes

```bash
pip install -r requirements-dev.txt && pytest
```

## CI

`examples/github-actions-audit.yml` roda a auditoria semanalmente via OIDC e falha o job se houver finding HIGH ou pior.

## Limitacoes

- A politica sugerida e um **ponto de partida em nivel de servico**. Para chegar em nivel de acao, use a geracao de politica
  do Access Analyzer baseada em CloudTrail.
- Nao avalia o efeito combinado de SCPs, permissions boundaries e session policies, nem `Deny` explicitos.
- Nao expande membros de grupos nos findings (o grupo e reportado como afetado).
- Access Advisor so rastreia acoes de nivel de acao para alguns servicos (ex.: S3, EC2, IAM, Lambda).

## Ideias para evoluir

Multi-conta com AWS Organizations (assumir role em cada conta), exportar para Security Hub (ASFF), diff entre execucoes,
simulacao com `iam:SimulatePrincipalPolicy`, remediacao com Terraform gerado a partir dos findings.
