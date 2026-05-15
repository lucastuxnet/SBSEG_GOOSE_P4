# Changelog

Todas as mudanças notáveis deste projeto serão documentadas neste arquivo.

O formato é baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.0.0/),
e este projeto adere ao [Semantic Versioning](https://semver.org/lang/pt-BR/).

---

## [1.1.0] - 2026-05-15

### Adicionado
- Suporte ao conversor de regras `convert_p4.py`: pipeline completo de `rules.py` → P4 → JSON
- Integração com a ferramenta [SBRC 2026](https://github.com/lucastuxnet/SBRC_2026) para geração de regras em alto nível
- Geração automática de relatórios em HTML e JSON após execução dos testes
- Diretório `logs/` com saída estruturada por timestamp (`.log`, `.json`, `.html`)
- Suporte ao arquivo `goose_convert.json` como backend alternativo ao `goose_ids.json`
- Argumento CLI `[interface] [json_file]` no `testar_ataques_log.py` para maior flexibilidade
- Flag `--help` no script de testes com mensagem de uso detalhada

### Alterado
- `testar_ataques_log.py` refatorado para suportar múltiplos arquivos JSON via argumento posicional
- Logging integrado via `journalctl` com captura em arquivo paralelo ao envio de pacotes
- Relatório de resumo agora inclui contagem de `Dropping packet` detectados no log do switch

### Corrigido
- Geração de código P4 com operadores de condição encadeados corretamente (`else if`)
- Tratamento de valores negativos em campos `stDiff` e `tDiff` na conversão Python → P4

---

## [1.0.0] - 2026-05-14

### Adicionado
- Implementação inicial do IDS GOOSE baseado em P4 (`goose_ids.p4`, `goose_ids.json`)
- Programa P4 completo com parser Ethernet + GOOSE (EtherType `0x88B8`)
- 21 regras de detecção cobrindo 8 categorias de ataque ao protocolo GOOSE IEC 61850:
  - **Grayhole** — SqNum baixo combinado com tDiff, StNum ou stDiff anômalos
  - **High StNum** — StNum acima de limiar com salto de estado ou atraso de sequência
  - **Injection** — SeqNum com salto abrupto ou status de estado inválido
  - **Inverse Replay** — Atraso temporal ou reversão de estado
  - **Masquerade Fake Fault** — Simulação de falha com timestamp ou stDiff suspeito
  - **Masquerade Fake Normal** — Simulação de estado normal com StNum ou timestamp fora do padrão
  - **Poisoned High Rate** — Estado prolongado ou timing anômalo (tDiff negativo)
  - **Random Replay** — Combinação de SqNum/StNum fora de padrão ou timeChange inesperado
- Script `testar_ataques_log.py` com suite de 21 testes automatizados + 1 caso de tráfego normal
- Script `veth.py` para criação de interfaces virtuais `veth0/veth1/veth2/veth3`
- Metadados P4: `sqdiff`, `stdiff`, `tdiff`, `timestamp_diff`, `state_valid`, flags de estado
- Ação `update_state()` para rastreamento de estado entre pacotes consecutivos
- Ação `drop_packet()` com `mark_to_drop()` como resposta a anomalias detectadas
- Suporte a `simple_switch` via BMv2 com interfaces `-i 0@veth0 -i 1@veth2`
- Licença MIT

---

## [Unreleased]

### Planejado
- Suporte a múltiplos fluxos GOOSE simultâneos (multi-stream tracking)
- Integração com painel de monitoramento em tempo real
- Exportação de alertas via syslog / SNMP
- Testes de regressão automatizados com CI/CD (GitHub Actions)
- Suporte a P4Runtime para instalação dinâmica de regras sem recompilação

---

[1.1.0]: https://github.com/lucastuxnet/SBSEC_GOOSE_P4/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/lucastuxnet/SBSEC_GOOSE_P4/releases/tag/v1.0.0
[Unreleased]: https://github.com/lucastuxnet/SBSEC_GOOSE_P4/compare/v1.1.0...HEAD
