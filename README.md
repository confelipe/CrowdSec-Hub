# 🛡️ CrowdSec Hub | Security & Threat Intelligence

Painel Executivo e Centro de Comando em Tempo Real para mitigação de ameaças, telemetria de tráfego, conformidade (LGPD/ISO 27001) e monitoramento de segurança com **CrowdSec IPS/WAF**, **Traefik Ingress Proxy**, **Loki/Promtail** e **Wazuh SIEM Central**.

---

## 🚀 Principais Recursos

1. **📊 Painel Executivo de Segurança:**
   - Score de postura de segurança em tempo real (99.2%).
   - Contadores de tráfego inspecionado, requisições confiáveis (*whitelist*) e bloqueios ativos.
   - Estimativas de ROI executivo: Horas de triagem economizadas e custos financeiros evitados.
   - Categorização dinâmica de ameaças (Probing/Scans, CVEs, Brute-Force e Injeções).

2. **🌐 Mapa Interativo de Fluxo, Proteção & Topologia:**
   - Grafo interativo renderizado em Canvas com partículas de tráfego em tempo real.
   - **Telemetria de Tráfego Real:** Partículas dinâmicas proporcionais ao volume real de requisições por serviço extraídas do `access.log` do Traefik.
   - **Pipeline SIEM Central:** Visualização do fluxo `Traefik -> Loki/Promtail -> Wazuh Agent -> Wazuh SIEM Central`.
   - **Health Checks Ativos & Análise de Queda em Cascata:** Probes em tempo real para cada nó com cálculo de impacto downstream.
   - **Simulador Interativo de Falhas:** Teste de resiliência e impacto visual de indisponibilidade de serviços.
   - **Modo Tela Cheia (Fullscreen) & Auto-Centralização:** Ajuste automático a qualquer monitor e resolução.

3. **🗺️ Mapa Global Vetorial de Ameaças (GeoIP):**
   - Mapa mundi escuro vetorial em alta definição (*Leaflet.js + CartoDB Dark Matter*).
   - Beacons de radar geolocalizados por coordenadas reais (Lat/Lng) proporcionais ao volume de ataques.
   - Ranking percentual de países atacantes e tooltips executivos.

4. **⚡ Feed de Alertas & Inteligência de Ameaças (Threat Intel):**
   - Feed de incidentes em tempo real com filtros por país, cenário e busca textual.
   - Modal com explicações detalhadas de CVEs neutralizadas, OWASP Top 10 e impactos evitados.

5. **🚫 Gestão de Decisões & Bloqueios Imediatos:**
   - Lista completa de decisões locais e comunitárias (CTI Consensus).
   - Formulário para aplicação instantânea de novos bloqueios manuais de IP/CIDR via LAPI.

6. **📥 Exportação de Auditoria & Conformidade:**
   - Exportação direta de relatórios e tabelas para `.csv` / Excel (UTF-8 BOM).
   - Relatório estruturado para diretoria e auditorias de conformidade LGPD e ISO 27001.

7. **⏱️ Modo NOC / Auto-Refresh:**
   - Seletor de sincronização automática com indicador de pulso (*Live Pulse*).

---

## 🏗️ Arquitetura do Sistema

```
[ Tráfego Confiável / Whitelist ]  ──┐
                                     ├──► [ Traefik Ingress Proxy (v3.7.5) ]
[ Ameaças & Scanners Globais ]    ──┘          │  ▲ (Live Query 42ms / Bouncer)
                                               │  │
                                               ▼  ▼
                                      [ CrowdSec Engine (LAPI) ] ◄──► [ CrowdSec CTI Hub ]
                                               │
                                               ▼ (JSON Access Logs)
                                      [ Loki & Promtail Logs ]
                                               │
                                               ▼ (Log Pipeline)
                                      [ Wazuh Agent (Host) ]
                                               │
                                               ▼ (1514/TCP Encrypted Stream)
                                      [ Wazuh SIEM Central (SOC) ]
                                               │
                                               ▼ (Proxy Seguro)
                         ┌─────────────────────┼─────────────────────┐
                         ▼                     ▼                     ▼
                  [ GLPI Helpdesk ]    [ Portal InfraAI ]    [ SAP Mobile ] ...
```

---

## 🛠️ Stack Tecnológica

- **Backend:** Python 3.11, FastAPI, Uvicorn, SQLite3, Httpx, Pydantic, PyYAML.
- **Frontend:** HTML5, CSS3 Moderno, JavaScript Vanilla (ES6+), Canvas API, Chart.js, Leaflet.js, Feather Icons.
- **Borda & Segurança:** Traefik v3.7.5, Traefik Bouncer v1.6.0, CrowdSec v1.7.8, Wazuh Agent v4.14.4.
- **Deploy & Orquestração:** Docker, Docker Compose, Bash scripts.

---

## 🚀 Como Executar

### Pré-requisitos
- Docker & Docker Compose
- Acesso à rede do Traefik (`traefik_traefik`)
- Volumes de configuração e dados montados (`/docker/traefik/...`)

### Subindo via Docker Compose
```bash
docker-compose up -d --build
```

O dashboard estará disponível em: `http://<IP_DO_SERVIDOR>:8090`

---

## 📄 Licença & Propriedade

Classificação: **Uso Interno / Segurança da Informação**
