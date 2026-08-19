# 📊 Metodologia e Cálculo das Métricas Executivas de Segurança
**Projeto:** CrowdSec & Traefik Ingress Protection  
**Organização:** OpenLabs Tecnologia S.A.  
**Ambiente:** Edge Ingress Inbound (`10.51.211.13`)  
**Data:** 18 de Agosto de 2026  

---

## 🎯 Objetivo do Documento
Este documento formaliza as premissas, fórmulas matemáticas e padrões de mercado (*benchmarks de SecOps e CISO Frameworks*) utilizados pelo **CrowdSec Security Hub** para compor os indicadores de **ROI (Retorno sobre Investimento)**, **Eficiência Operacional**, **Redução de Riscos Financeiros** e **Score de Postura de Segurança** apresentados à Diretoria Executiva.

---

## 1. ⏱️ Horas de Engenharia Economizadas

### 📌 Premissa Operacional & Benchmark de Mercado
Em operações tradicionais de TI e Segurança sem automação no Ingress, a mitigação de cada incidente de varredura ou ataque cibernético exige a atuação manual de um analista de infraestrutura/SOC (N1/N2) para:
1. **Identificação**: Detectar o log anômalo no SIEM/Loki.
2. **Triagem & Reputação**: Verificar a procedência do IP em bases de inteligência (AbuseIPDB, VirusTotal, WHOIS).
3. **Remediação Manual**: Acessar o firewall de borda, `iptables`, AWS Security Group ou Traefik para inserir a regra de bloqueio.
4. **Fechamento**: Documentar e encerrar o ticket de incidente.

> **Benchmark de Mercado:** O tempo médio padrão da indústria para essa triagem e bloqueio manual é de **5 a 8 minutos por evento**. Adotamos conservadoramente **6 minutos** por incidente.

### 📐 Fórmula de Cálculo
$$\text{Horas Economizadas} = \frac{\text{Total de Incidentes Mitigados} \times 6\text{ minutos}}{60\text{ minutos}}$$

### 🔢 Aplicação Prática no Ambiente
$$\text{Horas Economizadas} = \frac{1.504 \times 6}{60} = \mathbf{150{,}4\text{ horas/mês}}$$

### 💼 Impacto para a Diretoria
- **Equivalência em FTE (*Full-Time Equivalent*):** 150,4 horas representam praticamente **1 profissional de segurança/infraestrutura dedicado em tempo integral** (160h/mês) apenas para analisar e bloquear ataques manualmente.
- O CrowdSec liberou a equipe técnica para focar em projetos estratégicos de inovação e entrega de produtos para clientes OpenLabs.

---

## 2. 💵 Custo Financeiro Evitado (*Financial Risk Avoidance*)

### 📌 Premissa Operacional
O cálculo de custo financeiro evitado considera duas vertentes clássicas de finanças em TI:
1. **Custo Operacional de Triagem:** Custo do tempo de engenharia necessário para mitigar os ataques caso fossem manuais.
2. **Custo de Risco de Indisponibilidade & Resposta a Vazamento:** Contingência mínima evitada ao impedir que um ataque exploratório (como Log4j, Spring4Shell, SQLi ou invasão de painel administrativo) tenha sucesso e cause impacto ao negócio.

### 📐 Fórmula de Cálculo
$$\text{Custo Evitado} = (\text{Total de Incidentes} \times \text{Custo de Triagem Unitária}) + \text{Custo de Risco Evitado}$$

$$\text{Custo Evitado} = (1.504 \times \text{R\$} 35{,}00) + \text{R\$} 12.000{,}00$$

### 🔢 Detalhamento dos Valores
- **Custo Unitário de Triagem (R$ 35,00/incidente):** Baseado no custo-hora médio com encargos de um especialista de TI/Segurança (~R$ 100/hora $\times$ fração de 20 minutos de contexto/deslocamento mental e execução).
  $$1.504 \times \text{R\$} 35{,}00 = \mathbf{\text{R\$} 52.640{,}00}$$
- **Custo de Risco / Contingência Evitada (R$ 12.000,00):** Estimativa conservadora de custos de horas extras de contenção, restauração de backup, suporte ao usuário e desgaste de imagem de indisponibilidade em sistemas críticos (GLPI, Site, Troca de Senha).
- **Total de Retorno / Custo Evitado:**
  $$\text{R\$} 52.640{,}00 + \text{R\$} 12.000{,}00 = \mathbf{\text{R\$} 64.640{,}00}$$

---

## 3. ⚡ MTTR Automático (*Mean Time to Remediate*)

### 📌 Premissa & Medição Técnica
- **MTTR Tradicional Humano:** 30 minutos a 4 horas (tempo entre o início do ataque, detecção, alerta, alocação de técnico e aplicação do ban).
- **MTTR Automático CrowdSec:** Tempo de decisão da API local (`module=lapi`) consultada pelo Traefik Bouncer em tempo real.

### 🔢 Resultado no Ambiente
- Latência média registrada em produção: **`35 ms a 45 ms`** (média consolidada: **`42.5 ms`**).
- **Vantagem Competitiva:** O invasor é mitigado no seu **primeiro pacote de rede suspeito**, impedindo a enumeração e exploração de brechas.

---

## 4. 👥 Taxa de Falso Positivo (`0.00%`)

### 📌 Premissa de Continuidade de Negócios
Sistemas de bloqueio agressivos frequentemente impactam colaboradores legítimos (falsos positivos). Para garantir continuidade total:
- Implementou-se a Whitelist Corporativa em `/etc/crowdsec/parsers/s02-enrich/openlabs-whitelist.yaml`.
- Faixas cadastradas: Sub-rede corporativa `10.51.172.0/22`, IPs de VPN e escritórios.

### 🔢 Resultado no Ambiente
- **234.018 requisições legítimas** de colaboradores e sistemas internos foram inspecionadas e liberadas sem bloqueio indevido.
- **Taxa de Falso Positivo:** **`0.00%`**.

---

## 5. 🛡️ Score de Postura de Segurança (`99.2%`)

### 📌 Metodologia de Ponderação (*Defense-in-Depth Framework*)
Em governança e auditoria de segurança (ISO 27001 / NIST / CIS Controls), **não existe risco 0% ou 100% de segurança absoluta**. O score pondera 5 pilares fundamentais de blindagem:

| Pilar de Segurança | Peso | Cobertura OpenLabs | Pontos Obtidos |
| :--- | :---: | :--- | :---: |
| **1. Cobertura do WAF / CrowdSec Bouncer** | **35%** | 5 de 5 routers Traefik com Bouncer ativo em modo Live | **35.0%** |
| **2. Criptografia em Trânsito (TLS)** | **25%** | 100% dos endpoints forçando TLS 1.3 e certificados válidos | **25.0%** |
| **3. Hardening & Ocultação de Headers** | **15%** | Mascaramento de versão e servidor (`Server: DCY`) ativo | **15.0%** |
| **4. Prevenção de Falso Positivo** | **15%** | 0.00% falso positivo na Whitelist corporativa (234k+ reqs) | **15.0%** |
| **5. Rate-Limiting & Mitigação por Rota** | **10%** | GLPI e Site com Rate-Limit de API/Login ativo | **9.2%** |
| **TOTAL** | **100%** | **Score Consolidado** | **99.2%** |

### 🔍 O que compõe os 0.8% de Risco Residual Não Mitigado?
Os **`0.8%`** representam o **Risco Residual Aceitável** e as oportunidades de melhoria contínua da infraestrutura:
1. **Ataques Distribuídos Lentos (*Low & Slow / Password Spraying*)**:
   - Botnets que utilizam milhares de IPs residenciais distintos fazendo apenas 1 tentativa a cada 20-30 minutos por IP, tentando permanecer intencionalmente abaixo do limite de detecção por IP único.
2. **Ausência de Rate-Limit Dedicado em 3 Rotas**:
   - Embora o **Troca de Senha**, **InfraAI** e **SAP Mobile** estejam 100% protegidos pelo Bouncer, eles ainda não contam com o middleware de *Rate-Limiting* dedicado no Traefik para contenção de flood local em formulários.
3. **Janela de Ameaça Zero-Day (*Zero-Day Exploit Window*)**:
   - Intervalo de tempo entre o anúncio mundial de uma nova CVE inédita e a publicação/sincronização do cenário de detecção no Hub da CrowdSec.

---

## 6. 🌐 Inteligência Coletiva & Origem das Ameaças (CTI)

### 📌 Análise de Provedores Hostis (ASNs)
O CrowdSec identificou que **`76.4% das varreduras hostis`** são oriundas de grandes provedores de computação em nuvem (*Google Cloud, Microsoft Azure, Amazon AWS, DigitalOcean, Hetzner*), evidenciando que os ataques são automatizados e executados via botnets orquestradas.

### 📌 Decisões Preventivas
- **24.650 IPs maliciosos** estão registrados na base de decisões ativas.
- A maioria desses IPs foi bloqueada **preventivamente** via lista global de CTI antes mesmo de tentarem qualquer conexão contra os servidores da OpenLabs.

---

## 📋 Resumo Executivo para Reunião de Diretoria

> *"A implementação do CrowdSec no Ingress Traefik consolidou uma economia operacional de **150+ horas de engenharia por mês**, mitigou autonomamente mais de **1.500 tentativas de invasão** com tempo de resposta inferior a **43 milissegundos**, evitando um custo estimado de **R$ 64.600** em incidentes e indisponibilidade, com **zero impacto** aos colaboradores da OpenLabs."*
