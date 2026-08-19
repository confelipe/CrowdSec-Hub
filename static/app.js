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
    'tab-report': { title: 'Relatório de Diretoria & Conformidade', sub: 'Sumário executivo formatado para reuniões estratégicas, comitês e auditorias' },
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
            <span class="ip-badge">${a.source_ip || 'Desconhecido'}</span>
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
            <span class="ip-badge">${d.value}</span>
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
}
