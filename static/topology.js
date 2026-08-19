class SecurityTopology {
  constructor(canvasId) {
    this.canvas = document.getElementById(canvasId);
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext('2d');
    
    this.nodes = [];
    this.edges = [];
    this.particles = [];
    this.selectedNode = null;
    this.hoveredNode = null;
    this.draggingNode = null;
    this.isPaused = false;
    this.simulatedFailures = new Set();
    
    this.zoom = 1;
    this.panX = 0;
    this.panY = 0;
    this.isPanning = false;
    this.startX = 0;
    this.startY = 0;
    this.pulseAngle = 0;

    window.topologyInstance = this;

    this.initCanvasSize();
    this.setupEvents();
    this.animate = this.animate.bind(this);
    requestAnimationFrame(this.animate);
  }

  initCanvasSize() {
    if (!this.canvas) return;
    const container = this.canvas.parentElement;
    if (container) {
      const rect = container.getBoundingClientRect();
      this.canvas.width = (rect.width && rect.width > 50) ? rect.width : (container.clientWidth || 1050);
      this.canvas.height = (rect.height && rect.height > 50) ? rect.height : (container.clientHeight || 600);
    }
  }

  centerView() {
    if (!this.nodes || this.nodes.length === 0 || !this.canvas) return;

    let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
    this.nodes.forEach(n => {
      if (n.x < minX) minX = n.x;
      if (n.x > maxX) maxX = n.x;
      if (n.y < minY) minY = n.y;
      if (n.y > maxY) maxY = n.y;
    });

    const paddingX = 120;
    const paddingY = 80;
    const graphWidth = (maxX - minX) + paddingX * 2;
    const graphHeight = (maxY - minY) + paddingY * 2;
    const graphCenterX = (minX + maxX) / 2;
    const graphCenterY = (minY + maxY) / 2;

    const canvasWidth = this.canvas.width;
    const canvasHeight = this.canvas.height;

    // Scale so graph fits perfectly with clean margins
    const scaleX = canvasWidth / graphWidth;
    const scaleY = canvasHeight / graphHeight;
    this.zoom = Math.min(Math.max(Math.min(scaleX, scaleY) * 0.94, 0.6), 1.25);

    // Center pan
    this.panX = (canvasWidth / 2) - (graphCenterX * this.zoom);
    this.panY = (canvasHeight / 2) - (graphCenterY * this.zoom);
  }

  loadData(topologyData) {
    this.nodes = topologyData.nodes || [];
    this.edges = topologyData.edges || [];
    this.initCanvasSize();
    this.centerView();
    this.createParticles();
  }

  createParticles() {
    this.particles = [];
    this.edges.forEach((edge, idx) => {
      const fromNode = this.nodes.find(n => n.id === edge.from);
      const toNode = this.nodes.find(n => n.id === edge.to);
      if (fromNode && toNode) {
        // Use realistic particle count from real-time telemetry
        let count = edge.particle_count;
        if (!count) {
          count = edge.type === 'traffic_threat' ? 4 : (edge.type === 'traffic_safe' ? 5 : 2);
        }
        for (let i = 0; i < count; i++) {
          this.particles.push({
            edgeIdx: idx,
            progress: (i / count) + (Math.random() * (0.8 / count)),
            speed: (0.0032 + Math.random() * 0.001) * (edge.speed || 1),
            color: this.getEdgeColor(edge.type),
            radius: edge.type === 'traffic_threat' ? 3.5 : (count >= 6 ? 3.2 : 2.4)
          });
        }
      }
    });
  }

  getEdgeColor(type) {
    switch (type) {
      case 'traffic_safe': return '#10b981';
      case 'traffic_threat': return '#ef4444';
      case 'auth_check': return '#00f0ff';
      case 'sync': return '#3b82f6';
      case 'wazuh_stream': return '#c084fc';
      case 'log_stream': return '#94a3b8';
      case 'proxy_pass_warn': return '#f59e0b';
      default: return '#64748b';
    }
  }

  getNodeColor(group) {
    switch (group) {
      case 'source_safe': return { bg: '#064e3b', border: '#10b981', glow: 'rgba(16, 185, 129, 0.4)' };
      case 'source_danger': return { bg: '#450a0a', border: '#ef4444', glow: 'rgba(239, 68, 68, 0.4)' };
      case 'edge': return { bg: '#0c4a6e', border: '#0284c7', glow: 'rgba(2, 132, 199, 0.4)' };
      case 'security_core': return { bg: '#164e63', border: '#00f0ff', glow: 'rgba(0, 240, 255, 0.5)' };
      case 'cloud_intel': return { bg: '#1e1b4b', border: '#8b5cf6', glow: 'rgba(139, 92, 246, 0.4)' };
      case 'siem': return { bg: '#2e1065', border: '#c084fc', glow: 'rgba(192, 132, 252, 0.5)' };
      case 'observability': return { bg: '#1e293b', border: '#64748b', glow: 'rgba(100, 116, 139, 0.4)' };
      case 'target_secure': return { bg: '#022c22', border: '#10b981', glow: 'rgba(16, 185, 129, 0.3)' };
      case 'target_warning': return { bg: '#451a03', border: '#f59e0b', glow: 'rgba(245, 158, 11, 0.4)' };
      default: return { bg: '#0f172a', border: '#334155', glow: 'rgba(51, 65, 85, 0.3)' };
    }
  }

  toggleSimulateFailure(nodeId) {
    if (this.simulatedFailures.has(nodeId)) {
      this.simulatedFailures.delete(nodeId);
    } else {
      this.simulatedFailures.add(nodeId);
    }
    const node = this.nodes.find(n => n.id === nodeId);
    if (node && this.selectedNode && this.selectedNode.id === nodeId) {
      this.inspectNode(node);
    }
  }

  getDownstreamImpactedNodes() {
    const impacted = new Set();
    this.nodes.forEach(node => {
      const isFailed = (node.health && node.health.status === 'down') || this.simulatedFailures.has(node.id);
      if (isFailed && node.impact && node.impact.impacted_nodes) {
        node.impact.impacted_nodes.forEach(id => impacted.add(id));
      }
    });
    return impacted;
  }

  setupEvents() {
    window.addEventListener('resize', () => this.initCanvasSize());

    this.canvas.addEventListener('mousedown', (e) => {
      const rect = this.canvas.getBoundingClientRect();
      const mouseX = (e.clientX - rect.left - this.panX) / this.zoom;
      const mouseY = (e.clientY - rect.top - this.panY) / this.zoom;

      const clickedNode = this.nodes.find(n => {
        const dx = n.x - mouseX;
        const dy = n.y - mouseY;
        return Math.sqrt(dx * dx + dy * dy) < 28;
      });

      if (clickedNode) {
        this.draggingNode = clickedNode;
        this.selectedNode = clickedNode;
        this.inspectNode(clickedNode);
      } else {
        this.isPanning = true;
        this.startX = e.clientX - this.panX;
        this.startY = e.clientY - this.panY;
      }
    });

    this.canvas.addEventListener('mousemove', (e) => {
      const rect = this.canvas.getBoundingClientRect();
      const mouseX = (e.clientX - rect.left - this.panX) / this.zoom;
      const mouseY = (e.clientY - rect.top - this.panY) / this.zoom;

      if (this.draggingNode) {
        this.draggingNode.x = mouseX;
        this.draggingNode.y = mouseY;
        return;
      }

      if (this.isPanning) {
        this.panX = e.clientX - this.startX;
        this.panY = e.clientY - this.startY;
        return;
      }

      this.hoveredNode = this.nodes.find(n => {
        const dx = n.x - mouseX;
        const dy = n.y - mouseY;
        return Math.sqrt(dx * dx + dy * dy) < 28;
      });

      this.canvas.style.cursor = this.hoveredNode ? 'pointer' : (this.isPanning ? 'grabbing' : 'grab');
    });

    window.addEventListener('mouseup', () => {
      this.draggingNode = null;
      this.isPanning = false;
    });

    this.canvas.addEventListener('wheel', (e) => {
      e.preventDefault();
      const zoomFactor = e.deltaY < 0 ? 1.08 : 0.92;
      this.zoom = Math.min(Math.max(this.zoom * zoomFactor, 0.5), 2.2);
    });

    const closeBtn = document.getElementById('insp-close');
    if (closeBtn) {
      closeBtn.addEventListener('click', () => {
        document.getElementById('nodeInspector').classList.remove('open');
        this.selectedNode = null;
      });
    }

    const fsBtn = document.getElementById('btn-topo-fullscreen');
    const wrapper = document.querySelector('.topology-wrapper');
    if (fsBtn && wrapper) {
      const toggleFullscreen = () => {
        if (!document.fullscreenElement && !wrapper.classList.contains('fullscreen-active')) {
          if (wrapper.requestFullscreen) {
            wrapper.requestFullscreen().catch(() => {
              wrapper.classList.add('fullscreen-active');
              this.updateFullscreenUI(true);
            });
          } else {
            wrapper.classList.add('fullscreen-active');
            this.updateFullscreenUI(true);
          }
        } else {
          if (document.exitFullscreen && document.fullscreenElement) {
            document.exitFullscreen();
          }
          wrapper.classList.remove('fullscreen-active');
          this.updateFullscreenUI(false);
        }
      };

      fsBtn.addEventListener('click', toggleFullscreen);

      document.addEventListener('fullscreenchange', () => {
        const isFS = !!document.fullscreenElement;
        this.updateFullscreenUI(isFS);
        setTimeout(() => {
          this.initCanvasSize();
          this.centerView();
        }, 100);
      });
    }

    const resetBtn = document.getElementById('btn-topo-reset');
    if (resetBtn) {
      resetBtn.addEventListener('click', () => {
        this.centerView();
        this.simulatedFailures.clear();
      });
    }

    const pauseBtn = document.getElementById('btn-topo-pause');
    if (pauseBtn) {
      pauseBtn.addEventListener('click', () => {
        this.isPaused = !this.isPaused;
        pauseBtn.innerHTML = this.isPaused ? '<i data-feather="play"></i> <span>Retomar</span>' : '<i data-feather="pause"></i> <span>Pausar</span>';
        feather.replace();
      });
    }
  }

  updateFullscreenUI(isFS) {
    const fsBtn = document.getElementById('btn-topo-fullscreen');
    if (!fsBtn) return;
    if (isFS) {
      fsBtn.innerHTML = '<i data-feather="minimize-2"></i> <span>Sair da Tela Cheia</span>';
      fsBtn.classList.add('btn-primary');
      fsBtn.classList.remove('btn-outline');
    } else {
      fsBtn.innerHTML = '<i data-feather="maximize-2"></i> <span>Tela Cheia</span>';
      fsBtn.classList.remove('btn-primary');
      fsBtn.classList.add('btn-outline');
    }
    feather.replace();
    this.initCanvasSize();
    setTimeout(() => this.centerView(), 50);
  }

  inspectNode(node) {
    const drawer = document.getElementById('nodeInspector');
    const badge = document.getElementById('insp-badge');
    const title = document.getElementById('insp-title');
    const content = document.getElementById('insp-content');

    badge.textContent = (node.group || 'NODE').toUpperCase().replace('_', ' ');
    title.textContent = node.label;

    const isSimulated = this.simulatedFailures.has(node.id);
    const healthStatus = isSimulated ? 'down' : (node.health?.status || 'healthy');
    const latency = node.health?.latency_ms ? `${node.health.latency_ms} ms` : 'Ativo';
    const impact = node.impact || { level: 'ISOLADO', summary: 'Serviço Padrão', failure_impact: 'Impacto local na rota.' };

    const statusColor = healthStatus === 'healthy' ? 'var(--success)' : (healthStatus === 'degraded' ? 'var(--warning)' : 'var(--danger)');
    const statusText = isSimulated ? 'FALHA SIMULADA (OFFLINE)' : (healthStatus === 'healthy' ? `SAUDÁVEL (${latency})` : 'INDISPONÍVEL');

    let html = `
      <div class="insp-row">
        <span class="insp-key">Status de Saúde</span>
        <span class="insp-val" style="color: ${statusColor}; font-weight: 700;">${statusText}</span>
      </div>
      <div class="insp-row">
        <span class="insp-key">Endereço / Host</span>
        <span class="insp-val">${node.ip || node.backend || 'N/A'}</span>
      </div>
    `;

    if (node.ports) {
      html += `
        <div class="insp-row">
          <span class="insp-key">Portas Abertas</span>
          <span class="insp-val">${node.ports}</span>
        </div>
      `;
    }

    if (node.count) {
      html += `
        <div class="insp-row">
          <span class="insp-key">Métricas / Registros</span>
          <span class="insp-val" style="color: var(--primary);">${node.count}</span>
        </div>
      `;
    }

    if (node.traffic_meta) {
      html += `
        <div class="impact-box" style="background: rgba(14, 165, 233, 0.08); border: 1px solid rgba(14, 165, 233, 0.3); margin-top: 12px;">
          <div class="impact-header">
            <span style="font-size: 0.75rem; font-weight: 700; color: #38bdf8;">TELEMETRIA DE TRÁFEGO REAL</span>
            <span class="impact-level-tag" style="background: #0284c7; color: #ffffff;">${node.traffic_meta.share_percent}% DO INGRESS</span>
          </div>
          <p class="impact-desc" style="color: #e0f2fe; margin-bottom: 6px;">
            Este serviço consome <strong>${node.traffic_meta.share_percent}%</strong> das requisições roteadas pelo Traefik (~${node.traffic_meta.rpm} req/min).
          </p>
          <div style="font-size: 0.72rem; color: #94a3b8;">
            Amostra recente: <strong>${node.traffic_meta.requests_sampled.toLocaleString()} requisições</strong> processadas.
          </div>
        </div>
      `;
    }

    // Impact Analysis Box
    const impactClass = impact.level.toLowerCase().split(' ')[0];
    html += `
      <div class="impact-box ${impactClass}">
        <div class="impact-header">
          <span style="font-size: 0.75rem; font-weight: 700; color: #ffffff;">ANÁLISE DE IMPACTO</span>
          <span class="impact-level-tag ${impactClass}">${impact.level}</span>
        </div>
        <p class="impact-desc">${impact.failure_impact}</p>
        ${impact.impacted_nodes && impact.impacted_nodes.length > 0 ? `
          <div style="margin-top: 8px; font-size: 0.7rem; color: #cbd5e1;">
            <strong>Nós Afetados na Queda:</strong> ${impact.impacted_nodes.length} serviços downstream.
          </div>
        ` : ''}
      </div>

      <button class="btn-simulate-fail ${isSimulated ? 'active' : ''}" onclick="window.topologyInstance.toggleSimulateFailure('${node.id}')">
        <i data-feather="${isSimulated ? 'refresh-cw' : 'zap-off'}"></i>
        ${isSimulated ? 'Restaurar Serviço (Voltar ao Normal)' : '🧪 Simular Queda do Serviço'}
      </button>
    `;

    if (node.security) {
      html += `
        <div style="margin-top: 14px; font-size: 0.78rem; color: var(--text-muted); font-weight: 600;">CAMADAS DE SEGURANÇA</div>
        <ul style="margin-top: 6px; padding-left: 18px; color: var(--text-primary); font-size: 0.78rem; line-height: 1.6;">
          ${node.security.map(s => `<li>${s}</li>`).join('')}
        </ul>
      `;
    }

    if (node.details) {
      html += `<div style="margin-top: 14px; font-size: 0.78rem; color: var(--text-muted); font-weight: 600;">DETALHES TÉCNICOS</div>`;
      for (const [k, v] of Object.entries(node.details)) {
        html += `
          <div class="insp-row">
            <span class="insp-key">${k}</span>
            <span class="insp-val">${Array.isArray(v) ? v.join(', ') : v}</span>
          </div>
        `;
      }
    }

    content.innerHTML = html;
    drawer.classList.add('open');
    feather.replace();
  }

  animate() {
    this.ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);

    this.pulseAngle += 0.04;
    const pulseOffset = Math.sin(this.pulseAngle) * 3;

    this.ctx.save();
    this.ctx.translate(this.panX, this.panY);
    this.ctx.scale(this.zoom, this.zoom);

    // Draw Grid Background lines
    this.drawGrid();

    // Get impacted nodes set
    const impactedSet = this.getDownstreamImpactedNodes();

    // Draw Edges
    this.drawEdges(impactedSet);

    // Draw Particles
    if (!this.isPaused) {
      this.updateAndDrawParticles();
    }

    // Draw Nodes
    this.drawNodes(impactedSet, pulseOffset);

    this.ctx.restore();

    requestAnimationFrame(this.animate);
  }

  drawGrid() {
    this.ctx.strokeStyle = 'rgba(255, 255, 255, 0.02)';
    this.ctx.lineWidth = 1;
    const step = 40;
    const minX = -this.panX / this.zoom;
    const maxX = (this.canvas.width - this.panX) / this.zoom;
    const minY = -this.panY / this.zoom;
    const maxY = (this.canvas.height - this.panY) / this.zoom;

    for (let x = Math.floor(minX / step) * step; x < maxX; x += step) {
      this.ctx.beginPath();
      this.ctx.moveTo(x, minY);
      this.ctx.lineTo(x, maxY);
      this.ctx.stroke();
    }
    for (let y = Math.floor(minY / step) * step; y < maxY; y += step) {
      this.ctx.beginPath();
      this.ctx.moveTo(minX, y);
      this.ctx.lineTo(maxX, y);
      this.ctx.stroke();
    }
  }

  drawEdges(impactedSet) {
    this.edges.forEach(edge => {
      const fromNode = this.nodes.find(n => n.id === edge.from);
      const toNode = this.nodes.find(n => n.id === edge.to);
      if (!fromNode || !toNode) return;

      const fromFailed = (fromNode.health && fromNode.health.status === 'down') || this.simulatedFailures.has(fromNode.id);
      const toImpacted = impactedSet.has(toNode.id);

      this.ctx.beginPath();
      this.ctx.moveTo(fromNode.x, fromNode.y);
      this.ctx.lineTo(toNode.x, toNode.y);

      if (fromFailed || toImpacted) {
        this.ctx.setLineDash([5, 4]);
        this.ctx.strokeStyle = fromFailed ? '#ef4444' : '#f59e0b';
        this.ctx.lineWidth = 2;
      } else {
        this.ctx.setLineDash([]);
        this.ctx.strokeStyle = this.getEdgeColor(edge.type);
        this.ctx.lineWidth = edge.type === 'auth_check' ? 2 : 1.5;
      }

      this.ctx.globalAlpha = 0.45;
      this.ctx.stroke();
      this.ctx.setLineDash([]);
      this.ctx.globalAlpha = 1.0;

      // Draw Edge Label
      if (edge.label) {
        const midX = (fromNode.x + toNode.x) / 2;
        const midY = (fromNode.y + toNode.y) / 2;
        this.ctx.font = '10px Inter, sans-serif';
        this.ctx.fillStyle = (fromFailed || toImpacted) ? '#f87171' : 'rgba(148, 163, 184, 0.8)';
        this.ctx.textAlign = 'center';
        this.ctx.fillText(edge.label, midX, midY - 6);
      }
    });
  }

  updateAndDrawParticles() {
    this.particles.forEach(p => {
      const edge = this.edges[p.edgeIdx];
      if (!edge) return;
      const fromNode = this.nodes.find(n => n.id === edge.from);
      const toNode = this.nodes.find(n => n.id === edge.to);
      if (!fromNode || !toNode) return;

      const fromFailed = (fromNode.health && fromNode.health.status === 'down') || this.simulatedFailures.has(fromNode.id);
      if (fromFailed) return; // Freeze particles on dead routes

      p.progress += p.speed;
      if (p.progress > 1) p.progress = 0;

      const px = fromNode.x + (toNode.x - fromNode.x) * p.progress;
      const py = fromNode.y + (toNode.y - fromNode.y) * p.progress;

      this.ctx.beginPath();
      this.ctx.arc(px, py, p.radius, 0, Math.PI * 2);
      this.ctx.fillStyle = p.color;
      this.ctx.shadowColor = p.color;
      this.ctx.shadowBlur = 8;
      this.ctx.fill();
      this.ctx.shadowBlur = 0;
    });
  }

  drawNodes(impactedSet, pulseOffset) {
    this.nodes.forEach(node => {
      let colors = this.getNodeColor(node.group);
      const isHovered = this.hoveredNode === node;
      const isSelected = this.selectedNode === node;
      const radius = isHovered || isSelected ? 24 : 20;

      const isFailed = (node.health && node.health.status === 'down') || this.simulatedFailures.has(node.id);
      const isImpacted = impactedSet.has(node.id) && !isFailed;
      const isDegraded = node.health && node.health.status === 'degraded' && !isFailed && !isImpacted;

      if (isFailed) {
        colors = { bg: '#450a0a', border: '#ef4444', glow: 'rgba(239, 68, 68, 0.6)' };
      } else if (isImpacted) {
        colors = { bg: '#451a03', border: '#f59e0b', glow: 'rgba(245, 158, 11, 0.5)' };
      } else if (isDegraded) {
        colors = { bg: '#422006', border: '#f97316', glow: 'rgba(249, 115, 22, 0.4)' };
      }

      // Outer glow / Pulse ring
      this.ctx.beginPath();
      const glowRadius = (isFailed || isImpacted) ? (radius + 6 + pulseOffset) : (radius + 4);
      this.ctx.arc(node.x, node.y, glowRadius, 0, Math.PI * 2);
      this.ctx.fillStyle = colors.glow;
      this.ctx.fill();

      // Node Body
      this.ctx.beginPath();
      this.ctx.arc(node.x, node.y, radius, 0, Math.PI * 2);
      this.ctx.fillStyle = colors.bg;
      this.ctx.fill();
      this.ctx.strokeStyle = isSelected ? '#ffffff' : colors.border;
      this.ctx.lineWidth = isSelected ? 3 : (isFailed ? 2.5 : 2);
      this.ctx.stroke();

      // Center Core
      this.ctx.beginPath();
      this.ctx.arc(node.x, node.y, 4, 0, Math.PI * 2);
      this.ctx.fillStyle = colors.border;
      this.ctx.fill();

      // Health / Status Badge pill above node
      let healthBadgeText = '';
      let healthBadgeBg = '#10b981';

      if (isFailed) {
        healthBadgeText = '🔴 OFFLINE';
        healthBadgeBg = '#ef4444';
      } else if (isImpacted) {
        healthBadgeText = '⚠️ IMPACTADO';
        healthBadgeBg = '#f59e0b';
      } else if (isDegraded) {
        healthBadgeText = '🟠 DEGRADADO';
        healthBadgeBg = '#f97316';
      } else if (node.health && node.health.latency_ms !== undefined) {
        healthBadgeText = `🟢 ${node.health.latency_ms}ms`;
        healthBadgeBg = '#10b981';
      }

      if (healthBadgeText) {
        this.ctx.font = '700 8.5px JetBrains Mono, monospace';
        const badgeWidth = this.ctx.measureText(healthBadgeText).width + 10;
        const badgeY = node.y - radius - 14;

        this.ctx.fillStyle = 'rgba(15, 23, 42, 0.85)';
        this.ctx.strokeStyle = healthBadgeBg;
        this.ctx.lineWidth = 1;
        this.ctx.beginPath();
        this.ctx.roundRect(node.x - badgeWidth / 2, badgeY, badgeWidth, 14, 3);
        this.ctx.fill();
        this.ctx.stroke();

        this.ctx.fillStyle = healthBadgeBg;
        this.ctx.textAlign = 'center';
        this.ctx.fillText(healthBadgeText, node.x, badgeY + 10.5);
      }

      // Label below
      this.ctx.font = '600 11px Inter, sans-serif';
      this.ctx.fillStyle = isFailed ? '#fca5a5' : '#ffffff';
      this.ctx.textAlign = 'center';
      this.ctx.fillText(node.label, node.x, node.y + radius + 15);

      // Sub-label / Count
      if (node.count || node.status) {
        this.ctx.font = '9px JetBrains Mono, monospace';
        this.ctx.fillStyle = '#94a3b8';
        this.ctx.fillText(node.count || node.status.toUpperCase(), node.x, node.y + radius + 28);
      }
    });
  }
}
