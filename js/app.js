/**
 * VulnScan — App Controller
 */

(function () {
  'use strict';

  let activeScanner = null;
  let lastResults = null;

  // ─── Elements ───
  const scanBtn = document.getElementById('scan-btn');
  const targetInput = document.getElementById('target-input');
  const terminal = document.getElementById('terminal');
  const progressSection = document.getElementById('progress-section');
  const progressBar = document.getElementById('progress-bar');
  const progressLabel = document.getElementById('progress-label');
  const progressPct = document.getElementById('progress-pct');
  const progressModules = document.getElementById('progress-modules');
  const reportSection = document.getElementById('report');
  const summaryRow = document.getElementById('summary-row');
  const findingsList = document.getElementById('findings-list');
  const portGrid = document.getElementById('port-grid');
  const filterTabs = document.getElementById('filter-tabs');

  // ─── Init ───
  document.addEventListener('DOMContentLoaded', () => {
    setupFilters();
    setupExports();
    setupNewScan();
    animateHeroRadar();
    setupNavHighlight();

    // Default target placeholder interaction
    targetInput.addEventListener('keydown', e => {
      if (e.key === 'Enter') startScan();
    });
  });

  // ─── Scan ───
  scanBtn.addEventListener('click', startScan);

  function getModuleLabels() {
    const labelMap = {
      'mod-ports': 'Port Scanner',
      'mod-headers': 'HTTP Headers',
      'mod-ssl': 'SSL/TLS Audit',
      'mod-cve': 'CVE Lookup',
      'mod-dns': 'DNS Recon',
      'mod-waf': 'WAF Detection',
    };
    return Object.entries(labelMap)
      .filter(([id]) => document.getElementById(id)?.checked)
      .map(([, label]) => label);
  }

  async function startScan() {
    const target = targetInput.value.trim();
    if (!target) {
      flashInput();
      return;
    }

    const modules = getModuleLabels();
    if (modules.length === 0) {
      termLog('error', '[!] Select at least one module');
      return;
    }

    // Reset UI
    clearTerminal();
    reportSection.style.display = 'none';
    progressSection.style.display = 'block';
    scanBtn.disabled = true;
    scanBtn.querySelector('.scan-btn-text').textContent = 'SCANNING...';

    // Setup progress modules
    renderProgressModules(modules);
    updateProgress(0, 'Initializing...');

    // Run scanner
    activeScanner = new Scanner({
      target,
      profile: document.querySelector('input[name="profile"]:checked')?.value || 'quick',
      modules,
      onLog: (type, message) => termLog(type, message),
      onProgress: (pct, mod) => updateProgress(pct, `Completed: ${mod}`),
      onModuleUpdate: (mod, state) => updateModuleState(mod, state),
    });

    try {
      const results = await activeScanner.run();
      lastResults = results;
      showReport(results);
    } catch (err) {
      termLog('error', `[ERROR] Scan failed: ${err.message}`);
    } finally {
      scanBtn.disabled = false;
      scanBtn.querySelector('.scan-btn-text').textContent = 'LAUNCH SCAN';
      updateProgress(100, 'Scan Complete');
    }
  }

  // ─── Terminal ───
  function clearTerminal() {
    terminal.innerHTML = '<div class="term-cursor" id="cursor">█</div>';
  }

  function termLog(type, message) {
    const cursor = terminal.querySelector('#cursor');
    const div = document.createElement('div');
    div.className = `term-line ${type}`;
    div.textContent = message;
    terminal.insertBefore(div, cursor);
    terminal.scrollTop = terminal.scrollHeight;
  }

  // ─── Progress ───
  function updateProgress(pct, label) {
    progressBar.style.width = pct + '%';
    progressLabel.textContent = label;
    progressPct.textContent = pct + '%';
  }

  function renderProgressModules(modules) {
    progressModules.innerHTML = modules.map(m =>
      `<span class="pmod pending" id="pmod-${slugify(m)}">${m}</span>`
    ).join('');
  }

  function updateModuleState(mod, state) {
    const el = document.getElementById(`pmod-${slugify(mod)}`);
    if (el) {
      el.className = `pmod ${state}`;
    }
  }

  function slugify(s) {
    return s.toLowerCase().replace(/[^a-z0-9]/g, '-');
  }

  // ─── Report ───
  function showReport(results) {
    reportSection.style.display = 'block';
    reportSection.scrollIntoView({ behavior: 'smooth' });

    const report = new ReportGenerator(results.findings, results.ports, results.meta);
    report.renderSummaryCards(summaryRow);
    report.renderFindings(findingsList, 'all');
    report.renderPortMap(portGrid);

    // Store report for export
    reportSection._report = report;
  }

  // ─── Filters ───
  function setupFilters() {
    filterTabs?.addEventListener('click', e => {
      const tab = e.target.closest('.ftab');
      if (!tab) return;
      filterTabs.querySelectorAll('.ftab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      const filter = tab.dataset.filter;
      if (reportSection._report) {
        reportSection._report.renderFindings(findingsList, filter);
      }
    });
  }

  // ─── Exports ───
  function setupExports() {
    document.getElementById('export-json')?.addEventListener('click', () => {
      reportSection._report?.exportJSON();
    });
    document.getElementById('export-html')?.addEventListener('click', () => {
      reportSection._report?.exportHTML();
    });
  }

  function setupNewScan() {
    document.getElementById('new-scan-btn')?.addEventListener('click', () => {
      reportSection.style.display = 'none';
      progressSection.style.display = 'none';
      targetInput.value = '';
      targetInput.focus();
      clearTerminal();
      termLog('dim', '// VulnScan Terminal v2.4.1 — Educational Use Only');
      termLog('dim', '// Configure target and press LAUNCH SCAN to begin');
      document.getElementById('scanner').scrollIntoView({ behavior: 'smooth' });
    });
  }

  // ─── Helpers ───
  function flashInput() {
    targetInput.closest('.input-wrapper').style.borderColor = 'var(--red)';
    targetInput.placeholder = 'Please enter a target URL or IP';
    setTimeout(() => {
      targetInput.closest('.input-wrapper').style.borderColor = '';
      targetInput.placeholder = 'https://example.com or 192.168.1.1';
    }, 2000);
  }

  function animateHeroRadar() {
    // Add some blips to the radar
    const visual = document.querySelector('.hero-visual');
    if (!visual) return;
    const angles = [30, 90, 150, 210, 270, 330];
    angles.forEach((angle, i) => {
      setTimeout(() => {
        const blip = document.createElement('div');
        blip.style.cssText = `
          position:absolute;
          width:6px;height:6px;
          border-radius:50%;
          background:var(--gold);
          box-shadow:0 0 8px var(--gold);
          top:calc(50% + ${Math.cos(angle * Math.PI / 180) * (80 + Math.random() * 80)}px);
          left:calc(50% + ${Math.sin(angle * Math.PI / 180) * (80 + Math.random() * 80)}px);
          animation:blink ${1 + Math.random()}s ease infinite;
        `;
        visual.appendChild(blip);
      }, i * 200);
    });
  }

  function setupNavHighlight() {
    const sections = document.querySelectorAll('.section, .hero');
    const links = document.querySelectorAll('.nav-link');
    const observer = new IntersectionObserver(entries => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          const id = entry.target.id;
          links.forEach(l => {
            l.classList.toggle('active', l.getAttribute('href') === `#${id}`);
          });
        }
      });
    }, { threshold: 0.4 });
    sections.forEach(s => observer.observe(s));
  }
})();
