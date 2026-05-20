/**
 * VulnScan — Report Generator
 */

class ReportGenerator {
  constructor(findings, ports, meta) {
    this.findings = findings;
    this.ports = ports;
    this.meta = meta;
    this.timestamp = new Date().toISOString();
  }

  countBySeverity() {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of this.findings) {
      if (counts[f.severity] !== undefined) counts[f.severity]++;
    }
    return counts;
  }

  renderSummaryCards(container) {
    const counts = this.countBySeverity();
    const items = [
      { key: 'critical', label: 'Critical', icon: '💀' },
      { key: 'high', label: 'High', icon: '🔴' },
      { key: 'medium', label: 'Medium', icon: '🟡' },
      { key: 'low', label: 'Low', icon: '🔵' },
      { key: 'info', label: 'Info', icon: '⬜' },
    ];
    container.innerHTML = items.map(({ key, label }) => `
      <div class="sum-card ${key}">
        <span class="sum-num">${counts[key]}</span>
        <span class="sum-label">${label}</span>
      </div>
    `).join('');
  }

  renderFindings(container, filter = 'all') {
    const deduped = this.deduplicateFindings(this.findings);
    const filtered = filter === 'all' ? deduped : deduped.filter(f => f.severity === filter);

    if (filtered.length === 0) {
      container.innerHTML = `<div style="padding:32px;text-align:center;color:var(--white-dim);font-family:var(--ff-mono);font-size:0.8rem;">No findings for this filter.</div>`;
      return;
    }

    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    filtered.sort((a, b) => (severityOrder[a.severity] || 99) - (severityOrder[b.severity] || 99));

    container.innerHTML = filtered.map(f => `
      <div class="finding-item ${f.severity}" data-id="${f.id}" onclick="toggleFindingDetail('${f.id}')">
        <div>
          <span class="finding-badge badge-${f.severity}">${f.severity.toUpperCase()}</span>
        </div>
        <div class="finding-body">
          <h4>${f.name}</h4>
          <p>${f.description}</p>
          <div class="finding-meta">
            <span class="finding-tag">ID: ${f.id}</span>
            <span class="finding-tag">Category: ${f.category}</span>
            ${f.affected ? `<span class="finding-tag">Affects: ${f.affected[0]}</span>` : ''}
          </div>
          <div class="finding-detail" id="detail-${f.id}" style="display:none;margin-top:12px;padding:12px;background:var(--black);border:1px solid var(--border)">
            <p style="margin-bottom:8px;font-size:0.82rem;color:var(--gold);font-family:var(--ff-mono)">REMEDIATION:</p>
            <p style="font-size:0.82rem;color:var(--white-dim)">${f.remediation}</p>
            ${f.references && f.references.length > 0 ? `
              <p style="margin-top:8px;font-size:0.75rem;font-family:var(--ff-mono);color:var(--gold-dim)">REFERENCES:</p>
              ${f.references.map(r => `<a href="${r}" target="_blank" rel="noopener" style="display:block;font-size:0.72rem;color:var(--cyan);font-family:var(--ff-mono);word-break:break-all;">${r}</a>`).join('')}
            ` : ''}
          </div>
        </div>
        <div class="finding-cvss">${f.cvss > 0 ? `CVSS ${f.cvss.toFixed(1)}` : 'INFO'}</div>
      </div>
    `).join('');
  }

  renderPortMap(container) {
    const portNums = Object.keys(this.ports).map(Number).sort((a, b) => a - b);
    if (portNums.length === 0) {
      container.innerHTML = `<div style="color:var(--white-dim);font-size:0.8rem;font-family:var(--ff-mono)">No port data available.</div>`;
      return;
    }

    container.innerHTML = portNums.map(port => {
      const p = this.ports[port];
      const cls = p.state === 'open' ? 'port-open' : p.state === 'filtered' ? 'port-filtered' : 'port-closed';
      const tooltip = p.name ? `${p.name} — ${p.desc || p.state}` : p.state;
      return `<div class="port-item ${cls}" title="${tooltip}">${port}/${p.state === 'open' ? '🔴' : p.state === 'filtered' ? '🟡' : '⬜'} ${p.name || ''}</div>`;
    }).join('');
  }

  deduplicateFindings(findings) {
    const seen = new Set();
    return findings.filter(f => {
      if (!f || seen.has(f.id)) return false;
      seen.add(f.id);
      return true;
    });
  }

  exportJSON() {
    const data = {
      scanMeta: {
        tool: 'VulnScan v2.4.1',
        timestamp: this.timestamp,
        target: this.meta,
      },
      summary: this.countBySeverity(),
      findings: this.deduplicateFindings(this.findings),
      ports: this.ports,
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    this.download(blob, `vulnscan_report_${Date.now()}.json`);
  }

  exportHTML() {
    const counts = this.countBySeverity();
    const findings = this.deduplicateFindings(this.findings);
    const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>VulnScan Report — ${this.meta.host || 'Unknown'}</title>
<style>
  * { box-sizing:border-box; margin:0; padding:0 }
  body { background:#0a0a0a; color:#f0e6cc; font-family:Georgia,serif; padding:40px; }
  h1 { font-size:2rem; color:#c9a84c; border-bottom:2px solid #c9a84c; padding-bottom:16px; margin-bottom:24px }
  .meta { background:#111; border:1px solid #2a2a2a; padding:16px; margin-bottom:32px; font-family:monospace; font-size:0.85rem; }
  .meta p { margin:4px 0; color:#a09070 }
  .meta span { color:#e8c96a }
  .summary { display:flex; gap:16px; margin-bottom:32px }
  .sum { background:#111; border:1px solid #2a2a2a; padding:20px; text-align:center; flex:1 }
  .sum-num { font-size:2rem; font-weight:bold; display:block }
  .sum-label { font-size:0.7rem; color:#a09070; font-family:monospace; letter-spacing:0.1em }
  .critical .sum-num { color:#ff3333 }
  .high .sum-num { color:#ff8844 }
  .medium .sum-num { color:#c9a84c }
  .low .sum-num { color:#5599ff }
  .info .sum-num { color:#888 }
  .finding { border:1px solid #2a2a2a; margin-bottom:12px; padding:20px; border-left:4px solid }
  .finding.critical { border-left-color:#ff3333 }
  .finding.high { border-left-color:#ff8844 }
  .finding.medium { border-left-color:#c9a84c }
  .finding.low { border-left-color:#5599ff }
  .finding.info { border-left-color:#555 }
  .badge { font-family:monospace; font-size:0.65rem; padding:2px 8px; border:1px solid; display:inline-block; margin-bottom:10px }
  .badge-critical { color:#ff3333; border-color:#ff3333 }
  .badge-high { color:#ff8844; border-color:#ff8844 }
  .badge-medium { color:#c9a84c; border-color:#c9a84c }
  .badge-low { color:#5599ff; border-color:#5599ff }
  .badge-info { color:#888; border-color:#555 }
  h3 { color:#f0e6cc; margin-bottom:8px; font-size:1rem }
  p { color:#a09070; font-size:0.88rem; line-height:1.6 }
  .remed { background:#0d0d0d; border:1px solid #1a1a1a; padding:12px; margin-top:12px; font-size:0.82rem; color:#c9a84c }
  .footer { margin-top:40px; text-align:center; font-family:monospace; font-size:0.7rem; color:#2a2a2a }
  h2 { font-size:1.2rem; color:#c9a84c; margin:32px 0 16px; border-bottom:1px solid #1a1a1a; padding-bottom:8px }
</style>
</head>
<body>
<h1>VulnScan Vulnerability Report</h1>
<div class="meta">
  <p>Target: <span>${this.meta.host || this.meta.full || 'Unknown'}</span></p>
  <p>Protocol: <span>${this.meta.protocol || 'Unknown'}</span></p>
  <p>Scan Date: <span>${this.timestamp}</span></p>
  <p>Tool: <span>VulnScan v2.4.1 — Educational Use Only</span></p>
</div>

<h2>Summary</h2>
<div class="summary">
  <div class="sum critical"><span class="sum-num">${counts.critical}</span><span class="sum-label">CRITICAL</span></div>
  <div class="sum high"><span class="sum-num">${counts.high}</span><span class="sum-label">HIGH</span></div>
  <div class="sum medium"><span class="sum-num">${counts.medium}</span><span class="sum-label">MEDIUM</span></div>
  <div class="sum low"><span class="sum-num">${counts.low}</span><span class="sum-label">LOW</span></div>
  <div class="sum info"><span class="sum-num">${counts.info}</span><span class="sum-label">INFO</span></div>
</div>

<h2>Findings (${findings.length})</h2>
${findings.map(f => `
<div class="finding ${f.severity}">
  <span class="badge badge-${f.severity}">${f.severity.toUpperCase()}</span>
  ${f.cvss > 0 ? `<span style="float:right;font-family:monospace;font-size:0.8rem;color:#c9a84c">CVSS ${f.cvss.toFixed(1)}</span>` : ''}
  <h3>${f.name}</h3>
  <p style="margin-bottom:4px;font-family:monospace;font-size:0.7rem;color:#555">${f.id} · ${f.category}</p>
  <p>${f.description}</p>
  <div class="remed"><strong>Remediation:</strong> ${f.remediation}</div>
</div>`).join('')}

<div class="footer">VULNSCAN — Educational Penetration Testing Toolkit — ${this.timestamp}</div>
</body></html>`;
    const blob = new Blob([html], { type: 'text/html' });
    this.download(blob, `vulnscan_report_${Date.now()}.html`);
  }

  download(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }
}

function toggleFindingDetail(id) {
  const el = document.getElementById(`detail-${id}`);
  if (el) el.style.display = el.style.display === 'none' ? 'block' : 'none';
}
