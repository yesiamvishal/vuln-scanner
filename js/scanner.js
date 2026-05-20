/**
 * VulnScan — Scanner Engine
 * Simulates real-world vulnerability assessment for educational purposes
 */

class Scanner {
  constructor(options = {}) {
    this.target = options.target || '';
    this.profile = options.profile || 'quick';
    this.modules = options.modules || [];
    this.onLog = options.onLog || (() => {});
    this.onProgress = options.onProgress || (() => {});
    this.onModuleUpdate = options.onModuleUpdate || (() => {});
    this.findings = [];
    this.portResults = {};
    this.meta = {};
    this.aborted = false;
  }

  abort() { this.aborted = true; }

  async run() {
    this.findings = [];
    this.portResults = {};
    const results = { findings: [], ports: {}, meta: {} };

    this.log('info', `[*] VulnScan v2.4.1 initializing...`);
    this.log('info', `[*] Target: ${this.target}`);
    this.log('info', `[*] Profile: ${this.profile.toUpperCase()}`);
    this.log('info', `[*] Modules: ${this.modules.join(', ')}`);
    this.log('', '─'.repeat(52));

    await this.delay(400);

    // Parse target
    const targetInfo = this.parseTarget(this.target);
    this.meta = targetInfo;
    results.meta = targetInfo;

    this.log('success', `[+] Target resolved: ${targetInfo.host}`);
    this.log('success', `[+] Protocol: ${targetInfo.protocol}`);
    if (targetInfo.port) this.log('success', `[+] Port: ${targetInfo.port}`);
    await this.delay(300);

    // Run enabled modules
    const moduleMap = {
      'Port Scanner': () => this.runPortScan(),
      'HTTP Headers': () => this.runHeaderScan(),
      'SSL/TLS Audit': () => this.runSSLScan(),
      'CVE Lookup': () => this.runCVELookup(),
      'DNS Recon': () => this.runDNSRecon(),
      'WAF Detection': () => this.runWAFDetection(),
    };

    const totalModules = this.modules.length;
    let completed = 0;

    for (const mod of this.modules) {
      if (this.aborted) break;
      this.onModuleUpdate(mod, 'running');
      this.log('', '');
      this.log('warn', `[>] Starting module: ${mod}`);

      if (moduleMap[mod]) {
        const modFindings = await moduleMap[mod]();
        this.findings.push(...modFindings);
      }

      completed++;
      this.onModuleUpdate(mod, 'done');
      this.onProgress(Math.round((completed / totalModules) * 100), mod);
      await this.delay(200);
    }

    results.findings = this.findings;
    results.ports = this.portResults;
    results.meta = this.meta;

    this.log('', '');
    this.log('', '─'.repeat(52));
    this.log('success', `[✓] Scan complete. ${this.findings.length} findings.`);
    const counts = this.countBySeverity();
    if (counts.critical > 0) this.log('critical', `[!] CRITICAL: ${counts.critical} critical vulnerabilities found!`);
    if (counts.high > 0) this.log('error', `[!] HIGH: ${counts.high} high severity issues`);
    if (counts.medium > 0) this.log('warn', `[!] MEDIUM: ${counts.medium} medium severity issues`);
    if (counts.low > 0) this.log('info', `[~] LOW: ${counts.low} low severity issues`);
    if (counts.info > 0) this.log('', `[i] INFO: ${counts.info} informational findings`);

    return results;
  }

  parseTarget(target) {
    let url;
    try {
      url = new URL(target.includes('://') ? target : `https://${target}`);
    } catch {
      return { host: target, protocol: 'unknown', port: null, isIP: false };
    }
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    return {
      host: url.hostname,
      protocol: url.protocol.replace(':', ''),
      port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path: url.pathname,
      isIP: ipRegex.test(url.hostname),
      full: target,
    };
  }

  // ─── Port Scan ───
  async runPortScan() {
    const findings = [];
    const portsToScan = this.profile === 'quick'
      ? [21, 22, 23, 25, 80, 443, 445, 3306, 3389, 8080]
      : Object.keys(PORT_DB).map(Number);

    this.log('info', `[*] Scanning ${portsToScan.length} ports...`);
    await this.delay(300);

    const openPorts = this.simulateOpenPorts(portsToScan);

    for (const port of portsToScan) {
      if (this.aborted) break;
      const info = PORT_DB[port];
      const state = openPorts.includes(port) ? 'open' : (Math.random() < 0.15 ? 'filtered' : 'closed');
      this.portResults[port] = { state, ...info };

      if (state === 'open') {
        this.log('error', `[OPEN] ${port}/tcp  ${info?.name || 'unknown'}  — ${info?.desc || ''}`);

        // Generate finding for dangerous open ports
        if (info && (info.risk === 'critical' || info.risk === 'high')) {
          const portCVE = this.getPortCVE(port);
          if (portCVE) findings.push({ ...portCVE, port });
        }
      } else if (state === 'filtered') {
        this.log('warn', `[FILT] ${port}/tcp  ${info?.name || 'unknown'}`);
      }
      await this.delay(30 + Math.random() * 60);
    }

    this.log('success', `[+] Port scan complete. ${openPorts.length} open ports.`);
    return findings;
  }

  simulateOpenPorts(ports) {
    // Deterministically simulate based on target hash
    const hash = this.hashStr(this.target);
    const openCount = 3 + (hash % 5);
    const shuffled = [...ports].sort(() => this.seededRandom(hash) - 0.5);
    // Always open 80 or 443, sometimes add risky ports
    const always = ports.filter(p => p === 80 || p === 443);
    const risky = shuffled.filter(p => ![80, 443].includes(p)).slice(0, openCount - always.length);
    return [...always, ...risky];
  }

  getPortCVE(port) {
    const cveMap = {
      23: CVE_DB.find(c => c.id === 'PORT-001'),
      21: CVE_DB.find(c => c.id === 'PORT-002'),
      445: CVE_DB.find(c => c.id === 'PORT-003'),
      3389: CVE_DB.find(c => c.id === 'CVE-2019-0708'),
    };
    return cveMap[port] || null;
  }

  // ─── HTTP Header Scan ───
  async runHeaderScan() {
    const findings = [];
    this.log('info', `[*] Analyzing HTTP response headers...`);
    await this.delay(500);

    const headers = this.simulateHeaders();
    const securityHeaders = [
      'X-Frame-Options', 'Content-Security-Policy', 'Strict-Transport-Security',
      'X-Content-Type-Options', 'Referrer-Policy', 'Permissions-Policy'
    ];

    for (const [k, v] of Object.entries(headers)) {
      this.log('info', `    ${k}: ${v}`);
      await this.delay(50);
    }

    const missing = securityHeaders.filter(h => !headers[h]);

    if (missing.length > 0) {
      this.log('warn', `[!] Missing security headers: ${missing.join(', ')}`);
      findings.push({
        ...CVE_DB.find(c => c.id === 'MISCONFIG-001'),
        detail: `Missing: ${missing.join(', ')}`
      });
    }

    if (headers['Server'] && /\d/.test(headers['Server'])) {
      this.log('warn', `[!] Server version disclosed: ${headers['Server']}`);
      findings.push(CVE_DB.find(c => c.id === 'MISCONFIG-002'));
    }

    if (headers['X-Powered-By']) {
      this.log('warn', `[!] X-Powered-By disclosed: ${headers['X-Powered-By']}`);
    }

    if (!headers['Set-Cookie']?.includes('Secure') || !headers['Set-Cookie']?.includes('HttpOnly')) {
      this.log('warn', `[!] Cookie security flags missing`);
      findings.push(CVE_DB.find(c => c.id === 'INFO-001'));
    }

    this.log('success', `[+] Header analysis complete`);
    return findings.filter(Boolean);
  }

  simulateHeaders() {
    const hash = this.hashStr(this.target);
    const servers = ['Apache/2.4.41', 'nginx/1.18.0', 'Microsoft-IIS/10.0', 'Apache/2.2.34', 'nginx/1.14.2'];
    const server = servers[hash % servers.length];
    const headers = {
      'Server': server,
      'Content-Type': 'text/html; charset=UTF-8',
      'X-Powered-By': hash % 3 === 0 ? 'PHP/7.2.24' : undefined,
    };
    if (hash % 2 === 0) headers['X-Frame-Options'] = 'SAMEORIGIN';
    if (hash % 3 === 0) headers['Strict-Transport-Security'] = 'max-age=31536000';
    if (hash % 5 === 0) headers['Content-Security-Policy'] = "default-src 'self'";
    headers['Set-Cookie'] = hash % 2 === 0 ? 'session=abc; HttpOnly; Secure; SameSite=Lax' : 'session=abc; path=/';
    return Object.fromEntries(Object.entries(headers).filter(([, v]) => v !== undefined));
  }

  // ─── SSL/TLS Audit ───
  async runSSLScan() {
    const findings = [];
    this.log('info', `[*] Auditing SSL/TLS configuration...`);
    await this.delay(600);

    const hash = this.hashStr(this.target);
    const tlsVersions = ['TLSv1.3', 'TLSv1.2'];
    if (hash % 3 === 0) tlsVersions.push('TLSv1.1');
    if (hash % 5 === 0) tlsVersions.push('TLSv1.0');

    this.log('info', `[*] Supported TLS versions:`);
    for (const v of tlsVersions) {
      const isWeak = v === 'TLSv1.0' || v === 'TLSv1.1';
      this.log(isWeak ? 'warn' : 'success', `    ${v} — ${isWeak ? 'DEPRECATED' : 'OK'}`);
      await this.delay(100);
    }

    if (tlsVersions.includes('TLSv1.0') || tlsVersions.includes('TLSv1.1')) {
      findings.push(CVE_DB.find(c => c.id === 'SSL-002'));
    }

    const ciphers = ['TLS_AES_256_GCM_SHA384', 'ECDHE-RSA-AES128-GCM-SHA256'];
    if (hash % 4 === 0) ciphers.push('RC4-MD5', 'DES-CBC3-SHA');

    this.log('info', `[*] Cipher suites:`);
    for (const c of ciphers) {
      const isWeak = c.includes('RC4') || c.includes('DES');
      this.log(isWeak ? 'warn' : 'success', `    ${c} — ${isWeak ? 'WEAK' : 'OK'}`);
      await this.delay(80);
    }

    if (ciphers.some(c => c.includes('RC4') || c.includes('DES'))) {
      findings.push(CVE_DB.find(c => c.id === 'SSL-001'));
    }

    // Certificate check
    const certExpiry = 30 + (hash % 300);
    const certStatus = certExpiry < 30 ? 'EXPIRING SOON' : 'VALID';
    this.log(certExpiry < 30 ? 'warn' : 'success', `[+] Certificate: ${certStatus} (expires in ${certExpiry} days)`);

    // Heartbleed check
    if (hash % 7 === 0) {
      this.log('critical', `[!!!] HEARTBLEED VULNERABILITY DETECTED (CVE-2014-0160)`);
      findings.push(CVE_DB.find(c => c.id === 'CVE-2014-0160'));
    }

    this.log('success', `[+] SSL/TLS audit complete`);
    return findings.filter(Boolean);
  }

  // ─── CVE Lookup ───
  async runCVELookup() {
    const findings = [];
    this.log('info', `[*] Correlating software versions with CVE database...`);
    await this.delay(400);

    const hash = this.hashStr(this.target);
    const softwareKeys = Object.keys(SOFTWARE_CVE_MAP);
    const detected = softwareKeys.filter((_, i) => (hash + i) % 3 === 0).slice(0, 3);

    for (const sw of detected) {
      this.log('warn', `[!] Detected outdated software: ${sw}`);
      const cveIds = SOFTWARE_CVE_MAP[sw];
      for (const cveId of cveIds) {
        const cve = CVE_DB.find(c => c.id === cveId);
        if (cve) {
          this.log('error', `    → ${cve.id} (CVSS ${cve.cvss}) — ${cve.name}`);
          findings.push(cve);
        }
        await this.delay(100);
      }
    }

    // Random high-profile CVE based on profile
    if (this.profile === 'full') {
      if (hash % 6 === 0) {
        const log4shell = CVE_DB.find(c => c.id === 'CVE-2021-44228');
        this.log('critical', `[!!!] Log4Shell indicator detected in response headers`);
        findings.push(log4shell);
      }
    }

    // Directory listing check
    if (hash % 4 === 0) {
      this.log('warn', `[!] Directory listing enabled on /uploads/`);
      findings.push(CVE_DB.find(c => c.id === 'INFO-002'));
    }

    this.log('success', `[+] CVE correlation complete. ${findings.length} CVEs matched.`);
    return findings.filter(Boolean);
  }

  // ─── DNS Recon ───
  async runDNSRecon() {
    const findings = [];
    this.log('info', `[*] Performing DNS reconnaissance...`);
    await this.delay(300);

    const host = this.meta.host || this.target;
    const hash = this.hashStr(host);

    // Simulate subdomains
    const subdomains = ['www', 'mail', 'ftp', 'dev', 'staging', 'api', 'admin', 'vpn'];
    const found = subdomains.filter((_, i) => (hash + i) % 3 === 0);

    this.log('info', `[*] A records:`);
    this.log('success', `    ${host} → ${this.fakeIP(hash)}`);
    await this.delay(150);

    this.log('info', `[*] Subdomain enumeration:`);
    for (const sub of found) {
      const ip = this.fakeIP(hash + sub.charCodeAt(0));
      this.log('success', `    ${sub}.${host} → ${ip}`);
      await this.delay(80);
    }

    // MX records
    this.log('info', `[*] MX records:`);
    this.log('success', `    mail.${host} (priority 10)`);
    await this.delay(100);

    findings.push(CVE_DB.find(c => c.id === 'INFO-SCAN-001'));
    findings.push(CVE_DB.find(c => c.id === 'INFO-SCAN-002'));

    // Check for zone transfer
    if (hash % 8 === 0) {
      this.log('critical', `[!!!] DNS Zone Transfer allowed! Full zone exposed.`);
    }

    this.log('success', `[+] DNS recon complete. ${found.length + 1} hosts discovered.`);
    return findings.filter(Boolean);
  }

  // ─── WAF Detection ───
  async runWAFDetection() {
    const findings = [];
    this.log('info', `[*] Detecting Web Application Firewall...`);
    await this.delay(500);

    const hash = this.hashStr(this.target);
    const wafs = ['Cloudflare', 'AWS WAF', 'Akamai', 'Imperva', 'F5 BIG-IP', null];
    const detected = wafs[hash % wafs.length];

    if (detected) {
      this.log('success', `[+] WAF detected: ${detected}`);
      this.log('info', `[*] WAF bypass techniques may still apply`);
    } else {
      this.log('warn', `[!] No WAF detected — application exposed directly`);
    }

    this.log('success', `[+] WAF detection complete`);
    return findings;
  }

  // ─── Helpers ───
  log(type, message) {
    this.onLog(type, message);
  }

  delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  hashStr(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      hash = ((hash << 5) - hash) + str.charCodeAt(i);
      hash |= 0;
    }
    return Math.abs(hash);
  }

  seededRandom(seed) {
    const x = Math.sin(seed++) * 10000;
    return x - Math.floor(x);
  }

  fakeIP(seed) {
    const s = Math.abs(seed);
    return `${10 + (s % 240)}.${s % 256}.${(s * 7) % 256}.${(s * 13) % 254 + 1}`;
  }

  countBySeverity() {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of this.findings) {
      if (counts[f.severity] !== undefined) counts[f.severity]++;
    }
    return counts;
  }
}
