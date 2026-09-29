const tls = require('tls');
const dns = require('dns').promises;
const net = require('net');

const isPrivate = (ip) =>
  /^(10\.|127\.|0\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip) ||
  ip === '::1' || /^(fc|fd|fe80)/i.test(ip);

function flagsFor(host) {
  const f = [];
  if (net.isIP(host)) f.push('IP address used as host');
  if (host.includes('xn--')) f.push('Punycode (lookalike) domain');
  if (/\.(xyz|ru|tk|top|click|zip)$/.test(host)) f.push('High-risk TLD');
  if (/(login|verify|secure|account|update|wallet)[-.]|[-.](login|verify|secure)/.test(host)) f.push('Phishing-style keywords');
  if (host.split('.').length > 4) f.push('Excessive subdomains');
  return f;
}

function sslCheck(host) {
  return new Promise((resolve) => {
    const s = tls.connect({ host, port: 443, servername: host, timeout: 5000 }, () => {
      const c = s.getPeerCertificate();
      const days = Math.floor((new Date(c.valid_to) - Date.now()) / 864e5);
      const ok = s.authorized && days > 0;
      s.end();
      resolve({ ok, days });
    });
    s.on('error', () => resolve({ ok: false, days: 0 }));
    s.on('timeout', () => { s.destroy(); resolve({ ok: false, days: 0 }); });
  });
}

async function missingHeaders(url) {
  try {
    const r = await fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(6000) });
    return ['strict-transport-security', 'content-security-policy', 'x-content-type-options', 'x-frame-options']
      .filter((h) => !r.headers.has(h));
  } catch { return null; }
}

async function safeBrowsing(url) {
  const key = process.env.SAFE_BROWSING_KEY;
  if (!key) return null;
  try {
    const r = await fetch('https://safebrowsing.googleapis.com/v4/threatMatches:find?key=' + key, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      signal: AbortSignal.timeout(5000),
      body: JSON.stringify({
        client: { clientId: 'webguard', clientVersion: '1.0' },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
          platformTypes: ['ANY_PLATFORM'], threatEntryTypes: ['URL'], threatEntries: [{ url }],
        },
      }),
    });
    const j = await r.json();
    return !!(j.matches && j.matches.length);
  } catch { return null; }
}

function parseTarget(input) {
  let u;
  try { u = new URL(/^https?:\/\//i.test(input) ? input : 'https://' + input); } catch { u = null; }
  if (!u || !['http:', 'https:'].includes(u.protocol) || !u.hostname.includes('.')) {
    const e = new Error('Enter a valid website address'); e.status = 400; throw e;
  }
  return u;
}

async function scan(input) {
  const u = parseTarget(input);
  const host = u.hostname.toLowerCase();
  // SSRF guard: never scan internal addresses
  let addrs;
  try { addrs = await dns.lookup(host, { all: true }); }
  catch { const e = new Error('Domain could not be resolved'); e.status = 400; throw e; }
  if (addrs.some((a) => isPrivate(a.address))) {
    const e = new Error('Private or internal addresses cannot be scanned'); e.status = 400; throw e;
  }
  const [ssl, hdrs, flagged] = await Promise.all([sslCheck(host), missingHeaders(u.href), safeBrowsing(u.href)]);
  const flags = flagsFor(host);
  let score = 100;
  if (!ssl.ok) score -= 40;
  else if (ssl.days < 14) score -= 10;
  score -= flags.length * 15;
  if (hdrs) score -= hdrs.length * 5; else score -= 10;
  if (flagged) score = Math.min(score, 10);
  score = Math.max(0, score);
  const status = score >= 75 ? 'safe' : score >= 45 ? 'warning' : 'threat';
  return {
    url: u.href, host, score, status,
    checks: [
      { k: 'Malware scan', v: flagged === null ? 'No feed configured' : flagged ? 'Threat found' : 'Clean', ok: !flagged },
      { k: 'Phishing check', v: flags.length ? flags[0] : 'Clean', ok: !flags.length },
      { k: 'SSL certificate', v: ssl.ok ? `Valid (${ssl.days}d left)` : 'Invalid or missing', ok: ssl.ok },
      { k: 'Security headers', v: hdrs ? (hdrs.length ? `${hdrs.length} missing` : 'All present') : 'Unreachable', ok: !!hdrs && !hdrs.length },
      { k: 'Domain reputation', v: score >= 75 ? 'Good' : score >= 45 ? 'Fair' : 'Poor', ok: score >= 75 },
    ],
  };
}
module.exports = { scan, isPrivate, flagsFor, parseTarget };
