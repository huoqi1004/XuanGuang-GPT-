import fetch from "node-fetch";
import { getConfig } from "./config.js";

async function safeJson(r) {
  try { return await r.json(); } catch { return null; }
}

export async function queryThreatIntel(ip) {
  const cfg = getConfig();
  const out = { ip, sources: {} };
  try {
    const r = await fetch(`https://otx.alienvault.com/api/v1/indicators/IPv4/${ip}/general`);
    if (r.ok) {
      const j = await safeJson(r);
      out.sources.otx = j && j.pulse_info ? { count: j.pulse_info.count, pulses: j.pulse_info.pulses?.slice(0, 3)?.map(p => ({ name: p.name, created: p.created })) } : null;
    }
  } catch {}
  if (cfg.shodanApiKey) {
    try {
      const r = await fetch(`https://api.shodan.io/shodan/host/${ip}?key=${cfg.shodanApiKey}`);
      if (r.ok) {
        const j = await safeJson(r);
        out.sources.shodan = j ? { ports: j.ports, tags: j.tags, city: j.city, org: j.org } : null;
      }
    } catch {}
  }
  if (cfg.abuseIpdbKey) {
    try {
      const r = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90`, { headers: { Key: cfg.abuseIpdbKey, Accept: "application/json" } });
      if (r.ok) {
        const j = await safeJson(r);
        const d = j && j.data ? j.data : null;
        out.sources.abuseipdb = d ? { score: d.abuseConfidenceScore, totalReports: d.totalReports } : null;
      }
    } catch {}
  }
  if (cfg.virustotalApiKey) {
    try {
      const r = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, { headers: { "x-apikey": cfg.virustotalApiKey } });
      if (r.ok) {
        const j = await safeJson(r);
        const d = j && j.data ? j.data : null;
        const rep = d && d.attributes ? d.attributes.reputation : null;
        out.sources.virustotal = rep !== null ? { reputation: rep } : null;
      }
    } catch {}
  }
  return out;
}

export async function queryGlobalFeeds() {
  const out = { otxTrending: [], cisaKev: [] };
  try {
    const r = await fetch(`https://otx.alienvault.com/api/v1/pulses/trending`);
    if (r.ok) {
      const j = await safeJson(r);
      const pulses = Array.isArray(j) ? j : (j && j.pulses ? j.pulses : []);
      out.otxTrending = pulses.slice(0, 10).map(p => ({ name: p.name, modified: p.modified, tags: p.tags }));
    }
  } catch {}
  try {
    const r = await fetch(`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`);
    if (r.ok) {
      const j = await safeJson(r);
      const v = j && j.vulnerabilities ? j.vulnerabilities : [];
      out.cisaKev = v.slice(0, 20).map(x => ({ cveID: x.cveID, vendorProject: x.vendorProject, product: x.product, vulnerabilityName: x.vulnerabilityName, dateAdded: x.dateAdded }));
    }
  } catch {}
  return out;
}
