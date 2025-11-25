function normalizeIp(ip) {
  if (!ip) return "";
  if (ip.startsWith("::ffff:")) return ip.slice(7);
  if (ip.includes("%")) return ip.split("%")[0];
  return ip;
}

function ipToInt(ip) {
  const parts = ip.split(".").map(x => Number(x));
  if (parts.length !== 4 || parts.some(x => Number.isNaN(x))) return null;
  return ((parts[0] << 24) >>> 0) + ((parts[1] << 16) >>> 0) + ((parts[2] << 8) >>> 0) + (parts[3] >>> 0);
}

function inCIDR(ip, cidr) {
  const [base, bitsStr] = cidr.split("/");
  const bits = Number(bitsStr || 32);
  const ipInt = ipToInt(ip);
  const baseInt = ipToInt(base);
  if (ipInt === null || baseInt === null) return false;
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return (ipInt & mask) === (baseInt & mask);
}

function match(ip, list) {
  for (const entry of list) {
    const e = String(entry || "").trim();
    if (!e) continue;
    if (e.includes("/")) { if (inCIDR(ip, e)) return true; } else { if (ip === e) return true; }
  }
  return false;
}

export function ipBlocker(getConfig) {
  return (req, res, next) => {
    const cfg = getConfig();
    const enabled = Boolean(cfg.ipBlacklistEnabled);
    const list = Array.isArray(cfg.ipBlacklist) ? cfg.ipBlacklist : [];
    if (!enabled || list.length === 0) return next();
    const forwarded = (req.headers["x-forwarded-for"] || "").split(",")[0].trim();
    const remote = normalizeIp(forwarded || req.ip || (req.connection && req.connection.remoteAddress) || "");
    if (remote && match(remote, list)) return res.status(403).json({ error: "blocked" });
    next();
  };
}
