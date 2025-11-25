import net from "net";

function ipToInt(ip) {
  return ip.split(".").reduce((acc, oct) => (acc << 8) + Number(oct), 0) >>> 0;
}

function intToIp(int) {
  return [24, 16, 8, 0].map(shift => (int >>> shift) & 255).join(".");
}

function parseCIDR(cidr) {
  const [base, bitsStr] = cidr.split("/");
  const bits = Number(bitsStr || 24);
  const baseInt = ipToInt(base);
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  const network = baseInt & mask;
  const hostCount = 2 ** (32 - bits);
  const start = network + 1;
  const end = network + hostCount - 2;
  return { start, end };
}

function tryConnect(host, port, timeoutMs) {
  return new Promise(resolve => {
    const socket = new net.Socket();
    let done = false;
    const finish = result => {
      if (done) return;
      done = true;
      try { socket.destroy(); } catch {}
      resolve(result);
    };
    socket.setTimeout(timeoutMs);
    socket.once("connect", () => finish({ open: true }));
    socket.once("timeout", () => finish({ open: false }));
    socket.once("error", () => finish({ open: false }));
    socket.connect(port, host);
  });
}

export function createScanner({ timeoutMs = 1500, concurrency = 128 } = {}) {
  const defaultPorts = [22, 80, 443, 3389, 445, 139, 8080, 3306, 5432, 6379, 27017];
  async function scanHost(host, ports) {
    const targets = (ports && ports.length ? ports : defaultPorts).slice();
    const results = [];
    for (const p of targets) {
      const r = await tryConnect(host, p, timeoutMs);
      if (r.open) results.push(p);
    }
    return { host, openPorts: results };
  }
  async function scanCIDR(cidr, ports) {
    const { start, end } = parseCIDR(cidr);
    const hosts = [];
    for (let i = start; i <= end; i++) hosts.push(intToIp(i >>> 0));
    const out = [];
    let i = 0;
    async function worker() {
      while (i < hosts.length) {
        const idx = i++;
        const h = hosts[idx];
        const r = await scanHost(h, ports);
        if (r.openPorts.length) out.push(r);
      }
    }
    const workers = Array.from({ length: concurrency }, () => worker());
    await Promise.all(workers);
    return { cidr, assets: out, timestamp: Date.now() };
  }
  return { scanHost, scanCIDR };
}
