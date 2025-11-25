import express from "express";
import cors from "cors";
import { createScanner } from "./scanner.js";
import { generateReport } from "./deepseek.js";
import { getConfig, saveConfig, loadConfig } from "./config.js";
import { requireAuth, createToken, validatePassword, verifyUser, registerUser } from "./auth.js";
import { queryThreatIntel, queryGlobalFeeds } from "./intel.js";
import { generateSituationReport, generateDefensePlan, guardValidatePlan } from "./deepseek.js";
import { ipBlocker } from "./ipfilter.js";
import multer from "multer";
import { hashBuffer, quarantineWrite, vtLookupByHash, generateMalwareReport, analyzePoisoning } from "./av.js";

const app = express();
app.use(cors());
app.use(express.json());
app.use(ipBlocker(getConfig));

const scans = new Map();
const baselines = new Map();
const situations = new Map();
const defense = { enabled: false, timer: null, lastRunAt: 0, lastReport: null, actions: [] };
const avTasks = new Map();
const avStats = new Map();
const edgeDevices = new Map();
const edgeTasks = new Map();
loadConfig();

app.post("/api/scan", requireAuth, async (req, res) => {
  const { cidr, ports, model } = req.body || {};
  const id = Math.random().toString(36).slice(2);
  scans.set(id, { status: "running", result: null, error: null });
  res.json({ id });
  const cfg = getConfig();
  const scanner = createScanner({ timeoutMs: cfg.scanner.timeoutMs, concurrency: cfg.scanner.concurrency });
  try {
    const scanResult = await scanner.scanCIDR(cidr || "192.168.0.0/24", ports || undefined);
    const summary = buildSummary(scanResult);
    const intelEnabled = true;
    let intel = [];
    if (intelEnabled) {
      for (const a of scanResult.assets) {
        try { intel.push(await queryThreatIntel(a.host)); } catch {}
      }
    }
    const report = await generateReport(scanResult, { model: model || getConfig().deepseekModel || process.env.DEEPSEEK_MODEL || "deepseek-chat" });
    scans.set(id, { status: "done", result: { scan: scanResult, summary, intel, report }, error: null });
  } catch (e) {
    scans.set(id, { status: "error", result: null, error: String(e && e.message ? e.message : e) });
  }
});

app.get("/api/scan/:id", requireAuth, (req, res) => {
  const doc = scans.get(req.params.id);
  if (!doc) return res.status(404).json({ error: "not_found" });
  res.json(doc);
});

app.post("/api/login", (req, res) => {
  const { username, password } = req.body || {};
  const isAdmin = String(username || "") === "admin" && validatePassword(password);
  const isUser = verifyUser(String(username || ""), String(password || ""));
  if (!isAdmin && !isUser) return res.status(401).json({ error: "invalid_credentials" });
  const token = createToken();
  res.json({ token, user: { name: username || "admin" } });
});

app.post("/api/register", (req, res) => {
  const { username, password } = req.body || {};
  try {
    const u = registerUser(String(username || ""), String(password || ""));
    res.json({ ok: true, user: { name: u.username } });
  } catch (e) {
    res.status(400).json({ error: String(e && e.message ? e.message : e) });
  }
});

app.get("/api/config", requireAuth, (req, res) => {
  res.json(getConfig());
});

app.put("/api/config", requireAuth, (req, res) => {
  const next = req.body || {};
  const saved = saveConfig(next);
  res.json(saved);
});

function riskForPorts(ports) {
  const high = [445, 139, 3389, 27017, 6379];
  const medium = [22, 3306, 5432, 8080];
  if (ports.some(p => high.includes(p))) return "高";
  if (ports.some(p => medium.includes(p))) return "中";
  return ports.length ? "低" : "无";
}

function buildSummary(scan) {
  const assetCount = scan.assets.length;
  const portHistogram = {};
  const risks = [];
  for (const a of scan.assets) {
    for (const p of a.openPorts) portHistogram[p] = (portHistogram[p] || 0) + 1;
    risks.push({ host: a.host, risk: riskForPorts(a.openPorts) });
  }
  const suggestions = [
    "关闭不必要端口并限制外网访问",
    "启用防火墙与入侵检测并定期审计",
    "更新操作系统与服务版本，消除已知漏洞",
    "实施最小权限与强口令策略，启用多因素认证",
    "对数据库与远控端口进行访问白名单与加固"
  ];
  return { assetCount, portHistogram, risks, suggestions };
}

app.post("/api/remediation/:id", requireAuth, async (req, res) => {
  const id = req.params.id;
  const doc = scans.get(id);
  if (!doc || !doc.result) return res.status(404).json({ error: "not_found" });
  const plan = await buildRemediationPlan(doc.result.scan, doc.result.summary);
  res.json({ plan, note: "为安全起见，仅生成修复计划，不执行真实修复。" });
});

app.use(express.static("../web"));

const port = process.env.PORT ? Number(process.env.PORT) : 8787;
app.listen(port, () => {});

function rateLimiter({ windowMs = 60000, max = 60 } = {}) {
  const hits = new Map();
  return (req, res, next) => {
    const key = (req.headers["authorization"] || "") + ":" + (req.ip || "");
    const now = Date.now();
    const arr = hits.get(key) || [];
    const recent = arr.filter(ts => now - ts < windowMs);
    recent.push(now);
    hits.set(key, recent);
    if (recent.length > max) return res.status(429).json({ error: "rate_limited" });
    next();
  };
}

app.use(rateLimiter({ windowMs: 60000, max: 120 }));

app.post("/api/baseline", requireAuth, async (req, res) => {
  const { policy, useLastScanId, scanId } = req.body || {};
  const id = Math.random().toString(36).slice(2);
  baselines.set(id, { status: "running", result: null, error: null });
  res.json({ id });
  try {
    const currentScanId = useLastScanId ? Array.from(scans.keys()).pop() : scanId;
    const scanDoc = currentScanId ? scans.get(currentScanId) : null;
    const scanResult = scanDoc && scanDoc.result ? scanDoc.result.scan : { cidr: "", assets: [], timestamp: Date.now() };
    const summary = scanDoc && scanDoc.result ? scanDoc.result.summary : { assetCount: 0, portHistogram: {}, risks: [], suggestions: [] };
    const system = buildSystemInfo();
    const baseline = await generateBaselineReport({ policy: policy || "CIS_Level1", scan: scanResult, summary, system });
    baselines.set(id, { status: "done", result: baseline, error: null });
  } catch (e) {
    baselines.set(id, { status: "error", result: null, error: String(e && e.message ? e.message : e) });
  }
});

app.get("/api/baseline/:id", requireAuth, (req, res) => {
  const doc = baselines.get(req.params.id);
  if (!doc) return res.status(404).json({ error: "not_found" });
  res.json(doc);
});

function buildSystemInfo() {
  const os = process.platform;
  const release = process.release && process.release.name ? process.release.name : "node";
  const node = process.versions && process.versions.node ? process.versions.node : "";
  const uptime = Math.round(process.uptime());
  return { os, release, node, uptime };
}

app.post("/api/situational", requireAuth, async (req, res) => {
  const id = Math.random().toString(36).slice(2);
  situations.set(id, { status: "running", result: null, error: null });
  res.json({ id });
  try {
    const latestScanId = Array.from(scans.keys()).pop();
    const scanDoc = latestScanId ? scans.get(latestScanId) : null;
    const assets = scanDoc && scanDoc.result ? scanDoc.result.scan.assets : [];
    const intel = [];
    for (const a of assets) {
      try { intel.push(await queryThreatIntel(a.host)); } catch {}
    }
    const feeds = await queryGlobalFeeds();
    const report = await generateSituationReport({ assets, intel, feeds });
    situations.set(id, { status: "done", result: { assetsCount: assets.length, feeds, intel, report }, error: null });
  } catch (e) {
    situations.set(id, { status: "error", result: null, error: String(e && e.message ? e.message : e) });
  }
});

app.get("/api/situational/:id", requireAuth, (req, res) => {
  const doc = situations.get(req.params.id);
  if (!doc) return res.status(404).json({ error: "not_found" });
  res.json(doc);
});

app.post("/api/defense/start", requireAuth, (req, res) => {
  const cfg = getConfig();
  const { intervalSec, autoApply } = req.body || {};
  const iv = Number(intervalSec || cfg.defense.intervalSec || 120);
  const apply = Boolean(autoApply ?? cfg.defense.autoApply ?? false);
  if (defense.timer) clearInterval(defense.timer);
  defense.enabled = true;
  defense.timer = setInterval(async () => {
    await runDefenseCycle({ autoApply: apply });
  }, Math.max(30, iv) * 1000);
  res.json({ ok: true, enabled: true, intervalSec: iv, autoApply: apply });
});

app.post("/api/defense/stop", requireAuth, (req, res) => {
  defense.enabled = false;
  if (defense.timer) { clearInterval(defense.timer); defense.timer = null; }
  res.json({ ok: true, enabled: false });
});

app.get("/api/defense/status", requireAuth, (req, res) => {
  res.json({ enabled: defense.enabled, lastRunAt: defense.lastRunAt, report: defense.lastReport, actions: defense.actions.slice(-50) });
});

async function runDefenseCycle({ autoApply }) {
  try {
    const latestScanId = Array.from(scans.keys()).pop();
    const scanDoc = latestScanId ? scans.get(latestScanId) : null;
    const assets = scanDoc && scanDoc.result ? scanDoc.result.scan.assets : [];
    const feeds = await queryGlobalFeeds();
    const intel = [];
    for (const a of assets) {
      try { intel.push(await queryThreatIntel(a.host)); } catch {}
    }
    const context = { assets, feeds, intel };
    const planRes = await generateDefensePlan(context);
    const guardRes = await guardValidatePlan(planRes.plan);
    const maxActions = getConfig().defense?.maxActionsPerRun || 10;
    const actions = Array.isArray(planRes.plan.actions) ? planRes.plan.actions.slice(0, maxActions) : [];
    const applied = [];
    if (autoApply && guardRes && (guardRes.approve === true || String(guardRes.approve).toLowerCase() === "true")) {
      for (const act of actions) {
        applied.push({ action: act, appliedAt: Date.now(), status: "simulated" });
      }
    }
    defense.lastRunAt = Date.now();
    defense.lastReport = { guard: guardRes, plan: planRes.plan };
    defense.actions.push(...applied);
  } catch (e) {
    defense.lastReport = { error: String(e && e.message ? e.message : e) };
  }
}
const upload = multer({ storage: multer.memoryStorage() });

app.post("/api/av/upload", requireAuth, upload.single("file"), async (req, res) => {
  const id = Math.random().toString(36).slice(2);
  avTasks.set(id, { status: "running", result: null, error: null });
  res.json({ id });
  try {
    const cfg = getConfig();
    const max = (cfg.av?.maxUploadSizeMB || 10) * 1024 * 1024;
    const buf = req.file && req.file.buffer ? req.file.buffer : Buffer.from("");
    if (buf.length > max) throw new Error("file_too_large");
    const hash = hashBuffer(buf);
    quarantineWrite(hash, req.file.originalname || "file", buf);
    const vt = await vtLookupByHash(hash);
    const fam = vt && vt.ok && vt.data && vt.data.family ? vt.data.family : "Unknown";
    avStats.set(fam, (avStats.get(fam) || 0) + 1);
    const ctx = { hash, name: req.file.originalname || "file", size: buf.length, vt: vt, statsTop: Array.from(avStats.entries()).sort((a,b)=>b[1]-a[1]).slice(0,10) };
    const report = await generateMalwareReport(ctx);
    avTasks.set(id, { status: "done", result: { hash, vt, report, family: fam }, error: null });
  } catch (e) {
    avTasks.set(id, { status: "error", result: null, error: String(e && e.message ? e.message : e) });
  }
});

app.post("/api/av/hash", requireAuth, async (req, res) => {
  const { hash } = req.body || {};
  const id = Math.random().toString(36).slice(2);
  avTasks.set(id, { status: "running", result: null, error: null });
  res.json({ id });
  try {
    const vt = await vtLookupByHash(String(hash || ""));
    const fam = vt && vt.ok && vt.data && vt.data.family ? vt.data.family : "Unknown";
    avStats.set(fam, (avStats.get(fam) || 0) + 1);
    const ctx = { hash, vt, statsTop: Array.from(avStats.entries()).sort((a,b)=>b[1]-a[1]).slice(0,10) };
    const report = await generateMalwareReport(ctx);
    avTasks.set(id, { status: "done", result: { hash, vt, report, family: fam }, error: null });
  } catch (e) {
    avTasks.set(id, { status: "error", result: null, error: String(e && e.message ? e.message : e) });
  }
});

app.get("/api/av/result/:id", requireAuth, (req, res) => {
  const doc = avTasks.get(req.params.id);
  if (!doc) return res.status(404).json({ error: "not_found" });
  res.json(doc);
});

app.get("/api/av/stats", requireAuth, (req, res) => {
  const top = Array.from(avStats.entries()).sort((a,b)=>b[1]-a[1]).slice(0,20).map(([k,v])=>({ family:k, count:v }));
  res.json({ top });
});

app.post("/api/av/poison", requireAuth, async (req, res) => {
  const { text } = req.body || {};
  try {
    const r = await analyzePoisoning(String(text || ""));
    res.json(r);
  } catch (e) {
    res.status(500).json({ error: String(e && e.message ? e.message : e) });
  }
});

app.post("/api/edge/register", async (req, res) => {
  const cfg = getConfig();
  const sec = cfg.edgeSecret || "";
  const got = String(req.headers["x-edge-secret"] || "");
  if (sec && sec !== got) return res.status(401).json({ error: "unauthorized" });
  const id = String(req.body?.id || Math.random().toString(36).slice(2));
  const info = {
    id,
    name: String(req.body?.name || "edge"),
    board: String(req.body?.board || "unknown"),
    arch: String(req.body?.arch || ""),
    ip: String(req.ip || ""),
    capabilities: req.body?.capabilities || [],
    lastSeen: Date.now()
  };
  edgeDevices.set(id, info);
  res.json({ ok: true, id });
});

app.post("/api/edge/telemetry", async (req, res) => {
  const cfg = getConfig();
  const sec = cfg.edgeSecret || "";
  const got = String(req.headers["x-edge-secret"] || "");
  if (sec && sec !== got) return res.status(401).json({ error: "unauthorized" });
  const id = String(req.body?.id || "");
  const dev = edgeDevices.get(id);
  if (!dev) return res.status(404).json({ error: "not_found" });
  dev.lastSeen = Date.now();
  dev.telemetry = req.body?.telemetry || {};
  edgeDevices.set(id, dev);
  res.json({ ok: true });
});

app.get("/api/edge/tasks", async (req, res) => {
  const cfg = getConfig();
  const sec = cfg.edgeSecret || "";
  const got = String(req.headers["x-edge-secret"] || "");
  if (sec && sec !== got) return res.status(401).json({ error: "unauthorized" });
  const id = String(req.query?.id || "");
  const q = edgeTasks.get(id) || [];
  edgeTasks.set(id, []);
  res.json({ tasks: q });
});

app.post("/api/edge/taskresult", async (req, res) => {
  const cfg = getConfig();
  const sec = cfg.edgeSecret || "";
  const got = String(req.headers["x-edge-secret"] || "");
  if (sec && sec !== got) return res.status(401).json({ error: "unauthorized" });
  const id = String(req.body?.id || "");
  const dev = edgeDevices.get(id);
  if (!dev) return res.status(404).json({ error: "not_found" });
  dev.lastSeen = Date.now();
  dev.lastResult = req.body?.result || {};
  edgeDevices.set(id, dev);
  res.json({ ok: true });
});

app.get("/api/edge/list", requireAuth, (req, res) => {
  const list = Array.from(edgeDevices.values()).map(x => ({ id: x.id, name: x.name, board: x.board, arch: x.arch, lastSeen: x.lastSeen, telemetry: x.telemetry || {} }));
  res.json({ list });
});
