const views = {
  login: document.getElementById("view-login"),
  dashboard: document.getElementById("view-dashboard"),
  config: document.getElementById("view-config"),
  register: document.getElementById("view-register"),
  baseline: document.getElementById("view-baseline"),
  situation: document.getElementById("view-situation"),
  defense: document.getElementById("view-defense"),
  av: document.getElementById("view-av"),
  edge: document.getElementById("view-edge")
};

const cidrEl = document.getElementById("cidr");
const modelEl = document.getElementById("model");
const portsEl = document.getElementById("ports");
const startBtn = document.getElementById("start");
const statusEl = document.getElementById("status");
const reportEl = document.getElementById("report");
const tableEl = document.getElementById("table");
const portTableEl = document.getElementById("port-table");
const intelEl = document.getElementById("intel");
const btnRemediate = document.getElementById("btn-remediate");
const remediationEl = document.getElementById("remediation");
const btnPrint = document.getElementById("btn-print");
const btnSitStart = document.getElementById("btn-sit-start");
const sitStatus = document.getElementById("sit-status");
const sitFeeds = document.getElementById("sit-feeds");
const sitIntel = document.getElementById("sit-intel");
const sitReport = document.getElementById("sit-report");
const btnSitPrint = document.getElementById("btn-sit-print");
const dfAuto = document.getElementById("df-auto");
const dfInterval = document.getElementById("df-interval");
const btnDfStart = document.getElementById("btn-df-start");
const btnDfStop = document.getElementById("btn-df-stop");
const dfStatus = document.getElementById("df-status");
const dfReport = document.getElementById("df-report");
const dfActions = document.getElementById("df-actions");
const btnDfPrint = document.getElementById("btn-df-print");
const avFile = document.getElementById("av-file");
const btnAvUpload = document.getElementById("btn-av-upload");
const avStatus = document.getElementById("av-status");
const avHash = document.getElementById("av-hash");
const btnAvHash = document.getElementById("btn-av-hash");
const avText = document.getElementById("av-text");
const btnAvPoison = document.getElementById("btn-av-poison");
const avPoison = document.getElementById("av-poison");
const avReport = document.getElementById("av-report");
const avStats = document.getElementById("av-stats");
const btnAvPrint = document.getElementById("btn-av-print");
const btnEdgeRefresh = document.getElementById("btn-edge-refresh");
const edgeTable = document.getElementById("edge-table");
const edgeGuide = document.getElementById("edge-guide");
const blPolicy = document.getElementById("bl-policy");
const blUseLast = document.getElementById("bl-use-last");
const btnBlStart = document.getElementById("btn-bl-start");
const blStatus = document.getElementById("bl-status");
const blReport = document.getElementById("bl-report");
const btnBlPrint = document.getElementById("btn-bl-print");
const statAssets = document.getElementById("stat-assets");
const statHigh = document.getElementById("stat-high");
const statMedium = document.getElementById("stat-medium");
const statLow = document.getElementById("stat-low");

const loginUsername = document.getElementById("login-username");
const loginPassword = document.getElementById("login-password");
const btnLogin = document.getElementById("btn-login");
const loginStatus = document.getElementById("login-status");
const regUsername = document.getElementById("reg-username");
const regPassword = document.getElementById("reg-password");
const regConfirm = document.getElementById("reg-confirm");
const btnRegister = document.getElementById("btn-register");
const regStatus = document.getElementById("reg-status");

const cfgKey = document.getElementById("cfg-key");
const cfgBase = document.getElementById("cfg-base");
const cfgModel = document.getElementById("cfg-model");
const cfgConcurrency = document.getElementById("cfg-concurrency");
const cfgTimeout = document.getElementById("cfg-timeout");
const cfgAdmin = document.getElementById("cfg-admin");
const btnSaveCfg = document.getElementById("btn-save-cfg");
const cfgStatus = document.getElementById("cfg-status");
const cfgBlacklist = document.getElementById("cfg-blacklist");
const cfgBlacklistEnabled = document.getElementById("cfg-blacklist-enabled");

const state = {
  token: localStorage.getItem("token") || "",
  lastScanId: "",
  lastResult: null
};

function setView(name) {
  Object.keys(views).forEach(k => {
    views[k].style.display = k === name ? "block" : "none";
  });
}

function headers() {
  const h = { "Content-Type": "application/json" };
  if (state.token) h["Authorization"] = `Bearer ${state.token}`;
  return h;
}

async function apiGet(url) {
  const r = await fetch(url, { headers: headers() });
  return r;
}

async function apiPost(url, body) {
  const r = await fetch(url, { method: "POST", headers: headers(), body: JSON.stringify(body || {}) });
  return r;
}

async function apiPut(url, body) {
  const r = await fetch(url, { method: "PUT", headers: headers(), body: JSON.stringify(body || {}) });
  return r;
}

function renderTable(assets) {
  const rows = [
    `<tr><th>主机</th><th>开放端口</th><th>风险</th></tr>`,
    ...assets.map(a => `<tr><td>${a.host}</td><td>${a.openPorts.join(", ")}</td><td data-risk="${riskForPorts(a.openPorts)}">${riskForPorts(a.openPorts)}</td></tr>`)
  ];
  tableEl.innerHTML = rows.join("");
}

async function poll(id) {
  statusEl.textContent = "扫描进行中";
  reportEl.textContent = "";
  tableEl.innerHTML = "";
  while (true) {
    const r = await apiGet(`/api/scan/${id}`);
    if (!r.ok) break;
    const data = await r.json();
    if (data.status === "running") {
      await new Promise(res => setTimeout(res, 1000));
      continue;
    }
    if (data.status === "error") {
      statusEl.textContent = `错误: ${data.error}`;
      break;
    }
    statusEl.textContent = "完成";
    renderSummary(data.result.summary || { assetCount: 0, portHistogram: {}, risks: [] });
    renderTable(data.result.scan.assets);
    renderIntel(data.result.intel || []);
    reportEl.textContent = data.result.report.content;
    state.lastResult = data.result;
    break;
  }
}

btnLogin.onclick = async () => {
  loginStatus.textContent = "";
  const r = await apiPost("/api/login", { username: loginUsername.value.trim(), password: loginPassword.value });
  if (!r.ok) {
    loginStatus.textContent = "登录失败";
    return;
  }
  const data = await r.json();
  state.token = data.token;
  localStorage.setItem("token", state.token);
  location.hash = "#/dashboard";
};

async function loadConfig() {
  const r = await apiGet("/api/config");
  if (!r.ok) return;
  const data = await r.json();
  cfgKey.value = data.deepseekApiKey || "";
  cfgBase.value = data.deepseekApiBase || "";
  cfgModel.value = data.deepseekModel || "";
  cfgConcurrency.value = data.scanner && data.scanner.concurrency || 256;
  cfgTimeout.value = data.scanner && data.scanner.timeoutMs || 1500;
  cfgAdmin.value = data.adminPassword || "";
  cfgBlacklist.value = Array.isArray(data.ipBlacklist) ? data.ipBlacklist.join(", ") : "";
  cfgBlacklistEnabled.checked = Boolean(data.ipBlacklistEnabled);
}

btnSaveCfg.onclick = async () => {
  cfgStatus.textContent = "";
  const body = {
    deepseekApiKey: cfgKey.value,
    deepseekApiBase: cfgBase.value,
    deepseekModel: cfgModel.value,
    adminPassword: cfgAdmin.value,
    scanner: { concurrency: Number(cfgConcurrency.value), timeoutMs: Number(cfgTimeout.value) },
    ipBlacklist: cfgBlacklist.value.trim() ? cfgBlacklist.value.split(/[,\s]+/).filter(Boolean) : [],
    ipBlacklistEnabled: cfgBlacklistEnabled.checked
  };
  const r = await apiPut("/api/config", body);
  cfgStatus.textContent = r.ok ? "保存成功" : "保存失败";
};

startBtn.onclick = async () => {
  const cidr = cidrEl.value.trim();
  const model = modelEl.value.trim();
  const ports = portsEl.value.trim() ? portsEl.value.split(/[\,\s]+/).map(x => Number(x)).filter(Boolean) : undefined;
  const r = await apiPost("/api/scan", { cidr, model: model || undefined, ports });
  if (!r.ok) {
    statusEl.textContent = "请求失败，请检查登录与配置";
    return;
    }
  const data = await r.json();
  state.lastScanId = data.id;
  poll(data.id);
};

btnRemediate.onclick = async () => {
  remediationEl.textContent = "";
  if (!state.lastScanId) { statusEl.textContent = "请先完成一次扫描"; return; }
  const r = await apiPost(`/api/remediation/${state.lastScanId}`);
  if (!r.ok) { remediationEl.textContent = "生成失败"; return; }
  const data = await r.json();
  remediationEl.textContent = data.raw || JSON.stringify(data, null, 2);
};

function init() {
  const hash = location.hash || "#/login";
  if (hash === "#/config") {
    if (!state.token) { location.hash = "#/login"; return; }
    setView("config");
    loadConfig();
  } else if (hash === "#/dashboard") {
    if (!state.token) { location.hash = "#/login"; return; }
    setView("dashboard");
  } else if (hash === "#/baseline") {
    if (!state.token) { location.hash = "#/login"; return; }
    setView("baseline");
  } else if (hash === "#/situation") {
    if (!state.token) { location.hash = "#/login"; return; }
    setView("situation");
  } else if (hash === "#/defense") {
    if (!state.token) { location.hash = "#/login"; return; }
    setView("defense");
    refreshDefenseStatus();
  } else if (hash === "#/av") {
    if (!state.token) { location.hash = "#/login"; return; }
    setView("av");
    loadAvStats();
  } else if (hash === "#/edge") {
    if (!state.token) { location.hash = "#/login"; return; }
    setView("edge");
    renderEdgeGuide();
    loadEdgeList();
  } else if (hash === "#/register") {
    setView("register");
  } else {
    setView("login");
  }
}

window.onhashchange = init;
init();
btnPrint.onclick = () => {
  const s = state.lastResult?.summary || { assetCount: 0, portHistogram: {}, risks: [], suggestions: [] };
  const assets = state.lastResult?.scan?.assets || [];
  const report = state.lastResult?.report?.content || "";
  const html = `<!doctype html><html><head><meta charset='utf-8'><title>扫描报告</title>
  <style>body{font-family:Arial,system-ui;padding:24px;color:#111}h1{margin:0 0 8px}h2{margin-top:16px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #999;padding:6px;text-align:left}</style>
  </head><body>
  <h1>信息资产安全评估报告</h1>
  <div>资产数量: ${s.assetCount}</div>
  <h2>端口分布</h2>
  <table><tr><th>端口</th><th>资产数</th></tr>${Object.keys(s.portHistogram).map(p=>`<tr><td>${p}</td><td>${s.portHistogram[p]}</td></tr>`).join('')}</table>
  <h2>资产与风险</h2>
  <table><tr><th>主机</th><th>端口</th><th>风险</th></tr>${assets.map(a=>`<tr><td>${a.host}</td><td>${a.openPorts.join(', ')}</td><td>${riskForPorts(a.openPorts)}</td></tr>`).join('')}</table>
  <h2>建议措施</h2>
  <ul>${(s.suggestions||[]).map(x=>`<li>${x}</li>`).join('')}</ul>
  <h2>AI评估报告</h2>
  <pre style='white-space:pre-wrap;border:1px solid #ccc;padding:12px'>${report}</pre>
  </body></html>`;
  const w = window.open('', '_blank');
  w.document.write(html);
  w.document.close();
  w.focus();
  w.print();
};

async function refreshDefenseStatus() {
  dfStatus.textContent = "";
  dfReport.textContent = "";
  dfActions.innerHTML = "";
  const r = await apiGet("/api/defense/status");
  if (!r.ok) return;
  const d = await r.json();
  dfStatus.textContent = `启用: ${d.enabled} | 上次: ${d.lastRunAt ? new Date(d.lastRunAt).toLocaleString() : '-'}`;
  dfReport.textContent = JSON.stringify(d.report || {}, null, 2);
  dfActions.innerHTML = (d.actions||[]).map(x => `<div>${new Date(x.appliedAt).toLocaleString()} — ${JSON.stringify(x.action)}</div>`).join("");
}

btnDfStart.onclick = async () => {
  dfStatus.textContent = "";
  const body = { intervalSec: Number(dfInterval.value), autoApply: dfAuto.checked };
  const r = await apiPost("/api/defense/start", body);
  dfStatus.textContent = r.ok ? "已启动" : "启动失败";
  refreshDefenseStatus();
};

btnDfStop.onclick = async () => {
  const r = await apiPost("/api/defense/stop", {});
  dfStatus.textContent = r.ok ? "已停止" : "停止失败";
  refreshDefenseStatus();
};

btnDfPrint.onclick = () => {
  const report = dfReport.textContent || "";
  const html = `<!doctype html><html><head><meta charset='utf-8'><title>自动防御报告</title>
  <style>body{font-family:Arial,system-ui;padding:24px;color:#111}h1{margin:0 0 8px}</style></head>
  <body><h1>自动防御报告</h1><pre style='white-space:pre-wrap;border:1px solid #ccc;padding:12px'>${report}</pre></body></html>`;
  const w = window.open('', '_blank');
  w.document.write(html);
  w.document.close();
  w.focus();
  w.print();
};

async function loadAvStats() {
  const r = await apiGet("/api/av/stats");
  if (!r.ok) return;
  const d = await r.json();
  const rows = ["<tr><th>病毒家族</th><th>出现次数</th></tr>", ...(d.top||[]).map(x => `<tr><td>${x.family}</td><td>${x.count}</td></tr>`)];
  avStats.innerHTML = rows.join("");
}

btnAvUpload.onclick = async () => {
  avStatus.textContent = "";
  avReport.textContent = "";
  const f = avFile && avFile.files && avFile.files[0];
  if (!f) { avStatus.textContent = "请选择文件"; return; }
  const fd = new FormData();
  fd.append("file", f);
  const r = await fetch("/api/av/upload", { method: "POST", headers: state.token ? { Authorization: `Bearer ${state.token}` } : {}, body: fd });
  if (!r.ok) { avStatus.textContent = "上传失败"; return; }
  const data = await r.json();
  pollAv(data.id);
};

btnAvHash.onclick = async () => {
  avStatus.textContent = "";
  avReport.textContent = "";
  const h = avHash.value.trim();
  if (!h) { avStatus.textContent = "请输入SHA256"; return; }
  const r = await apiPost("/api/av/hash", { hash: h });
  if (!r.ok) { avStatus.textContent = "查杀失败"; return; }
  const data = await r.json();
  pollAv(data.id);
};

async function pollAv(id) {
  avStatus.textContent = "查杀进行中";
  while (true) {
    const r = await apiGet(`/api/av/result/${id}`);
    if (!r.ok) break;
    const d = await r.json();
    if (d.status === "running") { await new Promise(res => setTimeout(res, 1000)); continue; }
    if (d.status === "error") { avStatus.textContent = `错误: ${d.error}`; break; }
    avStatus.textContent = "完成";
    const vt = d.result.vt || {};
    const fam = d.result.family || "Unknown";
    const head = `家族: ${fam}`;
    const vtstats = vt.ok && vt.data ? vt.data.stats : {};
    const vtstr = JSON.stringify(vtstats || {}, null, 2);
    const rep = d.result.report && d.result.report.content ? d.result.report.content : "";
    avReport.textContent = `${head}\n\nVT统计:\n${vtstr}\n\n分析报告:\n${rep}`;
    loadAvStats();
    break;
  }
}

btnAvPoison.onclick = async () => {
  avPoison.textContent = "";
  const text = avText.value || "";
  const r = await apiPost("/api/av/poison", { text });
  if (!r.ok) { avPoison.textContent = "检测失败"; return; }
  const d = await r.json();
  avPoison.textContent = typeof d === "string" ? d : JSON.stringify(d, null, 2);
};

btnAvPrint.onclick = () => {
  const content = avReport.textContent || "";
  const html = `<!doctype html><html><head><meta charset='utf-8'><title>病毒分析报告</title>
  <style>body{font-family:Arial,system-ui;padding:24px;color:#111}h1{margin:0 0 8px}pre{white-space:pre-wrap;border:1px solid #ccc;padding:12px}</style></head>
  <body><h1>病毒分析报告</h1><pre>${content}</pre></body></html>`;
  const w = window.open('', '_blank');
  w.document.write(html);
  w.document.close();
  w.focus();
  w.print();
};

btnSitStart.onclick = async () => {
  sitStatus.textContent = "";
  sitFeeds.innerHTML = "";
  sitIntel.innerHTML = "";
  sitReport.textContent = "";
  const r = await apiPost("/api/situational", {});
  if (!r.ok) { sitStatus.textContent = "启动失败"; return; }
  const data = await r.json();
  pollSituational(data.id);
};

async function pollSituational(id) {
  sitStatus.textContent = "分析进行中";
  while (true) {
    const r = await apiGet(`/api/situational/${id}`);
    if (!r.ok) break;
    const data = await r.json();
    if (data.status === "running") {
      await new Promise(res => setTimeout(res, 1000));
      continue;
    }
    if (data.status === "error") { sitStatus.textContent = `错误: ${data.error}`; break; }
    sitStatus.textContent = "完成";
    renderFeeds(data.result.feeds || {});
    renderIntelList(data.result.intel || []);
    sitReport.textContent = data.result.report.content || "";
    break;
  }
}

function renderFeeds(feeds) {
  const otx = (feeds.otxTrending || []).map(p => `<div><strong>${p.name}</strong> <span>${p.modified||""}</span> <span>${(p.tags||[]).join(',')}</span></div>`).join("");
  const kev = (feeds.cisaKev || []).map(x => `<div><strong>${x.cveID}</strong> ${x.vendorProject} ${x.product} ${x.vulnerabilityName} ${x.dateAdded}</div>`).join("");
  sitFeeds.innerHTML = `<h3>OTX Trending</h3>${otx}<h3>CISA KEV</h3>${kev}`;
}

function renderIntelList(items) {
  const blocks = items.map(i => {
    const vt = i.sources.virustotal ? `VT声誉: ${i.sources.virustotal.reputation}` : "";
    const otx = i.sources.otx ? `OTX脉冲: ${i.sources.otx.count}` : "";
    const shodan = i.sources.shodan ? `Shodan端口: ${(i.sources.shodan.ports||[]).join(',')}` : "";
    const abuse = i.sources.abuseipdb ? `AbuseIPDB分数: ${i.sources.abuseipdb.score}` : "";
    const lines = [vt, otx, shodan, abuse].filter(Boolean).join(" | ");
    return `<div><strong>${i.ip}</strong> — ${lines}</div>`;
  });
  sitIntel.innerHTML = blocks.join("");
}

btnSitPrint.onclick = () => {
  const report = sitReport.textContent || "";
  const html = `<!doctype html><html><head><meta charset='utf-8'><title>态势感知报告</title>
  <style>body{font-family:Arial,system-ui;padding:24px;color:#111}h1{margin:0 0 8px}</style></head>
  <body><h1>态势感知报告</h1><pre style='white-space:pre-wrap;border:1px solid #ccc;padding:12px'>${report}</pre></body></html>`;
  const w = window.open('', '_blank');
  w.document.write(html);
  w.document.close();
  w.focus();
  w.print();
};

btnBlStart.onclick = async () => {
  blStatus.textContent = "";
  blReport.textContent = "";
  const body = { policy: blPolicy.value, useLastScanId: blUseLast.checked, scanId: state.lastScanId };
  const r = await apiPost("/api/baseline", body);
  if (!r.ok) { blStatus.textContent = "启动失败"; return; }
  const data = await r.json();
  pollBaseline(data.id);
};

async function pollBaseline(id) {
  blStatus.textContent = "排查进行中";
  while (true) {
    const r = await apiGet(`/api/baseline/${id}`);
    if (!r.ok) break;
    const data = await r.json();
    if (data.status === "running") {
      await new Promise(res => setTimeout(res, 1000));
      continue;
    }
    if (data.status === "error") { blStatus.textContent = `错误: ${data.error}`; break; }
    blStatus.textContent = "完成";
    blReport.textContent = data.result.content || JSON.stringify(data.result, null, 2);
    break;
  }
}

btnBlPrint.onclick = () => {
  const content = blReport.textContent || "";
  const html = `<!doctype html><html><head><meta charset='utf-8'><title>基线排查报告</title>
  <style>body{font-family:Arial,system-ui;padding:24px;color:#111}h1{margin:0 0 8px}</style></head>
  <body><h1>基线排查报告</h1><pre style='white-space:pre-wrap;border:1px solid #ccc;padding:12px'>${content}</pre></body></html>`;
  const w = window.open('', '_blank');
  w.document.write(html);
  w.document.close();
  w.focus();
  w.print();
};
btnRegister.onclick = async () => {
  regStatus.textContent = "";
  const u = regUsername.value.trim();
  const p = regPassword.value;
  const c = regConfirm.value;
  if (!u || !p || p !== c) { regStatus.textContent = "请检查用户名与密码输入"; return; }
  const r = await apiPost("/api/register", { username: u, password: p });
  if (!r.ok) { regStatus.textContent = "注册失败"; return; }
  regStatus.textContent = "注册成功，请登录";
  location.hash = "#/login";
};
function renderPorts(hist) {
  const ports = Object.keys(hist).sort((a,b) => hist[b]-hist[a]);
  const rows = [ `<tr><th>端口</th><th>资产数</th></tr>`, ...ports.map(p => `<tr><td>${p}</td><td>${hist[p]}</td></tr>`) ];
  portTableEl.innerHTML = rows.join("");
}

function riskForPorts(ports) {
  const high = [445,139,3389,27017,6379];
  const medium = [22,3306,5432,8080];
  if (ports.some(p => high.includes(p))) return "高";
  if (ports.some(p => medium.includes(p))) return "中";
  return ports.length ? "低" : "无";
}

function renderSummary(summary) {
  statAssets.textContent = String(summary.assetCount);
  const high = summary.risks.filter(r => r.risk === "高").length;
  const medium = summary.risks.filter(r => r.risk === "中").length;
  const low = summary.risks.filter(r => r.risk === "低").length;
  statHigh.textContent = String(high);
  statMedium.textContent = String(medium);
  statLow.textContent = String(low);
  renderPorts(summary.portHistogram || {});
}

function renderIntel(intel) {
  const blocks = intel.map(i => {
    const otx = i.sources.otx ? `OTX脉冲: ${i.sources.otx.count}` : "";
    const shodan = i.sources.shodan ? `Shodan端口: ${(i.sources.shodan.ports||[]).join(',')}` : "";
    const abuse = i.sources.abuseipdb ? `AbuseIPDB分数: ${i.sources.abuseipdb.score}` : "";
    const lines = [otx, shodan, abuse].filter(Boolean).join(" | ");
    return `<div class="intel-item"><strong>${i.ip}</strong> — ${lines}</div>`;
  });
  intelEl.innerHTML = blocks.join("");
}

async function loadEdgeList() {
  const r = await apiGet("/api/edge/list");
  if (!r.ok) return;
  const d = await r.json();
  const rows = ["<tr><th>ID</th><th>名称</th><th>板卡</th><th>架构</th><th>最后在线</th></tr>", ...(d.list||[]).map(x => `<tr><td>${x.id}</td><td>${x.name}</td><td>${x.board}</td><td>${x.arch}</td><td>${x.lastSeen ? new Date(x.lastSeen).toLocaleString() : '-'}</td></tr>`)];
  edgeTable.innerHTML = rows.join("");
}

function renderEdgeGuide() {
  const url = location.origin;
  const text = [
    `1. 在香橙开发板上安装 Python3 与 MindSpore`,
    `2. 将 edge/agent.py 拷贝到设备上并配置环境变量 EDGE_SECRET`,
    `3. 运行: python3 agent.py --server ${url} --id <设备ID> --name <设备名>`,
    `4. 设备会注册并上报遥测，云端可下发查杀与扫描任务`
  ].join('\n');
  edgeGuide.textContent = text;
}

btnEdgeRefresh.onclick = () => { loadEdgeList(); };
