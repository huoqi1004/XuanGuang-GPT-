// 只包含app.js的前半部分
const views = {
  login: document.getElementById("view-login"),
  dashboard: document.getElementById("view-dashboard"),
  config: document.getElementById("view-config"),
  register: document.getElementById("view-register"),
  baseline: document.getElementById("view-baseline"),
  situation: document.getElementById("view-situation"),
  defense: document.getElementById("view-defense"),
  av: document.getElementById("view-av"),
  edge: document.getElementById("view-edge"),
  aiChat: document.getElementById("view-ai-chat"),
  ids: document.getElementById("view-ids"),
  logging: document.getElementById("view-logging"),
  incidentResponse: document.getElementById("view-incident-response")
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