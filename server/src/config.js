import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dataDir = path.join(__dirname, "..", "data");
const cfgPath = path.join(dataDir, "config.json");

let cfg = null;

function ensureFile() {
  if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
  if (!fs.existsSync(cfgPath)) {
    const def = {
      deepseekApiKey: "",
      deepseekApiBase: "https://api.deepseek.com",
      deepseekModel: "deepseek-chat",
      shodanApiKey: "",
      abuseIpdbKey: "",
      virustotalApiKey: "",
      mispBaseUrl: "",
      mispApiKey: "",
      users: [],
      adminPassword: process.env.ADMIN_PASSWORD || "admin123",
      scanner: { concurrency: 256, timeoutMs: 1500 },
      defense: { enabled: false, intervalSec: 120, autoApply: false, primaryModel: "deepseek-chat", guardModel: "deepseek-chat", guardThreshold: "medium", maxActionsPerRun: 10 },
      ipBlacklistEnabled: true,
      ipBlacklist: [],
      edgeEnabled: true,
      edgeSecret: ""
    };
    fs.writeFileSync(cfgPath, JSON.stringify(def, null, 2));
  }
}

export function loadConfig() {
  ensureFile();
  const raw = fs.readFileSync(cfgPath, "utf8");
  cfg = JSON.parse(raw);
  return cfg;
}

export function getConfig() {
  if (!cfg) loadConfig();
  return cfg;
}

export function saveConfig(next) {
  cfg = { ...getConfig(), ...next };
  fs.writeFileSync(cfgPath, JSON.stringify(cfg, null, 2));
  return cfg;
}
