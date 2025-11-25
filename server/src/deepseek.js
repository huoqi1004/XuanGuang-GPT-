import fetch from "node-fetch";
import { getConfig } from "./config.js";

function buildPrompt(scan) {
  const assets = scan.assets.map(a => ({ host: a.host, openPorts: a.openPorts }));
  const input = { cidr: scan.cidr, assets };
  const text = JSON.stringify(input);
  return "根据以下扫描数据生成信息资产安全评估报告，包含风险等级分布、端口分布、潜在漏洞、修复建议、加固优先级、合规影响、摘要，以及表格列出每个资产的开放端口与风险。输出中文并结构化。\n\n" + text;
}

export async function generateReport(scan, { model }) {
  const cfg = getConfig();
  const key = cfg.deepseekApiKey || process.env.DEEPSEEK_API_KEY;
  if (!key) {
    const assets = scan.assets.map(a => `主机: ${a.host}\n开放端口: ${a.openPorts.join(", ")}`).join("\n\n");
    const content = `未检测到DeepSeek密钥，生成基础报告。\n\n扫描网段: ${scan.cidr}\n资产数量: ${scan.assets.length}\n\n资产列表:\n\n${assets}\n\n建议: 关闭不必要端口，更新系统与服务版本，启用防火墙与入侵检测，实施最小权限原则，强化口令策略与多因素认证。`;
    return { model, content };
  }
  const base = cfg.deepseekApiBase || process.env.DEEPSEEK_API_BASE || "https://api.deepseek.com";
  const url = `${base}/v1/chat/completions`;
  const body = {
    model,
    messages: [
      { role: "system", content: "你是资深安全专家，生成严谨可执行的评估报告" },
      { role: "user", content: buildPrompt(scan) }
    ]
  };
  const r = await fetch(url, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${key}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify(body)
  });
  if (!r.ok) throw new Error(`DeepSeek API error ${r.status}`);
  const data = await r.json();
  const content = data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content ? data.choices[0].message.content : "";
  return { model, content };
}

export async function buildRemediationPlan(scan, summary) {
  const cfg = getConfig();
  const key = cfg.deepseekApiKey || process.env.DEEPSEEK_API_KEY;
  const base = cfg.deepseekApiBase || process.env.DEEPSEEK_API_BASE || "https://api.deepseek.com";
  const url = `${base}/v1/chat/completions`;
  const body = {
    model: cfg.deepseekModel || "deepseek-chat",
    messages: [
      { role: "system", content: "你是资深安全工程师，请产出安全漏洞自动修复的步骤与可执行命令，注意分类为网络设备、主机、数据库、应用服务，标注风险等级与回滚计划。不要执行，仅生成计划。" },
      { role: "user", content: `扫描摘要: ${JSON.stringify(summary)}\n资产详情: ${JSON.stringify(scan.assets)}\n请生成详细修复计划。` }
    ]
  };
  if (!key) {
    return { steps: ["由于缺少密钥，生成通用修复建议：关闭不必要端口、限制外网访问、更新系统与服务、启用多因素认证、强制最小权限、部署防火墙与IDS。"], commands: [], risk: "中" };
  }
  const r = await fetch(url, { method: "POST", headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" }, body: JSON.stringify(body) });
  if (!r.ok) return { steps: ["生成计划失败"], commands: [], risk: "未知" };
  const j = await r.json();
  const content = j.choices?.[0]?.message?.content || "";
  return { raw: content };
}

export async function generateBaselineReport(input) {
  const cfg = getConfig();
  const key = cfg.deepseekApiKey || process.env.DEEPSEEK_API_KEY;
  const base = cfg.deepseekApiBase || process.env.DEEPSEEK_API_BASE || "https://api.deepseek.com";
  const url = `${base}/v1/chat/completions`;
  const body = {
    model: cfg.deepseekModel || "deepseek-chat",
    messages: [
      { role: "system", content: "你是资深安全合规与蓝队专家，请根据输入资产与系统信息，基于指定基线策略产出详尽的基线排查报告。输出检查项清单（合规/不合规）、风险等级与原因、整改建议与优先级、验证方式与回滚方案。结构化且中文。" },
      { role: "user", content: `基线策略: ${input.policy}\n系统信息: ${JSON.stringify(input.system)}\n资产摘要: ${JSON.stringify({ assetCount: input.summary.assetCount, portHistogram: input.summary.portHistogram })}\n资产详情: ${JSON.stringify(input.scan.assets)}\n请生成基线排查报告与清单。` }
    ]
  };
  if (!key) {
    return { content: "未配置DeepSeek密钥，返回通用基线建议：关闭不必要端口、启用系统与网络防火墙、更新系统补丁与服务、关闭匿名或弱认证、强制口令复杂度与锁定策略、启用审计日志与时间同步、限制远控服务对外暴露。" };
  }
  const r = await fetch(url, { method: "POST", headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" }, body: JSON.stringify(body) });
  if (!r.ok) return { content: "生成失败" };
  const j = await r.json();
  const content = j.choices?.[0]?.message?.content || "";
  return { content };
}
export async function generateSituationReport({ assets, intel, feeds }) {
  const cfg = getConfig();
  const key = cfg.deepseekApiKey || process.env.DEEPSEEK_API_KEY;
  const base = cfg.deepseekApiBase || process.env.DEEPSEEK_API_BASE || "https://api.deepseek.com";
  const url = `${base}/v1/chat/completions`;
  const body = {
    model: cfg.deepseekModel || "deepseek-chat",
    messages: [
      { role: "system", content: "你是资深安全分析师，请基于输入资产与威胁情报源的最新数据，进行态势感知与研判，输出当前风险态势、关注重点、攻击面变化、与建议行动清单（按优先级）。给出可能相关的CVE或战术手法，并给出检测与防护建议。中文结构化输出。" },
      { role: "user", content: `资产: ${JSON.stringify(assets)}\n情报: ${JSON.stringify(intel)}\n趋势: ${JSON.stringify(feeds)}\n请生成态势感知报告。` }
    ]
  };
  if (!key) {
    return { content: "未配置DeepSeek密钥，返回通用态势建议：关注近期热门CVE与远控、数据库、SMB等对外暴露端口；优先加固高风险资产，更新补丁与关闭不必要端口，启用入侵检测与多因素认证，收敛攻击面并进行审计与备份演练。" };
  }
  const r = await fetch(url, { method: "POST", headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" }, body: JSON.stringify(body) });
  if (!r.ok) return { content: "生成失败" };
  const j = await r.json();
  const content = j.choices?.[0]?.message?.content || "";
  return { content };
}

export async function generateDefensePlan(context) {
  const cfg = getConfig();
  const key = cfg.deepseekApiKey || process.env.DEEPSEEK_API_KEY;
  const base = cfg.deepseekApiBase || process.env.DEEPSEEK_API_BASE || "https://api.deepseek.com";
  const url = `${base}/v1/chat/completions`;
  const body = {
    model: cfg.defense?.primaryModel || cfg.deepseekModel || "deepseek-chat",
    messages: [
      { role: "system", content: "你是资深安全防御专家。基于输入的资产与威胁情报，生成自动化防御行动计划：动作列表（如阻断端口/隔离资产/调整访问控制/开启审计），每个动作包含影响范围、风险、回滚方法与验证步骤。输出结构化JSON。禁止执行真实命令，只给出计划。" },
      { role: "user", content: `上下文: ${JSON.stringify(context)}` }
    ]
  };
  if (!key) return { plan: { actions: [], note: "缺少密钥，返回空计划" } };
  const r = await fetch(url, { method: "POST", headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" }, body: JSON.stringify(body) });
  if (!r.ok) return { plan: { actions: [], note: "生成失败" } };
  const j = await r.json();
  const content = j.choices?.[0]?.message?.content || "";
  let parsed = null;
  try { parsed = JSON.parse(content); } catch { parsed = { actions: [], raw: content }; }
  return { plan: parsed };
}

export async function guardValidatePlan(plan) {
  const cfg = getConfig();
  const key = cfg.deepseekApiKey || process.env.DEEPSEEK_API_KEY;
  const base = cfg.deepseekApiBase || process.env.DEEPSEEK_API_BASE || "https://api.deepseek.com";
  const url = `${base}/v1/chat/completions`;
  const body = {
    model: cfg.defense?.guardModel || cfg.deepseekModel || "deepseek-chat",
    messages: [
      { role: "system", content: "你是安全守护与模型安全审计专家。审查输入的自动化防御计划，判断是否安全、是否存在错误阻断或过度权限、是否可能导致服务不可用或绕过认证。输出审批结果（approve/reject）、风险评级与理由；如拒绝，提供修改建议。禁止生成可执行命令。" },
      { role: "user", content: `待审计划: ${JSON.stringify(plan)}` }
    ]
  };
  if (!key) return { approve: false, risk: "unknown", reason: "缺少密钥" };
  const r = await fetch(url, { method: "POST", headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" }, body: JSON.stringify(body) });
  if (!r.ok) return { approve: false, risk: "unknown", reason: "审查失败" };
  const j = await r.json();
  const content = j.choices?.[0]?.message?.content || "";
  let parsed = null;
  try { parsed = JSON.parse(content); } catch { parsed = { approve: false, raw: content }; }
  return parsed;
}
