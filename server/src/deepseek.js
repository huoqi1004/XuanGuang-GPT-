import fetch from "node-fetch";
import { getConfig } from "./config.js";
// 使用动态导入来避免CommonJS和ES模块的兼容性问题
let mlIntegration = null;
async function getMlIntegration() {
  if (!mlIntegration) {
    try {
      // 尝试使用动态导入
      mlIntegration = await import("./ml/ml_integration.js");
      // 如果是CommonJS模块，取default导出
      if (mlIntegration && typeof mlIntegration === 'object' && 'default' in mlIntegration) {
        mlIntegration = mlIntegration.default;
      }
    } catch (e) {
      console.error("Failed to load ML integration:", e);
      // 创建一个模拟对象以便系统继续工作
      mlIntegration = {
        sendMessage: async () => ({
          response: "ML模型集成失败，使用默认响应。请检查Python环境和模型路径。"
        })
      };
    }
  }
  return mlIntegration;
}

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

// 使用本地机器学习模型处理对话
async function generateLocalChatResponse(messages) {
  try {
    // 获取ML集成对象
    const ml = await getMlIntegration();
    
    // 准备发送给本地模型的数据
    const lastUserMessage = messages
      .filter(msg => msg.role === 'user')
      .pop()?.content || '';
    
    // 发送给本地模型进行处理
    const result = await ml.sendMessage({
      action: 'chat_completion',
      messages: messages,
      query: lastUserMessage
    });
    
    return {
      model: "本地安全模型",
      content: result.response || "本地模型处理失败，无法生成回复。"
    };
  } catch (error) {
    console.error("Local ML model error:", error);
    // 如果本地模型失败，提供回退响应
    return {
      model: "本地安全模型(回退)",
      content: "我是本地安全AI助手。虽然无法连接到高级模型，但我可以提供基本的安全知识和建议。请提出您的问题，我将尽力帮助。\n\n常见安全问题包括：\n- 网络漏洞扫描与防护\n- 恶意软件检测与分析\n- 安全加固最佳实践\n- 威胁情报分析\n- 事件响应与恢复"
    };
  }
}

// AI对话功能 - 支持混合模型
export async function generateChatResponse(messages) {
  const cfg = getConfig();
  const key = cfg.deepseekApiKey || process.env.DEEPSEEK_API_KEY;
  const model = cfg.deepseekModel || "deepseek-chat";
  const useLocalModel = cfg.useLocalModel || false;
  
  // 确保消息格式正确
  const formattedMessages = messages.map(msg => ({
    role: msg.role,
    content: msg.content
  }));
  
  // 添加系统提示（如果用户消息中没有）
  const hasSystemMessage = formattedMessages.some(msg => msg.role === 'system');
  if (!hasSystemMessage) {
    formattedMessages.unshift({
      role: "system",
      content: "你是专业的安全专家AI助手，精通网络安全、漏洞评估、威胁检测、安全加固等领域。请提供专业、准确、实用的安全建议和解决方案。回答时使用中文，保持友好且专业的语气。"
    });
  }
  
  // 获取用户的最新问题
  const lastUserMessage = messages
    .filter(msg => msg.role === 'user')
    .pop()?.content || '';
  
  // 提供基础回复（当API和本地模型都不可用时）
  const getBasicResponse = () => {
    // 基于问题关键词提供基础安全建议
    let basicResponse = "我是安全AI助手。目前系统配置不完整，无法提供高级分析，但我可以分享一些基础安全知识：\n\n";
    
    if (lastUserMessage.includes('漏洞') || lastUserMessage.includes('扫描')) {
      basicResponse += "**漏洞扫描与管理**\n- 定期进行全面漏洞扫描（推荐使用Nessus、OpenVAS等工具）\n- 优先修复高危漏洞，尤其是远程代码执行类漏洞\n- 建立漏洞响应流程，设定修复时限\n- 定期更新扫描工具和漏洞库";
    } else if (lastUserMessage.includes('入侵') || lastUserMessage.includes('检测')) {
      basicResponse += "**入侵检测建议**\n- 部署入侵检测系统（IDS/IPS）监控异常流量\n- 配置日志集中管理，关注关键系统日志\n- 建立基线行为模型，快速识别异常\n- 实施网络分段，限制横向移动";
    } else if (lastUserMessage.includes('密码') || lastUserMessage.includes('认证')) {
      basicResponse += "**身份认证加固**\n- 实施强密码策略（长度≥12位，包含大小写字母、数字和特殊字符）\n- 启用多因素认证（MFA）\n- 定期强制密码更新\n- 限制登录尝试次数，实施账户锁定";
    } else {
      basicResponse += "**通用安全建议**\n- 定期更新系统和应用程序补丁\n- 部署防火墙，限制不必要的入站和出站连接\n- 实施最小权限原则\n- 定期备份重要数据并测试恢复流程\n- 开展安全意识培训\n- 制定并测试安全事件响应计划";
    }
    
    basicResponse += "\n\n提示：管理员可以通过配置DeepSeek API密钥或正确设置本地模型来启用完整功能。";
    
    return {
      model: "基础安全助手",
      content: basicResponse
    };
  };
  
  // 优先使用本地模型（如果配置或没有API密钥）
  if (useLocalModel || !key) {
    try {
      return await generateLocalChatResponse(formattedMessages);
    } catch (localError) {
      console.error("本地模型调用失败，使用基础回复:", localError);
      return getBasicResponse();
    }
  }
  
  // 使用远程API
  try {
    const base = cfg.deepseekApiBase || process.env.DEEPSEEK_API_BASE || "https://api.deepseek.com";
    const url = `${base}/v1/chat/completions`;
    
    const body = {
      model,
      messages: formattedMessages
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
    const content = data.choices?.[0]?.message?.content || "";
    
    // 可以选择在这里使用本地模型进行结果增强
    const enhanceWithLocalModel = cfg.enhanceWithLocalModel || false;
    if (enhanceWithLocalModel) {
      try {
        const ml = await getMlIntegration();
        const enhancedResult = await ml.sendMessage({
          action: 'enhance_response',
          originalResponse: content,
          messages: formattedMessages
        });
        return {
          model: `${model} (本地增强)`,
          content: enhancedResult.enhancedResponse || content
        };
      } catch (enhanceError) {
        // 增强失败时返回原始结果
        console.warn("Failed to enhance with local model:", enhanceError);
      }
    }
    
    return {
      model,
      content
    };
  } catch (error) {
    console.error("Chat API error:", error);
    // 远程API失败时回退到本地模型
    try {
      return await generateLocalChatResponse(formattedMessages);
    } catch (fallbackError) {
      console.error("本地模型回退也失败，使用基础回复:", fallbackError);
      return getBasicResponse();
    }
  }
}
