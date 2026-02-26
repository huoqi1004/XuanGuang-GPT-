import crypto from "crypto";
import { getConfig, saveConfig } from "./config.js";

const tokens = new Map();
const TOKEN_EXPIRY = 12 * 60 * 60 * 1000; // 12小时

// 定期清理过期token
function startTokenCleanup() {
  // 每小时清理一次过期token
  setInterval(() => {
    const now = Date.now();
    tokens.forEach((value, key) => {
      if (value.expireAt < now) {
        tokens.delete(key);
      }
    });
    console.log(`已清理过期token，当前活跃token数量: ${tokens.size}`);
  }, 60 * 60 * 1000);
}

// 启动token清理
startTokenCleanup();

// 创建token并关联用户信息
export function createToken(username) {
  const token = crypto.randomBytes(32).toString("hex"); // 增加token长度
  const expireAt = Date.now() + TOKEN_EXPIRY;
  tokens.set(token, { 
    username, 
    createdAt: Date.now(), 
    expireAt, 
    lastActivity: Date.now() 
  });
  return { token, expireAt };
}

// 验证token并返回验证结果对象
export function verifyToken(token) {
  if (!token || typeof token !== 'string') {
    return { valid: false, reason: 'invalid_format' };
  }
  
  const doc = tokens.get(token);
  if (!doc) {
    return { valid: false, reason: 'token_not_found' };
  }
  
  if (doc.expireAt < Date.now()) {
    tokens.delete(token);
    return { valid: false, reason: 'token_expired' };
  }
  
  // 更新最后活动时间
  doc.lastActivity = Date.now();
  tokens.set(token, doc);
  
  return { valid: true, username: doc.username, userInfo: doc };
}

// 增强的身份验证中间件
export function requireAuth(req, res, next) {
  try {
    const h = req.headers["authorization"] || "";
    const parts = h.split(" ");
    
    // 验证Bearer格式
    if (parts.length !== 2 || parts[0] !== "Bearer") {
      return res.status(401).json({ 
        error: "unauthorized", 
        message: "无效的授权格式，请使用Bearer token" 
      });
    }
    
    // 验证token
    const tokenResult = verifyToken(parts[1]);
    if (!tokenResult.valid) {
      let message = "无效的认证信息";
      if (tokenResult.reason === 'token_expired') {
        message = "认证已过期，请重新登录";
      } else if (tokenResult.reason === 'token_not_found') {
        message = "认证信息不存在";
      }
      
      return res.status(401).json({ 
        error: "unauthorized", 
        message,
        reason: tokenResult.reason 
      });
    }
    
    // 将用户信息附加到请求对象
    req.user = {
      username: tokenResult.username,
      ...tokenResult.userInfo
    };
    
    next();
  } catch (error) {
    console.error("身份验证错误:", error);
    return res.status(500).json({ 
      error: "internal_error", 
      message: "身份验证过程中发生错误" 
    });
  }
}

// 加盐哈希密码
function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.createHash('sha256')
    .update(password + salt)
    .digest('hex');
  return { hash, salt };
}

// 验证密码
export function validatePassword(pwd) {
  const cfg = getConfig();
  // 为了兼容性，先检查是否已经是哈希格式
  if (cfg.adminPassword && cfg.adminPassword.length === 64) {
    // 假设是SHA256哈希，这里简单比较
    const adminHash = crypto.createHash('sha256').update(String(pwd || '')).digest('hex');
    return adminHash === cfg.adminPassword;
  }
  return String(pwd || "") === String(cfg.adminPassword || "admin123");
}

export function findUser(username) {
  const cfg = getConfig();
  const list = Array.isArray(cfg.users) ? cfg.users : [];
  return list.find(u => u.username === username);
}

export function verifyUser(username, password) {
  const u = findUser(username);
  if (!u) return false;
  
  // 检查是否有盐值
  if (u.salt) {
    const { hash } = hashPassword(password, u.salt);
    return u.passhash === hash;
  }
  // 兼容旧的哈希方式
  return u.passhash === crypto.createHash("sha256").update(String(password)).digest("hex");
}

export function registerUser(username, password) {
  // 验证用户名格式
  if (!username || username.length < 3 || username.length > 32 || !/^[a-zA-Z0-9_]+$/.test(username)) {
    throw new Error("invalid_username_format");
  }
  
  // 验证密码强度
  if (!password || password.length < 6) {
    throw new Error("password_too_weak");
  }
  
  const cfg = getConfig();
  const list = Array.isArray(cfg.users) ? cfg.users : [];
  
  if (list.find(u => u.username === username)) {
    throw new Error("user_exists");
  }
  
  // 使用加盐哈希
  const { hash, salt } = hashPassword(password);
  const u = { 
    username, 
    passhash: hash, 
    salt,
    createdAt: Date.now(),
    role: 'user' // 默认角色
  };
  
  const next = { ...cfg, users: [...list, u] };
  saveConfig(next);
  
  return {
    username: u.username,
    createdAt: u.createdAt,
    role: u.role
  };
}

// 撤销token
export function revokeToken(token) {
  if (tokens.has(token)) {
    tokens.delete(token);
    return true;
  }
  return false;
}

// 获取当前活跃token数量
export function getActiveTokenCount() {
  return tokens.size;
}
