import crypto from "crypto";
import { getConfig, saveConfig } from "./config.js";

const tokens = new Map();

export function createToken() {
  const token = crypto.randomBytes(24).toString("hex");
  tokens.set(token, { createdAt: Date.now(), expireAt: Date.now() + 12 * 60 * 60 * 1000 });
  return token;
}

export function verifyToken(token) {
  const doc = tokens.get(token);
  if (!doc) return false;
  if (doc.expireAt < Date.now()) {
    tokens.delete(token);
    return false;
  }
  return true;
}

export function requireAuth(req, res, next) {
  const h = req.headers["authorization"] || "";
  const parts = h.split(" ");
  if (parts.length === 2 && parts[0] === "Bearer" && verifyToken(parts[1])) return next();
  res.status(401).json({ error: "unauthorized" });
}

export function validatePassword(pwd) {
  const cfg = getConfig();
  return String(pwd || "") === String(cfg.adminPassword || "admin123");
}

function hash(pwd) {
  return crypto.createHash("sha256").update(String(pwd)).digest("hex");
}

export function findUser(username) {
  const cfg = getConfig();
  const list = Array.isArray(cfg.users) ? cfg.users : [];
  return list.find(u => u.username === username);
}

export function verifyUser(username, password) {
  const u = findUser(username);
  if (!u) return false;
  return u.passhash === hash(password);
}

export function registerUser(username, password) {
  const cfg = getConfig();
  const list = Array.isArray(cfg.users) ? cfg.users : [];
  if (list.find(u => u.username === username)) throw new Error("user_exists");
  const u = { username, passhash: hash(password), createdAt: Date.now() };
  const next = { ...cfg, users: [...list, u] };
  saveConfig(next);
  return u;
}
