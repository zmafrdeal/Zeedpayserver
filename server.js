/*
 * Zeedpay backend
 *
 * This service exposes the API and can serve the two self-contained frontend
 * files from the same origin. The frontend can still be hosted separately and
 * can call this server from any origin while CORS_ALLOW_ORIGIN is left as "*".
 *
 * The upstream API returns transaction statuses asynchronously. The create
 * endpoints therefore return the upstream response, including pending,
 * successful, and failed responses. Upstream error bodies are passed through
 * without replacing their message.
 */

const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { Pool } = require("pg");

const app = express();
const PORT = Number(process.env.PORT || 10000);
const FRONTEND_STATIC_DIR = process.env.FRONTEND_STATIC_DIR
  ? path.resolve(process.env.FRONTEND_STATIC_DIR)
  : path.join(__dirname, "static");
const API_BASE_URL = (process.env.PAYMENTS_API_BASE_URL || "").replace(
  /\/+$/,
  "",
);
const PHONE_NAME_LOOKUP_PATH = stringValue(
  process.env.LIPILA_PHONE_NAME_LOOKUP_PATH,
) || "";
const PHONE_NAME_LOOKUP_METHOD = String(
  process.env.LIPILA_PHONE_NAME_LOOKUP_METHOD || "GET",
).toUpperCase();
const API_KEY = process.env.ZEEDPAY_API_KEY || "";
const CALLBACK_URL = process.env.ZEEDPAY_CALLBACK_URL || "";
const WEBHOOK_SECRET = process.env.ZEEDPAY_WEBHOOK_SECRET || "";
const CLIENT_TOKEN = process.env.ZEEDPAY_CLIENT_TOKEN || "";
const REQUEST_TIMEOUT_MS = Number(process.env.REQUEST_TIMEOUT_MS || 30000);
const SUPPORTED_CURRENCIES = new Set(["ZMW", "USD"]);
const SUPABASE_URL = (process.env.SUPABASE_URL || "").replace(/\/+$/, "");
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || "";
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || "";
// Admin authentication is intentionally independent from Supabase Auth.
// These values should be configured as Render environment variables and
// must never be placed in frontend files.
const ADMIN_EMAIL = normalizeEmail(
  process.env.ZEEDPAY_ADMIN_EMAIL || process.env.ADMIN_EMAIL || "",
);
const ADMIN_PASSWORD =
  process.env.ZEEDPAY_ADMIN_PASSWORD || process.env.ADMIN_PASSWORD || "";
const ADMIN_SESSION_SECRET =
  process.env.ZEEDPAY_ADMIN_SESSION_SECRET ||
  process.env.ADMIN_SESSION_SECRET ||
  "";
const ADMIN_SESSION_TTL_SECONDS = 8 * 60 * 60;
const PASSWORD_RESET_REDIRECT_URL =
  process.env.SUPABASE_PASSWORD_RESET_REDIRECT_URL || "";
// Render is outside Railway's private network, so prefer Railway's public URL.
// DATABASE_URL remains supported for portability and local testing.
const DATABASE_URL =
  process.env.DATABASE_PUBLIC_URL || process.env.DATABASE_URL || "";
const db = DATABASE_URL
  ? new Pool({
      connectionString: DATABASE_URL,
      ssl:
        process.env.DATABASE_SSL === "false"
          ? false
          : { rejectUnauthorized: false },
      max: Number(process.env.DATABASE_POOL_MAX || 10),
    })
  : null;
const processedWebhookIds = new Map();
const WEBHOOK_ID_TTL_MS = 24 * 60 * 60 * 1000;
const PIN_MAX_ATTEMPTS = 5;
const PIN_LOCK_MS = 24 * 60 * 60 * 1000;
const PLATFORM_FEE_PERCENT = Number(
  process.env.PLATFORM_TRANSACTION_FEE_PERCENT || 1.5,
);
const PLATFORM_FEE_FIXED = Number(process.env.PLATFORM_TRANSACTION_FEE_FIXED || 0);
const DEFAULT_WALLET_NAME = "Zeedpay Primary Wallet";
const LEGACY_DEFAULT_WALLET_NAME = "WAITAPP ONLINE ORDERS";
const IDENTIFIER_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const ORDER_REFERENCE_PATTERN = /^ZEEDP-[A-Z0-9]{12}$/;
const REFERRAL_BONUS = 5;
const NEW_USER_SIGNUP_BONUS = 0;
const DEPOSIT_COMMISSION_RATE = 0.05;
const COMMISSION_WITHDRAWAL_MINIMUM = 50;
const DEFAULT_FEATURES = [
  "collections",
  "withdrawals",
  "wallets",
  "payment_links",
  "referrals",
  "commissions",
  "feedback",
  "transactions",
  "mobile_money",
  "bank_withdrawals",
];

function jsonError(res, status, code, message, details) {
  const payload = {
    success: false,
    error: {
      code,
      message,
      ...(details === undefined ? {} : { details }),
    },
  };
  return res.status(status).json(payload);
}

function databaseErrorDetails(error) {
  return {
    message: error?.message || "Unknown database error",
    code: error?.code || null,
    constraint: error?.constraint || null,
    table: error?.table || null,
    column: error?.column || null,
    detail: error?.detail || null,
    hint: error?.hint || null,
  };
}

function frontendAsset(name) {
  const candidates = [
    path.join(FRONTEND_STATIC_DIR, name),
    path.join(__dirname, name),
  ];
  return candidates.find((candidate) => fs.existsSync(candidate)) || "";
}

function databaseRequired(res) {
  if (db) return true;
  jsonError(
    res,
    503,
    "DATABASE_NOT_CONFIGURED",
    "DATABASE_URL is not configured on the server",
  );
  return false;
}

function supabaseRequired(res) {
  if (SUPABASE_URL && SUPABASE_ANON_KEY) return true;
  jsonError(
    res,
    503,
    "SUPABASE_NOT_CONFIGURED",
    "SUPABASE_URL and SUPABASE_ANON_KEY are required on the server",
  );
  return false;
}

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function normalizeCountry(value) {
  return String(value || "").trim().toUpperCase().slice(0, 2);
}

function validEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizeEmail(value));
}

function validPin(value) {
  return /^\d{4,6}$/.test(String(value || ""));
}

function randomIdentifier(prefix, length = 10, separator = "_") {
  let value = "";
  while (value.length < length) {
    const bytes = crypto.randomBytes(length);
    for (const byte of bytes) {
      value += IDENTIFIER_ALPHABET[byte % IDENTIFIER_ALPHABET.length];
      if (value.length === length) break;
    }
  }
  return `${prefix}${separator}${value}`;
}

function randomCode(prefix, length = 8) {
  return randomIdentifier(prefix, length, "-");
}

function hashPin(pin) {
  return new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(16);
    crypto.scrypt(String(pin), salt, 64, (error, derivedKey) => {
      if (error) return reject(error);
      resolve(`scrypt:${salt.toString("hex")}:${derivedKey.toString("hex")}`);
    });
  });
}

function verifyPin(pin, encoded) {
  return new Promise((resolve, reject) => {
    const [algorithm, saltHex, hashHex] = String(encoded || "").split(":");
    if (algorithm !== "scrypt" || !saltHex || !hashHex) return resolve(false);
    crypto.scrypt(String(pin), Buffer.from(saltHex, "hex"), 64, (error, key) => {
      if (error) return reject(error);
      const expected = Buffer.from(hashHex, "hex");
      resolve(
        expected.length === key.length && crypto.timingSafeEqual(expected, key),
      );
    });
  });
}

function bearerToken(req) {
  const header = req.get("authorization") || "";
  return header.startsWith("Bearer ") ? header.slice(7).trim() : "";
}

function adminConfigured() {
  return Boolean(ADMIN_EMAIL && ADMIN_PASSWORD && ADMIN_SESSION_SECRET);
}

function secretsEqual(left, right) {
  const a = Buffer.from(String(left || ""));
  const b = Buffer.from(String(right || ""));
  return a.length > 0 && a.length === b.length && crypto.timingSafeEqual(a, b);
}

function createAdminToken() {
  const payload = Buffer.from(
    JSON.stringify({
      sub: "render-admin",
      email: ADMIN_EMAIL,
      role: "admin",
      exp: Math.floor(Date.now() / 1000) + ADMIN_SESSION_TTL_SECONDS,
    }),
  ).toString("base64url");
  const signature = crypto
    .createHmac("sha256", ADMIN_SESSION_SECRET)
    .update(payload)
    .digest("base64url");
  return `${payload}.${signature}`;
}

function verifyAdminToken(token) {
  if (!adminConfigured() || !token) return null;
  const [payloadPart, signaturePart] = String(token).split(".");
  if (!payloadPart || !signaturePart) return null;
  const expected = crypto
    .createHmac("sha256", ADMIN_SESSION_SECRET)
    .update(payloadPart)
    .digest();
  const received = Buffer.from(signaturePart, "base64url");
  if (
    expected.length !== received.length ||
    !crypto.timingSafeEqual(expected, received)
  ) {
    return null;
  }
  try {
    const payload = JSON.parse(
      Buffer.from(payloadPart, "base64url").toString("utf8"),
    );
    if (
      payload?.sub !== "render-admin" ||
      payload?.role !== "admin" ||
      payload?.email !== ADMIN_EMAIL ||
      Number(payload?.exp || 0) <= Math.floor(Date.now() / 1000)
    ) {
      return null;
    }
    return payload;
  } catch {
    return null;
  }
}

async function supabaseRequest(path, options = {}, token = "") {
  const headers = {
    accept: "application/json",
    "content-type": "application/json",
    apikey: options.apiKey || SUPABASE_ANON_KEY,
  };
  if (options.apiKey) headers.authorization = `Bearer ${options.apiKey}`;
  if (token) headers.authorization = `Bearer ${token}`;
  const response = await fetch(`${SUPABASE_URL}${path}`, {
    method: options.method || "GET",
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });
  const raw = await response.text();
  let data;
  try {
    data = raw ? JSON.parse(raw) : null;
  } catch {
    data = raw;
  }
  return { response, data };
}

function authErrorMessage(data, fallback) {
  return (
    (typeof data === "object" &&
      (data?.msg || data?.message || data?.error_description || data?.error)) ||
    fallback
  );
}

function publicMerchant(merchant, wallet) {
  return {
    id: merchant.id,
    merchantId: merchant.merchant_id,
    referralCode: merchant.referral_code,
    fullName: merchant.full_name,
    businessName: merchant.business_name || wallet?.name,
    phoneNumber: merchant.phone_number,
    email: merchant.email,
    country: merchant.country,
    accountStatus: merchant.account_status || "active",
    createdAt: merchant.created_at,
    transactionPinSet: Boolean(merchant.transaction_pin_hash),
    transactionPinLength: merchant.transaction_pin_length ? Number(merchant.transaction_pin_length) : null,
    pinLockedUntil: merchant.pin_locked_until,
    wallet: wallet
      ? {
          id: wallet.id,
          walletId: wallet.id,
          name: wallet.name,
          currency: wallet.currency,
          balance: Number(wallet.balance || 0),
        }
      : null,
  };
}

function publicWallet(wallet) {
  return wallet
    ? {
        id: wallet.wallet_code || wallet.id,
        walletId: wallet.wallet_code || wallet.id,
        name: wallet.name,
        currency: wallet.currency,
        balance: Number(wallet.balance || 0),
        primary: Boolean(wallet.is_primary),
        kind: wallet.wallet_kind || "primary",
      }
    : null;
}

async function merchantForRequest(req) {
  if (!db || !SUPABASE_URL || !SUPABASE_ANON_KEY) return null;
  const token = bearerToken(req);
  if (!token) return null;
  const result = await supabaseRequest("/auth/v1/user", {}, token);
  if (!result.response.ok || !result.data?.id) return null;
  const merchantResult = await db.query(
    `SELECT m.*, w.id AS wallet_id, w.wallet_code, w.name AS wallet_name, w.currency AS wallet_currency,
            w.balance AS wallet_balance
       FROM merchants m
       LEFT JOIN wallets w ON w.merchant_id = m.id AND w.is_primary = TRUE
      WHERE m.supabase_user_id = $1
      LIMIT 1`,
    [result.data.id],
  );
  if (!merchantResult.rows[0]) return null;
  const row = merchantResult.rows[0];
  return {
    supabaseUser: result.data,
    merchant: row,
    wallet: row.wallet_id
      ? {
          id: row.wallet_code || row.wallet_id,
          name: row.wallet_name,
          currency: row.wallet_currency,
          balance: row.wallet_balance,
        }
      : null,
  };
}

async function requireAuth(req, res, next) {
  if (!databaseRequired(res) || !supabaseRequired(res)) return;
  try {
    const identity = await merchantForRequest(req);
    if (!identity) {
      return jsonError(
        res,
        401,
        "UNAUTHORIZED",
        "Your session is missing or has expired. Please log in again.",
      );
    }
    if (identity.merchant.account_status && identity.merchant.account_status !== "active") {
      return jsonError(
        res,
        403,
        "ACCOUNT_DISABLED",
        "This account is disabled. Please contact support.",
        { status: identity.merchant.account_status },
      );
    }
    req.identity = identity;
    return next();
  } catch (error) {
    console.error("Authentication lookup failed:", error.message);
    return jsonError(res, 503, "AUTH_LOOKUP_FAILED", "Could not verify your session");
  }
}

async function requireAdmin(req, res, next) {
  if (!databaseRequired(res)) return;
  if (!adminConfigured()) {
    return jsonError(
      res,
      503,
      "ADMIN_NOT_CONFIGURED",
      "Admin credentials are not configured on the server.",
    );
  }
  const admin = verifyAdminToken(bearerToken(req));
  if (!admin) {
    return jsonError(
      res,
      401,
      "ADMIN_LOGIN_REQUIRED",
      "Admin login required or the session has expired.",
    );
  }
  req.admin = { id: admin.sub, email: admin.email, role: admin.role };
  return next();
}

async function writeAudit(admin, action, entityType, entityId, details = {}) {
  if (!db || !admin) return;
  await db.query(
    `INSERT INTO audit_logs (id, actor_email, action, entity_type, entity_id, details)
     VALUES ($1,$2,$3,$4,$5,$6::jsonb)`,
    [crypto.randomUUID(), admin.email, action, entityType, entityId || null, JSON.stringify(details)],
  );
}

async function requireTransactionPin(req, res, next) {
  const merchant = req.identity?.merchant;
  if (!merchant) return jsonError(res, 401, "UNAUTHORIZED", "Login required");
  if (!merchant.transaction_pin_hash) {
    return jsonError(
      res,
      428,
      "TRANSACTION_PIN_REQUIRED",
      "Create a transaction PIN before moving money out of your wallet.",
    );
  }
  const lockedUntil = merchant.pin_locked_until
    ? new Date(merchant.pin_locked_until).getTime()
    : 0;
  if (lockedUntil > Date.now()) {
    return jsonError(
      res,
      423,
      "TRANSACTION_PIN_LOCKED",
      "Transaction PIN attempts are locked for 24 hours.",
      { lockedUntil: merchant.pin_locked_until },
    );
  }
  const pin = req.body?.transactionPin || req.get("x-transaction-pin");
  if (!validPin(pin)) {
    return jsonError(res, 400, "INVALID_TRANSACTION_PIN", "Enter your 4 to 6 digit transaction PIN.");
  }
  try {
    const valid = await verifyPin(pin, merchant.transaction_pin_hash);
    if (!valid) {
      const attempts = Number(merchant.pin_failed_attempts || 0) + 1;
      const lock = attempts >= PIN_MAX_ATTEMPTS ? new Date(Date.now() + PIN_LOCK_MS) : null;
      await db.query(
        `UPDATE merchants
            SET pin_failed_attempts = $1, pin_locked_until = $2, updated_at = NOW()
          WHERE id = $3`,
        [lock ? PIN_MAX_ATTEMPTS : attempts, lock, merchant.id],
      );
      return jsonError(
        res,
        lock ? 423 : 401,
        lock ? "TRANSACTION_PIN_LOCKED" : "INVALID_TRANSACTION_PIN",
        lock
          ? "Too many incorrect PIN attempts. Try again after 24 hours."
          : `Incorrect transaction PIN. ${PIN_MAX_ATTEMPTS - attempts} attempt(s) remaining.`,
      );
    }
    delete req.body.transactionPin;
    return next();
  } catch (error) {
    console.error("Transaction PIN verification failed:", error.message);
    return jsonError(res, 503, "PIN_VERIFICATION_FAILED", "Could not verify the transaction PIN");
  }
}

async function initializeDatabase() {
  if (!db) return;
  await db.query(`
    CREATE EXTENSION IF NOT EXISTS pgcrypto;
    CREATE TABLE IF NOT EXISTS merchants (
      id TEXT PRIMARY KEY,
      supabase_user_id TEXT NOT NULL UNIQUE,
      email TEXT NOT NULL UNIQUE,
      full_name TEXT NOT NULL,
      business_name TEXT NOT NULL,
      phone_number TEXT NOT NULL UNIQUE,
      country TEXT NOT NULL,
      merchant_id TEXT NOT NULL UNIQUE,
      referral_code TEXT NOT NULL UNIQUE,
      transaction_pin_hash TEXT,
      pin_failed_attempts INTEGER NOT NULL DEFAULT 0,
      pin_locked_until TIMESTAMPTZ,
      pin_set_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS wallets (
      id TEXT PRIMARY KEY,
      wallet_code TEXT UNIQUE,
      merchant_id TEXT NOT NULL REFERENCES merchants(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      currency TEXT NOT NULL DEFAULT 'ZMW',
      balance NUMERIC(18, 2) NOT NULL DEFAULT 0,
      is_primary BOOLEAN NOT NULL DEFAULT TRUE,
      wallet_kind TEXT NOT NULL DEFAULT 'primary',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE (merchant_id, name)
    );
    CREATE INDEX IF NOT EXISTS merchants_email_lower_idx ON merchants (LOWER(email));
    CREATE INDEX IF NOT EXISTS wallets_merchant_idx ON wallets (merchant_id);
    CREATE TABLE IF NOT EXISTS wallet_transactions (
      id TEXT PRIMARY KEY,
      reference_id TEXT NOT NULL UNIQUE,
      merchant_id TEXT NOT NULL REFERENCES merchants(id) ON DELETE CASCADE,
      wallet_id TEXT NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
      operation TEXT NOT NULL,
      direction TEXT NOT NULL CHECK (direction IN ('in', 'out')),
      amount NUMERIC(18, 2) NOT NULL CHECK (amount > 0),
      fee_amount NUMERIC(18, 2) NOT NULL DEFAULT 0,
      net_amount NUMERIC(18, 2) NOT NULL,
      currency TEXT NOT NULL DEFAULT 'ZMW',
      status TEXT NOT NULL DEFAULT 'pending',
      external_id TEXT,
      provider_response JSONB,
      applied BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS wallet_transactions_merchant_idx
      ON wallet_transactions (merchant_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS wallet_transactions_reference_idx
      ON wallet_transactions (reference_id);
    CREATE TABLE IF NOT EXISTS wallet_ledger (
      id TEXT PRIMARY KEY,
      wallet_transaction_id TEXT NOT NULL UNIQUE REFERENCES wallet_transactions(id) ON DELETE RESTRICT,
      merchant_id TEXT NOT NULL REFERENCES merchants(id) ON DELETE CASCADE,
      wallet_id TEXT NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
      entry_type TEXT NOT NULL,
      amount NUMERIC(18, 2) NOT NULL,
      balance_before NUMERIC(18, 2) NOT NULL,
      balance_after NUMERIC(18, 2) NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS platform_fees (
      id TEXT PRIMARY KEY,
      wallet_transaction_id TEXT NOT NULL UNIQUE REFERENCES wallet_transactions(id) ON DELETE RESTRICT,
      merchant_id TEXT NOT NULL REFERENCES merchants(id) ON DELETE CASCADE,
      amount NUMERIC(18, 2) NOT NULL CHECK (amount >= 0),
      currency TEXT NOT NULL DEFAULT 'ZMW',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS payment_links (
      id TEXT PRIMARY KEY,
      merchant_id TEXT NOT NULL REFERENCES merchants(id) ON DELETE CASCADE,
      reference_id TEXT NOT NULL UNIQUE,
      title TEXT NOT NULL,
      description TEXT,
      amount NUMERIC(18, 2) NOT NULL CHECK (amount > 0),
      currency TEXT NOT NULL DEFAULT 'ZMW',
      customer_email TEXT,
      narration TEXT,
      checkout_url TEXT,
      photo_data TEXT,
      provider_response JSONB,
      status TEXT NOT NULL DEFAULT 'active',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS payment_links_merchant_idx
      ON payment_links (merchant_id, created_at DESC);
    CREATE TABLE IF NOT EXISTS notification_preferences (
      merchant_id TEXT PRIMARY KEY REFERENCES merchants(id) ON DELETE CASCADE,
      transaction_alerts BOOLEAN NOT NULL DEFAULT TRUE,
      security_alerts BOOLEAN NOT NULL DEFAULT TRUE,
      product_updates BOOLEAN NOT NULL DEFAULT FALSE,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS notifications (
      id TEXT PRIMARY KEY,
      merchant_id TEXT NOT NULL REFERENCES merchants(id) ON DELETE CASCADE,
      type TEXT NOT NULL,
      title TEXT NOT NULL,
      message TEXT NOT NULL,
      priority TEXT NOT NULL DEFAULT 'important',
      is_read BOOLEAN NOT NULL DEFAULT FALSE,
      dedupe_key TEXT NOT NULL UNIQUE,
      metadata JSONB,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS notifications_merchant_idx
      ON notifications (merchant_id, created_at DESC);
    CREATE TABLE IF NOT EXISTS feedback (
      id TEXT PRIMARY KEY,
      merchant_id TEXT NOT NULL REFERENCES merchants(id) ON DELETE CASCADE,
      category TEXT NOT NULL,
      message TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'new',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS feedback_merchant_idx
      ON feedback (merchant_id, created_at DESC);
    CREATE TABLE IF NOT EXISTS referral_earnings (
      id TEXT PRIMARY KEY,
      referrer_merchant_id TEXT NOT NULL REFERENCES merchants(id) ON DELETE CASCADE,
      referred_merchant_id TEXT NOT NULL REFERENCES merchants(id) ON DELETE CASCADE,
      earning_type TEXT NOT NULL CHECK (earning_type IN ('referral_bonus', 'deposit_commission')),
      amount NUMERIC(18, 2) NOT NULL CHECK (amount > 0),
      source_transaction_id TEXT REFERENCES wallet_transactions(id) ON DELETE SET NULL,
      source_reference TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE UNIQUE INDEX IF NOT EXISTS referral_earnings_source_idx
      ON referral_earnings (source_transaction_id)
      WHERE source_transaction_id IS NOT NULL;
    CREATE UNIQUE INDEX IF NOT EXISTS referral_bonus_once_idx
      ON referral_earnings (referrer_merchant_id, referred_merchant_id, earning_type)
      WHERE earning_type = 'referral_bonus';
    CREATE INDEX IF NOT EXISTS referral_earnings_referrer_idx
      ON referral_earnings (referrer_merchant_id, created_at DESC);
    CREATE TABLE IF NOT EXISTS platform_settings (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      deposit_fee_percent NUMERIC(8, 4) NOT NULL DEFAULT 1.5,
      deposit_fee_fixed NUMERIC(18, 2) NOT NULL DEFAULT 0,
      withdrawal_fee_percent NUMERIC(8, 4) NOT NULL DEFAULT 1.5,
      withdrawal_fee_fixed NUMERIC(18, 2) NOT NULL DEFAULT 0,
      signup_bonus NUMERIC(18, 2) NOT NULL DEFAULT 0,
      referral_bonus NUMERIC(18, 2) NOT NULL DEFAULT 5,
      commission_rate NUMERIC(8, 4) NOT NULL DEFAULT 5,
      commission_withdrawal_minimum NUMERIC(18, 2) NOT NULL DEFAULT 50,
      updated_by TEXT,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS merchant_features (
      merchant_id TEXT NOT NULL REFERENCES merchants(id) ON DELETE CASCADE,
      feature_key TEXT NOT NULL,
      enabled BOOLEAN NOT NULL DEFAULT TRUE,
      updated_by TEXT,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (merchant_id, feature_key)
    );
    CREATE TABLE IF NOT EXISTS audit_logs (
      id TEXT PRIMARY KEY,
      actor_email TEXT NOT NULL,
      action TEXT NOT NULL,
      entity_type TEXT NOT NULL,
      entity_id TEXT,
      details JSONB,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS audit_logs_created_idx ON audit_logs(created_at DESC);
  `);

  await db.query("ALTER TABLE merchants ADD COLUMN IF NOT EXISTS account_status TEXT NOT NULL DEFAULT 'active'");
  await db.query("ALTER TABLE wallets ADD COLUMN IF NOT EXISTS wallet_status TEXT NOT NULL DEFAULT 'active'");
  await db.query("ALTER TABLE wallets ADD COLUMN IF NOT EXISTS wallet_kind TEXT NOT NULL DEFAULT 'primary'");
  await db.query("ALTER TABLE merchants ADD COLUMN IF NOT EXISTS referred_by_merchant_id TEXT REFERENCES merchants(id)");
  await db.query("ALTER TABLE merchants ADD COLUMN IF NOT EXISTS referral_joined_at TIMESTAMPTZ");
  await db.query("ALTER TABLE merchants ADD COLUMN IF NOT EXISTS transaction_pin_length INTEGER");
  await db.query("ALTER TABLE platform_settings ADD COLUMN IF NOT EXISTS signup_bonus NUMERIC(18, 2) NOT NULL DEFAULT 0");
  await db.query("ALTER TABLE platform_settings ADD COLUMN IF NOT EXISTS referral_bonus NUMERIC(18, 2) NOT NULL DEFAULT 5");
  await db.query(
    "CREATE UNIQUE INDEX IF NOT EXISTS wallets_commission_idx ON wallets(merchant_id) WHERE wallet_kind = 'commission'",
  );
  // Add the public wallet identifier to databases created before this field
  // existed, then repair legacy display values created by the old frontend.
  await db.query("ALTER TABLE wallets ADD COLUMN IF NOT EXISTS wallet_code TEXT");
  await db.query(
    "CREATE UNIQUE INDEX IF NOT EXISTS wallets_wallet_code_idx ON wallets(wallet_code) WHERE wallet_code IS NOT NULL",
  );
  await db.query(
    "ALTER TABLE wallet_transactions ADD COLUMN IF NOT EXISTS provider_reference_id TEXT",
  );
  await db.query(
    "ALTER TABLE wallet_transactions ADD COLUMN IF NOT EXISTS note TEXT",
  );
  await db.query(
    "CREATE INDEX IF NOT EXISTS wallet_transactions_provider_reference_idx ON wallet_transactions(provider_reference_id)",
  );
  await migrateLegacyTransactionReferences();
  await db.query(
    `UPDATE wallets w
        SET name = m.business_name, updated_at = NOW()
       FROM merchants m
      WHERE w.merchant_id = m.id
        AND UPPER(w.name) = $1
        AND m.business_name IS NOT NULL
        AND m.business_name <> ''
        AND NOT EXISTS (
          SELECT 1
            FROM wallets existing
           WHERE existing.merchant_id = w.merchant_id
             AND existing.id <> w.id
             AND existing.name = m.business_name
        )`,
    [LEGACY_DEFAULT_WALLET_NAME],
  );

  const walletRows = await db.query(
    "SELECT id FROM wallets WHERE wallet_code IS NULL OR wallet_code = ''",
  );
  for (const wallet of walletRows.rows) {
    let assigned = false;
    for (let attempt = 0; attempt < 5 && !assigned; attempt += 1) {
      try {
        const result = await db.query(
          `UPDATE wallets SET wallet_code = $1, updated_at = NOW()
             WHERE id = $2 AND (wallet_code IS NULL OR wallet_code = '')`,
          [randomIdentifier("WAL", 10), wallet.id],
        );
        assigned = result.rowCount === 1;
      } catch (error) {
        if (error.code !== "23505") throw error;
      }
    }
  }

  const merchants = await db.query(
    "SELECT id, merchant_id, referral_code FROM merchants",
  );
  for (const merchant of merchants.rows) {
    if (!/^ZPM_[A-Z0-9]{10}$/.test(merchant.merchant_id)) {
      await db.query(
        "UPDATE merchants SET merchant_id = $1, updated_at = NOW() WHERE id = $2",
        [randomIdentifier("ZPM", 10), merchant.id],
      );
    }
    if (!/^ZEE-[A-Z0-9]{8}$/.test(merchant.referral_code)) {
      await db.query(
        "UPDATE merchants SET referral_code = $1, updated_at = NOW() WHERE id = $2",
        [randomCode("ZEE", 8), merchant.id],
      );
    }
  }
  const merchantsForCommissionWallets = await db.query(
    `SELECT m.id
       FROM merchants m
      WHERE NOT EXISTS (
        SELECT 1 FROM wallets w
         WHERE w.merchant_id = m.id AND w.wallet_kind = 'commission'
      )`,
  );
  for (const merchant of merchantsForCommissionWallets.rows) {
    await ensureCommissionWallet(merchant.id);
  }
  console.log("Railway database schema is ready");
}

async function migrateLegacyTransactionReferences() {
  const client = await db.connect();
  try {
    await client.query("BEGIN");
    const legacyTransactions = await client.query(
      `SELECT id, reference_id
         FROM wallet_transactions
        WHERE reference_id !~ '^ZEEDP-[A-Z0-9]{12}$'
        ORDER BY created_at ASC
        FOR UPDATE`,
    );
    for (const transaction of legacyTransactions.rows) {
      const oldReference = transaction.reference_id;
      let nextReference = makeReferenceId();
      let collision = await client.query(
        "SELECT 1 FROM wallet_transactions WHERE reference_id = $1",
        [nextReference],
      );
      while (collision.rows[0]) {
        nextReference = makeReferenceId();
        collision = await client.query(
          "SELECT 1 FROM wallet_transactions WHERE reference_id = $1",
          [nextReference],
        );
      }
      await client.query(
        `UPDATE wallet_transactions
            SET provider_reference_id = COALESCE(provider_reference_id, $1),
                reference_id = $2,
                updated_at = NOW()
          WHERE id = $3`,
        [oldReference, nextReference, transaction.id],
      );
      await client.query(
        `UPDATE payment_links
            SET reference_id = $1, updated_at = NOW()
          WHERE reference_id = $2`,
        [nextReference, oldReference],
      );
      await client.query(
        `UPDATE notifications
            SET dedupe_key = REPLACE(dedupe_key, $1, $2),
                message = REPLACE(message, $1, $2),
                metadata = CASE
                  WHEN metadata IS NULL THEN jsonb_build_object('referenceId', $2)
                  ELSE metadata || jsonb_build_object('referenceId', $2)
                END
          WHERE dedupe_key LIKE '%' || $1 || '%'
             OR message LIKE '%' || $1 || '%'`,
        [oldReference, nextReference],
      );
      await client.query(
        `UPDATE referral_earnings
            SET source_reference = $1
          WHERE source_reference = $2`,
        [nextReference, oldReference],
      );
    }
    const legacyLinks = await client.query(
      `SELECT id, reference_id
         FROM payment_links
        WHERE reference_id !~ '^ZEEDP-[A-Z0-9]{12}$'
        ORDER BY created_at ASC
        FOR UPDATE`,
    );
    for (const link of legacyLinks.rows) {
      let nextReference = makeReferenceId();
      let collision = await client.query(
        "SELECT 1 FROM payment_links WHERE reference_id = $1",
        [nextReference],
      );
      while (collision.rows[0]) {
        nextReference = makeReferenceId();
        collision = await client.query(
          "SELECT 1 FROM payment_links WHERE reference_id = $1",
          [nextReference],
        );
      }
      await client.query(
        `UPDATE payment_links
            SET reference_id = $1, updated_at = NOW()
          WHERE id = $2`,
        [nextReference, link.id],
      );
    }
    await client.query("COMMIT");
    if (legacyTransactions.rowCount || legacyLinks.rowCount) {
      console.log(
        `Migrated ${legacyTransactions.rowCount} legacy transaction reference(s) and ${legacyLinks.rowCount} legacy payment link reference(s) to ZEEDP`,
      );
    }
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

function moneyRound(value) {
  return Math.round(Number(value || 0) * 100) / 100;
}

async function getPlatformSettings() {
  const fallback = {
    depositFeePercent: PLATFORM_FEE_PERCENT,
    depositFeeFixed: PLATFORM_FEE_FIXED,
    withdrawalFeePercent: PLATFORM_FEE_PERCENT,
    withdrawalFeeFixed: PLATFORM_FEE_FIXED,
    signupBonus: NEW_USER_SIGNUP_BONUS,
    referralBonus: REFERRAL_BONUS,
    commissionRate: DEPOSIT_COMMISSION_RATE * 100,
    commissionWithdrawalMinimum: COMMISSION_WITHDRAWAL_MINIMUM,
  };
  if (!db) return fallback;
  const result = await db.query(
    `INSERT INTO platform_settings (id, deposit_fee_percent, deposit_fee_fixed,
       withdrawal_fee_percent, withdrawal_fee_fixed, signup_bonus, referral_bonus,
       commission_rate, commission_withdrawal_minimum)
     VALUES (1,$1,$2,$1,$2,$3,$4,$5,$6)
     ON CONFLICT (id) DO NOTHING
     RETURNING *`,
    [
      fallback.depositFeePercent,
      fallback.depositFeeFixed,
      fallback.signupBonus,
      fallback.referralBonus,
      fallback.commissionRate,
      fallback.commissionWithdrawalMinimum,
    ],
  );
  const row = result.rows[0] || (await db.query("SELECT * FROM platform_settings WHERE id = 1")).rows[0];
  return row
    ? {
        depositFeePercent: Number(row.deposit_fee_percent),
        depositFeeFixed: Number(row.deposit_fee_fixed),
        withdrawalFeePercent: Number(row.withdrawal_fee_percent),
        withdrawalFeeFixed: Number(row.withdrawal_fee_fixed),
        signupBonus: Number(row.signup_bonus),
        referralBonus: Number(row.referral_bonus),
        commissionRate: Number(row.commission_rate),
        commissionWithdrawalMinimum: Number(row.commission_withdrawal_minimum),
      }
    : fallback;
}

function transactionFee(amount, direction, settings = {}) {
  const percent = direction === "in"
    ? Number(settings.depositFeePercent ?? PLATFORM_FEE_PERCENT)
    : Number(settings.withdrawalFeePercent ?? PLATFORM_FEE_PERCENT);
  const fixed = direction === "in"
    ? Number(settings.depositFeeFixed ?? PLATFORM_FEE_FIXED)
    : Number(settings.withdrawalFeeFixed ?? PLATFORM_FEE_FIXED);
  const calculated = (Number(amount) * percent) / 100 + fixed;
  return moneyRound(Math.max(0, calculated));
}

function providerStatus(payload) {
  const keys = [
    "status",
    "state",
    "transactionStatus",
    "paymentStatus",
    "transaction_state",
    "payment_state",
  ];
  const seen = new Set();
  const visit = (value, depth = 0) => {
    if (depth > 4 || value == null || typeof value !== "object" || seen.has(value)) {
      return "";
    }
    seen.add(value);
    for (const key of keys) {
      if (typeof value[key] === "string" && value[key].trim()) return value[key].trim();
    }
    for (const child of Object.values(value)) {
      const found = visit(child, depth + 1);
      if (found) return found;
    }
    return "";
  };
  return visit(payload);
}

function providerExternalId(payload) {
  return (
    payload?.externalId ||
    payload?.external_id ||
    payload?.data?.externalId ||
    payload?.data?.external_id ||
    payload?.transaction?.externalId ||
    payload?.transaction?.id ||
    payload?.identifier ||
    payload?.data?.identifier ||
    null
  );
}

function providerReferenceId(payload) {
  return (
    payload?.referenceId ||
    payload?.reference_id ||
    payload?.data?.referenceId ||
    payload?.data?.reference_id ||
    payload?.transaction?.referenceId ||
    payload?.identifier ||
    payload?.data?.identifier ||
    null
  );
}

function providerCheckoutUrl(payload) {
  const keys = [
    "cardRedirectionUrl",
    "cardRedirectUrl",
    "redirectUrl",
    "checkoutUrl",
    "checkout_url",
  ];
  const seen = new Set();
  const visit = (value, depth = 0) => {
    if (depth > 4 || value == null || typeof value !== "object" || seen.has(value)) {
      return "";
    }
    seen.add(value);
    for (const key of keys) {
      if (typeof value[key] === "string" && value[key].trim()) return value[key].trim();
    }
    for (const child of Object.values(value)) {
      const found = visit(child, depth + 1);
      if (found) return found;
    }
    return "";
  };
  return visit(payload);
}

function successfulStatus(value) {
  return /success|complete|paid|settled|approved|processed/.test(
    String(value || "").toLowerCase(),
  );
}

function finalStatus(value) {
  return /success|complete|paid|settled|approved|processed|fail|cancel|reject|declin|expired|revers|refund/.test(
    String(value || "").toLowerCase(),
  );
}

async function transactionInput(body, operation, direction) {
  const source = body.collectionRequest || body;
  const amount = Number(source.amount);
  const settings = await getPlatformSettings();
  const feeAmount = transactionFee(amount, direction, settings);
  const suppliedReference = stringValue(source.referenceId);
  return {
    referenceId: ORDER_REFERENCE_PATTERN.test(suppliedReference || "")
      ? suppliedReference
      : makeReferenceId(),
    amount,
    feeAmount,
    netAmount: direction === "in" ? moneyRound(amount - feeAmount) : moneyRound(amount + feeAmount),
    currency: normalizeCurrency(source),
    operation,
    direction,
  };
}

function notificationPreferenceFor(type) {
  if (type === "product") return "product_updates";
  if (type === "welcome" || type === "security") return "security_alerts";
  return "transaction_alerts";
}

async function createNotification({
  merchantId,
  type,
  title,
  message,
  dedupeKey,
  metadata = {},
  priority = "important",
}) {
  if (!db || !merchantId) return null;
  const preference = notificationPreferenceFor(type);
  if (type !== "welcome") {
    const preferences = await db.query(
      `SELECT ${preference} AS enabled
         FROM notification_preferences
        WHERE merchant_id = $1`,
      [merchantId],
    );
    if (preferences.rows[0] && !preferences.rows[0].enabled) return null;
  }
  const result = await db.query(
    `INSERT INTO notifications
      (id, merchant_id, type, title, message, priority, dedupe_key, metadata)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb)
     ON CONFLICT (dedupe_key) DO NOTHING
     RETURNING *`,
    [
      crypto.randomUUID(),
      merchantId,
      type,
      title,
      message,
      priority,
      dedupeKey,
      JSON.stringify(metadata),
    ],
  );
  return result.rows[0] || null;
}

async function notifyTransaction(transaction, succeeded) {
  const direction = transaction.direction === "in"
    ? "Payment"
    : /settle|disbursement/i.test(transaction.operation || "")
      ? "Withdrawal"
      : "Money-out";
  const verb = succeeded ? "completed" : "failed";
  const amount = `${transaction.currency} ${Number(transaction.amount).toFixed(2)}`;
  return createNotification({
    merchantId: transaction.merchant_id,
    type: "transaction",
    title: `${direction} ${verb}`,
    message: `${direction} of ${amount} (${transaction.reference_id}) ${verb}.`,
    dedupeKey: `${transaction.merchant_id}:${transaction.reference_id}:${succeeded ? "success" : "failure"}`,
    metadata: {
      referenceId: transaction.reference_id,
      operation: transaction.operation,
      amount: Number(transaction.amount),
      currency: transaction.currency,
      status: transaction.status,
    },
  });
}

async function savePaymentLink(merchant, originalBody, normalizedBody, referenceId) {
  const collection = normalizedBody.collectionRequest || {};
  const photo = typeof originalBody.photo === "string" &&
    originalBody.photo.length <= 750000 &&
    originalBody.photo.startsWith("data:image/")
    ? originalBody.photo
    : null;
  await db.query(
    `INSERT INTO payment_links
      (id, merchant_id, reference_id, title, description, amount, currency,
       customer_email, narration, photo_data)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
     ON CONFLICT (reference_id) DO UPDATE SET
       title = EXCLUDED.title,
       description = EXCLUDED.description,
       customer_email = EXCLUDED.customer_email,
       narration = EXCLUDED.narration,
       photo_data = COALESCE(EXCLUDED.photo_data, payment_links.photo_data),
       updated_at = NOW()`,
    [
      crypto.randomUUID(),
      merchant.id,
      referenceId,
      stringValue(originalBody.title || collection.narration || "Card payment link"),
      stringValue(originalBody.description || originalBody.email || ""),
      Number(collection.amount),
      normalizeCurrency(collection),
      stringValue(originalBody.email),
      stringValue(collection.narration),
      photo,
    ],
  );
}

async function createPendingTransaction(merchant, body, operation, direction) {
  const input = await transactionInput(body, operation, direction);
  if (!Number.isFinite(input.amount) || input.amount <= 0) {
    throw new Error("amount must be a number greater than 0");
  }
  if (!SUPPORTED_CURRENCIES.has(input.currency)) {
    throw new Error("Unsupported transaction currency");
  }
  const walletResult = await db.query(
    `SELECT * FROM wallets
      WHERE merchant_id = $1 AND is_primary = TRUE
      ORDER BY created_at ASC LIMIT 1`,
    [merchant.id],
  );
  const wallet = walletResult.rows[0];
  if (!wallet) throw new Error("Primary wallet was not found");
  if (wallet.wallet_status && wallet.wallet_status !== "active") {
    const error = new Error("This wallet is frozen. Please contact support.");
    error.code = "WALLET_FROZEN";
    throw error;
  }
  if (direction === "out" && Number(wallet.balance) < input.netAmount) {
    const error = new Error("Insufficient wallet balance for amount and transaction fee");
    error.code = "INSUFFICIENT_BALANCE";
    throw error;
  }
  const id = crypto.randomUUID();
  const result = await db.query(
    `INSERT INTO wallet_transactions
      (id, reference_id, merchant_id, wallet_id, operation, direction, amount, fee_amount, net_amount, currency, status)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'pending')
     ON CONFLICT (reference_id) DO UPDATE SET
       merchant_id = EXCLUDED.merchant_id,
       wallet_id = EXCLUDED.wallet_id,
       operation = EXCLUDED.operation,
       direction = EXCLUDED.direction,
       amount = EXCLUDED.amount,
       fee_amount = EXCLUDED.fee_amount,
       net_amount = EXCLUDED.net_amount,
       currency = EXCLUDED.currency,
       updated_at = NOW()
     RETURNING *`,
    [
      id,
      input.referenceId,
      merchant.id,
      wallet.id,
      input.operation,
      input.direction,
      input.amount,
      input.feeAmount,
      input.netAmount,
      input.currency,
    ],
  );
  return result.rows[0];
}

async function executeInternalTransfer(merchant, body) {
  const amount = moneyRound(body.amount);
  if (!Number.isFinite(amount) || amount <= 0) throw new Error("amount must be greater than 0");
  const fromName = stringValue(body.fromWallet || body.from);
  const toName = stringValue(body.toWallet || body.to);
  if (!fromName || !toName || fromName === toName) {
    throw new Error("Choose two different wallets");
  }
  const client = await db.connect();
  let result;
  try {
    await client.query("BEGIN");
    result = await client.query(
      `SELECT * FROM wallets
        WHERE merchant_id = $1
          AND wallet_kind <> 'commission'
          AND name = ANY($2::text[])
        FOR UPDATE`,
      [merchant.id, [fromName, toName]],
    );
    const fromWallet = result.rows.find((wallet) => wallet.name === fromName);
    const toWallet = result.rows.find((wallet) => wallet.name === toName);
    if (!fromWallet || !toWallet) throw new Error("One or both wallets were not found");
    if ([fromWallet, toWallet].some((wallet) => wallet.wallet_status && wallet.wallet_status !== "active")) {
      throw new Error("One or more wallets are frozen. Please contact support.");
    }
    if (fromWallet.currency !== toWallet.currency) throw new Error("Wallet currencies must match");
    if (moneyRound(fromWallet.balance) < amount) throw new Error("Insufficient wallet balance");
    const group = crypto.randomUUID();
    const outId = crypto.randomUUID();
    const inId = crypto.randomUUID();
    const outReference = ORDER_REFERENCE_PATTERN.test(stringValue(body.referenceId) || "")
      ? stringValue(body.referenceId)
      : makeReferenceId();
    const inReference = makeReferenceId();
    await client.query(
      `INSERT INTO wallet_transactions
        (id, reference_id, merchant_id, wallet_id, operation, direction, amount, fee_amount, net_amount, currency, status, applied)
       VALUES
        ($1,$2,$3,$4,'internal_transfer','out',$5,0,$5,$6,'success',TRUE),
        ($7,$8,$3,$9,'internal_transfer','in',$5,0,$5,$6,'success',TRUE)`,
      [outId, outReference, merchant.id, fromWallet.id, amount, fromWallet.currency, inId, inReference, toWallet.id],
    );
    const beforeFrom = moneyRound(fromWallet.balance);
    const beforeTo = moneyRound(toWallet.balance);
    const afterFrom = moneyRound(beforeFrom - amount);
    const afterTo = moneyRound(beforeTo + amount);
    await client.query("UPDATE wallets SET balance = $1, updated_at = NOW() WHERE id = $2", [afterFrom, fromWallet.id]);
    await client.query("UPDATE wallets SET balance = $1, updated_at = NOW() WHERE id = $2", [afterTo, toWallet.id]);
    await client.query(
      `INSERT INTO wallet_ledger
        (id, wallet_transaction_id, merchant_id, wallet_id, entry_type, amount, balance_before, balance_after)
       VALUES
        ($1,$2,$3,$4,'internal_transfer_debit',$5,$6,$7),
        ($8,$9,$3,$10,'internal_transfer_credit',$5,$11,$12)`,
      [crypto.randomUUID(), outId, merchant.id, fromWallet.id, -amount, beforeFrom, afterFrom,
       crypto.randomUUID(), inId, toWallet.id, beforeTo, afterTo],
    );
    await client.query(
      `INSERT INTO platform_fees (id, wallet_transaction_id, merchant_id, amount, currency)
       VALUES ($1,$2,$3,0,$4),($5,$6,$3,0,$4)
       ON CONFLICT (wallet_transaction_id) DO NOTHING`,
      [crypto.randomUUID(), outId, merchant.id, fromWallet.currency, crypto.randomUUID(), inId],
    );
    await client.query("COMMIT");
    return { referenceId: outReference, amount, currency: fromWallet.currency, balance: afterFrom };
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

async function reconcileTransaction({
  referenceId,
  merchantId,
  status,
  payload = {},
  externalId = null,
}) {
  if (!db || !referenceId) return null;
  const client = await db.connect();
  try {
    await client.query("BEGIN");
    const result = await client.query(
      `SELECT t.*, w.balance AS current_balance
         FROM wallet_transactions t
         JOIN wallets w ON w.id = t.wallet_id
         WHERE (t.reference_id = $1 OR t.provider_reference_id = $1)
           AND ($2::text IS NULL OR t.merchant_id = $2)
        FOR UPDATE`,
      [referenceId, merchantId || null],
    );
    const transaction = result.rows[0];
    if (!transaction) {
      await client.query("ROLLBACK");
      return null;
    }
    const nextStatus = String(status || providerStatus(payload) || transaction.status).toLowerCase();
    const providerJson = payload && typeof payload === "object" ? payload : { raw: String(payload) };
    const providerReference = providerReferenceId(providerJson);
    if (!successfulStatus(nextStatus) || transaction.applied || !finalStatus(nextStatus)) {
      await client.query(
        `UPDATE wallet_transactions
            SET status = $1, external_id = COALESCE($2, external_id),
                provider_reference_id = COALESCE($3, provider_reference_id),
                provider_response = $4::jsonb, updated_at = NOW()
          WHERE id = $5`,
        [
          nextStatus,
          externalId || providerExternalId(providerJson),
          providerReference,
          JSON.stringify(providerJson),
          transaction.id,
        ],
      );
      await client.query("COMMIT");
      if (finalStatus(nextStatus) && !successfulStatus(nextStatus)) {
        try {
          await notifyTransaction({ ...transaction, status: nextStatus }, false);
        } catch (error) {
          console.error("Failure notification could not be created:", error.message);
        }
      }
      return { ...transaction, status: nextStatus, applied: transaction.applied };
    }
    const before = moneyRound(transaction.current_balance);
    const delta =
      transaction.direction === "in"
        ? moneyRound(transaction.net_amount)
        : -moneyRound(transaction.net_amount);
    const after = moneyRound(before + delta);
    if (after < 0) {
      await client.query(
        `UPDATE wallet_transactions
            SET status = 'balance_error', external_id = COALESCE($1, external_id),
                provider_reference_id = COALESCE($2, provider_reference_id),
                provider_response = $3::jsonb, updated_at = NOW()
          WHERE id = $4`,
        [
          externalId || providerExternalId(providerJson),
          providerReference,
          JSON.stringify(providerJson),
          transaction.id,
        ],
      );
      await client.query("COMMIT");
      return { ...transaction, status: "balance_error", applied: false };
    }
    await client.query(
      `UPDATE wallets SET balance = $1, updated_at = NOW() WHERE id = $2`,
      [after, transaction.wallet_id],
    );
    await client.query(
      `INSERT INTO wallet_ledger
        (id, wallet_transaction_id, merchant_id, wallet_id, entry_type, amount, balance_before, balance_after)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
       ON CONFLICT (wallet_transaction_id) DO NOTHING`,
      [
        crypto.randomUUID(),
        transaction.id,
        transaction.merchant_id,
        transaction.wallet_id,
        transaction.direction === "in" ? "collection_credit" : "disbursement_debit",
        delta,
        before,
        after,
      ],
    );
    await client.query(
      `INSERT INTO platform_fees (id, wallet_transaction_id, merchant_id, amount, currency)
       VALUES ($1,$2,$3,$4,$5)
       ON CONFLICT (wallet_transaction_id) DO NOTHING`,
      [
        crypto.randomUUID(),
        transaction.id,
        transaction.merchant_id,
        transaction.fee_amount,
        transaction.currency,
      ],
    );
    await client.query(
      `UPDATE wallet_transactions
          SET status = $1, applied = TRUE, external_id = COALESCE($2, external_id),
              provider_reference_id = COALESCE($3, provider_reference_id),
              provider_response = $4::jsonb, updated_at = NOW()
        WHERE id = $5`,
      [
        nextStatus,
        externalId || providerExternalId(providerJson),
        providerReference,
        JSON.stringify(providerJson),
        transaction.id,
      ],
    );
    if (transaction.direction === "in") {
      try {
        await awardDepositCommission(client, {
          ...transaction,
          status: nextStatus,
        });
      } catch (error) {
        console.error("Deposit commission could not be credited:", error.message);
        throw error;
      }
    }
    await client.query("COMMIT");
    try {
      await notifyTransaction({ ...transaction, status: nextStatus }, true);
    } catch (error) {
      console.error("Success notification could not be created:", error.message);
    }
    return { ...transaction, status: nextStatus, applied: true, balance: after };
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

async function createLedgerForRequest(req, res, body, operation, direction) {
  try {
    const source = body.collectionRequest || body;
    if (!ORDER_REFERENCE_PATTERN.test(stringValue(source.referenceId) || "")) {
      source.referenceId = makeReferenceId();
    }
    return await createPendingTransaction(req.identity.merchant, body, operation, direction);
  } catch (error) {
    jsonError(
      res,
      error.code === "INSUFFICIENT_BALANCE" ? 409 : error.code === "WALLET_FROZEN" ? 423 : 503,
      error.code || "TRANSACTION_RECORD_FAILED",
      error.message || "Could not record the transaction",
    );
    return null;
  }
}

function firstDefined(...values) {
  return values.find((value) => value !== undefined && value !== null);
}

function stringValue(value) {
  return typeof value === "string" ? value.trim() : value;
}

function normalizePhoneNumber(value) {
  const original = stringValue(value);
  if (!original) return original;
  let digits = String(original).replace(/\D/g, "");
  if (digits.startsWith("00")) digits = digits.slice(2);
  if (digits.startsWith("260")) return digits;
  if (digits.startsWith("0")) return `260${digits.slice(1)}`;
  return digits.length === 9 ? `260${digits}` : original;
}

function accountNameFromPayload(payload) {
  const keys = new Set([
    "name",
    "accountName",
    "account_name",
    "accountHolderName",
    "account_holder_name",
    "customerName",
    "customer_name",
    "fullName",
    "full_name",
  ]);
  const visited = new Set();
  const find = (value, depth = 0) => {
    if (depth > 5 || value === null || value === undefined) return "";
    if (typeof value === "string") return value.trim();
    if (typeof value !== "object" || visited.has(value)) return "";
    visited.add(value);
    for (const [key, child] of Object.entries(value)) {
      if (keys.has(key) && typeof child === "string" && child.trim()) {
        return child.trim();
      }
    }
    for (const child of Object.values(value)) {
      const found = find(child, depth + 1);
      if (found) return found;
    }
    return "";
  };
  return find(payload);
}

function makeReferenceId() {
  return randomIdentifier("ZEEDP", 12, "-");
}

async function ensureCommissionWallet(merchantId, executor = db) {
  const existing = await executor.query(
    `SELECT * FROM wallets
      WHERE merchant_id = $1 AND wallet_kind = 'commission'
      LIMIT 1`,
    [merchantId],
  );
  if (existing.rows[0]) return existing.rows[0];
  const wallet = await executor.query(
    `INSERT INTO wallets
      (id, wallet_code, merchant_id, name, currency, balance, is_primary, wallet_kind)
     VALUES ($1,$2,$3,'Commission Wallet','ZMW',0,FALSE,'commission')
     RETURNING *`,
    [crypto.randomUUID(), randomIdentifier("WAL", 10), merchantId],
  );
  return wallet.rows[0];
}

async function creditCommission(client, {
  referrerMerchantId,
  referredMerchantId,
  earningType,
  amount,
  sourceTransactionId = null,
  sourceReference = null,
}) {
  const value = moneyRound(amount);
  if (!referrerMerchantId || !Number.isFinite(value) || value <= 0) return null;
  const wallet = await ensureCommissionWallet(referrerMerchantId, client);
  const earning = await client.query(
    `INSERT INTO referral_earnings
      (id, referrer_merchant_id, referred_merchant_id, earning_type, amount,
       source_transaction_id, source_reference)
     VALUES ($1,$2,$3,$4,$5,$6,$7)
     ON CONFLICT DO NOTHING
     RETURNING *`,
    [
      crypto.randomUUID(),
      referrerMerchantId,
      referredMerchantId,
      earningType,
      value,
      sourceTransactionId,
      sourceReference,
    ],
  );
  if (!earning.rows[0]) return null;
  const transactionId = crypto.randomUUID();
  const referenceId = makeReferenceId();
  const before = moneyRound(wallet.balance);
  const after = moneyRound(before + value);
  await client.query(
    `INSERT INTO wallet_transactions
      (id, reference_id, merchant_id, wallet_id, operation, direction,
       amount, fee_amount, net_amount, currency, status, applied)
     VALUES ($1,$2,$3,$4,$5,'in',$6,0,$6,'ZMW','success',TRUE)`,
    [
      transactionId,
      referenceId,
      referrerMerchantId,
      wallet.id,
      earningType,
      value,
    ],
  );
  await client.query(
    "UPDATE wallets SET balance = $1, updated_at = NOW() WHERE id = $2",
    [after, wallet.id],
  );
  await client.query(
    `INSERT INTO wallet_ledger
      (id, wallet_transaction_id, merchant_id, wallet_id, entry_type,
       amount, balance_before, balance_after)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
    [
      crypto.randomUUID(),
      transactionId,
      referrerMerchantId,
      wallet.id,
      earningType === "referral_bonus" ? "referral_bonus_credit" : "deposit_commission_credit",
      value,
      before,
      after,
    ],
  );
  return {
    earning: earning.rows[0],
    transactionId,
    referenceId,
    balance: after,
  };
}

async function awardDepositCommission(client, transaction) {
  if (transaction.direction !== "in" || !/collection/i.test(transaction.operation || "")) {
    return null;
  }
  const referred = await client.query(
    "SELECT referred_by_merchant_id FROM merchants WHERE id = $1",
    [transaction.merchant_id],
  );
  const referrerMerchantId = referred.rows[0]?.referred_by_merchant_id;
  if (!referrerMerchantId) return null;
  const settings = await getPlatformSettings();
  return creditCommission(client, {
    referrerMerchantId,
    referredMerchantId: transaction.merchant_id,
    earningType: "deposit_commission",
    amount: moneyRound(Number(transaction.amount) * Number(settings.commissionRate) / 100),
    sourceTransactionId: transaction.id,
    sourceReference: transaction.reference_id,
  });
}

async function creditSignupBonus(client, { merchantId, walletId, amount }) {
  const value = moneyRound(amount);
  if (!merchantId || !walletId || !Number.isFinite(value) || value <= 0) return null;
  const walletResult = await client.query(
    "SELECT balance, currency FROM wallets WHERE id = $1 FOR UPDATE",
    [walletId],
  );
  const wallet = walletResult.rows[0];
  if (!wallet) return null;
  const before = moneyRound(wallet.balance);
  const after = moneyRound(before + value);
  const transactionId = crypto.randomUUID();
  const referenceId = makeReferenceId();
  await client.query(
    `INSERT INTO wallet_transactions
      (id, reference_id, merchant_id, wallet_id, operation, direction,
       amount, fee_amount, net_amount, currency, status, applied)
     VALUES ($1,$2,$3,$4,'signup_bonus','in',$5,0,$5,$6,'success',TRUE)`,
    [transactionId, referenceId, merchantId, walletId, value, wallet.currency || "ZMW"],
  );
  await client.query(
    "UPDATE wallets SET balance = $1, updated_at = NOW() WHERE id = $2",
    [after, walletId],
  );
  await client.query(
    `INSERT INTO wallet_ledger
      (id, wallet_transaction_id, merchant_id, wallet_id, entry_type,
       amount, balance_before, balance_after)
     VALUES ($1,$2,$3,$4,'signup_bonus_credit',$5,$6,$7)`,
    [crypto.randomUUID(), transactionId, merchantId, walletId, value, before, after],
  );
  return { amount: value, referenceId, balance: after };
}

function referenceFrom(body) {
  const supplied = stringValue(body.referenceId);
  return ORDER_REFERENCE_PATTERN.test(supplied || "")
    ? supplied
    : makeReferenceId();
}

function validateCommonAmountCurrency(body) {
  const amount = Number(body.amount);
  if (!Number.isFinite(amount) || amount <= 0) {
    return "amount must be a number greater than 0";
  }

  const currency = stringValue(body.currency || "ZMW").toUpperCase();
  if (!SUPPORTED_CURRENCIES.has(currency)) {
    return `currency must be one of: ${Array.from(SUPPORTED_CURRENCIES).join(", ")}`;
  }

  return null;
}

function requireFields(body, fields) {
  const missing = fields.filter((field) => {
    const value = body[field];
    return value === undefined || value === null || String(value).trim() === "";
  });
  return missing.length ? `Missing required field(s): ${missing.join(", ")}` : null;
}

function getCallbackUrl(body) {
  return stringValue(
    firstDefined(body.callbackUrl, body.callbackURL, CALLBACK_URL),
  );
}

function upstreamHeaders(callbackUrl) {
  const headers = {
    accept: "application/json",
    "content-type": "application/json",
    "x-api-key": API_KEY,
  };
  if (callbackUrl) headers.callbackUrl = callbackUrl;
  return headers;
}

async function preservePendingTransaction(ledgerTransaction, reason) {
  if (!ledgerTransaction?.referenceId) return;
  try {
    await reconcileTransaction({
      referenceId: ledgerTransaction.referenceId,
      merchantId: ledgerTransaction.merchantId,
      status: "pending",
      payload: {
        status: "pending",
        gatewayError: reason,
        recordedAt: new Date().toISOString(),
      },
    });
  } catch (error) {
    console.error("Pending transaction preservation failed:", error.message);
  }
}

async function proxyJson(res, path, body, callbackUrl, ledgerTransaction = null) {
  if (!API_BASE_URL) {
    return jsonError(
      res,
      503,
      "SERVER_MISCONFIGURED",
      "PAYMENTS_API_BASE_URL is not configured",
    );
  }
  if (!API_KEY) {
    return jsonError(
      res,
      503,
      "SERVER_MISCONFIGURED",
      "ZEEDPAY_API_KEY is not configured",
    );
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const upstreamResponse = await fetch(`${API_BASE_URL}${path}`, {
      method: "POST",
      headers: upstreamHeaders(callbackUrl),
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    if (ledgerTransaction) return forwardLedgerResponse(res, upstreamResponse, ledgerTransaction);
    return await forwardResponse(res, upstreamResponse);
  } catch (error) {
    if (error.name === "AbortError") {
      await preservePendingTransaction(
        ledgerTransaction,
        `Payment API timeout after ${REQUEST_TIMEOUT_MS}ms`,
      );
      return jsonError(
        res,
        504,
        "UPSTREAM_TIMEOUT",
        `Payment API did not respond within ${REQUEST_TIMEOUT_MS}ms`,
        ledgerTransaction
          ? { referenceId: ledgerTransaction.referenceId, status: "pending", retryable: true }
          : undefined,
      );
    }
    console.error("Upstream request failed:", error.message);
    await preservePendingTransaction(ledgerTransaction, error.message);
    return jsonError(
      res,
      502,
      "UPSTREAM_NETWORK_ERROR",
      error.message,
      ledgerTransaction
        ? { referenceId: ledgerTransaction.referenceId, status: "pending", retryable: true }
        : undefined,
    );
  } finally {
    clearTimeout(timeout);
  }
}

async function proxyGet(res, path, ledgerTransaction = null) {
  if (!API_BASE_URL) {
    return jsonError(
      res,
      503,
      "SERVER_MISCONFIGURED",
      "PAYMENTS_API_BASE_URL is not configured",
    );
  }
  if (!API_KEY) {
    return jsonError(
      res,
      503,
      "SERVER_MISCONFIGURED",
      "ZEEDPAY_API_KEY is not configured",
    );
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const upstreamResponse = await fetch(`${API_BASE_URL}${path}`, {
      method: "GET",
      headers: {
        accept: "application/json",
        "x-api-key": API_KEY,
      },
      signal: controller.signal,
    });
    if (ledgerTransaction) return forwardLedgerResponse(res, upstreamResponse, ledgerTransaction);
    return await forwardResponse(res, upstreamResponse);
  } catch (error) {
    if (error.name === "AbortError") {
      await preservePendingTransaction(
        ledgerTransaction,
        `Payment API timeout after ${REQUEST_TIMEOUT_MS}ms`,
      );
      return jsonError(
        res,
        504,
        "UPSTREAM_TIMEOUT",
        `Payment API did not respond within ${REQUEST_TIMEOUT_MS}ms`,
        ledgerTransaction
          ? { referenceId: ledgerTransaction.referenceId, status: "pending", retryable: true }
          : undefined,
      );
    }
    console.error("Upstream request failed:", error.message);
    await preservePendingTransaction(ledgerTransaction, error.message);
    return jsonError(
      res,
      502,
      "UPSTREAM_NETWORK_ERROR",
      error.message,
      ledgerTransaction
        ? { referenceId: ledgerTransaction.referenceId, status: "pending", retryable: true }
        : undefined,
    );
  } finally {
    clearTimeout(timeout);
  }
}

async function proxyMobileMoneyNameLookup(res, phoneNumber, network = "") {
  if (!PHONE_NAME_LOOKUP_PATH) {
    return jsonError(
      res,
      501,
      "PHONE_NAME_LOOKUP_UNAVAILABLE",
      "The configured payment provider does not expose a phone-name lookup endpoint",
    );
  }
  if (!API_BASE_URL || !API_KEY) {
    return jsonError(
      res,
      503,
      "SERVER_MISCONFIGURED",
      "PAYMENTS_API_BASE_URL and ZEEDPAY_API_KEY are required for phone-name lookup",
    );
  }

  const endpoint = /^https?:\/\//i.test(PHONE_NAME_LOOKUP_PATH)
    ? new URL(PHONE_NAME_LOOKUP_PATH)
    : new URL(
        `${API_BASE_URL}/${PHONE_NAME_LOOKUP_PATH.replace(/^\/+/, "")}`,
      );
  endpoint.searchParams.set("accountNumber", phoneNumber);
  endpoint.searchParams.set("phoneNumber", phoneNumber);
  if (network) endpoint.searchParams.set("network", network);

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const options = {
      method: PHONE_NAME_LOOKUP_METHOD === "POST" ? "POST" : "GET",
      headers: upstreamHeaders(""),
      signal: controller.signal,
    };
    if (options.method === "POST") {
      options.body = JSON.stringify({
        accountNumber: phoneNumber,
        phoneNumber,
        ...(network ? { network } : {}),
      });
    }
    const upstreamResponse = await fetch(endpoint, options);
    const raw = await upstreamResponse.text();
    let payload;
    try {
      payload = raw ? JSON.parse(raw) : {};
    } catch {
      payload = { raw };
    }
    if (!upstreamResponse.ok) {
      return res.status(upstreamResponse.status).json(payload);
    }
    const name = accountNameFromPayload(payload);
    return res.json({
      success: true,
      found: Boolean(name),
      phoneNumber,
      name: name || null,
      accountName: name || null,
    });
  } catch (error) {
    if (error.name === "AbortError") {
      return jsonError(
        res,
        504,
        "PHONE_NAME_LOOKUP_TIMEOUT",
        `Phone-name lookup did not respond within ${REQUEST_TIMEOUT_MS}ms`,
      );
    }
    console.error("Phone-name lookup failed:", error.message);
    return jsonError(res, 502, "PHONE_NAME_LOOKUP_FAILED", error.message);
  } finally {
    clearTimeout(timeout);
  }
}

async function forwardResponse(res, upstreamResponse) {
  const raw = await upstreamResponse.text();

  /*
   * Do not wrap or replace non-2xx upstream responses. This keeps the
   * gateway's actual HTTP status, error code, and message visible while
   * testing. The same rule also keeps successful response fields intact.
   */
  const contentType = upstreamResponse.headers.get("content-type");
  if (contentType) res.set("content-type", contentType);
  return res.status(upstreamResponse.status).send(raw);
}

async function forwardLedgerResponse(res, upstreamResponse, ledgerTransaction) {
  const raw = await upstreamResponse.text();
  let payload;
  try {
    payload = raw ? JSON.parse(raw) : {};
  } catch {
    payload = { raw };
  }
  try {
    await reconcileTransaction({
      referenceId: ledgerTransaction.referenceId,
      merchantId: ledgerTransaction.merchantId,
      status: upstreamResponse.ok ? providerStatus(payload) || "pending" : "failed",
      payload,
      externalId: providerExternalId(payload),
    });
  } catch (error) {
    console.error("Transaction reconciliation failed:", error.message);
  }
  const checkoutUrl = providerCheckoutUrl(payload);
  if (checkoutUrl && ledgerTransaction) {
    try {
      await db.query(
        `UPDATE payment_links
            SET checkout_url = $1, provider_response = $2::jsonb, updated_at = NOW()
          WHERE reference_id = $3`,
        [checkoutUrl, JSON.stringify(payload), ledgerTransaction.referenceId],
      );
    } catch (error) {
      console.error("Payment link could not be updated:", error.message);
    }
  }
  if (payload && typeof payload === "object" && !Array.isArray(payload)) {
    const upstreamReference = providerReferenceId(payload);
    if (upstreamReference && upstreamReference !== ledgerTransaction.referenceId) {
      payload.providerReferenceId = upstreamReference;
    }
    payload.referenceId = ledgerTransaction.referenceId;
    if (Object.prototype.hasOwnProperty.call(payload, "reference_id")) {
      payload.reference_id = ledgerTransaction.referenceId;
    }
    if (payload.data && typeof payload.data === "object" && !Array.isArray(payload.data)) {
      if (Object.prototype.hasOwnProperty.call(payload.data, "referenceId")) {
        payload.data.referenceId = ledgerTransaction.referenceId;
      }
      if (Object.prototype.hasOwnProperty.call(payload.data, "reference_id")) {
        payload.data.reference_id = ledgerTransaction.referenceId;
      }
    }
  }
  const contentType = upstreamResponse.headers.get("content-type");
  if (payload && typeof payload === "object" && !Array.isArray(payload)) {
    return res.status(upstreamResponse.status).json(payload);
  }
  if (contentType) res.set("content-type", contentType);
  return res.status(upstreamResponse.status).send(raw);
}

function normalizeCurrency(body) {
  return stringValue(body.currency || "ZMW").toUpperCase();
}

function normalizeCardRequest(body) {
  const customerInfo = body.customerInfo || {};
  const collectionRequest = body.collectionRequest || {};
  const merged = {
    ...body,
    ...customerInfo,
    ...collectionRequest,
  };
  const referenceId = referenceFrom(merged);

  return {
    customerInfo: {
      firstName: stringValue(firstDefined(customerInfo.firstName, body.firstName)),
      lastName: stringValue(firstDefined(customerInfo.lastName, body.lastName)),
      phoneNumber: normalizePhoneNumber(
        firstDefined(customerInfo.phoneNumber, body.phoneNumber),
      ),
      city: stringValue(firstDefined(customerInfo.city, body.city)),
      country: stringValue(firstDefined(customerInfo.country, body.country)),
      address: stringValue(firstDefined(customerInfo.address, body.address)),
      email: stringValue(firstDefined(customerInfo.email, body.email)),
      zip: stringValue(firstDefined(customerInfo.zip, body.zip)),
    },
    collectionRequest: {
      referenceId,
      amount: Number(merged.amount),
      narration: stringValue(merged.narration),
      accountNumber: stringValue(merged.accountNumber),
      currency: normalizeCurrency(merged),
      backUrl: stringValue(firstDefined(merged.backUrl, body.backURL)),
      referenceData: stringValue(merged.referenceData || referenceId),
    },
  };
}

function normalizeMobileCollection(body) {
  const referenceId = referenceFrom(body);
  return {
    referenceId,
    amount: Number(body.amount),
    narration: stringValue(body.narration),
    accountNumber: normalizePhoneNumber(body.accountNumber),
    currency: normalizeCurrency(body),
    ...(body.email ? { email: stringValue(body.email) } : {}),
    ...(body.referenceData
      ? { referenceData: stringValue(body.referenceData) }
      : {}),
  };
}

function normalizeMobileDisbursement(body) {
  const referenceId = referenceFrom(body);
  return {
    referenceId,
    amount: Number(body.amount),
    accountNumber: normalizePhoneNumber(body.accountNumber),
    currency: normalizeCurrency(body),
    ...(body.narration ? { narration: stringValue(body.narration) } : {}),
    ...(body.referenceData
      ? { referenceData: stringValue(body.referenceData) }
      : {}),
  };
}

function normalizeBankDisbursement(body) {
  const referenceId = referenceFrom(body);
  return {
    referenceId,
    amount: Number(body.amount),
    currency: normalizeCurrency(body),
    narration: stringValue(body.narration),
    accountNumber: stringValue(body.accountNumber),
    swiftCode: stringValue(body.swiftCode),
    firstName: stringValue(body.firstName),
    lastName: stringValue(body.lastName),
    accountHolderName: stringValue(body.accountHolderName),
    phoneNumber: normalizePhoneNumber(body.phoneNumber),
    ...(body.email ? { email: stringValue(body.email) } : {}),
    ...(body.referenceData
      ? { referenceData: stringValue(body.referenceData) }
      : {}),
  };
}

function validateTransaction(body, requiredFields) {
  const amountCurrencyError = validateCommonAmountCurrency(body);
  if (amountCurrencyError) return amountCurrencyError;
  return requireFields(body, requiredFields);
}

async function validateAndProxy(
  req,
  res,
  body,
  requiredFields,
  path,
  normalize,
  operation,
  direction,
) {
  const validationError = validateTransaction(body, requiredFields);
  if (validationError) {
    return jsonError(res, 400, "BAD_REQUEST", validationError);
  }
  const normalized = normalize(body);
  const ledger = await createLedgerForRequest(
    req,
    res,
    normalized,
    operation,
    direction,
  );
  if (!ledger) return;
  return proxyJson(
    res,
    path,
    normalized,
    getCallbackUrl(body),
    { referenceId: ledger.reference_id, merchantId: req.identity.merchant.id },
  );
}

function verifyWebhookSignature(rawBody, headers) {
  if (!WEBHOOK_SECRET) {
    return {
      valid: false,
      status: 503,
      message: "ZEEDPAY_WEBHOOK_SECRET is not configured",
    };
  }

  const webhookId = headers["webhook-id"];
  const timestamp = headers["webhook-timestamp"];
  const signatureHeader = headers["webhook-signature"];
  if (!webhookId || !timestamp || !signatureHeader) {
    return {
      valid: false,
      status: 400,
      message:
        "Missing webhook-id, webhook-timestamp, or webhook-signature header",
    };
  }

  const timestampNumber = Number(timestamp);
  if (!Number.isFinite(timestampNumber)) {
    return {
      valid: false,
      status: 400,
      message: "webhook-timestamp must be a Unix timestamp in seconds",
    };
  }

  if (Math.abs(Date.now() / 1000 - timestampNumber) > 300) {
    return {
      valid: false,
      status: 400,
      message: "Webhook timestamp is outside the five-minute tolerance",
    };
  }

  const secret = WEBHOOK_SECRET.replace(/^whsec_/, "");
  let key;
  try {
    key = Buffer.from(secret, "base64");
  } catch {
    return {
      valid: false,
      status: 500,
      message: "ZEEDPAY_WEBHOOK_SECRET is not valid base64",
    };
  }

  if (key.length !== 32) {
    return {
      valid: false,
      status: 500,
      message: "ZEEDPAY_WEBHOOK_SECRET must decode to exactly 32 bytes",
    };
  }

  const signedPayload = `${webhookId}.${timestamp}.${rawBody.toString("utf8")}`;
  const expected = `v1,${crypto
    .createHmac("sha256", key)
    .update(signedPayload)
    .digest("base64")}`;

  const valid = signatureHeader.split(/\s+/).some((candidate) => {
    const expectedBuffer = Buffer.from(expected);
    const candidateBuffer = Buffer.from(candidate.trim());
    return (
      expectedBuffer.length === candidateBuffer.length &&
      crypto.timingSafeEqual(expectedBuffer, candidateBuffer)
    );
  });

  return valid
    ? { valid: true }
    : { valid: false, status: 400, message: "Invalid webhook signature" };
}

function cleanupWebhookIds() {
  const cutoff = Date.now() - WEBHOOK_ID_TTL_MS;
  for (const [id, seenAt] of processedWebhookIds) {
    if (seenAt < cutoff) processedWebhookIds.delete(id);
  }
}

// CORS is deliberately open for the initial separated-frontend deployment.
app.use((req, res, next) => {
  res.set("Access-Control-Allow-Origin", process.env.CORS_ALLOW_ORIGIN || "*");
  res.set("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS");
  res.set(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization, X-Requested-With, X-Transaction-Pin",
  );
  if (req.method === "OPTIONS") return res.sendStatus(204);
  return next();
});

// Optional protection for calls from the future Zeedpay frontend. Leave unset
// to allow all frontends during testing, as requested.
app.use((req, res, next) => {
  if (
    !CLIENT_TOKEN ||
    req.path === "/health" ||
    req.path === "/" ||
    req.path === "/api/v1/webhooks/payment" ||
    req.path.startsWith("/api/v1/auth/")
  ) {
    return next();
  }
  const authorization = req.get("authorization") || "";
  if (authorization !== `Bearer ${CLIENT_TOKEN}`) {
    return jsonError(res, 401, "UNAUTHORIZED", "Invalid or missing client token");
  }
  return next();
});

app.post(
  "/api/v1/webhooks/payment",
  express.raw({ type: "application/json", limit: "1mb" }),
  async (req, res) => {
    const rawBody = Buffer.isBuffer(req.body) ? req.body : Buffer.from("");
    const verification = verifyWebhookSignature(rawBody, req.headers);
    if (!verification.valid) {
      return jsonError(
        res,
        verification.status,
        "WEBHOOK_VERIFICATION_FAILED",
        verification.message,
      );
    }

    cleanupWebhookIds();
    const webhookId = req.get("webhook-id");
    if (processedWebhookIds.has(webhookId)) {
      return res.status(200).json({
        received: true,
        duplicate: true,
        webhookId,
      });
    }

    let payload;
    try {
      payload = JSON.parse(rawBody.toString("utf8"));
    } catch {
      return jsonError(res, 400, "INVALID_JSON", "Webhook body is not valid JSON");
    }

    const webhookReference = providerReferenceId(payload);
    const webhookStatus = providerStatus(payload);
    let ledgerResult = null;
    if (webhookReference && db) {
      try {
        ledgerResult = await reconcileTransaction({
          referenceId: webhookReference,
          status: webhookStatus || "pending",
          payload,
          externalId: providerExternalId(payload),
        });
      } catch (error) {
        console.error("Webhook ledger reconciliation failed:", error.message);
        return jsonError(
          res,
          500,
          "LEDGER_RECONCILIATION_FAILED",
          "Webhook received but the wallet ledger could not be updated",
        );
      }
    }
    processedWebhookIds.set(webhookId, Date.now());

    console.log(
      JSON.stringify({
        event: "payment_webhook_received",
        webhookId,
        referenceId: webhookReference,
        status: webhookStatus || null,
        type: payload.type || null,
        ledgerApplied: Boolean(ledgerResult?.applied),
      }),
    );

    return res.status(200).json({ received: true, webhookId });
  },
);

app.use(express.json({ limit: "1mb" }));

app.get("/api/v1/auth/check-email", async (req, res) => {
  if (!databaseRequired(res)) return;
  const email = normalizeEmail(req.query.email);
  if (!validEmail(email)) return res.json({ available: false, valid: false });
  try {
    const result = await db.query(
      "SELECT 1 FROM merchants WHERE LOWER(email) = $1 LIMIT 1",
      [email],
    );
    return res.json({ available: result.rowCount === 0, valid: true });
  } catch (error) {
    return jsonError(res, 503, "DATABASE_ERROR", "Could not check the email address");
  }
});

app.get("/api/v1/auth/check-phone", async (req, res) => {
  if (!databaseRequired(res)) return;
  const phone = normalizePhoneNumber(req.query.phone);
  if (!phone || String(phone).replace(/\D/g, "").length < 9) {
    return res.json({ available: false, valid: false });
  }
  try {
    const result = await db.query(
      "SELECT 1 FROM merchants WHERE phone_number = $1 LIMIT 1",
      [phone],
    );
    return res.json({ available: result.rowCount === 0, valid: true });
  } catch (error) {
    return jsonError(res, 503, "DATABASE_ERROR", "Could not check the phone number");
  }
});

app.post("/api/v1/auth/signup", async (req, res) => {
  if (!databaseRequired(res) || !supabaseRequired(res)) return;
  const body = req.body || {};
  const fullName = stringValue(body.fullName);
  const businessName = stringValue(body.businessName);
  const phoneNumber = normalizePhoneNumber(body.phoneNumber);
  const email = normalizeEmail(body.email);
  const country = normalizeCountry(body.country);
  const password = String(body.password || "");
  const submittedReferralCode = stringValue(body.referralCode || body.ref);
  if (!fullName || !businessName || !phoneNumber || !validEmail(email) || !country) {
    return jsonError(res, 400, "BAD_REQUEST", "Complete all required account details.");
  }
  if (String(phoneNumber).replace(/\D/g, "").length < 9) {
    return jsonError(res, 400, "BAD_REQUEST", "Enter a valid phone number.");
  }
  if (password.length < 8) {
    return jsonError(res, 400, "BAD_REQUEST", "Password must be at least 8 characters.");
  }
  if (body.confirmPassword !== undefined && password !== String(body.confirmPassword)) {
    return jsonError(res, 400, "BAD_REQUEST", "Passwords do not match.");
  }
  if (!body.acceptTerms) {
    return jsonError(res, 400, "TERMS_REQUIRED", "Accept the terms and conditions to continue.");
  }
  const duplicate = await db.query(
    "SELECT email, phone_number FROM merchants WHERE LOWER(email) = $1 OR phone_number = $2 LIMIT 1",
    [email, phoneNumber],
  );
  if (duplicate.rows[0]) {
    return jsonError(
      res,
      409,
      duplicate.rows[0].email === email ? "EMAIL_IN_USE" : "PHONE_IN_USE",
      duplicate.rows[0].email === email
        ? "That email address is already in use."
        : "That phone number is already in use.",
    );
  }
  let referrer = null;
  if (submittedReferralCode) {
    const referralResult = await db.query(
      "SELECT id FROM merchants WHERE UPPER(referral_code) = UPPER($1) LIMIT 1",
      [submittedReferralCode],
    );
    if (!referralResult.rows[0]) {
      return jsonError(res, 400, "INVALID_REFERRAL_CODE", "That referral code is not valid.");
    }
    referrer = referralResult.rows[0];
  }
  const platformSettings = await getPlatformSettings();
  let signupBonusAwarded = null;
  let referralBonusAwarded = null;
  let authResult;
  let recoveredAuthUser = false;
  try {
    authResult = await supabaseRequest("/auth/v1/signup", {
      method: "POST",
      body: { email, password },
    });
  } catch (error) {
    return jsonError(res, 502, "SUPABASE_NETWORK_ERROR", "Could not reach Supabase Auth");
  }
  if (!authResult.response.ok || !authResult.data?.user?.id) {
    // If the first attempt created the Auth user but failed while creating the
    // merchant profile, allow a retry with the same verified credentials to
    // finish the local setup instead of trapping the user behind
    // "User already registered".
    const signupError = String(authErrorMessage(authResult.data, "")).toLowerCase();
    const mayBeOrphanedAuthUser = authResult.response.status === 400
      && /already|registered|exists/.test(signupError);
    let existingAuthResult = null;
    if (mayBeOrphanedAuthUser) {
      try {
        existingAuthResult = await supabaseRequest("/auth/v1/token?grant_type=password", {
          method: "POST",
          body: { email, password },
        });
      } catch (error) {
        console.error("Supabase orphan-account recovery failed:", error.message);
      }
    }
    if (existingAuthResult?.response.ok && existingAuthResult.data?.user?.id) {
      authResult = existingAuthResult;
      recoveredAuthUser = true;
    } else {
      const originalAuthError = authErrorMessage(
        authResult.data,
        "Supabase could not create the account",
      );
      const recoveryError = existingAuthResult
        ? authErrorMessage(
            existingAuthResult.data,
            "The existing Supabase account could not be used to finish setup",
          )
        : "The existing Supabase account could not be used to finish setup";
      if (mayBeOrphanedAuthUser) {
        return jsonError(
          res,
          409,
          "AUTH_ACCOUNT_EXISTS",
          `Supabase already has this account, but its merchant profile is not complete. ${recoveryError}`,
          {
            supabaseError: String(originalAuthError),
            recoveryError: String(recoveryError),
          },
        );
      }
      return jsonError(
        res,
        authResult.response.status || 400,
        "SIGNUP_FAILED",
        originalAuthError,
      );
    }
  }
  const supabaseUserId = authResult.data.user.id;
  const merchantId = randomIdentifier("ZPM", 10);
  const referralCode = randomCode("ZEE", 8);
  const merchantRowId = crypto.randomUUID();
  const walletId = crypto.randomUUID();
  const walletCode = randomIdentifier("WAL", 10);
  const walletName = businessName.slice(0, 120);
  const client = await db.connect();
  try {
    await client.query("BEGIN");
    await client.query(
      `INSERT INTO merchants
        (id, supabase_user_id, email, full_name, business_name, phone_number, country, merchant_id, referral_code,
         referred_by_merchant_id, referral_joined_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,CASE WHEN $10::text IS NULL THEN NULL ELSE NOW() END)`,
      [
        merchantRowId,
        supabaseUserId,
        email,
        fullName,
        businessName,
        phoneNumber,
        country,
        merchantId,
        referralCode,
        referrer?.id || null,
      ],
    );
    await client.query(
      `INSERT INTO wallets (id, wallet_code, merchant_id, name, currency, balance, is_primary)
       VALUES ($1,$2,$3,$4,'ZMW',0,TRUE)`,
      [walletId, walletCode, merchantRowId, walletName],
    );
    await ensureCommissionWallet(merchantRowId, client);
    signupBonusAwarded = await creditSignupBonus(client, {
      merchantId: merchantRowId,
      walletId,
      amount: platformSettings.signupBonus,
    });
    if (referrer) {
      referralBonusAwarded = await creditCommission(client, {
        referrerMerchantId: referrer.id,
        referredMerchantId: merchantRowId,
        earningType: "referral_bonus",
        amount: platformSettings.referralBonus,
      });
    }
    await client.query("COMMIT");
  } catch (error) {
    try {
      await client.query("ROLLBACK");
    } catch (rollbackError) {
      console.error("Merchant creation rollback failed:", rollbackError.message);
    }
    if (SUPABASE_SERVICE_ROLE_KEY) {
      try {
        await supabaseRequest(`/auth/v1/admin/users/${encodeURIComponent(supabaseUserId)}`, {
          method: "DELETE",
          apiKey: SUPABASE_SERVICE_ROLE_KEY,
        });
      } catch (cleanupError) {
        console.error("Supabase signup cleanup failed:", cleanupError.message);
      }
    } else {
      console.error(
        "Supabase signup cleanup skipped: SUPABASE_SERVICE_ROLE_KEY is not configured",
      );
    }
    const details = databaseErrorDetails(error);
    console.error("Merchant creation failed:", details);
    return jsonError(
      res,
      500,
      "MERCHANT_CREATION_FAILED",
      `Merchant account setup failed: ${details.message}`,
      details,
    );
  } finally {
    client.release();
  }
  if (signupBonusAwarded) {
    try {
      await createNotification({
        merchantId: merchantRowId,
        type: "welcome",
        title: "Signup bonus received",
        message: `K${signupBonusAwarded.amount.toFixed(2)} has been added to your primary wallet.`,
        dedupeKey: `${merchantRowId}:signup-bonus`,
        metadata: { amount: signupBonusAwarded.amount, referenceId: signupBonusAwarded.referenceId },
      });
    } catch (error) {
      console.error("Signup bonus notification could not be created:", error.message);
    }
  }
  if (referralBonusAwarded) {
    try {
      await createNotification({
        merchantId: referrer.id,
        type: "referral",
        title: "Referral bonus received",
        message: `K${Number(referralBonusAwarded.earning.amount).toFixed(2)} has been added to your commission wallet.`,
        dedupeKey: `${referrer.id}:referral-bonus:${merchantRowId}`,
        metadata: { amount: referralBonusAwarded.earning.amount, referredMerchantId: merchantRowId },
      });
    } catch (error) {
      console.error("Referral bonus notification could not be created:", error.message);
    }
  }
  try {
    await createNotification({
      merchantId: merchantRowId,
      type: "welcome",
      title: "Welcome to Zeedpay",
      message: "Your merchant account and primary wallet are ready.",
      dedupeKey: `${merchantRowId}:welcome`,
      metadata: { merchantId },
    });
  } catch (error) {
    console.error("Welcome notification could not be created:", error.message);
  }
  return res.status(201).json({
    success: true,
    message: "Account created. You can now log in.",
    email,
    requiresEmailConfirmation: !authResult.data.access_token && !recoveredAuthUser,
  });
});

app.post("/api/v1/auth/login", async (req, res) => {
  if (!databaseRequired(res) || !supabaseRequired(res)) return;
  const identifier = stringValue(req.body?.identifier);
  const password = String(req.body?.password || "");
  if (!identifier || !password) {
    return jsonError(res, 400, "BAD_REQUEST", "Enter your email or phone number and password.");
  }
  let email = normalizeEmail(identifier);
  if (!validEmail(email)) {
    const phone = normalizePhoneNumber(identifier);
    const lookup = await db.query(
      "SELECT email FROM merchants WHERE phone_number = $1 LIMIT 1",
      [phone],
    );
    if (!lookup.rows[0]) {
      return jsonError(res, 401, "INVALID_LOGIN", "Phone number or password is incorrect.");
    }
    email = lookup.rows[0].email;
  }
  let authResult;
  try {
    authResult = await supabaseRequest("/auth/v1/token?grant_type=password", {
      method: "POST",
      body: { email, password },
    });
  } catch (error) {
    return jsonError(res, 502, "SUPABASE_NETWORK_ERROR", "Could not reach Supabase Auth");
  }
  if (!authResult.response.ok || !authResult.data?.access_token) {
    return jsonError(
      res,
      authResult.response.status === 400 ? 401 : authResult.response.status || 401,
      "INVALID_LOGIN",
      "Email, phone number, or password is incorrect.",
    );
  }
  const merchantResult = await db.query(
    `SELECT m.*, w.id AS wallet_id, w.wallet_code, w.name AS wallet_name, w.currency AS wallet_currency,
            w.balance AS wallet_balance
       FROM merchants m
       LEFT JOIN wallets w ON w.merchant_id = m.id AND w.is_primary = TRUE
      WHERE m.supabase_user_id = $1 LIMIT 1`,
    [authResult.data.user?.id],
  );
  if (!merchantResult.rows[0]) {
    return jsonError(res, 409, "PROFILE_NOT_FOUND", "Your Auth account has no merchant profile yet.");
  }
  const row = merchantResult.rows[0];
  if (row.account_status && row.account_status !== "active") {
    return jsonError(
      res,
      403,
      "ACCOUNT_DISABLED",
      "This account is disabled. Please contact support.",
      { status: row.account_status },
    );
  }
  return res.json({
    success: true,
    accessToken: authResult.data.access_token,
    refreshToken: authResult.data.refresh_token,
    expiresIn: authResult.data.expires_in,
    merchant: publicMerchant(row, row.wallet_id
      ? { id: row.wallet_code || row.wallet_id, name: row.wallet_name, currency: row.wallet_currency, balance: row.wallet_balance }
      : null),
  });
});

app.post("/api/v1/auth/forgot-password", async (req, res) => {
  if (!supabaseRequired(res)) return;
  const email = normalizeEmail(req.body?.email);
  if (!validEmail(email)) return jsonError(res, 400, "BAD_REQUEST", "Enter a valid email address.");
  try {
    const result = await supabaseRequest("/auth/v1/recover", {
      method: "POST",
      body: {
        email,
        ...(PASSWORD_RESET_REDIRECT_URL ? { redirect_to: PASSWORD_RESET_REDIRECT_URL } : {}),
      },
    });
    if (!result.response.ok) {
      return jsonError(res, 400, "RESET_FAILED", authErrorMessage(result.data, "Could not send the reset email"));
    }
  } catch (error) {
    return jsonError(res, 502, "SUPABASE_NETWORK_ERROR", "Could not reach Supabase Auth");
  }
  return res.json({
    success: true,
    message: "If an account exists for that email, a password reset email has been sent.",
  });
});

app.put("/api/v1/auth/password", requireAuth, async (req, res) => {
  const password = String(req.body?.password || "");
  if (password.length < 8) {
    return jsonError(res, 400, "BAD_REQUEST", "Password must be at least 8 characters.");
  }
  const result = await supabaseRequest(
    "/auth/v1/user",
    { method: "PUT", body: { password } },
    bearerToken(req),
  );
  if (!result.response.ok) {
    return jsonError(res, 400, "PASSWORD_UPDATE_FAILED", authErrorMessage(result.data, "Could not update your password"));
  }
  try {
    await createNotification({
      merchantId: req.identity.merchant.id,
      type: "security",
      title: "Password updated",
      message: "Your merchant account password was changed successfully.",
      dedupeKey: `${req.identity.merchant.id}:password:${Date.now()}`,
    });
  } catch (error) {
    console.error("Password notification could not be created:", error.message);
  }
  return res.json({ success: true, message: "Password updated." });
});

app.get("/api/v1/auth/me", requireAuth, (req, res) => {
  return res.json({
    success: true,
    merchant: publicMerchant(req.identity.merchant, req.identity.wallet),
  });
});

app.put("/api/v1/profile", requireAuth, async (req, res) => {
  const fullName = stringValue(req.body?.fullName);
  const businessName = stringValue(req.body?.businessName);
  const email = normalizeEmail(req.body?.email);
  const country = normalizeCountry(req.body?.country);
  if (!fullName || !businessName || !validEmail(email) || !country) {
    return jsonError(res, 400, "BAD_REQUEST", "Enter a valid name, business name, email and country.");
  }
  if (email !== normalizeEmail(req.identity.merchant.email)) {
    const duplicate = await db.query(
      "SELECT 1 FROM merchants WHERE LOWER(email) = $1 AND id <> $2 LIMIT 1",
      [email, req.identity.merchant.id],
    );
    if (duplicate.rows[0]) return jsonError(res, 409, "EMAIL_IN_USE", "That email address is already in use.");
    const authResult = await supabaseRequest(
      "/auth/v1/user",
      { method: "PUT", body: { email } },
      bearerToken(req),
    );
    if (!authResult.response.ok) {
      return jsonError(res, 400, "EMAIL_UPDATE_FAILED", authErrorMessage(authResult.data, "Could not update your email address"));
    }
  }
  try {
    const result = await db.query(
      `UPDATE merchants
          SET full_name = $1, business_name = $2, email = $3, country = $4, updated_at = NOW()
        WHERE id = $5
        RETURNING *`,
      [fullName, businessName, email, country, req.identity.merchant.id],
    );
    await db.query(
      "UPDATE wallets SET name = $1, updated_at = NOW() WHERE merchant_id = $2 AND is_primary = TRUE",
      [businessName, req.identity.merchant.id],
    );
    return res.json({
      success: true,
      merchant: publicMerchant(result.rows[0], req.identity.wallet),
      message: email !== normalizeEmail(req.identity.merchant.email)
        ? "Profile updated. Confirm the new email address if Supabase requests it."
        : "Profile updated.",
    });
  } catch (error) {
    if (error.code === "23505") return jsonError(res, 409, "EMAIL_IN_USE", "That email address is already in use.");
    return jsonError(res, 503, "DATABASE_ERROR", "Could not update your profile");
  }
});

async function referralResponse(merchantId) {
  const commissionWallet = await ensureCommissionWallet(merchantId);
  const referrals = await db.query(
    `SELECT m.id, m.full_name, m.business_name, m.email, m.referral_joined_at,
            COALESCE(SUM(e.amount) FILTER (WHERE e.earning_type = 'referral_bonus'), 0) AS referral_bonus,
            COALESCE(SUM(e.amount) FILTER (WHERE e.earning_type = 'deposit_commission'), 0) AS deposit_commission,
            COALESCE(SUM(e.amount), 0) AS total_earned
       FROM merchants m
       LEFT JOIN referral_earnings e ON e.referred_merchant_id = m.id
      WHERE m.referred_by_merchant_id = $1
      GROUP BY m.id
      ORDER BY m.referral_joined_at DESC NULLS LAST, m.created_at DESC`,
    [merchantId],
  );
  const totals = await db.query(
    `SELECT COALESCE(SUM(amount), 0) AS total_earned,
            COUNT(*) FILTER (WHERE earning_type = 'referral_bonus') AS referral_bonus_count,
            COUNT(*) FILTER (WHERE earning_type = 'deposit_commission') AS commission_count
       FROM referral_earnings
      WHERE referrer_merchant_id = $1`,
    [merchantId],
  );
  const row = totals.rows[0] || {};
  return {
    referralCode: (await db.query("SELECT referral_code FROM merchants WHERE id = $1", [merchantId])).rows[0]?.referral_code || "",
    totalReferrals: referrals.rowCount,
    totalEarned: Number(row.total_earned || 0),
    referralBonusCount: Number(row.referral_bonus_count || 0),
    commissionCount: Number(row.commission_count || 0),
    commissionBalance: Number(commissionWallet.balance || 0),
    referrals: referrals.rows.map((referral) => ({
      id: referral.id,
      name: referral.full_name,
      businessName: referral.business_name,
      email: referral.email,
      joinedAt: referral.referral_joined_at,
      referralBonus: Number(referral.referral_bonus || 0),
      depositCommission: Number(referral.deposit_commission || 0),
      totalEarned: Number(referral.total_earned || 0),
    })),
  };
}

app.get("/api/v1/referrals", requireAuth, async (req, res) => {
  try {
    return res.json({ success: true, referrals: await referralResponse(req.identity.merchant.id) });
  } catch (error) {
    console.error("Referral summary failed:", error.message);
    return jsonError(res, 503, "DATABASE_ERROR", "Could not load referral earnings");
  }
});

app.get("/api/v1/referral-settings", requireAuth, async (req, res) => {
  try {
    const settings = await getPlatformSettings();
    return res.json({
      success: true,
      settings: {
        signupBonus: settings.signupBonus,
        referralBonus: settings.referralBonus,
        commissionRate: settings.commissionRate,
      },
    });
  } catch (error) {
    console.error("Referral settings failed:", error.message);
    return jsonError(res, 503, "DATABASE_ERROR", "Could not load referral settings");
  }
});

function publicWalletTransaction(row) {
  return {
    id: row.reference_id,
    reference: row.reference_id,
    ledgerId: row.id,
    operation: row.operation,
    note: row.note || null,
    direction: row.direction,
    amount: Number(row.amount),
    charge: Number(row.fee_amount || 0),
    net: Number(row.net_amount || row.amount),
    currency: row.currency,
    state: row.status,
    applied: row.applied,
    sourceReference: row.source_reference || null,
    updated: row.updated_at,
    created: row.created_at,
  };
}

app.get("/api/v1/commission", requireAuth, async (req, res) => {
  try {
    const settings = await getPlatformSettings();
    const wallet = await ensureCommissionWallet(req.identity.merchant.id);
    const result = await db.query(
      `SELECT t.id, t.reference_id, t.operation, t.direction, t.amount, t.fee_amount,
              t.net_amount, t.currency, t.status, t.applied, t.created_at, t.updated_at,
              e.source_reference
         FROM wallet_transactions t
         JOIN wallets w ON w.id = t.wallet_id
         LEFT JOIN referral_earnings e ON e.source_transaction_id = t.id
        WHERE t.merchant_id = $1 AND w.wallet_kind = 'commission'
        ORDER BY t.created_at DESC
        LIMIT 100`,
      [req.identity.merchant.id],
    );
    return res.json({
      success: true,
      wallet: publicWallet(wallet),
      transactions: result.rows.map(publicWalletTransaction),
      minimumWithdrawal: settings.commissionWithdrawalMinimum,
    });
  } catch (error) {
    console.error("Commission wallet failed:", error.message);
    return jsonError(res, 503, "DATABASE_ERROR", "Could not load the commission wallet");
  }
});

async function executeCommissionWithdrawal(merchantId, requestedAmount) {
  const client = await db.connect();
  try {
    await client.query("BEGIN");
    const result = await client.query(
      `SELECT * FROM wallets
        WHERE merchant_id = $1 AND wallet_kind IN ('commission', 'primary')
        ORDER BY CASE WHEN wallet_kind = 'commission' THEN 0 ELSE 1 END
        FOR UPDATE`,
      [merchantId],
    );
    const commissionWallet = result.rows.find((wallet) => wallet.wallet_kind === "commission");
    const primaryWallet = result.rows.find((wallet) => wallet.wallet_kind === "primary" && wallet.is_primary);
    if (!commissionWallet || !primaryWallet) throw new Error("Commission or primary wallet was not found");
    const balance = moneyRound(commissionWallet.balance);
    const amount = moneyRound(requestedAmount || balance);
    const settings = await getPlatformSettings();
    if (amount < settings.commissionWithdrawalMinimum) {
      const error = new Error(`Commission withdrawals start at ZMW ${settings.commissionWithdrawalMinimum.toFixed(2)}`);
      error.code = "COMMISSION_MINIMUM";
      throw error;
    }
    if (amount > balance) throw new Error("Commission wallet balance is too low");
    if (commissionWallet.currency !== primaryWallet.currency) throw new Error("Wallet currencies must match");
    const debitId = crypto.randomUUID();
    const creditId = crypto.randomUUID();
    const debitReference = makeReferenceId();
    const creditReference = makeReferenceId();
    const beforeCommission = moneyRound(commissionWallet.balance);
    const beforePrimary = moneyRound(primaryWallet.balance);
    const afterCommission = moneyRound(beforeCommission - amount);
    const afterPrimary = moneyRound(beforePrimary + amount);
    await client.query(
      `INSERT INTO wallet_transactions
        (id, reference_id, merchant_id, wallet_id, operation, direction, amount, fee_amount, net_amount, currency, status, applied)
       VALUES
        ($1,$2,$3,$4,'commission_withdrawal','out',$5,0,$5,$6,'success',TRUE),
        ($7,$8,$3,$9,'commission_withdrawal','in',$5,0,$5,$6,'success',TRUE)`,
      [debitId, debitReference, merchantId, commissionWallet.id, amount, commissionWallet.currency,
       creditId, creditReference, primaryWallet.id],
    );
    await client.query("UPDATE wallets SET balance = $1, updated_at = NOW() WHERE id = $2", [afterCommission, commissionWallet.id]);
    await client.query("UPDATE wallets SET balance = $1, updated_at = NOW() WHERE id = $2", [afterPrimary, primaryWallet.id]);
    await client.query(
      `INSERT INTO wallet_ledger
        (id, wallet_transaction_id, merchant_id, wallet_id, entry_type, amount, balance_before, balance_after)
       VALUES
        ($1,$2,$3,$4,'commission_withdrawal_debit',$5,$6,$7),
        ($8,$9,$3,$10,'commission_withdrawal_credit',$5,$11,$12)`,
      [crypto.randomUUID(), debitId, merchantId, commissionWallet.id, -amount, beforeCommission, afterCommission,
       crypto.randomUUID(), creditId, primaryWallet.id, beforePrimary, afterPrimary],
    );
    await client.query("COMMIT");
    return { amount, commissionBalance: afterCommission, walletBalance: afterPrimary, referenceId: debitReference };
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

app.post("/api/v1/commission/withdraw", requireAuth, requireTransactionPin, async (req, res) => {
  try {
    const withdrawal = await executeCommissionWithdrawal(req.identity.merchant.id, Number(req.body?.amount));
    await createNotification({
      merchantId: req.identity.merchant.id,
      type: "transaction",
      title: "Commission withdrawn",
      message: `ZMW ${withdrawal.amount.toFixed(2)} moved to your primary wallet.`,
      dedupeKey: `${req.identity.merchant.id}:${withdrawal.referenceId}:success`,
      metadata: withdrawal,
    });
    return res.status(201).json({ success: true, withdrawal });
  } catch (error) {
    return jsonError(
      res,
      error.code === "COMMISSION_MINIMUM" ? 409 : 400,
      error.code || "COMMISSION_WITHDRAWAL_FAILED",
      error.message || "Could not withdraw commission",
    );
  }
});

app.post("/api/v1/wallet/pin", requireAuth, async (req, res) => {
  const newPin = String(req.body?.newPin || "");
  const currentPin = String(req.body?.currentPin || "");
  if (!validPin(newPin)) {
    return jsonError(res, 400, "INVALID_TRANSACTION_PIN", "PIN must contain 4 to 6 digits.");
  }
  const merchant = req.identity.merchant;
  if (merchant.transaction_pin_hash) {
    if (!validPin(currentPin) || !(await verifyPin(currentPin, merchant.transaction_pin_hash))) {
      return jsonError(res, 401, "INVALID_TRANSACTION_PIN", "Enter your current transaction PIN to change it.");
    }
  }
  const encoded = await hashPin(newPin);
  await db.query(
    `UPDATE merchants
        SET transaction_pin_hash = $1, transaction_pin_length = $2,
            pin_failed_attempts = 0, pin_locked_until = NULL,
            pin_set_at = COALESCE(pin_set_at, NOW()), updated_at = NOW()
      WHERE id = $3`,
    [encoded, newPin.length, merchant.id],
  );
  try {
    await createNotification({
      merchantId: merchant.id,
      type: "security",
      title: merchant.transaction_pin_hash ? "Transaction PIN changed" : "Transaction PIN created",
      message: "Your transaction PIN settings were updated.",
      dedupeKey: `${merchant.id}:pin:${Date.now()}`,
    });
  } catch (error) {
    console.error("PIN notification could not be created:", error.message);
  }
  return res.json({ success: true, transactionPinSet: true, transactionPinLength: newPin.length });
});

app.post("/api/v1/wallet/pin/verify", requireAuth, async (req, res) => {
  const pin = String(req.body?.pin || "");
  const merchant = req.identity.merchant;
  if (!merchant.transaction_pin_hash) {
    return jsonError(res, 428, "TRANSACTION_PIN_REQUIRED", "Create a transaction PIN first.");
  }
  const lockedUntil = merchant.pin_locked_until
    ? new Date(merchant.pin_locked_until).getTime()
    : 0;
  if (lockedUntil > Date.now()) {
    return jsonError(res, 423, "TRANSACTION_PIN_LOCKED", "Transaction PIN attempts are locked for 24 hours.");
  }
  if (!validPin(pin) || !(await verifyPin(pin, merchant.transaction_pin_hash))) {
    const attempts = Number(merchant.pin_failed_attempts || 0) + 1;
    const lock = attempts >= PIN_MAX_ATTEMPTS ? new Date(Date.now() + PIN_LOCK_MS) : null;
    await db.query(
      `UPDATE merchants SET pin_failed_attempts = $1, pin_locked_until = $2, updated_at = NOW() WHERE id = $3`,
      [lock ? PIN_MAX_ATTEMPTS : attempts, lock, merchant.id],
    );
    return jsonError(
      res,
      lock ? 423 : 401,
      lock ? "TRANSACTION_PIN_LOCKED" : "INVALID_TRANSACTION_PIN",
      lock ? "Too many incorrect PIN attempts. Try again after 24 hours." : "Incorrect transaction PIN.",
    );
  }
  if (!merchant.transaction_pin_length) {
    await db.query(
      "UPDATE merchants SET transaction_pin_length = $1, updated_at = NOW() WHERE id = $2",
      [pin.length, merchant.id],
    );
  }
  return res.json({ success: true, valid: true, transactionPinLength: pin.length });
});

app.post("/api/v1/admin/login", async (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const password = String(req.body?.password || "");
  if (!validEmail(email) || !password) {
    return jsonError(res, 400, "BAD_REQUEST", "Enter the admin email and password.");
  }
  if (!adminConfigured()) {
    return jsonError(
      res,
      503,
      "ADMIN_NOT_CONFIGURED",
      "Admin credentials are not configured on the server.",
    );
  }
  if (!secretsEqual(email, ADMIN_EMAIL) || !secretsEqual(password, ADMIN_PASSWORD)) {
    return jsonError(res, 401, "INVALID_ADMIN_LOGIN", "Admin email or password is incorrect.");
  }
  return res.json({
    success: true,
    accessToken: createAdminToken(),
    expiresIn: ADMIN_SESSION_TTL_SECONDS,
    admin: { email: ADMIN_EMAIL, role: "admin" },
  });
});

app.get("/api/v1/admin/overview", requireAdmin, async (req, res) => {
  try {
    const [users, balances, transactions, feedback, recent] = await Promise.all([
      db.query(`SELECT COUNT(*)::int AS total,
          COUNT(*) FILTER (WHERE account_status = 'active')::int AS active,
          COUNT(*) FILTER (WHERE account_status = 'suspended')::int AS suspended,
          COUNT(*) FILTER (WHERE account_status = 'disabled')::int AS disabled
        FROM merchants`),
      db.query(`SELECT COALESCE(SUM(balance) FILTER (WHERE wallet_kind = 'primary'),0) AS balance,
          COALESCE(SUM(balance) FILTER (WHERE wallet_kind = 'commission'),0) AS commissions
        FROM wallets`),
      db.query(`SELECT COUNT(*)::int AS total,
          COUNT(*) FILTER (WHERE status = 'pending')::int AS pending,
          COALESCE(SUM(amount) FILTER (WHERE direction = 'in' AND status IN ('success','completed','paid','settled','approved')),0) AS deposits,
          COALESCE(SUM(amount) FILTER (WHERE direction = 'out' AND status IN ('success','completed','paid','settled','approved')),0) AS withdrawals
        FROM wallet_transactions`),
      db.query("SELECT COUNT(*)::int AS open FROM feedback WHERE status IN ('new','open')"),
      db.query(`SELECT t.reference_id, t.operation, t.direction, t.amount, t.currency, t.status, t.created_at,
          m.business_name, m.email
        FROM wallet_transactions t JOIN merchants m ON m.id = t.merchant_id
        ORDER BY t.created_at DESC LIMIT 8`),
    ]);
    return res.json({
      success: true,
      users: users.rows[0],
      balances: { primary: Number(balances.rows[0].balance), commissions: Number(balances.rows[0].commissions) },
      transactions: {
        total: transactions.rows[0].total,
        pending: transactions.rows[0].pending,
        deposits: Number(transactions.rows[0].deposits),
        withdrawals: Number(transactions.rows[0].withdrawals),
      },
      support: { open: feedback.rows[0].open },
      recent: recent.rows.map((row) => ({
        reference: row.reference_id, operation: row.operation, direction: row.direction,
        amount: Number(row.amount), currency: row.currency, status: row.status,
        created: row.created_at, businessName: row.business_name, email: row.email,
      })),
    });
  } catch (error) {
    console.error("Admin overview failed:", error.message);
    return jsonError(res, 503, "DATABASE_ERROR", "Could not load admin overview.");
  }
});

app.get("/api/v1/admin/users", requireAdmin, async (req, res) => {
  const limit = Math.min(Math.max(Number(req.query.limit) || 50, 1), 100);
  const offset = Math.max(Number(req.query.offset) || 0, 0);
  const search = stringValue(req.query.search) || "";
  const status = stringValue(req.query.status) || "";
  try {
    const result = await db.query(
      `SELECT m.id, m.merchant_id, m.full_name, m.business_name, m.email, m.phone_number,
          m.country, m.account_status, m.created_at, w.id AS wallet_id, w.wallet_code,
          w.balance, w.currency, COALESCE(n.unread,0)::int AS unread
        FROM merchants m
        LEFT JOIN wallets w ON w.merchant_id = m.id AND w.is_primary = TRUE
        LEFT JOIN (SELECT merchant_id, COUNT(*) AS unread FROM notifications
          WHERE is_read = FALSE GROUP BY merchant_id) n ON n.merchant_id = m.id
        WHERE ($1 = '' OR LOWER(m.email) LIKE LOWER($2) OR LOWER(m.full_name) LIKE LOWER($2)
          OR LOWER(m.business_name) LIKE LOWER($2) OR m.merchant_id ILIKE $2)
          AND ($3 = '' OR m.account_status = $3)
        ORDER BY m.created_at DESC LIMIT $4 OFFSET $5`,
      [search, `%${search}%`, status, limit, offset],
    );
    const count = await db.query(
      `SELECT COUNT(*)::int AS total FROM merchants m
        WHERE ($1 = '' OR LOWER(m.email) LIKE LOWER($2) OR LOWER(m.full_name) LIKE LOWER($2)
          OR LOWER(m.business_name) LIKE LOWER($2) OR m.merchant_id ILIKE $2)
          AND ($3 = '' OR m.account_status = $3)`,
      [search, `%${search}%`, status],
    );
    return res.json({
      success: true, total: count.rows[0].total,
      users: result.rows.map((row) => ({
        id: row.id, merchantId: row.merchant_id, name: row.full_name, businessName: row.business_name,
        email: row.email, phone: row.phone_number, country: row.country, status: row.account_status,
        created: row.created_at, unread: row.unread,
        wallet: row.wallet_id ? { id: row.wallet_id, code: row.wallet_code, balance: Number(row.balance), currency: row.currency } : null,
      })),
    });
  } catch (error) {
    console.error("Admin users failed:", error.message);
    return jsonError(res, 503, "DATABASE_ERROR", "Could not load users.");
  }
});

app.patch("/api/v1/admin/users/:id/status", requireAdmin, async (req, res) => {
  const status = stringValue(req.body?.status);
  if (!["active", "suspended", "disabled"].includes(status)) {
    return jsonError(res, 400, "BAD_REQUEST", "Status must be active, suspended, or disabled.");
  }
  try {
    const result = await db.query(
      `UPDATE merchants SET account_status = $1, updated_at = NOW()
        WHERE id = $2 OR merchant_id = $2
        RETURNING id, merchant_id, account_status`,
      [status, req.params.id],
    );
    if (!result.rows[0]) return jsonError(res, 404, "USER_NOT_FOUND", "User was not found.");
    await writeAudit(req.admin, `user_${status}`, "merchant", result.rows[0].id, { status });
    return res.json({ success: true, user: { id: result.rows[0].id, merchantId: result.rows[0].merchant_id, status } });
  } catch (error) {
    return jsonError(res, 503, "DATABASE_ERROR", "Could not update user status.");
  }
});

app.get("/api/v1/admin/settings", requireAdmin, async (req, res) => {
  try {
    const settings = await getPlatformSettings();
    return res.json({ success: true, settings });
  } catch (error) {
    return jsonError(res, 503, "DATABASE_ERROR", "Could not load platform settings.");
  }
});

app.patch("/api/v1/admin/settings", requireAdmin, async (req, res) => {
  const fields = {
    depositFeePercent: "deposit_fee_percent",
    depositFeeFixed: "deposit_fee_fixed",
    withdrawalFeePercent: "withdrawal_fee_percent",
    withdrawalFeeFixed: "withdrawal_fee_fixed",
    signupBonus: "signup_bonus",
    referralBonus: "referral_bonus",
    commissionRate: "commission_rate",
    commissionWithdrawalMinimum: "commission_withdrawal_minimum",
  };
  const updates = Object.entries(fields).filter(([key]) => req.body?.[key] !== undefined);
  if (!updates.length) return jsonError(res, 400, "BAD_REQUEST", "No settings supplied.");
  const values = [req.admin.email];
  const assignments = [];
  for (const [key, column] of updates) {
    const value = Number(req.body[key]);
    if (!Number.isFinite(value) || value < 0 || value > 100000) {
      return jsonError(res, 400, "BAD_REQUEST", `${key} must be a valid non-negative number.`);
    }
    values.push(value);
    assignments.push(`${column} = $${values.length}`);
  }
  try {
    await db.query(
      `INSERT INTO platform_settings (id) VALUES (1) ON CONFLICT (id) DO NOTHING;
       UPDATE platform_settings SET ${assignments.join(", ")}, updated_by = $1, updated_at = NOW() WHERE id = 1`,
      values,
    );
    await writeAudit(req.admin, "settings_updated", "platform_settings", "1",
      Object.fromEntries(updates.map(([key]) => [key, Number(req.body[key])])),
    );
    return res.json({ success: true, settings: await getPlatformSettings() });
  } catch (error) {
    console.error("Admin settings update failed:", error.message);
    return jsonError(res, 503, "DATABASE_ERROR", "Could not save platform settings.");
  }
});

app.post("/api/v1/admin/notifications", requireAdmin, async (req, res) => {
  const title = stringValue(req.body?.title);
  const message = stringValue(req.body?.message);
  const type = stringValue(req.body?.type) || "product";
  const priority = stringValue(req.body?.priority) || "important";
  const recipients = Array.isArray(req.body?.merchantIds) ? req.body.merchantIds.filter(Boolean) : [];
  if (!title || !message || title.length > 120 || message.length > 1000) {
    return jsonError(res, 400, "BAD_REQUEST", "Add a title and a message within the allowed length.");
  }
  try {
    const users = recipients.length
      ? await db.query("SELECT id FROM merchants WHERE id = ANY($1::text[])", [recipients])
      : await db.query("SELECT id FROM merchants WHERE account_status = 'active'");
    let sent = 0;
    for (const user of users.rows) {
      const result = await db.query(
        `INSERT INTO notifications (id, merchant_id, type, title, message, priority, dedupe_key, metadata)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb) ON CONFLICT (dedupe_key) DO NOTHING`,
        [crypto.randomUUID(), user.id, type, title, message, priority,
          `admin:${crypto.randomUUID()}`, JSON.stringify({ sentBy: req.admin.email })],
      );
      sent += result.rowCount;
    }
    await writeAudit(req.admin, "notification_sent", "notification", null, { recipients: recipients.length ? recipients : "all_active", sent, title });
    return res.status(201).json({ success: true, sent });
  } catch (error) {
    return jsonError(res, 503, "DATABASE_ERROR", "Could not send notifications.");
  }
});

app.get("/api/v1/admin/users/:id/features", requireAdmin, async (req, res) => {
  try {
    const result = await db.query("SELECT feature_key, enabled FROM merchant_features WHERE merchant_id = $1", [req.params.id]);
    const features = Object.fromEntries(DEFAULT_FEATURES.map((key) => [key, true]));
    result.rows.forEach((row) => { features[row.feature_key] = row.enabled; });
    return res.json({ success: true, features });
  } catch (error) {
    return jsonError(res, 503, "DATABASE_ERROR", "Could not load user features.");
  }
});

app.patch("/api/v1/admin/users/:id/features", requireAdmin, async (req, res) => {
  const entries = Object.entries(req.body?.features || {});
  const invalid = entries.find(([key, value]) => !DEFAULT_FEATURES.includes(key) || typeof value !== "boolean");
  if (invalid) return jsonError(res, 400, "BAD_REQUEST", "Invalid feature setting.");
  try {
    const user = await db.query("SELECT id FROM merchants WHERE id = $1 OR merchant_id = $1", [req.params.id]);
    if (!user.rows[0]) return jsonError(res, 404, "USER_NOT_FOUND", "User was not found.");
    for (const [key, enabled] of entries) {
      await db.query(
        `INSERT INTO merchant_features (merchant_id, feature_key, enabled, updated_by, updated_at)
         VALUES ($1,$2,$3,$4,NOW()) ON CONFLICT (merchant_id, feature_key)
         DO UPDATE SET enabled = EXCLUDED.enabled, updated_by = EXCLUDED.updated_by, updated_at = NOW()`,
        [user.rows[0].id, key, enabled, req.admin.email],
      );
    }
    await writeAudit(req.admin, "features_updated", "merchant", user.rows[0].id, { features: req.body.features });
    const features = Object.fromEntries(DEFAULT_FEATURES.map((key) => [key, true]));
    entries.forEach(([key, enabled]) => { features[key] = enabled; });
    return res.json({ success: true, features });
  } catch (error) {
    return jsonError(res, 503, "DATABASE_ERROR", "Could not save user features.");
  }
});

app.get("/api/v1/features", requireAuth, async (req, res) => {
  try {
    const result = await db.query("SELECT feature_key, enabled FROM merchant_features WHERE merchant_id = $1", [req.identity.merchant.id]);
    const features = Object.fromEntries(DEFAULT_FEATURES.map((key) => [key, true]));
    result.rows.forEach((row) => { features[row.feature_key] = row.enabled; });
    return res.json({ success: true, features });
  } catch (error) {
    return jsonError(res, 503, "DATABASE_ERROR", "Could not load feature settings.");
  }
});

app.get("/api/v1/admin/feedback", requireAdmin, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT f.id, f.category, f.message, f.status, f.created_at, m.id AS merchant_id,
          m.full_name, m.business_name, m.email
        FROM feedback f JOIN merchants m ON m.id = f.merchant_id
        ORDER BY f.created_at DESC LIMIT 200`,
    );
    return res.json({ success: true, feedback: result.rows.map((row) => ({
      id: row.id, category: row.category, message: row.message, status: row.status,
      created: row.created_at, merchantId: row.merchant_id, name: row.full_name,
      businessName: row.business_name, email: row.email,
    })) });
  } catch (error) {
    return jsonError(res, 503, "DATABASE_ERROR", "Could not load support feedback.");
  }
});

app.patch("/api/v1/admin/feedback/:id", requireAdmin, async (req, res) => {
  const status = stringValue(req.body?.status);
  if (!["new", "open", "in_progress", "resolved", "closed"].includes(status)) {
    return jsonError(res, 400, "BAD_REQUEST", "Invalid feedback status.");
  }
  try {
    const result = await db.query("UPDATE feedback SET status = $1 WHERE id = $2 RETURNING id, status", [status, req.params.id]);
    if (!result.rows[0]) return jsonError(res, 404, "FEEDBACK_NOT_FOUND", "Feedback was not found.");
    await writeAudit(req.admin, "feedback_status_updated", "feedback", req.params.id, { status });
    return res.json({ success: true, feedback: result.rows[0] });
  } catch (error) {
    return jsonError(res, 503, "DATABASE_ERROR", "Could not update feedback.");
  }
});

app.get("/api/v1/admin/audit-logs", requireAdmin, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT id, actor_email, action, entity_type, entity_id, details, created_at
        FROM audit_logs ORDER BY created_at DESC LIMIT 250`,
    );
    return res.json({ success: true, logs: result.rows.map((row) => ({
      id: row.id, actor: row.actor_email, action: row.action, entityType: row.entity_type,
      entityId: row.entity_id, details: row.details, created: row.created_at,
    })) });
  } catch (error) {
    return jsonError(res, 503, "DATABASE_ERROR", "Could not load audit logs.");
  }
});

app.get("/api/v1/admin/commissions", requireAdmin, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT e.id, e.earning_type, e.amount, e.source_reference, e.created_at,
          r.business_name AS referrer_business, r.email AS referrer_email,
          d.business_name AS referred_business, d.email AS referred_email
        FROM referral_earnings e
        JOIN merchants r ON r.id = e.referrer_merchant_id
        JOIN merchants d ON d.id = e.referred_merchant_id
        ORDER BY e.created_at DESC LIMIT 250`,
    );
    return res.json({ success: true, commissions: result.rows.map((row) => ({
      id: row.id, type: row.earning_type, amount: Number(row.amount), reference: row.source_reference,
      created: row.created_at, referrer: row.referrer_business || row.referrer_email,
      referred: row.referred_business || row.referred_email,
    })) });
  } catch (error) {
    return jsonError(res, 503, "DATABASE_ERROR", "Could not load commissions.");
  }
});

app.get("/api/v1/admin/payment-links", requireAdmin, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT p.id, p.reference_id, p.title, p.amount, p.currency, p.status, p.checkout_url,
          p.created_at, m.business_name, m.email
        FROM payment_links p JOIN merchants m ON m.id = p.merchant_id
        WHERE p.status <> 'deleted' ORDER BY p.created_at DESC LIMIT 250`,
    );
    return res.json({ success: true, links: result.rows.map((row) => ({
      id: row.id, reference: row.reference_id, title: row.title, amount: Number(row.amount),
      currency: row.currency, status: row.status, url: row.checkout_url, created: row.created_at,
      businessName: row.business_name, email: row.email,
    })) });
  } catch (error) {
    return jsonError(res, 503, "DATABASE_ERROR", "Could not load payment links.");
  }
});

app.get("/api/v1/admin/transactions", requireAdmin, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT t.id, t.reference_id, t.operation, t.direction, t.amount, t.fee_amount,
          t.net_amount, t.currency, t.status, t.applied, t.note, t.created_at, t.updated_at,
          m.business_name, m.email, w.wallet_code
        FROM wallet_transactions t JOIN merchants m ON m.id = t.merchant_id
        JOIN wallets w ON w.id = t.wallet_id
        ORDER BY t.created_at DESC LIMIT 300`,
    );
    return res.json({ success: true, transactions: result.rows.map((row) => ({
      id: row.id, reference: row.reference_id, operation: row.operation, direction: row.direction,
      amount: Number(row.amount), fee: Number(row.fee_amount), net: Number(row.net_amount),
      currency: row.currency, status: row.status, applied: row.applied, note: row.note || null, created: row.created_at,
      updated: row.updated_at, businessName: row.business_name, email: row.email, wallet: row.wallet_code,
    })) });
  } catch (error) {
    return jsonError(res, 503, "DATABASE_ERROR", "Could not load transactions.");
  }
});

app.get("/api/v1/admin/wallets", requireAdmin, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT w.id, w.wallet_code, w.name, w.currency, w.balance, w.wallet_kind,
          w.wallet_status, w.is_primary, w.updated_at, m.id AS merchant_id,
          m.merchant_id AS public_merchant_id, m.business_name, m.email
        FROM wallets w JOIN merchants m ON m.id = w.merchant_id
        ORDER BY w.updated_at DESC LIMIT 300`,
    );
    return res.json({ success: true, wallets: result.rows.map((row) => ({
      id: row.id, code: row.wallet_code, name: row.name, currency: row.currency,
      balance: Number(row.balance), kind: row.wallet_kind, status: row.wallet_status,
      primary: row.is_primary, updated: row.updated_at, merchantId: row.merchant_id,
      publicMerchantId: row.public_merchant_id, businessName: row.business_name, email: row.email,
    })) });
  } catch (error) {
    return jsonError(res, 503, "DATABASE_ERROR", "Could not load wallets.");
  }
});

app.patch("/api/v1/admin/wallets/:id/status", requireAdmin, async (req, res) => {
  const status = stringValue(req.body?.status);
  if (!["active", "frozen"].includes(status)) return jsonError(res, 400, "BAD_REQUEST", "Wallet status must be active or frozen.");
  try {
    const result = await db.query(
      `UPDATE wallets SET wallet_status = $1, updated_at = NOW()
        WHERE id = $2 OR wallet_code = $2
        RETURNING id, wallet_code, wallet_status`,
      [status, req.params.id],
    );
    if (!result.rows[0]) return jsonError(res, 404, "WALLET_NOT_FOUND", "Wallet was not found.");
    await writeAudit(req.admin, `wallet_${status}`, "wallet", result.rows[0].id, { status });
    return res.json({ success: true, wallet: { id: result.rows[0].id, code: result.rows[0].wallet_code, status } });
  } catch (error) {
    return jsonError(res, 503, "DATABASE_ERROR", "Could not update wallet status.");
  }
});

app.post("/api/v1/admin/wallets/:id/adjust", requireAdmin, async (req, res) => {
  const delta = Number(req.body?.amount);
  const trialFunds = req.body?.type === "trial_funds" || req.body?.trialFunds === true;
  const direction = trialFunds ? "credit" : stringValue(req.body?.direction);
  const reason = stringValue(req.body?.reason) || "Admin balance adjustment";
  const note = stringValue(req.body?.note || req.body?.transactionNote)
    || (trialFunds ? "Zeedpay trial funds — explore the site" : reason);
  if (!Number.isFinite(delta) || delta <= 0 || !["credit", "debit"].includes(direction)) {
    return jsonError(res, 400, "BAD_REQUEST", "Enter a positive amount and choose credit or debit.");
  }
  if (note.length > 300) {
    return jsonError(res, 400, "BAD_REQUEST", "The transaction note must be 300 characters or less.");
  }
  const client = await db.connect();
  try {
    await client.query("BEGIN");
    const walletResult = await client.query("SELECT * FROM wallets WHERE id = $1 OR wallet_code = $1 FOR UPDATE", [req.params.id]);
    const wallet = walletResult.rows[0];
    if (!wallet) {
      await client.query("ROLLBACK");
      return jsonError(res, 404, "WALLET_NOT_FOUND", "Wallet was not found.");
    }
    const value = moneyRound(delta);
    const before = moneyRound(wallet.balance);
    const after = moneyRound(direction === "credit" ? before + value : before - value);
    if (after < 0) {
      await client.query("ROLLBACK");
      return jsonError(res, 409, "INSUFFICIENT_BALANCE", "A debit cannot reduce the wallet below zero.");
    }
    const transactionId = crypto.randomUUID();
    const referenceId = makeReferenceId();
    await client.query(
      `INSERT INTO wallet_transactions
        (id, reference_id, merchant_id, wallet_id, operation, direction, amount, fee_amount, net_amount, currency, status, applied, note)
       VALUES ($1,$2,$3,$4,$5,$6,$7,0,$7,$8,'success',TRUE,$9)`,
      [transactionId, referenceId, wallet.merchant_id, wallet.id,
        trialFunds ? "trial_funds" : "admin_adjustment",
        direction === "credit" ? "in" : "out", value, wallet.currency, note],
    );
    await client.query("UPDATE wallets SET balance = $1, updated_at = NOW() WHERE id = $2", [after, wallet.id]);
    await client.query(
      `INSERT INTO wallet_ledger
        (id, wallet_transaction_id, merchant_id, wallet_id, entry_type, amount, balance_before, balance_after)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [crypto.randomUUID(), transactionId, wallet.merchant_id, wallet.id,
        trialFunds ? "trial_funds_credit" : `admin_${direction}`,
        direction === "credit" ? value : -value, before, after],
    );
    await client.query("COMMIT");
    await writeAudit(req.admin, trialFunds ? "trial_funds_granted" : `wallet_${direction}`, "wallet", wallet.id,
      { amount: value, reason, note, before, after, referenceId });
    return res.status(201).json({ success: true, referenceId, balance: after, type: trialFunds ? "trial_funds" : "adjustment", note });
  } catch (error) {
    await client.query("ROLLBACK");
    console.error("Admin wallet adjustment failed:", error.message);
    return jsonError(res, 503, "DATABASE_ERROR", "Could not adjust wallet balance.");
  } finally {
    client.release();
  }
});

app.get("/", (req, res) => {
  const authFile = frontendAsset("auth.html");
  if (authFile) return res.sendFile(authFile);
  return res.json({
    status: "ok",
    service: "zeedpay-backend",
    message: "Backend is running. Open the separately deployed Zeedpay static site.",
  });
});

// If the frontend files are bundled with this service, serve them from either
// FRONTEND_STATIC_DIR or the service directory. In a separated Render setup
// these files are not present here, so the API remains backend-only and does
// not generate an ENOENT error when Render probes the root URL.
app.get("/auth.html", (req, res) => {
  const file = frontendAsset("auth.html");
  if (!file) return jsonError(res, 404, "FRONTEND_NOT_HOSTED_HERE", "auth.html is hosted by the separate static site");
  return res.sendFile(file);
});

app.get("/index.html", (req, res) => {
  const file = frontendAsset("index.html");
  if (!file) return jsonError(res, 404, "FRONTEND_NOT_HOSTED_HERE", "index.html is hosted by the separate static site");
  return res.sendFile(file);
});

app.get("/admin.html", (req, res) => {
  const file = frontendAsset("admin.html");
  if (!file) return jsonError(res, 404, "FRONTEND_NOT_HOSTED_HERE", "admin.html is hosted by the separate static site");
  return res.sendFile(file);
});

app.get("/manifest.json", (req, res) => {
  const file = frontendAsset("manifest.json");
  if (!file) return jsonError(res, 404, "FRONTEND_NOT_HOSTED_HERE", "manifest.json is hosted by the separate static site");
  return res.sendFile(file);
});

app.get("/sw.js", (req, res) => {
  const file = frontendAsset("sw.js");
  if (!file) return jsonError(res, 404, "FRONTEND_NOT_HOSTED_HERE", "sw.js is hosted by the separate static site");
  return res.sendFile(file);
});

app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    service: "zeedpay-backend",
    environment: process.env.PAYMENTS_API_BASE_URL
      ? "configured"
      : "not-configured",
    apiKeyConfigured: Boolean(API_KEY),
    webhookVerificationConfigured: Boolean(WEBHOOK_SECRET),
    databaseConfigured: Boolean(DATABASE_URL),
    supabaseConfigured: Boolean(SUPABASE_URL && SUPABASE_ANON_KEY),
    adminConfigured: adminConfigured(),
    platformFeePercent: PLATFORM_FEE_PERCENT,
    platformFeeFixed: PLATFORM_FEE_FIXED,
    supportedCurrencies: Array.from(SUPPORTED_CURRENCIES),
    timestamp: new Date().toISOString(),
  });
});

app.get("/api/v1/config/currencies", (req, res) => {
  res.json({
    success: true,
    currencies: Array.from(SUPPORTED_CURRENCIES),
    defaultCurrency: "ZMW",
  });
});

app.get("/api/v1/wallet/balance", requireAuth, (req, res) => {
  const wallet = req.identity.wallet;
  return res.json({
    success: true,
    merchantId: req.identity.merchant.merchant_id,
    wallet: wallet
      ? {
          id: wallet.id,
          walletId: wallet.id,
          name: wallet.name,
          currency: wallet.currency,
          balance: Number(wallet.balance || 0),
        }
      : null,
    balance: Number(wallet?.balance || 0),
  });
});

app.get("/api/v1/wallets", requireAuth, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT id, wallet_code, name, currency, balance, is_primary, wallet_kind, created_at
         FROM wallets
        WHERE merchant_id = $1 AND wallet_kind <> 'commission'
        ORDER BY is_primary DESC, created_at ASC`,
      [req.identity.merchant.id],
    );
    return res.json({
      success: true,
      wallets: result.rows.map((wallet) => ({
        id: wallet.wallet_code || wallet.id,
        walletId: wallet.wallet_code || wallet.id,
        name: wallet.name,
        currency: wallet.currency,
        balance: Number(wallet.balance),
        primary: wallet.is_primary,
        kind: wallet.wallet_kind || "primary",
        created: wallet.created_at,
      })),
    });
  } catch (error) {
    return jsonError(res, 503, "DATABASE_ERROR", "Could not load wallets");
  }
});

app.post("/api/v1/wallets", requireAuth, async (req, res) => {
  const name = stringValue(req.body?.name);
  const currency = normalizeCurrency(req.body || {});
  if (name.length < 2 || name.length > 120) {
    return jsonError(res, 400, "BAD_REQUEST", "Wallet name must be 2 to 120 characters");
  }
  if (!SUPPORTED_CURRENCIES.has(currency)) {
    return jsonError(res, 400, "BAD_REQUEST", "Unsupported wallet currency");
  }
  try {
    const walletCode = randomIdentifier("WAL", 10);
    const result = await db.query(
      `INSERT INTO wallets (id, wallet_code, merchant_id, name, currency, balance, is_primary)
       VALUES ($1,$2,$3,$4,$5,0,FALSE)
       RETURNING id, wallet_code, name, currency, balance, is_primary, created_at`,
      [crypto.randomUUID(), walletCode, req.identity.merchant.id, name, currency],
    );
    return res.status(201).json({
      success: true,
      wallet: { ...result.rows[0], id: result.rows[0].wallet_code, walletId: result.rows[0].wallet_code },
    });
  } catch (error) {
    if (error.code === "23505") return jsonError(res, 409, "WALLET_EXISTS", "A wallet with that name already exists");
    return jsonError(res, 503, "DATABASE_ERROR", "Could not create wallet");
  }
});

app.post("/api/v1/wallet/transfer", requireAuth, requireTransactionPin, async (req, res) => {
  try {
    const transfer = await executeInternalTransfer(req.identity.merchant, req.body || {});
    try {
      await createNotification({
        merchantId: req.identity.merchant.id,
        type: "transaction",
        title: "Wallet transfer completed",
        message: `Internal transfer of ${transfer.currency} ${transfer.amount.toFixed(2)} completed.`,
        dedupeKey: `${req.identity.merchant.id}:${transfer.referenceId}:success`,
        metadata: transfer,
      });
    } catch (error) {
      console.error("Transfer notification could not be created:", error.message);
    }
    return res.status(201).json({ success: true, transfer });
  } catch (error) {
    return jsonError(
      res,
      error.message === "Insufficient wallet balance" ? 409 : 400,
      "TRANSFER_FAILED",
      error.message,
    );
  }
});

app.get("/api/v1/wallet/transactions", requireAuth, async (req, res) => {
  const limit = Math.min(Math.max(Number(req.query.limit) || 50, 1), 100);
  const offset = Math.max(Number(req.query.offset) || 0, 0);
  const values = [req.identity.merchant.id, limit, offset];
  const statusFilter = stringValue(req.query.status);
  const operationFilter = stringValue(req.query.operation);
  let filters = "WHERE t.merchant_id = $1";
  if (statusFilter) {
    values.push(statusFilter.toLowerCase());
    filters += ` AND t.status = $${values.length}`;
  }
  if (operationFilter) {
    values.push(operationFilter.toLowerCase());
    filters += ` AND t.operation = $${values.length}`;
  }
  try {
    const result = await db.query(
      `SELECT t.id, t.reference_id, t.operation, t.direction, t.amount, t.fee_amount,
               t.net_amount, t.currency, t.status, t.external_id, t.provider_reference_id,
               t.applied, t.note,
              t.provider_response, t.created_at, t.updated_at, w.name AS wallet_name
         FROM wallet_transactions t
         JOIN wallets w ON w.id = t.wallet_id
        ${filters}
        ORDER BY t.created_at DESC
        LIMIT $2 OFFSET $3`,
      values,
    );
    return res.json({
      success: true,
      transactions: result.rows.map((row) => ({
        id: row.reference_id,
        reference: row.reference_id,
        ledgerId: row.id,
        operation: row.operation,
        note: row.note || null,
        direction: row.direction,
        amount: Number(row.amount),
        charge: Number(row.fee_amount),
        net: Number(row.net_amount),
        currency: row.currency,
        state: row.status,
        externalId: row.external_id,
        providerReference: row.provider_reference_id,
        applied: row.applied,
        providerResponse: row.provider_response,
        wallet: row.wallet_name,
        updated: row.updated_at,
        created: row.created_at,
      })),
    });
  } catch (error) {
    console.error("Transaction list failed:", error.message);
    return jsonError(res, 503, "DATABASE_ERROR", "Could not load transactions");
  }
});

app.post("/api/v1/wallet/transactions/reconcile", requireAuth, async (req, res) => {
  const referenceId = stringValue(req.body?.referenceId);
  if (!referenceId) return jsonError(res, 400, "BAD_REQUEST", "referenceId is required");
  try {
    const transaction = await reconcileTransaction({
      referenceId,
      merchantId: req.identity.merchant.id,
      status: stringValue(req.body?.status) || "pending",
      payload: req.body?.providerResponse || {},
      externalId: stringValue(req.body?.externalId) || null,
    });
    if (!transaction) return jsonError(res, 404, "TRANSACTION_NOT_FOUND", "Transaction was not found");
    return res.json({
      success: true,
      applied: Boolean(transaction.applied),
      status: transaction.status,
    });
  } catch (error) {
    console.error("Transaction reconciliation failed:", error.message);
    return jsonError(res, 503, "LEDGER_RECONCILIATION_FAILED", "Could not update the wallet ledger");
  }
});

app.get("/api/v1/notifications", requireAuth, async (req, res) => {
  const limit = Math.min(Math.max(Number(req.query.limit) || 50, 1), 100);
  try {
    const result = await db.query(
      `SELECT id, type, title, message, priority, is_read, metadata, created_at
         FROM notifications
        WHERE merchant_id = $1
        ORDER BY created_at DESC
        LIMIT $2`,
      [req.identity.merchant.id, limit],
    );
    return res.json({
      success: true,
      notifications: result.rows.map((row) => ({
        id: row.id,
        type: row.type,
        title: row.title,
        message: row.message,
        priority: row.priority,
        read: row.is_read,
        metadata: row.metadata,
        created: row.created_at,
      })),
    });
  } catch (error) {
    console.error("Notification list failed:", error.message);
    return jsonError(res, 503, "DATABASE_ERROR", "Could not load notifications");
  }
});

app.patch("/api/v1/notifications/:id/read", requireAuth, async (req, res) => {
  try {
    const result = await db.query(
      `UPDATE notifications SET is_read = TRUE
        WHERE id = $1 AND merchant_id = $2
        RETURNING id`,
      [req.params.id, req.identity.merchant.id],
    );
    if (!result.rows[0]) return jsonError(res, 404, "NOTIFICATION_NOT_FOUND", "Notification was not found");
    return res.json({ success: true });
  } catch (error) {
    return jsonError(res, 503, "DATABASE_ERROR", "Could not update notification");
  }
});

app.post("/api/v1/notifications/read-all", requireAuth, async (req, res) => {
  try {
    await db.query(
      "UPDATE notifications SET is_read = TRUE WHERE merchant_id = $1 AND is_read = FALSE",
      [req.identity.merchant.id],
    );
    return res.json({ success: true });
  } catch (error) {
    return jsonError(res, 503, "DATABASE_ERROR", "Could not update notifications");
  }
});

app.get("/api/v1/notification-preferences", requireAuth, async (req, res) => {
  try {
    const result = await db.query(
      `INSERT INTO notification_preferences (merchant_id)
       VALUES ($1)
       ON CONFLICT (merchant_id) DO UPDATE SET merchant_id = EXCLUDED.merchant_id
       RETURNING transaction_alerts, security_alerts, product_updates`,
      [req.identity.merchant.id],
    );
    return res.json({ success: true, preferences: result.rows[0] });
  } catch (error) {
    return jsonError(res, 503, "DATABASE_ERROR", "Could not load notification settings");
  }
});

app.patch("/api/v1/notification-preferences", requireAuth, async (req, res) => {
  const allowed = ["transaction_alerts", "security_alerts", "product_updates"];
  const updates = allowed.filter((key) => typeof req.body?.[key] === "boolean");
  if (!updates.length) return jsonError(res, 400, "BAD_REQUEST", "No notification settings supplied");
  const values = [req.identity.merchant.id];
  const assignments = [];
  for (const key of updates) {
    values.push(req.body[key]);
    assignments.push(`${key} = $${values.length}`);
  }
  try {
    const result = await db.query(
      `INSERT INTO notification_preferences (merchant_id, ${updates.join(", ")})
       VALUES ($1, ${updates.map((_, index) => `$${index + 2}`).join(", ")})
       ON CONFLICT (merchant_id) DO UPDATE SET ${assignments.join(", ")}, updated_at = NOW()
       RETURNING transaction_alerts, security_alerts, product_updates`,
      values,
    );
    return res.json({ success: true, preferences: result.rows[0] });
  } catch (error) {
    console.error("Notification preferences update failed:", error.message);
    return jsonError(res, 503, "DATABASE_ERROR", "Could not save notification settings");
  }
});

app.post("/api/v1/feedback", requireAuth, async (req, res) => {
  const category = stringValue(req.body?.category) || "General";
  const message = stringValue(req.body?.message);
  if (!message || message.length > 500) {
    return jsonError(res, 400, "BAD_REQUEST", "Feedback must contain 1 to 500 characters");
  }
  try {
    const result = await db.query(
      `INSERT INTO feedback (id, merchant_id, category, message)
       VALUES ($1,$2,$3,$4)
       RETURNING id, created_at`,
      [crypto.randomUUID(), req.identity.merchant.id, category.slice(0, 80), message],
    );
    return res.status(201).json({ success: true, feedback: result.rows[0] });
  } catch (error) {
    return jsonError(res, 503, "DATABASE_ERROR", "Could not save feedback");
  }
});

app.post("/api/v1/collections/card", requireAuth, async (req, res) => {
  const body = normalizeCardRequest(req.body || {});
  const validationError =
    validateTransaction(body.collectionRequest, [
      "amount",
      "accountNumber",
      "currency",
      "narration",
      "backUrl",
      "referenceData",
    ]) ||
    requireFields(body.customerInfo, [
      "firstName",
      "lastName",
      "phoneNumber",
      "city",
      "country",
      "address",
      "zip",
      "email",
    ]);
  if (validationError) {
    return jsonError(res, 400, "BAD_REQUEST", validationError);
  }
  const ledger = await createLedgerForRequest(
    req,
    res,
    body,
    "card_collection",
    "in",
  );
  if (!ledger) return;
  return proxyJson(
    res,
    "/api/v1/collections/card",
    body,
    getCallbackUrl(req.body || {}),
    { referenceId: ledger.reference_id, merchantId: req.identity.merchant.id },
  );
});

// A card collection response includes cardRedirectionUrl. This endpoint is
// the Zeedpay payment-link entry point until a separate reusable-link endpoint
// is made available by the upstream API documentation.
app.post("/api/v1/payment-link", requireAuth, async (req, res) => {
  const body = normalizeCardRequest(req.body || {});
  const validationError =
    validateTransaction(body.collectionRequest, [
      "amount",
      "accountNumber",
      "currency",
      "narration",
      "backUrl",
      "referenceData",
    ]) ||
    requireFields(body.customerInfo, [
      "firstName",
      "lastName",
      "phoneNumber",
      "city",
      "country",
      "address",
      "zip",
      "email",
    ]);
  if (validationError) {
    return jsonError(res, 400, "BAD_REQUEST", validationError);
  }
  const ledger = await createLedgerForRequest(
    req,
    res,
    body,
    "payment_link_collection",
    "in",
  );
  if (!ledger) return;
  try {
    await savePaymentLink(req.identity.merchant, req.body || {}, body, ledger.reference_id);
  } catch (error) {
    console.error("Payment link could not be saved:", error.message);
    return jsonError(res, 503, "PAYMENT_LINK_SAVE_FAILED", "Could not save the payment link");
  }
  return proxyJson(
    res,
    "/api/v1/collections/card",
    body,
    getCallbackUrl(req.body || {}),
    { referenceId: ledger.reference_id, merchantId: req.identity.merchant.id },
  );
});
app.post("/api/v1/payment-links", requireAuth, (req, res) => {
  req.url = "/api/v1/payment-link";
  return app.handle(req, res);
});

app.get("/api/v1/payment-links", requireAuth, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT id, reference_id, title, description, amount, currency,
              customer_email, narration, checkout_url, photo_data, status, created_at, updated_at
         FROM payment_links
        WHERE merchant_id = $1 AND status <> 'deleted'
        ORDER BY created_at DESC
        LIMIT 100`,
      [req.identity.merchant.id],
    );
    return res.json({
      success: true,
      links: result.rows.map((row) => ({
        id: row.id,
        reference: row.reference_id,
        title: row.title,
        description: row.description,
        amount: Number(row.amount),
        currency: row.currency,
        email: row.customer_email,
        narration: row.narration,
        url: row.checkout_url || "",
        photo: row.photo_data || "",
        state: row.status,
        created: row.created_at,
        updated: row.updated_at,
      })),
    });
  } catch (error) {
    console.error("Payment link list failed:", error.message);
    return jsonError(res, 503, "DATABASE_ERROR", "Could not load payment links");
  }
});

app.patch("/api/v1/payment-links/:id", requireAuth, async (req, res) => {
  const nextStatus = stringValue(req.body?.status);
  if (!["active", "inactive"].includes(nextStatus)) {
    return jsonError(
      res,
      400,
      "BAD_REQUEST",
      "Payment link status must be active or inactive",
    );
  }
  try {
    const result = await db.query(
      `UPDATE payment_links
          SET status = $1, updated_at = NOW()
        WHERE merchant_id = $2
          AND (id = $3 OR reference_id = $3)
          AND status <> 'deleted'
      RETURNING id, reference_id, status, updated_at`,
      [nextStatus, req.identity.merchant.id, req.params.id],
    );
    if (!result.rows[0]) {
      return jsonError(res, 404, "PAYMENT_LINK_NOT_FOUND", "Payment link was not found");
    }
    return res.json({
      success: true,
      link: {
        id: result.rows[0].id,
        reference: result.rows[0].reference_id,
        state: result.rows[0].status,
        updated: result.rows[0].updated_at,
      },
    });
  } catch (error) {
    console.error("Payment link status update failed:", error.message);
    return jsonError(res, 503, "DATABASE_ERROR", "Could not update payment link");
  }
});

app.delete("/api/v1/payment-links/:id", requireAuth, async (req, res) => {
  try {
    const result = await db.query(
      `UPDATE payment_links
          SET status = 'deleted', updated_at = NOW()
        WHERE merchant_id = $1
          AND (id = $2 OR reference_id = $2)
          AND status <> 'deleted'
      RETURNING id, reference_id`,
      [req.identity.merchant.id, req.params.id],
    );
    if (!result.rows[0]) {
      return jsonError(res, 404, "PAYMENT_LINK_NOT_FOUND", "Payment link was not found");
    }
    return res.json({
      success: true,
      deleted: true,
      id: result.rows[0].id,
      reference: result.rows[0].reference_id,
    });
  } catch (error) {
    console.error("Payment link deletion failed:", error.message);
    return jsonError(res, 503, "DATABASE_ERROR", "Could not delete payment link");
  }
});

app.get("/api/v1/mobile-money/account-name", requireAuth, async (req, res) => {
  const phoneNumber = normalizePhoneNumber(
    firstDefined(req.query.phoneNumber, req.query.phone),
  );
  if (!phoneNumber || String(phoneNumber).replace(/\D/g, "").length < 12) {
    return jsonError(
      res,
      400,
      "BAD_REQUEST",
      "A valid Zambian mobile phone number is required",
    );
  }
  return proxyMobileMoneyNameLookup(
    res,
    phoneNumber,
    stringValue(req.query.network) || "",
  );
});

app.post("/api/v1/collections/mobile-money", requireAuth, (req, res) =>
  validateAndProxy(
    req,
    res,
    req.body || {},
    ["amount", "accountNumber", "currency", "narration"],
    "/api/v1/collections/mobile-money",
    normalizeMobileCollection,
    "collection",
    "in",
  ),
);

app.get("/api/v1/collections/check-status", requireAuth, (req, res) => {
  const referenceId = stringValue(req.query.referenceId);
  if (!referenceId) {
    return jsonError(
      res,
      400,
      "BAD_REQUEST",
      "Missing required query parameter: referenceId",
    );
  }
  return proxyGet(
    res,
    `/api/v1/collections/check-status?referenceId=${encodeURIComponent(
      referenceId,
    )}`,
    { referenceId, merchantId: req.identity.merchant.id },
  );
});

app.post("/api/v1/disbursements/mobile-money", requireAuth, requireTransactionPin, (req, res) =>
  validateAndProxy(
    req,
    res,
    req.body || {},
    ["amount", "accountNumber", "currency"],
    "/api/v1/disbursements/mobile-money",
    normalizeMobileDisbursement,
    "disbursement",
    "out",
  ),
);

app.post("/api/v1/disbursements/bank", requireAuth, requireTransactionPin, (req, res) =>
  validateAndProxy(
    req,
    res,
    req.body || {},
    [
      "amount",
      "currency",
      "narration",
      "accountNumber",
      "swiftCode",
      "firstName",
      "lastName",
      "accountHolderName",
      "phoneNumber",
    ],
    "/api/v1/disbursements/bank",
    normalizeBankDisbursement,
    "bank_disbursement",
    "out",
  ),
);

app.get("/api/v1/disbursements/check-status", requireAuth, (req, res) => {
  const referenceId = stringValue(req.query.referenceId);
  if (!referenceId) {
    return jsonError(
      res,
      400,
      "BAD_REQUEST",
      "Missing required query parameter: referenceId",
    );
  }
  return proxyGet(
    res,
    `/api/v1/disbursements/check-status?referenceId=${encodeURIComponent(
      referenceId,
    )}`,
    { referenceId, merchantId: req.identity.merchant.id },
  );
});

/*
 * The supplied documentation describes settlement as a wallet-to-bank
 * transfer, while documenting the callable bank and mobile-money payout
 * endpoints under disbursements. These aliases expose Zeedpay's settlement
 * naming while forwarding to those documented payout endpoints.
 */
app.post("/api/v1/settlements/bank", requireAuth, requireTransactionPin, (req, res) =>
  validateAndProxy(
    req,
    res,
    req.body || {},
    [
      "amount",
      "currency",
      "narration",
      "accountNumber",
      "swiftCode",
      "firstName",
      "lastName",
      "accountHolderName",
      "phoneNumber",
    ],
    "/api/v1/disbursements/bank",
    normalizeBankDisbursement,
    "settlement",
    "out",
  ),
);

app.post("/api/v1/settlements/mobile-money", requireAuth, requireTransactionPin, (req, res) =>
  validateAndProxy(
    req,
    res,
    req.body || {},
    ["amount", "accountNumber", "currency"],
    "/api/v1/disbursements/mobile-money",
    normalizeMobileDisbursement,
    "settlement",
    "out",
  ),
);

app.post("/api/v1/settle/bank", (req, res) => {
  req.url = "/api/v1/settlements/bank";
  return app.handle(req, res);
});
app.post("/api/v1/settle/mobile-money", (req, res) => {
  req.url = "/api/v1/settlements/mobile-money";
  return app.handle(req, res);
});

app.use((req, res) => {
  return jsonError(
    res,
    404,
    "NOT_FOUND",
    `Route not found: ${req.method} ${req.originalUrl}`,
  );
});

app.use((error, req, res, next) => {
  if (error instanceof SyntaxError && "body" in error) {
    return jsonError(res, 400, "INVALID_JSON", "Request body is not valid JSON");
  }
  console.error("Unhandled server error:", error);
  return jsonError(
    res,
    500,
    "INTERNAL_SERVER_ERROR",
    error.message || "Internal server error",
  );
});

initializeDatabase()
  .catch((error) => {
    console.error("Railway database initialization failed:", error.message);
    if (process.env.FAIL_ON_DATABASE_ERROR === "true") process.exitCode = 1;
  })
  .finally(() => {
    app.listen(PORT, "0.0.0.0", () => {
      console.log(`Zeedpay API listening on port ${PORT}`);
      console.log(`Payment API base URL: ${API_BASE_URL}`);
      if (!DATABASE_URL) console.warn("DATABASE_URL is not configured; auth and wallet routes will return 503.");
      if (!SUPABASE_URL || !SUPABASE_ANON_KEY) console.warn("SUPABASE_URL/SUPABASE_ANON_KEY are not configured; auth routes will return 503.");
      if (!adminConfigured()) console.warn("ZEEDPAY_ADMIN_EMAIL, ZEEDPAY_ADMIN_PASSWORD, and ZEEDPAY_ADMIN_SESSION_SECRET are not fully configured; admin login will return 503.");
      if (!API_KEY) {
        console.warn("ZEEDPAY_API_KEY is not configured; payment requests will return 503.");
      }
    });
  });