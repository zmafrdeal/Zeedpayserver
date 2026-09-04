/*
 * Zeedpay backend
 *
 * This service is intentionally an API-only proxy. It does not read or serve
 * HTML files. The frontend can be hosted separately and can call this server
 * from any origin while CORS_ALLOW_ORIGIN is left as "*".
 *
 * The upstream API returns transaction statuses asynchronously. The create
 * endpoints therefore return the upstream response, including pending,
 * successful, and failed responses. Upstream error bodies are passed through
 * without replacing their message.
 */

const express = require("express");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();
const PORT = Number(process.env.PORT || 10000);
const API_BASE_URL = (process.env.PAYMENTS_API_BASE_URL || "").replace(
  /\/+$/,
  "",
);
const API_KEY = process.env.ZEEDPAY_API_KEY || "";
const CALLBACK_URL = process.env.ZEEDPAY_CALLBACK_URL || "";
const WEBHOOK_SECRET = process.env.ZEEDPAY_WEBHOOK_SECRET || "";
const CLIENT_TOKEN = process.env.ZEEDPAY_CLIENT_TOKEN || "";
const REQUEST_TIMEOUT_MS = Number(process.env.REQUEST_TIMEOUT_MS || 30000);
const SUPPORTED_CURRENCIES = new Set(["ZMW", "USD"]);
const SUPABASE_URL = (process.env.SUPABASE_URL || "").replace(/\/+$/, "");
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || "";
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || "";
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

function randomCode(prefix, bytes = 5) {
  return `${prefix}-${crypto.randomBytes(bytes).toString("hex").toUpperCase()}`;
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
    businessName: merchant.business_name,
    phoneNumber: merchant.phone_number,
    email: merchant.email,
    country: merchant.country,
    createdAt: merchant.created_at,
    transactionPinSet: Boolean(merchant.transaction_pin_hash),
    pinLockedUntil: merchant.pin_locked_until,
    wallet: wallet
      ? {
          id: wallet.id,
          name: wallet.name,
          currency: wallet.currency,
          balance: Number(wallet.balance || 0),
        }
      : null,
  };
}

async function merchantForRequest(req) {
  if (!db || !SUPABASE_URL || !SUPABASE_ANON_KEY) return null;
  const token = bearerToken(req);
  if (!token) return null;
  const result = await supabaseRequest("/auth/v1/user", {}, token);
  if (!result.response.ok || !result.data?.id) return null;
  const merchantResult = await db.query(
    `SELECT m.*, w.id AS wallet_id, w.name AS wallet_name, w.currency AS wallet_currency,
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
          id: row.wallet_id,
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
    req.identity = identity;
    return next();
  } catch (error) {
    console.error("Authentication lookup failed:", error.message);
    return jsonError(res, 503, "AUTH_LOOKUP_FAILED", "Could not verify your session");
  }
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
      merchant_id TEXT NOT NULL REFERENCES merchants(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      currency TEXT NOT NULL DEFAULT 'ZMW',
      balance NUMERIC(18, 2) NOT NULL DEFAULT 0,
      is_primary BOOLEAN NOT NULL DEFAULT TRUE,
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
  `);
  console.log("Railway database schema is ready");
}

function moneyRound(value) {
  return Math.round(Number(value || 0) * 100) / 100;
}

function transactionFee(amount) {
  const calculated =
    (Number(amount) * PLATFORM_FEE_PERCENT) / 100 + PLATFORM_FEE_FIXED;
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

function transactionInput(body, operation, direction) {
  const source = body.collectionRequest || body;
  const amount = Number(source.amount);
  const feeAmount = transactionFee(amount);
  return {
    referenceId: stringValue(source.referenceId) || makeReferenceId(),
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
  const direction = transaction.direction === "in" ? "Payment" : "Money-out";
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
  const input = transactionInput(body, operation, direction);
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
     ON CONFLICT (reference_id) DO UPDATE SET updated_at = NOW()
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
        WHERE merchant_id = $1 AND name = ANY($2::text[])
        FOR UPDATE`,
      [merchant.id, [fromName, toName]],
    );
    const fromWallet = result.rows.find((wallet) => wallet.name === fromName);
    const toWallet = result.rows.find((wallet) => wallet.name === toName);
    if (!fromWallet || !toWallet) throw new Error("One or both wallets were not found");
    if (fromWallet.currency !== toWallet.currency) throw new Error("Wallet currencies must match");
    if (moneyRound(fromWallet.balance) < amount) throw new Error("Insufficient wallet balance");
    const group = crypto.randomUUID();
    const outId = crypto.randomUUID();
    const inId = crypto.randomUUID();
    const outReference = stringValue(body.referenceId) || `TRF-${crypto.randomBytes(8).toString("hex").toUpperCase()}`;
    const inReference = `${outReference}-IN`;
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
        WHERE t.reference_id = $1 AND ($2::text IS NULL OR t.merchant_id = $2)
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
    if (!successfulStatus(nextStatus) || transaction.applied || !finalStatus(nextStatus)) {
      await client.query(
        `UPDATE wallet_transactions
            SET status = $1, external_id = COALESCE($2, external_id),
                provider_response = $3::jsonb, updated_at = NOW()
          WHERE id = $4`,
        [nextStatus, externalId || providerExternalId(providerJson), JSON.stringify(providerJson), transaction.id],
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
                provider_response = $2::jsonb, updated_at = NOW()
          WHERE id = $3`,
        [externalId || providerExternalId(providerJson), JSON.stringify(providerJson), transaction.id],
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
              provider_response = $3::jsonb, updated_at = NOW()
        WHERE id = $4`,
      [
        nextStatus,
        externalId || providerExternalId(providerJson),
        JSON.stringify(providerJson),
        transaction.id,
      ],
    );
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
    if (!source.referenceId) source.referenceId = makeReferenceId();
    return await createPendingTransaction(req.identity.merchant, body, operation, direction);
  } catch (error) {
    jsonError(
      res,
      error.code === "INSUFFICIENT_BALANCE" ? 409 : 503,
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

function makeReferenceId() {
  const now = new Date();
  const yyyy = now.getUTCFullYear();
  const mm = String(now.getUTCMonth() + 1).padStart(2, "0");
  const dd = String(now.getUTCDate()).padStart(2, "0");
  const hh = String(now.getUTCHours()).padStart(2, "0");
  const min = String(now.getUTCMinutes()).padStart(2, "0");
  const ss = String(now.getUTCSeconds()).padStart(2, "0");
  const ms = String(now.getUTCMilliseconds()).padStart(3, "0");
  const suffix = crypto.randomInt(1000, 10000);
  return `ZEEDP-${yyyy}${mm}${dd}-${hh}${min}${ss}-${ms}-${suffix}`;
}

function referenceFrom(body) {
  return stringValue(body.referenceId) || makeReferenceId();
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
      return jsonError(
        res,
        504,
        "UPSTREAM_TIMEOUT",
        `Payment API did not respond within ${REQUEST_TIMEOUT_MS}ms`,
      );
    }
    console.error("Upstream request failed:", error.message);
    return jsonError(res, 502, "UPSTREAM_NETWORK_ERROR", error.message);
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
      return jsonError(
        res,
        504,
        "UPSTREAM_TIMEOUT",
        `Payment API did not respond within ${REQUEST_TIMEOUT_MS}ms`,
      );
    }
    console.error("Upstream request failed:", error.message);
    return jsonError(res, 502, "UPSTREAM_NETWORK_ERROR", error.message);
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
  const contentType = upstreamResponse.headers.get("content-type");
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
  res.set("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
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
  let authResult;
  try {
    authResult = await supabaseRequest("/auth/v1/signup", {
      method: "POST",
      body: { email, password },
    });
  } catch (error) {
    return jsonError(res, 502, "SUPABASE_NETWORK_ERROR", "Could not reach Supabase Auth");
  }
  if (!authResult.response.ok || !authResult.data?.user?.id) {
    return jsonError(
      res,
      authResult.response.status || 400,
      "SIGNUP_FAILED",
      authErrorMessage(authResult.data, "Supabase could not create the account"),
    );
  }
  const supabaseUserId = authResult.data.user.id;
  const merchantId = `LPM-${crypto.randomBytes(6).toString("hex").toUpperCase()}`;
  const referralCode = randomCode("LIP", 5);
  const merchantRowId = crypto.randomUUID();
  const walletId = crypto.randomUUID();
  const walletName = businessName.toUpperCase().slice(0, 120);
  const client = await db.connect();
  try {
    await client.query("BEGIN");
    await client.query(
      `INSERT INTO merchants
        (id, supabase_user_id, email, full_name, business_name, phone_number, country, merchant_id, referral_code)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
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
      ],
    );
    await client.query(
      `INSERT INTO wallets (id, merchant_id, name, currency, balance, is_primary)
       VALUES ($1,$2,$3,'ZMW',0,TRUE)`,
      [walletId, merchantRowId, walletName],
    );
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    if (SUPABASE_SERVICE_ROLE_KEY) {
      try {
        await supabaseRequest(`/auth/v1/admin/users/${encodeURIComponent(supabaseUserId)}`, {
          method: "DELETE",
          apiKey: SUPABASE_SERVICE_ROLE_KEY,
        });
      } catch (cleanupError) {
        console.error("Supabase signup cleanup failed:", cleanupError.message);
      }
    }
    console.error("Merchant creation failed:", error.message);
    return jsonError(res, 500, "MERCHANT_CREATION_FAILED", "Could not finish creating your merchant account");
  } finally {
    client.release();
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
    requiresEmailConfirmation: !authResult.data.access_token,
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
    `SELECT m.*, w.id AS wallet_id, w.name AS wallet_name, w.currency AS wallet_currency,
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
  return res.json({
    success: true,
    accessToken: authResult.data.access_token,
    refreshToken: authResult.data.refresh_token,
    expiresIn: authResult.data.expires_in,
    merchant: publicMerchant(row, row.wallet_id
      ? { id: row.wallet_id, name: row.wallet_name, currency: row.wallet_currency, balance: row.wallet_balance }
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
        SET transaction_pin_hash = $1, pin_failed_attempts = 0, pin_locked_until = NULL,
            pin_set_at = COALESCE(pin_set_at, NOW()), updated_at = NOW()
      WHERE id = $2`,
    [encoded, merchant.id],
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
  return res.json({ success: true, transactionPinSet: true });
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
  return res.json({ success: true, valid: true });
});

app.get("/", (req, res) => {
  res.json({
    name: "Zeedpay API",
    status: "ok",
    message: "API-only service; frontend files are hosted separately.",
  });
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
      `SELECT id, name, currency, balance, is_primary, created_at
         FROM wallets WHERE merchant_id = $1 ORDER BY is_primary DESC, created_at ASC`,
      [req.identity.merchant.id],
    );
    return res.json({
      success: true,
      wallets: result.rows.map((wallet) => ({
        id: wallet.id,
        name: wallet.name,
        currency: wallet.currency,
        balance: Number(wallet.balance),
        primary: wallet.is_primary,
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
    const result = await db.query(
      `INSERT INTO wallets (id, merchant_id, name, currency, balance, is_primary)
       VALUES ($1,$2,$3,$4,0,FALSE)
       RETURNING id, name, currency, balance, is_primary, created_at`,
      [crypto.randomUUID(), req.identity.merchant.id, name, currency],
    );
    return res.status(201).json({ success: true, wallet: result.rows[0] });
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
              t.net_amount, t.currency, t.status, t.external_id, t.applied,
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
        direction: row.direction,
        amount: Number(row.amount),
        charge: Number(row.fee_amount),
        net: Number(row.net_amount),
        currency: row.currency,
        state: row.status,
        externalId: row.external_id,
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
        WHERE merchant_id = $1
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
      if (!API_KEY) {
        console.warn("ZEEDPAY_API_KEY is not configured; payment requests will return 503.");
      }
    });
  });