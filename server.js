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

const app = express();
const PORT = Number(process.env.PORT || 10000);
const API_BASE_URL = (
  process.env.PAYMENTS_API_BASE_URL || "https://api.lipila.dev"
).replace(/\/+$/, "");
const API_KEY = process.env.ZEEDPAY_API_KEY || "";
const CALLBACK_URL = process.env.ZEEDPAY_CALLBACK_URL || "";
const WEBHOOK_SECRET = process.env.ZEEDPAY_WEBHOOK_SECRET || "";
const CLIENT_TOKEN = process.env.ZEEDPAY_CLIENT_TOKEN || "";
const REQUEST_TIMEOUT_MS = Number(process.env.REQUEST_TIMEOUT_MS || 30000);
const SUPPORTED_CURRENCIES = new Set(["ZMW", "USD"]);
const processedWebhookIds = new Map();
const WEBHOOK_ID_TTL_MS = 24 * 60 * 60 * 1000;

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

function firstDefined(...values) {
  return values.find((value) => value !== undefined && value !== null);
}

function stringValue(value) {
  return typeof value === "string" ? value.trim() : value;
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

async function proxyJson(res, path, body, callbackUrl) {
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

async function proxyGet(res, path) {
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
      phoneNumber: stringValue(
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
    accountNumber: stringValue(body.accountNumber),
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
    accountNumber: stringValue(body.accountNumber),
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
    phoneNumber: stringValue(body.phoneNumber),
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

function validateAndProxy(res, body, requiredFields, path, normalize) {
  const validationError = validateTransaction(body, requiredFields);
  if (validationError) {
    return jsonError(res, 400, "BAD_REQUEST", validationError);
  }
  const normalized = normalize(body);
  return proxyJson(res, path, normalized, getCallbackUrl(body));
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
    "Content-Type, Authorization, X-Requested-With",
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
    req.path === "/api/v1/webhooks/payment"
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
  (req, res) => {
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

    processedWebhookIds.set(webhookId, Date.now());
    let payload;
    try {
      payload = JSON.parse(rawBody.toString("utf8"));
    } catch {
      return jsonError(res, 400, "INVALID_JSON", "Webhook body is not valid JSON");
    }

    console.log(
      JSON.stringify({
        event: "payment_webhook_received",
        webhookId,
        referenceId: payload.referenceId || payload.identifier || null,
        status: payload.status || null,
        type: payload.type || null,
      }),
    );

    return res.status(200).json({ received: true, webhookId });
  },
);

app.use(express.json({ limit: "1mb" }));

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
      : "sandbox-default",
    apiKeyConfigured: Boolean(API_KEY),
    webhookVerificationConfigured: Boolean(WEBHOOK_SECRET),
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

app.get("/api/v1/wallet/balance", (req, res) =>
  proxyGet(res, "/api/v1/merchants/balance"),
);

app.post("/api/v1/collections/card", (req, res) => {
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
  return proxyJson(
    res,
    "/api/v1/collections/card",
    body,
    getCallbackUrl(req.body || {}),
  );
});

// A card collection response includes cardRedirectionUrl. This endpoint is
// the Zeedpay payment-link entry point until a separate reusable-link endpoint
// is made available by the upstream API documentation.
app.post("/api/v1/payment-link", (req, res) => {
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
  return proxyJson(
    res,
    "/api/v1/collections/card",
    body,
    getCallbackUrl(req.body || {}),
  );
});
app.post("/api/v1/payment-links", (req, res) => {
  req.url = "/api/v1/payment-link";
  return app.handle(req, res);
});

app.post("/api/v1/collections/mobile-money", (req, res) =>
  validateAndProxy(
    res,
    req.body || {},
    ["amount", "accountNumber", "currency", "narration"],
    "/api/v1/collections/mobile-money",
    normalizeMobileCollection,
  ),
);

app.get("/api/v1/collections/check-status", (req, res) => {
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
  );
});

app.post("/api/v1/disbursements/mobile-money", (req, res) =>
  validateAndProxy(
    res,
    req.body || {},
    ["amount", "accountNumber", "currency"],
    "/api/v1/disbursements/mobile-money",
    normalizeMobileDisbursement,
  ),
);

app.post("/api/v1/disbursements/bank", (req, res) =>
  validateAndProxy(
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
  ),
);

app.get("/api/v1/disbursements/check-status", (req, res) => {
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
  );
});

/*
 * The supplied documentation describes settlement as a wallet-to-bank
 * transfer, while documenting the callable bank and mobile-money payout
 * endpoints under disbursements. These aliases expose Zeedpay's settlement
 * naming while forwarding to those documented payout endpoints.
 */
app.post("/api/v1/settlements/bank", (req, res) =>
  validateAndProxy(
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
  ),
);

app.post("/api/v1/settlements/mobile-money", (req, res) =>
  validateAndProxy(
    res,
    req.body || {},
    ["amount", "accountNumber", "currency"],
    "/api/v1/disbursements/mobile-money",
    normalizeMobileDisbursement,
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

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Zeedpay API listening on port ${PORT}`);
  console.log(`Payment API base URL: ${API_BASE_URL}`);
  if (!API_KEY) {
    console.warn("ZEEDPAY_API_KEY is not configured; payment requests will return 503.");
  }
});