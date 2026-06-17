#!/usr/bin/env node
import { execFile as execFileCallback, spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import fsp from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { fileURLToPath, pathToFileURL } from "node:url";
import { loadDevEnv, root as repoRoot } from "./dev-env.mjs";

const execFile = promisify(execFileCallback);

export const WEB_ORIGIN = "http://localhost:3000";
export const API_ORIGIN = "http://127.0.0.1:4100";
export const BROWSER_API_ORIGIN = "http://localhost:4100";
export const EXPECTED_PORTS = Object.freeze({
  postgres: 5433,
  nats: 4222,
  natsMonitor: 8222,
  api: 4100,
  web: 3000
});

export function isOAuthWellKnownMetadataRequest(url) {
  try {
    const parsed = new URL(url);
    return (
      parsed.origin === WEB_ORIGIN &&
      (parsed.pathname === "/.well-known/oauth-protected-resource" ||
        parsed.pathname === "/.well-known/oauth-protected-resource/api/v1/mcp" ||
        parsed.pathname === "/.well-known/oauth-authorization-server")
    );
  } catch {
    return false;
  }
}

export function isDirectProductApiV1BrowserRequest(url, requestType) {
  return (
    requestType !== "Document" &&
    /\/api\/v1\//.test(url) &&
    !isOAuthWellKnownMetadataRequest(url)
  );
}

export const CANONICAL_ROUTES = Object.freeze([
  {
    path: "/",
    url: `${WEB_ORIGIN}/`,
    expectedText: "SaaS Detection & Response"
  },
  {
    path: "/incidents",
    url: `${WEB_ORIGIN}/incidents`,
    expectedText: "SaaS incidents"
  },
  {
    path: "/incidents/inc_demo_vendor_drive_response",
    url: `${WEB_ORIGIN}/incidents/inc_demo_vendor_drive_response`,
    expectedText: "Vendor app Drive access may expose board materials"
  },
  {
    path: "/findings",
    url: `${WEB_ORIGIN}/findings`,
    expectedText: "All findings"
  },
  {
    path: "/findings/fnd_demo_public_repo",
    url: `${WEB_ORIGIN}/findings/fnd_demo_public_repo`,
    expectedText: "Public GitHub repository created"
  },
  {
    path: "/connectors",
    url: `${WEB_ORIGIN}/connectors`,
    expectedText: "SaaS connectors"
  },
  {
    path: "/siem-connectors",
    url: `${WEB_ORIGIN}/siem-connectors`,
    expectedText: "SIEM destinations"
  },
  {
    path: "/apps",
    url: `${WEB_ORIGIN}/apps`,
    expectedText: "Connected apps"
  },
  {
    path: "/apps/int_demo_github",
    url: `${WEB_ORIGIN}/apps/int_demo_github`,
    expectedText: "GitHub Enterprise"
  },
  {
    path: "/shadow-it",
    url: `${WEB_ORIGIN}/shadow-it`,
    expectedText: "Vendor Analytics Add-on"
  },
  {
    path: "/shadow-it/oauth-apps",
    url: `${WEB_ORIGIN}/shadow-it/oauth-apps`,
    expectedText: "OAuth Apps"
  },
  {
    path: "/security",
    url: `${WEB_ORIGIN}/security`,
    expectedText: "Security graph"
  },
  {
    path: "/security/privileged-identities",
    url: `${WEB_ORIGIN}/security/privileged-identities`,
    expectedText: "Privileged identities"
  },
  {
    path: "/settings",
    url: `${WEB_ORIGIN}/settings`,
    expectedText: "Personal settings"
  },
  {
    path: "/settings/organization",
    url: `${WEB_ORIGIN}/settings/organization`,
    expectedText: "Organization settings"
  }
]);

export const REQUIRED_REPORT_SECTIONS = Object.freeze([
  "serviceStatus",
  "health",
  "browser",
  "routes",
  "safeMutations",
  "workerSmokes",
  "redaction",
  "cleanup"
]);

export const WORKER_SMOKE_COMMANDS = Object.freeze([
  {
    label: "go-ingestion-worker",
    command: "npm",
    args: ["run", "worker:ingestion", "--", "-once", "-limit", "1"],
    timeoutMs: 120_000
  },
  {
    label: "go-siem-worker",
    command: "npm",
    args: ["run", "worker:siem", "--", "-once", "-limit", "1"],
    timeoutMs: 120_000
  }
]);

const MISSION_PORTS = Object.freeze({
  [EXPECTED_PORTS.web]: "web",
  [EXPECTED_PORTS.api]: "api",
  [EXPECTED_PORTS.postgres]: "postgres",
  [EXPECTED_PORTS.nats]: "nats",
  [EXPECTED_PORTS.natsMonitor]: "natsMonitor"
});

const BENIGN_CONNECT_FAILURES = new Set([
  "/aperio.v1.AperioService/GetCurrentSession"
]);

const PRODUCT_API_RE = /\/(?:api\/v1|aperio\.v1\.AperioService)\//;
const SECRET_SCAN_PATTERNS = [
  /aperio_session=(?!\[REDACTED_COOKIE\])[^;\s"]+/i,
  /Authorization:\s*Bearer\s+(?!\[REDACTED_BEARER\])\S+/i,
  /postgres(?:ql)?:\/\/[^:\s/@]+:[^@\s]+@/i,
  /DemoPass1234/,
  /stale-smoke-token/
];

function nowIso() {
  return new Date().toISOString();
}

function commandString(command, args = []) {
  return [command, ...args].join(" ");
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function childEnv(extra = {}) {
  const env = { ...process.env, ...extra };
  for (const [key, value] of Object.entries(env)) {
    if (value === undefined || value === null) {
      delete env[key];
    }
  }
  return env;
}

function tailLines(text, maxLines = 20) {
  const lines = redactEvidence(text).split(/\r?\n/).filter(Boolean);
  return lines.slice(Math.max(0, lines.length - maxLines));
}

function summarizeError(error) {
  if (error instanceof CommandFailure) {
    return {
      message: redactEvidence(error.message),
      command: error.result.command,
      exitCode: error.result.exitCode,
      timedOut: error.result.timedOut,
      stdoutTail: error.result.stdoutTail,
      stderrTail: error.result.stderrTail
    };
  }
  return {
    message: redactEvidence(error instanceof Error ? error.message : String(error))
  };
}

export function redactEvidence(value) {
  let text = typeof value === "string" ? value : JSON.stringify(value);
  text = text.replace(
    /postgres:\/\/[^:\s/@]+:[^@\s]+@/gi,
    "postgres://[REDACTED_DSN]@"
  );
  text = text.replace(
    /postgresql:\/\/[^:\s/@]+:[^@\s]+@/gi,
    "postgresql://[REDACTED_DSN]@"
  );
  text = text.replace(/aperio_session=[^;\s"]+/gi, "aperio_session=[REDACTED_COOKIE]");
  text = text.replace(/(Cookie:\s*)[^\n\r]+/gi, "$1[REDACTED_COOKIE]");
  text = text.replace(
    /(Authorization:\s*Bearer\s+)[^\s\n\r]+/gi,
    "$1[REDACTED_BEARER]"
  );
  text = text.replace(/\bBearer\s+[A-Za-z0-9._~+/-]+=*/g, "Bearer [REDACTED_BEARER]");
  text = text.replace(/(\bpassword\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,}]+)/gi, "$1[REDACTED]");
  text = text.replace(/(\btoken\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,}]+)/gi, "$1[REDACTED]");
  text = text.replace(/DemoPass1234/g, "[REDACTED_PASSWORD]");
  text = text.replace(/stale-smoke-token/g, "[REDACTED_TOKEN]");
  return text;
}

export function createInitialReport() {
  return {
    schema: "aperio.local-e2e-smoke.v1",
    status: "pending",
    startedAt: nowIso(),
    finishedAt: null,
    durationMs: null,
    serviceStatus: {
      expectedPorts: EXPECTED_PORTS,
      listenerBaseline: null,
      startedServices: [],
      reusedPreExistingServices: [],
      startedProcesses: []
    },
    health: {
      healthz: null,
      readyz: null,
      connect: null
    },
    browser: {
      origin: WEB_ORIGIN,
      login: null,
      emptyAuthLocalStorage: null,
      staleAuthToken: null,
      refreshDeepLink: null,
      logout: null,
      consoleFailures: [],
      networkFailures: [],
      directApiV1Requests: [],
      authorizationBearerRequests: [],
      siemConnectors: null
    },
    routes: CANONICAL_ROUTES.map((route) => ({
      path: route.path,
      url: route.url,
      expectedText: route.expectedText,
      status: "pending"
    })),
    safeMutations: [
      {
        surface: "/siem-connectors CRUD/test-ping/delete",
        status: "pending",
        reason:
          "Creates one local JSON_FILE SIEM destination through the browser, queues a test-ping through the Go API, drains it with the bounded Go dispatcher, and deletes the destination before logout."
      }
    ],
    workerSmokes: [],
    redaction: {
      status: "pending",
      checks: []
    },
    cleanup: {
      status: "pending",
      listenerBaseline: null,
      listenerPostRun: null,
      stoppedProcesses: [],
      stoppedServices: [],
      orphanWorkers: [],
      unexpectedListeners: []
    }
  };
}

class CommandFailure extends Error {
  constructor(result) {
    super(`${result.command} failed with exit code ${result.exitCode}`);
    this.result = result;
  }
}

async function readCommandOutput(command, args, options = {}) {
  const { stdout } = await execFile(command, args, {
    cwd: repoRoot,
    env: childEnv(options.env),
    timeout: options.timeoutMs ?? 30_000,
    maxBuffer: options.maxBuffer ?? 1024 * 1024
  });
  return stdout.trim();
}

async function runCommand(command, args, options = {}) {
  const startedAt = Date.now();
  const result = {
    label: options.label ?? command,
    command: commandString(command, args),
    exitCode: null,
    timedOut: false,
    durationMs: null,
    stdoutTail: [],
    stderrTail: []
  };

  await new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: repoRoot,
      env: childEnv(options.env),
      stdio: ["ignore", "pipe", "pipe"],
      detached: process.platform !== "win32",
      shell: false
    });

    let stdout = "";
    let stderr = "";
    let settled = false;
    let sigkillTimer = null;
    const timeout = setTimeout(() => {
      result.timedOut = true;
      terminateProcessGroup(child, "SIGTERM");
      sigkillTimer = setTimeout(() => terminateProcessGroup(child, "SIGKILL"), 5_000);
    }, options.timeoutMs ?? 120_000);

    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString("utf8");
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString("utf8");
    });
    child.on("error", (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      if (sigkillTimer) clearTimeout(sigkillTimer);
      reject(error);
    });
    child.on("exit", (code, signal) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      if (sigkillTimer) clearTimeout(sigkillTimer);
      result.exitCode = code ?? (signal ? 128 : 1);
      result.durationMs = Date.now() - startedAt;
      result.stdoutTail = tailLines(stdout);
      result.stderrTail = tailLines(stderr);
      resolve();
    });
  });

  if (result.exitCode !== 0) {
    throw new CommandFailure(result);
  }
  return result;
}

function startProcess(label, command, args, options = {}) {
  const child = spawn(command, args, {
    cwd: repoRoot,
    env: childEnv(options.env),
    stdio: ["ignore", "pipe", "pipe"],
    detached: process.platform !== "win32",
    shell: false
  });
  const processInfo = {
    label,
    command: commandString(command, args),
    pid: child.pid,
    stdout: "",
    stderr: "",
    startedAt: nowIso()
  };
  child.stdout.on("data", (chunk) => {
    processInfo.stdout += chunk.toString("utf8");
    processInfo.stdout = processInfo.stdout.slice(-20_000);
  });
  child.stderr.on("data", (chunk) => {
    processInfo.stderr += chunk.toString("utf8");
    processInfo.stderr = processInfo.stderr.slice(-20_000);
  });
  child.on("exit", (code, signal) => {
    processInfo.exitCode = code;
    processInfo.signal = signal;
    processInfo.exitedAt = nowIso();
  });
  child.on("error", (error) => {
    processInfo.error = redactEvidence(error.message);
  });
  return { child, info: processInfo };
}

function terminateProcessGroup(child, signal = "SIGTERM") {
  if (!child.pid) {
    return;
  }
  try {
    if (process.platform !== "win32") {
      process.kill(-child.pid, signal);
    } else {
      child.kill(signal);
    }
  } catch (error) {
    if (error?.code !== "ESRCH") {
      throw error;
    }
  }
}

async function stopChildProcess(entry, report) {
  if (!entry?.child || entry.child.exitCode !== null || entry.child.signalCode !== null) {
    return;
  }
  const pid = entry.child.pid;
  terminateProcessGroup(entry.child, "SIGTERM");
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    if (entry.child.exitCode !== null || entry.child.signalCode !== null) {
      report.cleanup.stoppedProcesses.push({
        label: entry.info.label,
        pid,
        signal: "SIGTERM"
      });
      return;
    }
    await sleep(250);
  }
  terminateProcessGroup(entry.child, "SIGKILL");
  report.cleanup.stoppedProcesses.push({
    label: entry.info.label,
    pid,
    signal: "SIGKILL"
  });
}

async function lsofPort(port) {
  try {
    const { stdout } = await execFile("lsof", [
      "-nP",
      `-iTCP:${port}`,
      "-sTCP:LISTEN"
    ]);
    const lines = stdout.trim().split(/\r?\n/).filter(Boolean).slice(1);
    return lines.map((line) => {
      const [command, pid, user, ...rest] = line.trim().split(/\s+/);
      return {
        command,
        pid: Number(pid),
        user,
        summary: redactEvidence(rest.join(" "))
      };
    });
  } catch (error) {
    if (error?.code === 1) {
      return [];
    }
    throw error;
  }
}

async function listenerBaseline() {
  const entries = {};
  for (const [port, name] of Object.entries(MISSION_PORTS)) {
    entries[name] = {
      port: Number(port),
      listeners: await lsofPort(Number(port))
    };
  }
  return entries;
}

function failIfApiOrWebAlreadyListening(baseline) {
  const conflicts = ["api", "web"].filter(
    (name) => baseline[name]?.listeners?.length > 0
  );
  if (conflicts.length > 0) {
    const details = conflicts
      .map((name) => `${name}:${baseline[name].port}`)
      .join(", ");
    throw new Error(
      `Refusing to start smoke harness because pre-existing API/web listeners are present on ${details}`
    );
  }
  const natsClientListening = baseline.nats?.listeners?.length > 0;
  const natsMonitorListening = baseline.natsMonitor?.listeners?.length > 0;
  if (natsClientListening !== natsMonitorListening) {
    throw new Error(
      "Refusing to start smoke harness because only one NATS listener is present; cleanup ownership would be ambiguous"
    );
  }
}

async function assertExpectedLocalPorts(report) {
  const [dbPort, natsPort, natsMonitorPort] = await Promise.all([
    readCommandOutput("node", ["scripts/dev-config.mjs", "db-port"]),
    readCommandOutput("node", ["scripts/dev-config.mjs", "nats-port"]),
    readCommandOutput("node", ["scripts/dev-config.mjs", "nats-monitor-port"])
  ]);
  const actual = {
    postgres: Number(dbPort),
    nats: Number(natsPort),
    natsMonitor: Number(natsMonitorPort),
    api: EXPECTED_PORTS.api,
    web: EXPECTED_PORTS.web
  };
  report.serviceStatus.configuredPorts = actual;
  for (const [name, expected] of Object.entries(EXPECTED_PORTS)) {
    if (actual[name] !== expected) {
      throw new Error(
        `${name} port ${actual[name]} does not match the required local E2E port ${expected}`
      );
    }
  }
}

async function waitFor(name, fn, timeoutMs = 60_000, intervalMs = 750) {
  const deadline = Date.now() + timeoutMs;
  let lastError;
  while (Date.now() < deadline) {
    try {
      const value = await fn();
      if (value) {
        return value;
      }
    } catch (error) {
      lastError = error;
    }
    await sleep(intervalMs);
  }
  throw new Error(
    `${name} did not become ready within ${timeoutMs}ms${
      lastError ? `: ${redactEvidence(lastError.message)}` : ""
    }`
  );
}

async function fetchJson(url, init = {}) {
  const response = await fetch(url, init);
  const text = await response.text();
  let body = null;
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = { raw: redactEvidence(text.slice(0, 500)) };
    }
  }
  return {
    ok: response.ok,
    status: response.status,
    body
  };
}

async function checkHttpHealth(report) {
  const healthz = await fetchJson(`${API_ORIGIN}/healthz`);
  report.health.healthz = {
    statusCode: healthz.status,
    status: healthz.body?.status ?? null,
    service: healthz.body?.service ?? null
  };
  if (!healthz.ok || healthz.body?.status !== "ok") {
    throw new Error("/healthz did not report ok");
  }

  const readyz = await fetchJson(`${API_ORIGIN}/readyz`);
  report.health.readyz = {
    statusCode: readyz.status,
    status: readyz.body?.status ?? null,
    service: readyz.body?.service ?? null,
    components: readyz.body?.components ?? []
  };
  if (!readyz.ok || readyz.body?.status !== "ok") {
    throw new Error("/readyz did not report ok");
  }

  const connect = await fetchJson(`${API_ORIGIN}/aperio.v1.AperioService/CheckHealth`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Connect-Protocol-Version": "1"
    },
    body: "{}"
  });
  report.health.connect = {
    statusCode: connect.status,
    status: connect.body?.status ?? null,
    service: connect.body?.service ?? null,
    components: connect.body?.components ?? []
  };
  if (!connect.ok || connect.body?.status !== "ok") {
    throw new Error("Connect CheckHealth did not report ok");
  }
}

async function waitForWebLogin() {
  await waitFor("web /login", async () => {
    const response = await fetch(`${WEB_ORIGIN}/login`, {
      redirect: "manual"
    });
    return response.status >= 200 && response.status < 500;
  }, 90_000);
}

async function psWorkerSnapshot() {
  const { stdout } = await execFile("ps", ["-axo", "pid=,ppid=,command="], {
    maxBuffer: 1024 * 1024
  });
  return stdout
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) =>
      /(?:cmd\/(?:ingestion-worker|siem-dispatcher)|worker:(?:ingestion|siem)(?::go)?)/.test(
        line
      )
    )
    .map((line) => redactEvidence(line));
}

async function runWorkerSmokes(report) {
  const before = await psWorkerSnapshot();
  for (const smoke of WORKER_SMOKE_COMMANDS) {
    const startedAt = nowIso();
    const result = await runCommand(smoke.command, smoke.args, {
      label: smoke.label,
      timeoutMs: smoke.timeoutMs,
      env: { DOCKER_HOST: undefined }
    });
    report.workerSmokes.push({
      label: smoke.label,
      command: result.command,
      status: "passed",
      exitCode: result.exitCode,
      durationMs: result.durationMs,
      startedAt,
      stdoutTail: result.stdoutTail,
      stderrTail: result.stderrTail
    });
  }
  const after = await psWorkerSnapshot();
  const beforeSet = new Set(before);
  const unexpected = after.filter((line) => !beforeSet.has(line));
  report.cleanup.orphanWorkers = unexpected;
  if (unexpected.length > 0) {
    throw new Error(`Go worker smoke left orphan processes: ${unexpected.join("; ")}`);
  }
}

async function findChromeExecutable() {
  if (process.env.SMOKE_E2E_CHROME && fs.existsSync(process.env.SMOKE_E2E_CHROME)) {
    return process.env.SMOKE_E2E_CHROME;
  }
  const candidates = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"
  ];
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }
  for (const binary of [
    "google-chrome",
    "google-chrome-stable",
    "chromium",
    "chromium-browser",
    "microsoft-edge"
  ]) {
    try {
      const found = await readCommandOutput("which", [binary]);
      if (found) return found;
    } catch {
      // Keep trying other candidates.
    }
  }
  throw new Error(
    "No Chrome/Chromium executable found for local browser smoke validation"
  );
}

async function readDevToolsPort(userDataDir) {
  const filePath = path.join(userDataDir, "DevToolsActivePort");
  const contents = await waitFor("Chrome DevToolsActivePort", async () => {
    try {
      const raw = await fsp.readFile(filePath, "utf8");
      return raw.trim();
    } catch {
      return null;
    }
  }, 30_000, 250);
  const [port] = contents.split(/\r?\n/);
  const parsed = Number(port);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new Error("Chrome DevToolsActivePort did not contain a valid port");
  }
  return parsed;
}

function createFrame(opcode, payload = Buffer.alloc(0)) {
  const length = payload.length;
  let header;
  if (length < 126) {
    header = Buffer.alloc(2);
    header[1] = 0x80 | length;
  } else if (length < 65536) {
    header = Buffer.alloc(4);
    header[1] = 0x80 | 126;
    header.writeUInt16BE(length, 2);
  } else {
    header = Buffer.alloc(10);
    header[1] = 0x80 | 127;
    header.writeBigUInt64BE(BigInt(length), 2);
  }
  header[0] = 0x80 | opcode;
  const mask = crypto.randomBytes(4);
  const masked = Buffer.alloc(payload.length);
  for (let i = 0; i < payload.length; i += 1) {
    masked[i] = payload[i] ^ mask[i % 4];
  }
  return Buffer.concat([header, mask, masked]);
}

class MinimalWebSocket {
  constructor(wsUrl) {
    this.url = new URL(wsUrl);
    this.listeners = new Map();
    this.buffer = Buffer.alloc(0);
    this.readyState = 0;
    this.socket = null;
    this.handshakeComplete = false;
    this.handshakeBuffer = Buffer.alloc(0);
    this.connect();
  }

  addEventListener(type, listener) {
    if (!this.listeners.has(type)) this.listeners.set(type, []);
    this.listeners.get(type).push(listener);
  }

  emit(type, event = {}) {
    for (const listener of this.listeners.get(type) ?? []) {
      listener(event);
    }
  }

  connect() {
    const key = crypto.randomBytes(16).toString("base64");
    this.socket = net.createConnection(
      {
        host: this.url.hostname,
        port: Number(this.url.port || 80)
      },
      () => {
        const request = [
          `GET ${this.url.pathname}${this.url.search} HTTP/1.1`,
          `Host: ${this.url.host}`,
          "Upgrade: websocket",
          "Connection: Upgrade",
          `Sec-WebSocket-Key: ${key}`,
          "Sec-WebSocket-Version: 13",
          "\r\n"
        ].join("\r\n");
        this.socket.write(request);
      }
    );
    this.socket.on("data", (chunk) => this.onData(chunk));
    this.socket.on("error", (error) => this.emit("error", { error }));
    this.socket.on("close", () => {
      this.readyState = 3;
      this.emit("close", {});
    });
  }

  onData(chunk) {
    if (!this.handshakeComplete) {
      this.handshakeBuffer = Buffer.concat([this.handshakeBuffer, chunk]);
      const marker = this.handshakeBuffer.indexOf("\r\n\r\n");
      if (marker === -1) {
        return;
      }
      const header = this.handshakeBuffer.slice(0, marker).toString("utf8");
      if (!/^HTTP\/1\.1 101/i.test(header)) {
        this.emit("error", { error: new Error("WebSocket upgrade failed") });
        this.close();
        return;
      }
      this.handshakeComplete = true;
      this.readyState = 1;
      this.emit("open", {});
      const rest = this.handshakeBuffer.slice(marker + 4);
      this.handshakeBuffer = Buffer.alloc(0);
      if (rest.length === 0) {
        return;
      }
      this.buffer = Buffer.concat([this.buffer, rest]);
    } else {
      this.buffer = Buffer.concat([this.buffer, chunk]);
    }
    this.parseFrames();
  }

  parseFrames() {
    for (;;) {
      if (this.buffer.length < 2) return;
      const first = this.buffer[0];
      const second = this.buffer[1];
      const opcode = first & 0x0f;
      let length = second & 0x7f;
      let offset = 2;
      if (length === 126) {
        if (this.buffer.length < 4) return;
        length = this.buffer.readUInt16BE(2);
        offset = 4;
      } else if (length === 127) {
        if (this.buffer.length < 10) return;
        length = Number(this.buffer.readBigUInt64BE(2));
        offset = 10;
      }
      const masked = Boolean(second & 0x80);
      const maskOffset = masked ? 4 : 0;
      if (this.buffer.length < offset + maskOffset + length) return;
      let payload = this.buffer.slice(offset + maskOffset, offset + maskOffset + length);
      if (masked) {
        const mask = this.buffer.slice(offset, offset + 4);
        payload = Buffer.from(payload.map((byte, index) => byte ^ mask[index % 4]));
      }
      this.buffer = this.buffer.slice(offset + maskOffset + length);
      if (opcode === 0x1) {
        this.emit("message", { data: payload.toString("utf8") });
      } else if (opcode === 0x8) {
        this.close();
        return;
      } else if (opcode === 0x9) {
        this.socket.write(createFrame(0x0a, payload));
      }
    }
  }

  send(data) {
    if (this.readyState !== 1) {
      throw new Error("WebSocket is not open");
    }
    this.socket.write(createFrame(0x1, Buffer.from(data)));
  }

  close() {
    if (this.readyState === 3) return;
    this.readyState = 2;
    try {
      this.socket.write(createFrame(0x8));
    } catch {
      // Ignore close write races.
    }
    this.socket.end();
  }
}

function openWebSocket(wsUrl) {
  if (typeof WebSocket === "function") {
    return new WebSocket(wsUrl);
  }
  return new MinimalWebSocket(wsUrl);
}

class CdpClient {
  constructor(wsUrl) {
    this.ws = openWebSocket(wsUrl);
    this.nextId = 1;
    this.pending = new Map();
    this.handlers = new Map();
    this.opened = new Promise((resolve, reject) => {
      this.ws.addEventListener("open", () => resolve());
      this.ws.addEventListener("error", (event) =>
        reject(event.error ?? new Error("CDP WebSocket error"))
      );
    });
    this.ws.addEventListener("message", (event) => this.onMessage(event.data));
  }

  static async connect(wsUrl) {
    const client = new CdpClient(wsUrl);
    await client.opened;
    return client;
  }

  on(method, handler) {
    if (!this.handlers.has(method)) this.handlers.set(method, []);
    this.handlers.get(method).push(handler);
  }

  onMessage(raw) {
    const message = JSON.parse(raw);
    if (message.id && this.pending.has(message.id)) {
      const { resolve, reject, timer } = this.pending.get(message.id);
      clearTimeout(timer);
      this.pending.delete(message.id);
      if (message.error) {
        reject(new Error(`${message.error.message}: ${message.error.data ?? ""}`));
      } else {
        resolve(message.result ?? {});
      }
      return;
    }
    if (message.method) {
      for (const handler of this.handlers.get(message.method) ?? []) {
        handler(message.params ?? {});
      }
    }
  }

  command(method, params = {}, timeoutMs = 15_000) {
    const id = this.nextId++;
    const payload = JSON.stringify({ id, method, params });
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`CDP command timed out: ${method}`));
      }, timeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      this.ws.send(payload);
    });
  }

  close() {
    this.ws.close();
  }
}

async function launchBrowser(report) {
  const executable = await findChromeExecutable();
  const userDataDir = await fsp.mkdtemp(path.join(os.tmpdir(), "aperio-smoke-chrome-"));
  const args = [
    "--headless=new",
    "--remote-debugging-port=0",
    `--user-data-dir=${userDataDir}`,
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-background-networking",
    "--disable-dev-shm-usage",
    "about:blank"
  ];
  const browser = startProcess("chrome", executable, args, {
    env: { DOCKER_HOST: undefined }
  });
  let cdp = null;
  try {
    report.serviceStatus.startedProcesses.push({
      label: "chrome",
      pid: browser.child.pid,
      command: "Chrome/Chromium --headless --remote-debugging-port=0"
    });
    const port = await readDevToolsPort(userDataDir);
    const targetResponse = await fetch(
      `http://127.0.0.1:${port}/json/new?${encodeURIComponent("about:blank")}`,
      { method: "PUT" }
    );
    if (!targetResponse.ok) {
      throw new Error(`Unable to create Chrome DevTools target: ${targetResponse.status}`);
    }
    const target = await targetResponse.json();
    cdp = await CdpClient.connect(target.webSocketDebuggerUrl);
    return {
      process: browser,
      cdp,
      userDataDir,
      remoteDebuggingPort: port
    };
  } catch (error) {
    try {
      cdp?.close();
    } catch {
      // Ignore CDP close races during startup cleanup.
    }
    await stopChildProcess(browser, report);
    await fsp.rm(userDataDir, { recursive: true, force: true });
    throw error;
  }
}

function cdpArgText(args = []) {
  return redactEvidence(
    args
      .map((arg) => {
        if ("value" in arg) return String(arg.value);
        if ("description" in arg) return String(arg.description);
        return "";
      })
      .join(" ")
      .slice(0, 500)
  );
}

function isRelevantProductFailure(entry) {
  if (!PRODUCT_API_RE.test(entry.url)) {
    return false;
  }
  const pathName = new URL(entry.url).pathname;
  if (entry.status === 401 && entry.phase === "logout") {
    return false;
  }
  if (
    entry.status === 401 &&
    BENIGN_CONNECT_FAILURES.has(pathName) &&
    (entry.phase === "pre-login" || entry.phase === "login" || entry.phase === "logout")
  ) {
    return false;
  }
  return entry.status >= 400;
}

export function isBenignBrowserLog(text) {
  return (
    text.includes("eval() is not supported in this environment") ||
    text.includes("React requires eval() in development mode") ||
    text.includes("Failed to load resource:") ||
    text.includes("_clientMiddlewareManifest.js") ||
    (text.includes("ENOENT: no such file or directory") &&
      text.includes("/.next/dev/server/app/") &&
      text.includes("/build-manifest.json"))
  );
}

async function evaluate(cdp, expression, options = {}) {
  const result = await cdp.command("Runtime.evaluate", {
    expression,
    returnByValue: true,
    awaitPromise: Boolean(options.awaitPromise)
  });
  if (result.exceptionDetails) {
    throw new Error(
      `Browser evaluation failed: ${result.exceptionDetails.text ?? "unknown"}`
    );
  }
  return result.result?.value;
}

async function waitForExpression(cdp, label, expression, timeoutMs = 30_000) {
  return waitFor(label, async () => {
    const value = await evaluate(cdp, expression);
    return value || null;
  }, timeoutMs, 500);
}

async function navigateAndCheck(cdp, route) {
  await cdp.command("Page.navigate", { url: route.url });
  await waitForExpression(
    cdp,
    `route ${route.path}`,
    `(() => {
      const expectedPath = ${JSON.stringify(route.path)};
      const expectedText = ${JSON.stringify(route.expectedText)};
      const text = document.body?.innerText || "";
      return location.pathname === expectedPath &&
        document.readyState !== "loading" &&
        !text.includes("Checking workspace session") &&
        text.includes(expectedText);
    })()`,
    45_000
  );
  return evaluate(
    cdp,
    `(() => {
      const text = document.body?.innerText || "";
      const expectedText = ${JSON.stringify(route.expectedText)};
      return {
        path: location.pathname,
        h1: document.querySelector("h1")?.innerText || "",
        title: document.title,
        expectedTextFound: text.includes(expectedText),
        codeNotFound: text.includes("CodeNotFound"),
        unableToLoad: /Unable to load/.test(text),
        signInVisible: location.pathname !== "/login" && text.includes("Sign in"),
        bodySample: text.slice(0, 500)
      };
    })()`
  );
}

async function browserConnectRpc(cdp, method, body = {}) {
  const result = await evaluate(
    cdp,
    `fetch(${JSON.stringify(`${BROWSER_API_ORIGIN}/aperio.v1.AperioService/${method}`)}, {
      method: "POST",
      headers: {"Content-Type": "application/json", "Connect-Protocol-Version": "1"},
      credentials: "include",
      body: ${JSON.stringify(JSON.stringify(body))}
    }).then(async (response) => {
      const text = await response.text();
      let parsed = null;
      if (text) {
        try {
          parsed = JSON.parse(text);
        } catch {
          parsed = {raw: text.slice(0, 500)};
        }
      }
      return {ok: response.ok, status: response.status, body: parsed};
    })`,
    { awaitPromise: true }
  );
  if (!result.ok) {
    throw new Error(
      `${method} failed with status ${result.status}: ${redactEvidence(
        JSON.stringify(result.body)
      )}`
    );
  }
  return result.body;
}

async function runSiemConnectorCrudFlow(cdp, report, setPhase) {
  const suffix = `${Date.now()}-${crypto.randomBytes(3).toString("hex")}`;
  const destinationName = `Smoke JSON ${suffix}`;
  const filePath = `smoke/${suffix}.jsonl`;
  let destinationId = null;
  let createdFilePath = null;
  try {
    setPhase("siem-connectors:create");
    await cdp.command("Page.navigate", { url: `${WEB_ORIGIN}/siem-connectors` });
    await waitForExpression(
      cdp,
      "SIEM connectors page before CRUD",
      `location.pathname === "/siem-connectors" && document.body.innerText.includes("SIEM destinations") && document.body.innerText.includes("JSON Lines File")`,
      45_000
    );
    await evaluate(
      cdp,
      `(() => {
        const buttons = [...document.querySelectorAll("button")]
          .filter((button) => button.innerText.includes("Add destination"));
        const button = buttons.find((candidate) => {
          let node = candidate.parentElement;
          for (let depth = 0; node && depth < 7; depth += 1, node = node.parentElement) {
            const text = node.innerText || "";
            if (text.includes("JSON Lines File") && !text.includes("Splunk HEC")) {
              return true;
            }
          }
          return false;
        });
        if (!button) throw new Error("JSON Lines File add button not found");
        button.click();
        return true;
      })()`
    );
    await waitForExpression(
      cdp,
      "JSON Lines File dialog",
      `document.body.innerText.includes("Add JSON Lines File destination")`,
      15_000
    );
    await evaluate(
      cdp,
      `(() => {
        const setValue = (input, value) => {
          if (!input) throw new Error("missing SIEM dialog input");
          const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value").set;
          setter.call(input, value);
          input.dispatchEvent(new Event("input", { bubbles: true }));
          input.dispatchEvent(new Event("change", { bubbles: true }));
        };
        const fieldInput = (labelText) => {
          const label = [...document.querySelectorAll("[role='dialog'] label")]
            .find((entry) => (entry.textContent || "").includes(labelText));
          return label?.parentElement?.querySelector("input");
        };
        setValue(fieldInput("Name"), ${JSON.stringify(destinationName)});
        setValue(fieldInput("Export file path"), ${JSON.stringify(filePath)});
        document.querySelector("[role='dialog'] form").requestSubmit();
        return true;
      })()`
    );
    await waitForExpression(
      cdp,
      "created SIEM destination visible",
      `document.body.innerText.includes(${JSON.stringify(destinationName)}) && !document.body.innerText.includes("Adding…")`,
      30_000
    );
    const listAfterCreate = await browserConnectRpc(cdp, "ListSiemDestinations", {});
    const created = listAfterCreate?.data?.find(
      (destination) => destination.name === destinationName
    );
    const expectedFilePathSuffix = filePath.split("/").join(path.sep);
    if (!created?.id || created.kind !== "JSON_FILE" || !created.filePath?.endsWith(expectedFilePathSuffix)) {
      throw new Error(
        `Created SIEM destination did not round-trip expected JSON_FILE fields: ${redactEvidence(
          JSON.stringify(created)
        )}`
      );
    }
    createdFilePath = created.filePath;
    const serializedCreated = JSON.stringify(created);
    if (/token|encrypted/i.test(serializedCreated)) {
      throw new Error("Created SIEM destination list response exposed token fields");
    }
    destinationId = created.id;

    setPhase("siem-connectors:test-ping");
    await evaluate(
      cdp,
      `(() => {
        const row = [...document.querySelectorAll("tr")]
          .find((entry) => entry.innerText.includes(${JSON.stringify(destinationName)}));
        if (!row) throw new Error("created SIEM destination row not found");
        const testButton = [...row.querySelectorAll("button")]
          .find((button) => button.innerText.includes("Test"));
        if (!testButton) throw new Error("created SIEM destination test button not found");
        testButton.click();
        return true;
      })()`
    );
    await waitForExpression(
      cdp,
      "SIEM test-ping queued toast",
      `document.body.innerText.includes("SIEM test payload queued for dispatcher") || document.body.innerText.includes("Test delivery succeeded")`,
      30_000
    );
    const listBeforeDrain = await browserConnectRpc(cdp, "ListSiemDestinations", {});
    const beforeDrain = listBeforeDrain?.data?.find(
      (destination) => destination.id === destinationId
    );
    setPhase("siem-connectors:go-dispatcher-drain");
    const drain = await runCommand("npm", ["run", "worker:siem", "--", "-once", "-limit", "5"], {
      label: "siem connector test-ping drain",
      timeoutMs: 120_000,
      env: { DOCKER_HOST: undefined }
    });
    setPhase("siem-connectors:status-refresh");
    await cdp.command("Page.reload", { ignoreCache: true });
    await waitForExpression(
      cdp,
      "SIEM destination health after drain",
      `(() => {
        const row = [...document.querySelectorAll("tr")]
          .find((entry) => entry.innerText.includes(${JSON.stringify(destinationName)}));
        return row && row.innerText.includes("1 ok") && row.innerText.includes("0 fail");
      })()`,
      45_000
    );
    const listAfterDrain = await browserConnectRpc(cdp, "ListSiemDestinations", {});
    const afterDrain = listAfterDrain?.data?.find(
      (destination) => destination.id === destinationId
    );
    const afterDrainOK = afterDrain?.deliveriesOk ?? 0;
    const afterDrainFail = afterDrain?.deliveriesFail ?? 0;
    if (!afterDrain || afterDrainOK < 1 || afterDrainFail !== 0) {
      throw new Error(
        `SIEM destination health did not update after Go dispatcher drain: ${redactEvidence(
          JSON.stringify(afterDrain)
        )}`
      );
    }

    setPhase("siem-connectors:delete");
    await evaluate(
      cdp,
      `(() => {
        const row = [...document.querySelectorAll("tr")]
          .find((entry) => entry.innerText.includes(${JSON.stringify(destinationName)}));
        if (!row) throw new Error("SIEM destination row missing before delete");
        const buttons = [...row.querySelectorAll("button")];
        const deleteButton = buttons[buttons.length - 1];
        if (!deleteButton) throw new Error("SIEM destination delete button missing");
        deleteButton.click();
        return true;
      })()`
    );
    await waitForExpression(
      cdp,
      "SIEM destination removed from browser list",
      `!document.body.innerText.includes(${JSON.stringify(destinationName)})`,
      30_000
    );
    const listAfterDelete = await browserConnectRpc(cdp, "ListSiemDestinations", {});
    if (listAfterDelete?.data?.some((destination) => destination.id === destinationId)) {
      throw new Error("Deleted SIEM destination remained visible through Go API list");
    }
    if (createdFilePath) {
      await fsp.rm(createdFilePath, { force: true });
    }
    report.browser.siemConnectors = {
      status: "passed",
      route: "/siem-connectors",
      destinationId,
      destinationName,
      kind: "JSON_FILE",
      filePath,
      healthBeforeDrain: beforeDrain
        ? {
            deliveriesOk: beforeDrain.deliveriesOk ?? 0,
            deliveriesFail: beforeDrain.deliveriesFail ?? 0,
            status: beforeDrain.status
          }
        : null,
      healthAfterDrain: {
        deliveriesOk: afterDrainOK,
        deliveriesFail: afterDrainFail,
        status: afterDrain.status
      },
      workerDrain: {
        command: drain.command,
        exitCode: drain.exitCode,
        stdoutTail: drain.stdoutTail,
        stderrTail: drain.stderrTail
      },
      redaction: "List responses contained no token or encrypted token fields"
    };
    report.safeMutations[0] = {
      ...report.safeMutations[0],
      status: "passed",
      destinationId,
      destinationName
    };
  } catch (error) {
    report.safeMutations[0] = {
      ...report.safeMutations[0],
      status: "failed",
      error: summarizeError(error)
    };
    if (destinationId) {
      try {
        await browserConnectRpc(cdp, "DeleteSiemDestination", { id: destinationId });
      } catch {
        // Keep the original browser-flow failure; seed/migrate remains idempotent.
      }
    }
    if (createdFilePath) {
      await fsp.rm(createdFilePath, { force: true }).catch(() => undefined);
    }
    throw error;
  }
}

async function runBrowserValidation(report) {
  const browser = await launchBrowser(report);
  let currentPhase = "startup";
  const requests = new Map();
  const routeFailureStart = () =>
    report.browser.networkFailures.length + report.browser.consoleFailures.length;

  try {
    const { cdp } = browser;
    await cdp.command("Page.enable");
    await cdp.command("Runtime.enable");
    await cdp.command("Network.enable");
    await cdp.command("Log.enable").catch(() => undefined);

    cdp.on("Runtime.consoleAPICalled", (params) => {
      const text = cdpArgText(params.args);
      if (
        (params.type === "error" || params.type === "assert") &&
        !isBenignBrowserLog(text)
      ) {
        report.browser.consoleFailures.push({
          phase: currentPhase,
          source: "console",
          type: params.type,
          text
        });
      }
    });
    cdp.on("Runtime.exceptionThrown", (params) => {
      report.browser.consoleFailures.push({
        phase: currentPhase,
        source: "exception",
        text: redactEvidence(
          params.exceptionDetails?.exception?.description ??
            params.exceptionDetails?.text ??
            "uncaught exception"
        )
      });
    });
    cdp.on("Log.entryAdded", (params) => {
      const text = params.entry?.text ?? "";
      if (params.entry?.level === "error" && !isBenignBrowserLog(text)) {
        report.browser.consoleFailures.push({
          phase: currentPhase,
          source: "log",
          text: redactEvidence(text || "log error")
        });
      }
    });
    cdp.on("Network.requestWillBeSent", (params) => {
      const url = params.request?.url ?? "";
      const headers = params.request?.headers ?? {};
      requests.set(params.requestId, {
        url,
        method: params.request?.method,
        type: params.type,
        phase: currentPhase
      });
      if (isDirectProductApiV1BrowserRequest(url, params.type)) {
        report.browser.directApiV1Requests.push({
          phase: currentPhase,
          method: params.request?.method,
          url: redactEvidence(url)
        });
      }
      const authHeader = Object.entries(headers).find(
        ([key]) => key.toLowerCase() === "authorization"
      );
      if (authHeader && /Bearer\s+/i.test(String(authHeader[1]))) {
        report.browser.authorizationBearerRequests.push({
          phase: currentPhase,
          url: redactEvidence(url),
          header: "Authorization: Bearer [REDACTED_BEARER]"
        });
      }
    });
    cdp.on("Network.responseReceived", (params) => {
      const request = requests.get(params.requestId);
      if (!request) return;
      const entry = {
        phase: request.phase,
        method: request.method,
        url: redactEvidence(request.url),
        status: params.response?.status ?? 0,
        type: request.type
      };
      if (isRelevantProductFailure({ ...entry, url: request.url })) {
        report.browser.networkFailures.push(entry);
      }
    });
    cdp.on("Network.loadingFailed", (params) => {
      const request = requests.get(params.requestId);
      if (!request) return;
      if (params.errorText === "net::ERR_ABORTED") return;
      if (!PRODUCT_API_RE.test(request.url) && request.type !== "Document") return;
      report.browser.networkFailures.push({
        phase: request.phase,
        method: request.method,
        url: redactEvidence(request.url),
        errorText: redactEvidence(params.errorText ?? "loading failed"),
        type: request.type
      });
    });

    currentPhase = "pre-login";
    await cdp.command("Page.navigate", { url: `${WEB_ORIGIN}/login` });
    await waitForExpression(
      cdp,
      "login page",
      `document.body?.innerText.includes("Sign in") && location.pathname === "/login"`,
      45_000
    );
    const emptyLocalStorage = await evaluate(
      cdp,
      `(() => {
        localStorage.removeItem("aperio.auth.token");
        return localStorage.getItem("aperio.auth.token") === null;
      })()`
    );
    report.browser.emptyAuthLocalStorage = {
      status: emptyLocalStorage ? "passed" : "failed"
    };

    // Wait for React to hydrate the form before submitting. The SSR HTML shows
    // "Sign in" before client JS attaches the onSubmit handler, so without this
    // gate the form can fire a native GET submit instead of the React fetch.
    // React attaches __reactProps$* onto interactive elements during hydration.
    await waitForExpression(
      cdp,
      "login form hydrated",
      `(() => { const form = document.querySelector("form"); if (!form) return false; return Object.keys(form).some((k) => k.startsWith("__reactProps$")); })()`,
      60_000
    );

    currentPhase = "login";
    const password = process.env.DEMO_OWNER_PASSWORD ?? "DemoPass1234";
    await evaluate(
      cdp,
      `(() => {
        const setValue = (selector, value) => {
          const input = document.querySelector(selector);
          if (!input) throw new Error("missing input " + selector);
          const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value").set;
          setter.call(input, value);
          input.dispatchEvent(new Event("input", { bubbles: true }));
          input.dispatchEvent(new Event("change", { bubbles: true }));
        };
        setValue('input[autocomplete="organization"]', 'aperio-demo');
        setValue('input[type="email"]', 'security@aperio.local');
        setValue('input[type="password"]', ${JSON.stringify(password)});
        document.querySelector("form").requestSubmit();
        return true;
      })()`
    );
    await waitForExpression(
      cdp,
      "login redirect",
      `location.pathname === "/"`,
      90_000
    );
    const sessionReady = await waitFor(
      "cookie-backed current session after login",
      () =>
        evaluate(
          cdp,
          `fetch(${JSON.stringify(`${BROWSER_API_ORIGIN}/aperio.v1.AperioService/GetCurrentSession`)}, {
            method: "POST",
            headers: {"Content-Type": "application/json", "Connect-Protocol-Version": "1"},
            credentials: "include",
            body: "{}"
          }).then((response) => response.ok)`,
          { awaitPromise: true }
      ),
      30_000,
      500
    );
    report.browser.login = {
      status: "passed",
      path: await evaluate(cdp, "location.pathname"),
      cookieBackedSession: sessionReady ? "passed" : "failed",
      credentialSource: process.env.DEMO_OWNER_PASSWORD
        ? "DEMO_OWNER_PASSWORD"
        : "seed-default"
    };

    currentPhase = "stale-auth-token";
    await evaluate(
      cdp,
      `(() => {
        localStorage.setItem("aperio.auth.token", "stale-smoke-token");
        return true;
      })()`
    );

    for (let index = 0; index < CANONICAL_ROUTES.length; index += 1) {
      const route = CANONICAL_ROUTES[index];
      currentPhase = `route:${route.path}`;
      const failureCountBefore = routeFailureStart();
      const snapshot = await navigateAndCheck(cdp, route);
      const failed =
        !snapshot.expectedTextFound ||
        snapshot.codeNotFound ||
        snapshot.unableToLoad ||
        snapshot.signInVisible ||
        routeFailureStart() > failureCountBefore;
      report.routes[index] = {
        ...report.routes[index],
        status: failed ? "failed" : "passed",
        h1: redactEvidence(snapshot.h1),
        title: redactEvidence(snapshot.title),
        expectedTextFound: snapshot.expectedTextFound,
        codeNotFound: snapshot.codeNotFound,
        unableToLoad: snapshot.unableToLoad,
        signInVisible: snapshot.signInVisible,
        bodySample: redactEvidence(snapshot.bodySample)
      };
      if (failed) {
        throw new Error(`Route smoke failed for ${route.path}`);
      }
    }

    await runSiemConnectorCrudFlow(cdp, report, (phase) => {
      currentPhase = phase;
    });

    currentPhase = "refresh-deep-link";
    await cdp.command("Page.navigate", {
      url: `${WEB_ORIGIN}/findings/fnd_demo_public_repo`
    });
    await waitForExpression(
      cdp,
      "deep link before refresh",
      `location.pathname === "/findings/fnd_demo_public_repo" && document.body.innerText.includes("Public GitHub repository created")`,
      45_000
    );
    await cdp.command("Page.reload", { ignoreCache: true });
    await waitForExpression(
      cdp,
      "deep link after refresh",
      `location.pathname === "/findings/fnd_demo_public_repo" && document.body.innerText.includes("Public GitHub repository created")`,
      45_000
    );
    report.browser.refreshDeepLink = {
      status: "passed",
      path: "/findings/fnd_demo_public_repo"
    };
    report.browser.staleAuthToken = {
      status:
        report.browser.authorizationBearerRequests.length === 0 ? "passed" : "failed",
      key: "aperio.auth.token",
      behavior: "ignored by ConnectRPC cookie-backed requests"
    };
    if (report.browser.authorizationBearerRequests.length > 0) {
      throw new Error("Browser sent Authorization bearer headers while stale auth token was present");
    }
    if (report.browser.directApiV1Requests.length > 0) {
      throw new Error("Browser issued direct /api/v1 product requests");
    }

    currentPhase = "logout";
    const logoutResult = await evaluate(
      cdp,
      `fetch(${JSON.stringify(`${BROWSER_API_ORIGIN}/aperio.v1.AperioService/LogoutCurrentSession`)}, {
        method: "POST",
        headers: {"Content-Type": "application/json", "Connect-Protocol-Version": "1"},
        credentials: "include",
        body: "{}"
      }).then((response) => ({status: response.status, ok: response.ok}))`,
      { awaitPromise: true }
    );
    await cdp.command("Page.navigate", { url: `${WEB_ORIGIN}/findings` });
    await waitForExpression(
      cdp,
      "logout protected redirect",
      `location.pathname === "/login"`,
      30_000
    );
    report.browser.logout = {
      status: logoutResult.ok ? "passed" : "failed",
      logoutStatusCode: logoutResult.status,
      protectedRouteAfterLogout: await evaluate(cdp, "location.pathname")
    };
    if (!logoutResult.ok) {
      throw new Error("Logout RPC failed");
    }
    if (report.browser.consoleFailures.length > 0) {
      throw new Error("Browser console reported relevant failures");
    }
    if (report.browser.networkFailures.length > 0) {
      throw new Error("Browser network reported relevant product failures");
    }
    return browser;
  } catch (error) {
    await closeBrowser(browser, report);
    throw error;
  }
}

async function closeBrowser(browser, report) {
  if (!browser) return;
  try {
    browser.cdp?.close();
  } catch {
    // Ignore CDP close races.
  }
  await stopChildProcess(browser.process, report);
  if (browser.userDataDir) {
    await fsp.rm(browser.userDataDir, { recursive: true, force: true });
  }
}

function runRedactionSelfCheck(report) {
  const raw = [
    "Cookie: aperio_session=s3cr3t-cookie; other=value",
    "Authorization: Bearer secret-token",
    "password=DemoPass1234",
    "token=stale-smoke-token",
    "postgres://aperio:aperio@127.0.0.1:5433/aperio?sslmode=disable"
  ].join("\n");
  const redacted = redactEvidence(raw);
  const checks = [
    {
      name: "cookie",
      passed: !redacted.includes("s3cr3t-cookie") && redacted.includes("[REDACTED_COOKIE]")
    },
    {
      name: "bearer",
      passed: !redacted.includes("secret-token") && redacted.includes("[REDACTED_BEARER]")
    },
    {
      name: "password",
      passed: !redacted.includes("DemoPass1234") && redacted.includes("password=[REDACTED]")
    },
    {
      name: "dsn",
      passed:
        !redacted.includes("aperio:aperio@") &&
        redacted.includes("postgres://[REDACTED_DSN]@127.0.0.1:5433")
    }
  ];
  const serialized = JSON.stringify(report);
  const reportLeakChecks = SECRET_SCAN_PATTERNS.map((pattern, index) => ({
    name: `report-scan-${index + 1}`,
    passed: !pattern.test(serialized)
  }));
  const allChecks = [...checks, ...reportLeakChecks];
  return {
    status: allChecks.every((check) => check.passed) ? "passed" : "failed",
    checks: allChecks
  };
}

async function stopHarnessService(service, report) {
  const result = await runCommand("docker", ["compose", "-p", "aperio", "stop", service], {
    label: `docker compose stop ${service}`,
    timeoutMs: 60_000,
    env: { DOCKER_HOST: undefined }
  });
  report.cleanup.stoppedServices.push({
    service,
    command: result.command,
    exitCode: result.exitCode
  });
}

async function cleanupHarness(state, report) {
  const cleanupErrors = [];
  try {
    if (state.browser) {
      await closeBrowser(state.browser, report);
      state.browser = null;
    }
  } catch (error) {
    cleanupErrors.push(error);
  }
  for (const processEntry of [...state.processes].reverse()) {
    try {
      await stopChildProcess(processEntry, report);
    } catch (error) {
      cleanupErrors.push(error);
    }
  }
  for (const service of [...state.startedServices].reverse()) {
    try {
      await stopHarnessService(service, report);
    } catch (error) {
      cleanupErrors.push(error);
    }
  }

  try {
    const post = await listenerBaseline();
    report.cleanup.listenerPostRun = post;
    const unexpected = [];
    for (const name of ["api", "web"]) {
      if (post[name]?.listeners?.length > 0) {
        unexpected.push({ name, port: post[name].port, listeners: post[name].listeners });
      }
    }
    for (const service of state.startedServices) {
      const names = service === "postgres" ? ["postgres"] : ["nats", "natsMonitor"];
      for (const name of names) {
        if (post[name]?.listeners?.length > 0) {
          unexpected.push({ name, port: post[name].port, listeners: post[name].listeners });
        }
      }
    }
    report.cleanup.unexpectedListeners = unexpected;
    if (unexpected.length > 0) {
      cleanupErrors.push(new Error("Unexpected harness-owned listeners remain"));
    }
  } catch (error) {
    cleanupErrors.push(error);
  }

  report.cleanup.status = cleanupErrors.length === 0 ? "passed" : "failed";
  if (cleanupErrors.length > 0) {
    report.cleanup.errors = cleanupErrors.map(summarizeError);
  }
}

async function writeReportIfRequested(report) {
  const reportPath = process.env.SMOKE_E2E_REPORT;
  if (!reportPath) {
    return;
  }
  await fsp.mkdir(path.dirname(reportPath), { recursive: true });
  await fsp.writeFile(reportPath, `${JSON.stringify(report, null, 2)}\n`);
}

async function runSmokeE2E() {
  loadDevEnv();
  const report = createInitialReport();
  const startedAt = Date.now();
  const state = {
    processes: [],
    startedServices: [],
    browser: null
  };

  try {
    await assertExpectedLocalPorts(report);
    const pre = await listenerBaseline();
    report.serviceStatus.listenerBaseline = pre;
    report.cleanup.listenerBaseline = pre;
    failIfApiOrWebAlreadyListening(pre);

    const postgresPreExisting = pre.postgres.listeners.length > 0;
    const natsPreExisting =
      pre.nats.listeners.length > 0 || pre.natsMonitor.listeners.length > 0;

    await runCommand("make", ["db-up"], {
      label: "start postgres",
      timeoutMs: 120_000,
      env: { DOCKER_HOST: undefined }
    });
    if (postgresPreExisting) {
      report.serviceStatus.reusedPreExistingServices.push("postgres");
    } else {
      state.startedServices.push("postgres");
      report.serviceStatus.startedServices.push("postgres");
    }

    await runCommand("make", ["nats-up"], {
      label: "start nats",
      timeoutMs: 120_000,
      env: { DOCKER_HOST: undefined }
    });
    if (natsPreExisting) {
      report.serviceStatus.reusedPreExistingServices.push("nats");
    } else {
      state.startedServices.push("nats");
      report.serviceStatus.startedServices.push("nats");
    }

    await runCommand("make", ["migrate"], {
      label: "apply migrations",
      timeoutMs: 120_000
    });
    await runCommand("make", ["seed"], {
      label: "seed deterministic data",
      timeoutMs: 120_000
    });

    const goDatabaseUrl = await readCommandOutput("node", [
      "scripts/dev-config.mjs",
      "go-database-url"
    ]);
    const apiProcess = startProcess("go-api", "go", ["run", "./cmd/aperio"], {
      env: {
        DATABASE_URL: goDatabaseUrl,
        APERIO_CONNECT_ADDR: "127.0.0.1:4100",
        APERIO_WEB_ORIGIN: WEB_ORIGIN,
        NEXT_PUBLIC_CONNECT_API_BASE_URL: BROWSER_API_ORIGIN
      }
    });
    state.processes.push(apiProcess);
    report.serviceStatus.startedProcesses.push({
      label: apiProcess.info.label,
      pid: apiProcess.child.pid,
      command: apiProcess.info.command
    });
    await waitFor("Go API /readyz", async () => {
      if (apiProcess.info.exitCode !== undefined || apiProcess.info.error) {
        throw new Error(
          `Go API exited before readiness: ${redactEvidence(apiProcess.info.stderr)}`
        );
      }
      const response = await fetch(`${API_ORIGIN}/readyz`).catch(() => null);
      return response?.ok;
    }, 90_000);
    await checkHttpHealth(report);

    const webProcess = startProcess("next-web", "npx", [
      "next",
      "dev",
      "apps/web",
      "--webpack",
      "-p",
      "3000"
    ], {
      env: {
        NEXT_PUBLIC_CONNECT_API_BASE_URL: BROWSER_API_ORIGIN,
        APERIO_WEB_ORIGIN: WEB_ORIGIN
      }
    });
    state.processes.push(webProcess);
    report.serviceStatus.startedProcesses.push({
      label: webProcess.info.label,
      pid: webProcess.child.pid,
      command: webProcess.info.command
    });
    await waitForWebLogin();

    state.browser = await runBrowserValidation(report);
    // runBrowserValidation keeps the browser open long enough to return it for
    // centralized cleanup; close it now so the post-listener proof is tighter.
    await closeBrowser(state.browser, report);
    state.browser = null;

    await runWorkerSmokes(report);
    report.redaction = runRedactionSelfCheck(report);
    if (report.redaction.status !== "passed") {
      throw new Error("Redaction self-check failed");
    }
    if (report.routes.some((route) => route.status !== "passed")) {
      throw new Error("One or more canonical routes failed");
    }
    report.status = "passed";
  } catch (error) {
    report.status = "failed";
    report.error = summarizeError(error);
    report.processDiagnostics = state.processes.map((p) => ({
      label: p.info.label,
      pid: p.info.pid,
      stdoutTail: tailLines(p.info.stdout ?? ""),
      stderrTail: tailLines(p.info.stderr ?? "")
    }));
  } finally {
    await cleanupHarness(state, report);
    if (report.cleanup.status !== "passed") {
      report.status = "failed";
    }
    report.finishedAt = nowIso();
    report.durationMs = Date.now() - startedAt;
    const redaction = runRedactionSelfCheck(report);
    if (redaction.status !== "passed") {
      report.redaction = redaction;
      report.status = "failed";
    } else if (report.redaction.status === "pending") {
      report.redaction = redaction;
    }
    await writeReportIfRequested(report);
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  }
  return report;
}

async function main() {
  const report = await runSmokeE2E();
  if (report.status !== "passed") {
    process.exitCode = 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`${redactEvidence(error.stack ?? error.message ?? String(error))}\n`);
    process.exitCode = 1;
  });
}
