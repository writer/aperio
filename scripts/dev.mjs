import { spawn, spawnSync } from "node:child_process";
import net from "node:net";
import readline from "node:readline";
import { loadDevEnv, root } from "./dev-env.mjs";

const devEnv = loadDevEnv();

const setupOnly = process.argv.includes("--setup-only");
const skipDocker = process.env.APERIO_DEV_SKIP_DOCKER === "1";
const skipMigrate = process.env.APERIO_DEV_SKIP_MIGRATE === "1";
const webPort = process.env.APERIO_WEB_PORT ?? "3000";

await avoidDefaultPortConflicts(devEnv.defaulted);
await setupInfra();
await run("npm", ["run", "db:generate"]);
if (!skipMigrate) {
  await run("npx", ["prisma", "migrate", "deploy", "--schema", "packages/db/prisma/schema.prisma"]);
}

if (setupOnly) {
  process.exit(0);
}

const children = [
  start("connect", "go", ["run", "./cmd/aperio"], { essential: true }),
  start("web", "npx", ["next", "dev", "apps/web", "-p", webPort], { essential: true }),
  startWorker("ingestion", "./cmd/ingestion-worker"),
  startWorker("siem", "./cmd/siem-dispatcher"),
  startWorker("google", "./cmd/google-workspace-poller"),
  startWorker("google-bigquery", "./cmd/google-workspace-bigquery-sync"),
  startWorker("google-directory", "./cmd/google-workspace-directory-sync"),
  startWorker("google-oauth", "./cmd/google-workspace-oauth-sync")
];

let shuttingDown = false;
for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => shutdown(0));
}

async function avoidDefaultPortConflicts(defaulted) {
  if (skipDocker) {
    return;
  }
  const needsNats = usesNatsEventBus();
  if (defaulted.has("DATABASE_URL")) {
    // Only rewrite defaulted URLs. If a developer supplied DATABASE_URL, assume
    // they intentionally chose that host/port and leave it untouched.
    const composePort = await composePublishedHostPort("postgres", 5432);
    if (composePort) {
      usePostgresPort(composePort);
    } else if (await canConnect("127.0.0.1", 5432)) {
      const port = await freePort();
      usePostgresPort(port);
      console.warn(`[dev] 127.0.0.1:5432 is in use; starting Aperio Postgres on ${port}`);
    }
  }
  if (needsNats && defaulted.has("APERIO_NATS_URL")) {
    // NATS is optional and only participates when APERIO_EVENT_BUS=nats, keeping
    // the default dev loop usable without an event broker.
    const composePort = await composePublishedHostPort("nats", 4222);
    if (composePort) {
      useNatsPort(composePort);
    } else if (await canConnect("127.0.0.1", 4222)) {
      const port = await freePort();
      useNatsPort(port);
      console.warn(`[dev] 127.0.0.1:4222 is in use; starting Aperio NATS on ${port}`);
    }
  }
  if (needsNats && !process.env.APERIO_NATS_MONITOR_PORT) {
    const composePort = await composePublishedHostPort("nats", 8222);
    if (composePort) {
      process.env.APERIO_NATS_MONITOR_PORT = String(composePort);
    } else if (await canConnect("127.0.0.1", 8222)) {
      process.env.APERIO_NATS_MONITOR_PORT = String(await freePort());
    }
  }
}

function usePostgresPort(port) {
  process.env.APERIO_POSTGRES_PORT = String(port);
  process.env.DATABASE_URL = `postgresql://aperio:aperio@127.0.0.1:${port}/aperio?schema=public`;
}

function useNatsPort(port) {
  process.env.APERIO_NATS_PORT = String(port);
  process.env.APERIO_NATS_URL = `nats://127.0.0.1:${port}`;
}

async function setupInfra() {
  const needsNats = usesNatsEventBus();
  const services = [];
  if (!(await canConnect(databaseHost(), databasePort()))) {
    services.push("postgres");
  }
  if (needsNats && !(await canConnect(natsHost(), natsPort()))) {
    services.push("nats");
  }
  if (!skipDocker && services.length > 0 && (await commandExists("docker"))) {
    await run("docker", ["compose", "up", "-d", ...services]);
  } else if (!skipDocker) {
    // If Docker is absent but services are already reachable, continue. If a
    // service is missing, the waitForTcp call below will fail with the target.
    const reason = services.length === 0 ? "Required local services are already reachable" : "docker is not available";
    console.warn(`[dev] ${reason}; skipping docker compose startup`);
  }
  await waitForTcp("postgres", databaseHost(), databasePort(), 30_000);
  if (needsNats) {
    await waitForTcp("nats", natsHost(), natsPort(), 30_000);
  }
}

function usesNatsEventBus() {
  return String(process.env.APERIO_EVENT_BUS ?? "").trim().toLowerCase() === "nats";
}

function databaseHost() {
  return parsedURL(process.env.DATABASE_URL)?.hostname ?? "127.0.0.1";
}

function databasePort() {
  return Number(parsedURL(process.env.DATABASE_URL)?.port || 5432);
}

function natsHost() {
  return parsedURL(process.env.APERIO_NATS_URL)?.hostname ?? "127.0.0.1";
}

function natsPort() {
  return Number(parsedURL(process.env.APERIO_NATS_URL)?.port || 4222);
}

function parsedURL(value) {
  try {
    return value ? new URL(value) : null;
  } catch {
    return null;
  }
}

async function commandExists(command) {
  return new Promise((resolve) => {
    const probe = spawn(command, ["--version"], { stdio: "ignore", shell: process.platform === "win32" });
    probe.on("error", () => resolve(false));
    probe.on("exit", (code) => resolve(code === 0));
  });
}

async function composePublishedHostPort(service, containerPort) {
  if (!(await commandExists("docker"))) {
    return null;
  }
  return new Promise((resolve) => {
    let output = "";
    const probe = spawn("docker", ["compose", "port", service, String(containerPort)], {
      cwd: root,
      env: process.env,
      stdio: ["ignore", "pipe", "ignore"],
      shell: process.platform === "win32"
    });
    probe.stdout.on("data", (chunk) => {
      output += chunk.toString();
    });
    probe.on("error", () => resolve(false));
    probe.on("exit", (code) => {
      if (code !== 0) {
        resolve(null);
        return;
      }
      // docker compose prints host:port; keep only the published host port so we
      // can align default env vars with an already-running compose stack.
      const port = (
        output
          .split(/\r?\n/)
          .map((line) => line.trim())
          .filter(Boolean)
          .map((line) => Number(line.slice(line.lastIndexOf(":") + 1)))
          .find((publishedPort) => Number.isInteger(publishedPort) && publishedPort > 0)
      );
      resolve(port ?? null);
    });
  });
}

async function waitForTcp(label, host, port, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await canConnect(host, port)) {
      console.log(`[dev] ${label} is reachable at ${host}:${port}`);
      return;
    }
    await sleep(500);
  }
  throw new Error(`${label} was not reachable at ${host}:${port}`);
}

function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      server.close(() => {
        if (address && typeof address === "object") {
          resolve(address.port);
        } else {
          reject(new Error("could not allocate a free local port"));
        }
      });
    });
  });
}

function canConnect(host, port) {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host, port, timeout: 1000 });
    socket.once("connect", () => {
      socket.destroy();
      resolve(true);
    });
    socket.once("timeout", () => {
      socket.destroy();
      resolve(false);
    });
    socket.once("error", () => resolve(false));
  });
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function run(command, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd: root, env: process.env, stdio: "inherit", shell: process.platform === "win32" });
    child.on("error", reject);
    child.on("exit", (code) => {
      if (code === 0) {
        resolve();
      } else {
        reject(new Error(`${command} ${args.join(" ")} exited with ${code}`));
      }
    });
  });
}

function startWorker(label, pkg) {
  // The workers expect a pgx-safe DATABASE_URL just like their npm scripts.
  // We resolve it once at orchestrator start so the child inherits the same
  // override that `npm run worker:*` would compute.
  let databaseURL = process.env.DATABASE_URL;
  try {
    const probe = spawnSync("node", ["scripts/dev-config.mjs", "go-database-url"], {
      cwd: root,
      env: process.env,
      encoding: "utf8"
    });
    if (probe.status === 0 && probe.stdout) {
      const resolved = probe.stdout.trim();
      if (resolved) {
        databaseURL = resolved;
      }
    }
  } catch {
    // Fall back to whatever DATABASE_URL is already in the environment.
  }
  // Auxiliary on purpose: a worker compile error or fatal-on-startup must
  // never tear down the web/API dev loop. The slot auto-restarts with
  // capped exponential backoff so the worker recovers as soon as the
  // developer fixes the underlying issue.
  return start(label, "go", ["run", pkg], { essential: false, env: { DATABASE_URL: databaseURL } });
}

// MAX_WORKER_RESTART_DELAY caps the auto-restart backoff so a permanently
// broken worker doesn't spin tight, but is short enough that recovery
// after a fix feels instant in the dev loop.
const MAX_WORKER_RESTART_DELAY = 30_000;

function start(label, command, args, options = {}) {
  const essential = options.essential ?? true;
  const env = options.env ? { ...process.env, ...options.env } : process.env;
  // Slot is what we store in `children` so `terminate()` always sees the
  // CURRENT child after an auxiliary restart, not a stale handle.
  const slot = { child: null, restartCount: 0, get pid() { return this.child?.pid; }, kill(sig) { return this.child?.kill(sig); } };

  // scheduleAuxiliaryRestart is shared by both the exit and error handlers
  // so a transient spawn failure (EAGAIN/EMFILE/ENOENT under load) is
  // recovered the same way as a fatal-after-spawn. Node emits 'error'
  // WITHOUT a following 'exit' when the process cannot be spawned at all;
  // routing the restart through this single helper means the worker comes
  // back up either way and the helper's contract (auxiliary workers
  // recover automatically) is preserved on both paths.
  function scheduleAuxiliaryRestart(reason) {
    slot.restartCount += 1;
    const delay = Math.min(MAX_WORKER_RESTART_DELAY, 1_000 * 2 ** Math.min(slot.restartCount - 1, 5));
    console.error(
      `[${label}] ${reason} (worker only; web + API unaffected). Restart #${slot.restartCount} in ${delay}ms.`
    );
    setTimeout(() => {
      if (!shuttingDown) {
        spawnOnce();
      }
    }, delay);
  }

  function spawnOnce() {
    const child = spawn(command, args, {
      cwd: root,
      env,
      stdio: ["ignore", "pipe", "pipe"],
      shell: process.platform === "win32",
      detached: process.platform !== "win32"
    });
    slot.child = child;
    pipe(label, child.stdout);
    pipe(label, child.stderr);
    child.on("exit", (code, signal) => {
      if (shuttingDown) {
        return;
      }
      if (essential) {
        console.error(`[${label}] exited with ${signal ?? code}; tearing down dev stack`);
        shutdown(code ?? 1);
        return;
      }
      // Auxiliary worker: keep web + API up. Schedule a backoff restart
      // so a transient fatal (compile error, missing config, transient
      // db unavailability) recovers automatically when fixed.
      scheduleAuxiliaryRestart(`exited with ${signal ?? code}`);
    });
    child.on("error", (error) => {
      if (shuttingDown) {
        return;
      }
      if (essential) {
        console.error(`[${label}] ${error.message}`);
        shutdown(1);
        return;
      }
      // Spawn failures (EAGAIN/EMFILE/ENOENT) emit 'error' WITHOUT a
      // matching 'exit', so the restart must be scheduled here too;
      // otherwise a single transient spawn failure leaves the worker
      // permanently dead for the rest of the dev session.
      scheduleAuxiliaryRestart(`spawn failed: ${error.message}`);
    });
  }

  spawnOnce();
  return slot;
}

function pipe(label, stream) {
  readline.createInterface({ input: stream }).on("line", (line) => {
    console.log(`[${label}] ${line}`);
  });
}

function terminate(slot, signal) {
  // slot may be the bare child (legacy) or a {child, restartCount} bookkeeping
  // object returned by start(); resolve to the active child either way.
  const child = slot.child ?? slot;
  if (!child || !child.pid) {
    return;
  }
  try {
    if (process.platform === "win32") {
      const killer = spawn("taskkill", ["/pid", String(child.pid), "/T", "/F"], { stdio: "ignore" });
      killer.on("error", () => {});
      child.kill(signal);
    } else {
      // Children are started detached on POSIX, so killing the negative pid tears
      // down the whole process group (Next, Go, and their descendants).
      process.kill(-child.pid, signal);
    }
  } catch {
    try {
      child.kill(signal);
    } catch {
      // process already exited
    }
  }
}

function shutdown(exitCode) {
  if (shuttingDown) {
    return;
  }
  shuttingDown = true;
  process.exitCode = exitCode;
  for (const child of children) {
    terminate(child, "SIGTERM");
  }
  // Give dev servers a short graceful window, then force-kill remaining process
  // groups so ports are not left occupied for the next run.
  setTimeout(() => {
    for (const child of children) {
      terminate(child, "SIGKILL");
    }
    process.exit(exitCode);
  }, 750);
}
