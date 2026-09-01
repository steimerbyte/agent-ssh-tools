// agent-ssh-tools — Pi coding-agent extension
// SSH profile manager + read/write/edit/exec tools with agent-safety
// hardening. Inspired by the original pi-ssh-tools plugin; adds probe-
// before-activate, verify-block, profile+alias resolver, timeouts, and
// SHA-256 unchanged-detection. See README for the full feature list.

import * as _nodeChild_process from "node:child_process";
import * as _nodeDns from "node:dns";
import * as _nodeFs from "node:fs";
import * as _nodeNet from "node:net";
import * as _nodeOs from "node:os";
import * as _nodePath from "node:path";
import * as _nodeCrypto from "node:crypto";

import * as _piCodingAgent from "@earendil-works/pi-coding-agent";
import * as _piTui from "@earendil-works/pi-tui";

// ---- constants ---------------------------------------------------------

const SSH_STATUS_KEY = "ssh-tools";
const SSH_TOOL_NAMES = ["ssh_target_select", "ssh_read", "ssh_write", "ssh_edit", "ssh_bash", "ssh_scp"];
const SSH_CONFIG_PATH = _nodePath.join(_nodeOs.homedir(), ".ssh", "config");
const PROFILES_FILE = _nodePath.join(_nodeOs.homedir(), ".config", "agent-ssh-tools", "profiles.json");
const DEFAULT_PROBE_SECONDS = 6;
const DEFAULT_SSH_TIMEOUT_SECONDS = 30;
const DEFAULT_SCP_TIMEOUT_SECONDS = 600;

// ---- shell quoting -----------------------------------------------------

function shellQuote(value) {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

// ---- path normalization -------------------------------------------------

function normalizeRemoteDir(path) {
  return path.length > 1 ? path.replace(/\/+$/, "") : path;
}

function joinRemote(cwd, p) {
  if (!cwd) return p;
  return _nodePath.posix.join(cwd, p);
}

// ---- profiles.json I/O --------------------------------------------------

function readProfiles() {
  if (!_nodeFs.existsSync(PROFILES_FILE)) return { profiles: {}, aliases: {} };
  try {
    const data = JSON.parse(_nodeFs.readFileSync(PROFILES_FILE, "utf8"));
    return {
      profiles: (data && data.profiles) || {},
      aliases:  (data && data.aliases)  || {}
    };
  } catch {
    return { profiles: {}, aliases: {} };
  }
}

// ---- ~/.ssh/config parser ---------------------------------------------

// Module-level cache for ssh_config profiles. Re-parsed only when the
// file's mtime changes (or after TTL). Saves a few ms per tool call in
// sessions that call ssh_target_select multiple times.
const sshConfigCache = { mtimeMs: 0, profiles: null, ts: 0 };
const SSH_CONFIG_CACHE_TTL_MS = 5_000;

function parseSshConfigProfiles() {
  if (!_nodeFs.existsSync(SSH_CONFIG_PATH)) return [];
  const stat = _nodeFs.statSync(SSH_CONFIG_PATH);
  const now = Date.now();
  if (sshConfigCache.profiles &&
      sshConfigCache.mtimeMs === stat.mtimeMs &&
      (now - sshConfigCache.ts) < SSH_CONFIG_CACHE_TTL_MS) {
    return sshConfigCache.profiles;
  }
  const text = _nodeFs.readFileSync(SSH_CONFIG_PATH, "utf8");
  const profiles = new Map();
  for (const rawLine of text.split("\n")) {
    const line = rawLine.replace(/\s+#.*$/, "").trim();
    if (!line) continue;
    const match = line.match(/^Host\s+(.+)$/i);
    if (!match) continue;
    for (const alias of match[1].split(/\s+/).map(s => s.trim()).filter(Boolean)) {
      if (alias.includes("*") || alias.includes("?") || alias.startsWith("!")) continue;
      if (!profiles.has(alias)) profiles.set(alias, { name: alias, remote: alias });
    }
  }
  const arr = Array.from(profiles.values()).sort((a, b) => a.name.localeCompare(b.name));
  sshConfigCache.mtimeMs = stat.mtimeMs;
  sshConfigCache.profiles = arr;
  sshConfigCache.ts = now;
  return arr;
}

// Refresh profile list from both profiles.json aliases and ~/.ssh/config.
// Returns { sshConfigProfiles, merged } where merged is what users see.
function refreshProfiles() {
  const data = readProfiles();
  const customProfiles = Object.entries(data.profiles).map(([name, p]) => ({
    name,
    remote: p.host || name,
    cwd:    p.cwd || undefined
  }));
  const sshConfigProfiles = parseSshConfigProfiles();
  // ssh_config profiles are only listed when no custom profile with the same
  // name exists — explicit overrides win, matching the resolution order.
  const customNames = new Set(customProfiles.map(p => p.name));
  const merged = [
    ...customProfiles,
    ...sshConfigProfiles.filter(p => !customNames.has(p.name))
  ];
  return { sshConfigProfiles, merged };
}

// Resolve a target argument to { name, remote, cwd }.
// Resolution order:
//   1. profiles.json aliases[arg]
//   2. profiles.json profiles[arg] (custom host + cwd)
//   3. ~/.ssh/config Host block
//   4. raw arg as fallback (marked `untrusted: true`)
//
// Inline ":path" syntax sets an inline cwd that always wins.
//
// `untrusted: true` means the name did not match any configured source.
// Callers should refuse to probe in that state — passing arbitrary
// strings to ssh(1) would let a typo or prompt-injection turn into
// a connection attempt to the wrong host.
// Whitelist for safe target strings. ssh hostnames/aliases/paths are
// allowed to contain letters, digits, dots, hyphens, underscores and
// slashes (for user@host:port notation). Anything else — newlines,
// shell metacharacters, spaces — is rejected. Prevents command
// injection through profile names, inline cwd, or ssh_config entries
// and keeps before_agent_start prompts free of newline-based prompt
// injection. Single ':' separator allowed for host:/path syntax.
const SAFE_TARGET_RE = /^[A-Za-z0-9._@\-\/:]+$/;

function isSafeTargetString(s) {
  return typeof s === "string" && s.length > 0 && SAFE_TARGET_RE.test(s);
}

function normalizeTargetArg(arg) {
  const trimmed = (arg || "").trim();
  if (!trimmed) return { name: "", remote: "", cwd: undefined, untrusted: true, error: "empty target" };
  if (!isSafeTargetString(trimmed)) {
    return {
      name: trimmed,
      remote: "",
      cwd: undefined,
      untrusted: true,
      error: `target '${trimmed.slice(0, 60)}' contains unsafe characters (allowed: A-Z a-z 0-9 . _ @ - / :)`,
    };
  }

  const data = readProfiles();
  const aliases  = data.aliases  || {};
  const profiles = data.profiles || {};

  let resolved = aliases[trimmed] || trimmed;
  let inlineCwd;
  const colon = resolved.indexOf(":");
  if (colon > 0) {
    inlineCwd = resolved.slice(colon + 1);
    resolved  = resolved.slice(0, colon);
  }

  // Inline cwd must also pass the whitelist (no newlines, no shell
  // metacharacters that could break out of `cd <cwd> && cmd`).
  if (inlineCwd && !isSafeTargetString(inlineCwd)) {
    return {
      name: resolved,
      remote: "",
      cwd: undefined,
      untrusted: true,
      error: `inline cwd '${inlineCwd.slice(0, 60)}' contains unsafe characters`,
    };
  }

  // ssh-config match wins over same-name profile (Host block is the
  // canonical source for host/port/identity), but cwd from profile is
  // ignored when inline cwd is given.
  const sshCfg = parseSshConfigProfiles().find(p => p.name === resolved);

  // Sanitise any cwd that originated from profiles.json / ssh_config.
  const safeCwd = (c) => (c && isSafeTargetString(c)) ? c : undefined;

  const prof = profiles[resolved];
  let remote, cwd;
  // sshConfigAlias from profiles.json: when set, probe() will resolve the
  // alias via `ssh -G <alias>` instead of DNS. The resolved hostname from
  // ssh -G becomes the `remote` for TCP-connect and ssh-whoami.
  let sshConfigAlias;
  let _sshTrace;
  if (sshCfg) {
    remote = sshCfg.remote;
    cwd    = safeCwd(inlineCwd) || safeCwd(prof ? prof.cwd : undefined);
  } else if (prof) {
    remote = (prof.host && isSafeTargetString(prof.host)) ? prof.host : resolved;
    cwd    = safeCwd(inlineCwd) || safeCwd(prof.cwd);
    // Carry sshConfigAlias through so probe() can use it instead of DNS.
    sshConfigAlias = (prof.sshConfigAlias && isSafeTargetString(prof.sshConfigAlias)) ? prof.sshConfigAlias : undefined;
    // Resolve hostname via ssh -G so downstream ssh calls (buildVerifyBlock,
    // ssh_bash, ssh_read, etc.) use the IP instead of the profile name.
    if (sshConfigAlias) {
      try {
        const r = _nodeChild_process.spawnSync(
          "ssh", ["-G", sshConfigAlias],
          { encoding: "utf8", timeout: 5000 }
        );
        if (r.status === 0) {
          const lines = r.stdout.split("\n").reduce((acc, l) => {
            const kv = l.trim().split(/\s+/);
            if (kv.length >= 2) acc[kv[0].toLowerCase()] = kv.slice(1).join(" ");
            return acc;
          }, {} as Record<string, string>);
          const resolvedHost = lines.hostname || sshConfigAlias;
          if (isSafeTargetString(resolvedHost)) {
            _sshTrace = `[ssh-ts] ssh -G ${sshConfigAlias} → hostname=${resolvedHost} (was ${remote})`;
            remote = resolvedHost;
          } else {
            _sshTrace = `[ssh-ts] ssh -G ${sshConfigAlias} → hostname=${resolvedHost} REJECTED by isSafeTargetString`;
          }
        } else {
          _sshTrace = `[ssh-ts] ssh -G ${sshConfigAlias} failed status=${r.status} stderr=${r.stderr?.toString().slice(0,200)}`;
        }
      } catch (e) {
        _sshTrace = `[ssh-ts] ssh -G ${sshConfigAlias} threw: ${e.message}`;
      }
    }
  } else {
    // No profile, no alias, no ssh-config Host block. Do NOT silently
    // pass this through to ssh(1) — the user probably mistyped or the
    // model invented a name. Caller must reject via `untrusted: true`.
    return {
      name: resolved,
      remote: resolved,
      cwd: safeCwd(inlineCwd),
      untrusted: true,
      error: `target '${trimmed}' not found in profiles, aliases, or ~/.ssh/config`,
    };
  }

  // Final gate: any cwd we kept must be safe. If ssh_config provided
  // an unsafe cwd, drop it.
  if (cwd && !isSafeTargetString(cwd)) cwd = undefined;

  const result = { name: resolved, remote, cwd, untrusted: false, sshConfigAlias };
  if (_sshTrace) result._sshTrace = _sshTrace;
  return result;
}

// Human-readable list of available targets for error messages.
function sshCliAvailableTargets(): string {
  const data = readProfiles();
  const profNames = Object.keys(data.profiles || {});
  const sshHosts = parseSshConfigProfiles().map(p => p.name);
  const aliasNames = Object.keys(data.aliases || {});
  // profile names first, then alias->target, then ssh-config hosts not already covered
  const out: string[] = [...profNames];
  for (const [alias, target] of Object.entries(data.aliases || {})) {
    out.push(`${alias} -> ${target}`);
  }
  for (const h of sshHosts) {
    if (!profNames.includes(h)) out.push(h);
  }
  if (aliasNames.length === 0 && profNames.length === 0 && sshHosts.length === 0) {
    return "(none configured)";
  }
  return out.join(", ");
}

// ---- ssh wrappers -----------------------------------------------------

// sshExec: existing core wrapper. Keeps stdout/stderr separate; tools
// can build their own verbose headers from these primitives.
function sshExec(remote, command, options = {}) {
  return new Promise((resolve, reject) => {
    // Always enforce key-only auth to prevent ssh_askpass hang on wrong user/key.
    const args = [
      "-o", "BatchMode=yes",
      "-o", "PreferredAuthentications=publickey"
    ];
    if (typeof options.timeoutSeconds === "number" && options.timeoutSeconds > 0) {
      args.push("-o", `ConnectTimeout=${options.timeoutSeconds}`);
    }
    if (options.identityFile && isSafeTargetString(options.identityFile)) args.push("-i", options.identityFile);
    if (options.user         && isSafeTargetString(options.user))         args.push("-l", options.user);
    if (typeof options.port === "number" && options.port !== 22)          args.push("-p", String(options.port));
    args.push(remote, command);

    const child = _nodeChild_process.spawn("ssh", args, {
      stdio: ["pipe", "pipe", "pipe"]
    });

    const stdoutChunks = [];
    const stderrChunks = [];
    let killed = false;

    const killTimer = typeof options.timeoutSeconds === "number" && options.timeoutSeconds > 0
      ? setTimeout(() => {
          killed = true;
          try { child.kill("SIGKILL"); } catch {}
        }, options.timeoutSeconds * 1000)
      : undefined;

    // Live-streaming: pipe stdout/stderr through a throttler that calls
    // onUpdate() at most every ~150ms with accumulated content. The full
    // stream is still captured in stdoutChunks/stderrChunks so the
    // final result.content can include everything.
    const throttledUpdate = options.onUpdate ? createStreamThrottler(options.onUpdate) : null;
    child.stdout.on("data", d => {
      stdoutChunks.push(d);
      options.onStdoutData?.(d);
      throttledUpdate?.onChunk(d, "stdout");
    });
    child.stderr.on("data", d => {
      stderrChunks.push(d);
      options.onStderrData?.(d);
      throttledUpdate?.onChunk(d, "stderr");
    });
    if (options.stdin !== undefined) {
      child.stdin.write(options.stdin);
      child.stdin.end();
    } else {
      child.stdin.end();
    }
    child.on("error", err => {
      if (killTimer) clearTimeout(killTimer);
      throttledUpdate?.flush();
      reject(err);
    });
    child.on("close", exitCode => {
      if (killTimer) clearTimeout(killTimer);
      throttledUpdate?.flush();
      if (killed) {
        reject(new Error(`timeout:${options.timeoutSeconds}`));
        return;
      }
      // Cap output buffers to prevent OOM on commands that produce
      // 100+ MB (e.g. accidental `cat /var/log/syslog`). When the cap is
      // hit, the captured buffer stays at the cap and a flag is set
      // so callers can surface "output truncated" to the user.
      const outCap = options.maxOutputBytes ?? 10 * 1024 * 1024;
      let stdout = Buffer.concat(stdoutChunks);
      let stderr = Buffer.concat(stderrChunks);
      let truncated = false;
      if (stdout.length > outCap) { stdout = stdout.subarray(0, outCap); truncated = true; }
      if (stderr.length > outCap) { stderr = stderr.subarray(0, outCap); truncated = true; }
      resolve({
        stdout,
        stderr,
        truncated,
        exitCode
      });
    });
  });
}

// Stream-throttler: collects stdout/stderr chunks and calls onUpdate at
// most every THROTTLE_MS. Prevents UI flooding when remote commands
// emit thousands of small lines (e.g. `tail -f`, `docker pull`).
function createStreamThrottler(onUpdate) {
  const THROTTLE_MS = 150;
  // Visible-buffer cap: don't ship more than ~64KB to the UI at once
  // to avoid memory blowup on huge outputs. The captured full buffer
  // remains in the tool's stdoutChunks/stderrChunks for the final
  // result.content.
  const VISIBLE_CAP = 64 * 1024;
  let pendingText = "";
  let timer = null;
  let flushed = false;
  function flush() {
    if (timer) { clearTimeout(timer); timer = null; }
    if (!pendingText) return;
    const text = pendingText;
    pendingText = "";
    try {
      onUpdate({
        content: [{ type: "text", text }],
        details: { streaming: true }
      });
    } catch { /* ignore — UI may be gone */ }
  }
  function onChunk(chunk, source) {
    // Truncate to last VISIBLE_CAP bytes (keep tail) — preserves most
    // recent output when streams grow long. We don't keep head because
    // docker pull / tail -f output is more useful as a tail.
    pendingText += chunk.toString("utf8");
    if (pendingText.length > VISIBLE_CAP) {
      pendingText = "…" + pendingText.slice(pendingText.length - VISIBLE_CAP);
    }
    if (timer) return;
    timer = setTimeout(() => { timer = null; flush(); }, THROTTLE_MS);
  }
  return { onChunk, flush };
}

// Format a one-line verbose header that prefixes every ssh_* tool result.
// Shows target host, command, exit code, ms, stderr-summary.
//   $ ssh pve-docker 'whoami'   exit=0  546ms
function formatSshHeader(remote, command, exitCode, elapsedMs, stderrText) {
  const cmdShort = command.length > 80 ? command.slice(0, 77) + "..." : command;
  const errShort = stderrText ? stderrText.split("\n")[0].slice(0, 60) : "";
  let line = `$ ssh ${remote} ${JSON.stringify(cmdShort)}  exit=${exitCode}  ${elapsedMs}ms`;
  if (errShort) line += `\n  stderr: ${errShort}`;
  return line;
}

// Run an ssh command, return a verbose envelope the tools can prepend
// to their content blocks. Always non-throwing; tools inspect `exit`/`stderr`.
async function sshExecVerbose(remote, command, options = {}) {
  const t0 = Date.now();
  let exit = 0;
  let stdout: Buffer = Buffer.alloc(0);
  let stderr: Buffer = Buffer.alloc(0);
  let truncated = false;
  try {
    const r = await sshExec(remote, command, options);
    exit = r.exitCode;
    stdout = r.stdout;
    stderr = r.stderr;
    truncated = (r as any).truncated === true;
  } catch (e: any) {
    exit = 124;
    stderr = Buffer.from(String(e?.message ?? e));
  }
  const elapsed = Date.now() - t0;
  const header = formatSshHeader(remote, command, exit, elapsed, stderr.toString("utf8").trim());
  return { exit, stdout, stderr, elapsedMs: elapsed, truncated, header };
}

async function sshOk(remote, command, options = {}) {
  const { stdout, stderr, exitCode } = await sshExec(remote, command, options);
  if (exitCode !== 0) {
    const msg = stderr.toString("utf8").trim() || stdout.toString("utf8").trim() || "unknown ssh error";
    throw new Error(`SSH failed (${exitCode}): ${msg}`);
  }
  return stdout;
}

// Categorize an ssh failure into agent-friendly reasons.
// Returns { ok: true, user, ip } or { ok: false, reason, detail, ip }.
//
// When sshConfigAlias is set (profiles.json sshConfigAlias field), the
// alias is resolved via `ssh -G <alias>` instead of a DNS lookup. This
// bypasses DNS for ~/.ssh/config Host aliases that have no DNS record.
async function probe(remote, seconds = DEFAULT_PROBE_SECONDS, sshConfigAlias?: string) {
  let ip: string;
  let resolvedUser: string | undefined;
  let resolvedPort: number;
  let resolvedIdentityFile: string | undefined;

  if (sshConfigAlias) {
    // Resolve via ssh -G: hostname, user, port, identityfile from ~/.ssh/config.
    // Do NOT use DNS — the alias may not exist in DNS.
    // Use spawnSync for cross-node-version compatibility (Node 26 changed
    // promises.exec to return streams instead of strings for stdout/stderr).
    let parsed: { hostname: string; port: number; user?: string; identityFile?: string } | null = null;
    try {
      const r = _nodeChild_process.spawnSync(
        "ssh", ["-G", sshConfigAlias],
        { encoding: "utf8", timeout: 5000 }
      );
      if (r.status === 0) {
        const lines = r.stdout.split("\n").reduce((acc, l) => {
          const kv = l.trim().split(/\s+/);
          if (kv.length >= 2) acc[kv[0].toLowerCase()] = kv.slice(1).join(" ");
          return acc;
        }, {} as Record<string, string>);
        const hostname = lines.hostname || sshConfigAlias;
        const port = parseInt(lines.port, 10) || 22;
        const user = lines.user || undefined;
        let identityFile = lines.identityfile;
        if (identityFile?.startsWith("~")) identityFile = _nodeOs.homedir() + identityFile.slice(1);
        parsed = { hostname, port, user, identityFile };
      }
    } catch { /* keep parsed = null */ }
    if (!parsed) {
      return { ok: false, reason: "unreachable", detail: `ssh -G ${sshConfigAlias} failed`, ip: "" };
    }
    ip = parsed.hostname;
    resolvedUser = parsed.user;
    resolvedPort = parsed.port;
    resolvedIdentityFile = parsed.identityFile;
  } else {
    // DNS lookup with its own short timeout so a slow DNS resolver does
    // not eat the whole probe budget. Fall back to the raw hostname if
    // the lookup hangs.
    const dnsTimeout = new Promise<string>(resolve => {
      setTimeout(() => resolve(remote), Math.min(seconds * 1000, 1500));
    });
    const dnsLookup = (async () => {
      try {
        return (await _nodeDns.promises.lookup(remote)).address;
      } catch {
        return remote;
      }
    })();
    ip = await Promise.race([dnsLookup, dnsTimeout]);
  }

  // Step 1: TCP connect on resolved port (default 22).
  const portOk = await new Promise(resolve => {
    const sock = _nodeNet.createConnection({ host: ip, port: resolvedPort ?? 22, family: 4 });
    let done = false;
    const finish = v => { if (!done) { done = true; resolve(v); } };
    sock.setTimeout(seconds * 1000);
    sock.once("connect", () => { sock.destroy(); finish(true); });
    sock.once("timeout", () => { sock.destroy(); finish("timeout"); });
    sock.once("error", e => finish(e.code || "error"));
  });
  if (portOk !== true) {
    const port = resolvedPort ?? 22;
    const reason = portOk === "timeout" || /timeout/i.test(String(portOk))
      ? "unreachable" : "unreachable";
    const detail = portOk === "timeout"
      ? `no TCP response on ${ip}:${port} within ${seconds}s`
      : `TCP connect to ${ip}:${port} failed: ${portOk}`;
    return { ok: false, reason, detail, ip };
  }

  // Step 2: ssh whoami with resolved identityfile, user, and port.
  // Use the resolved IP as the SSH target — NOT the sshConfigAlias name.
  const args: string[] = [
    "-o", `ConnectTimeout=${seconds}`,
    "-o", "BatchMode=yes",
    "-o", "PreferredAuthentications=publickey",
    ...(resolvedIdentityFile ? ["-i", resolvedIdentityFile] : []),
    ...(resolvedUser       ? ["-l", resolvedUser]         : []),
    ...(resolvedPort && resolvedPort !== 22 ? ["-p", String(resolvedPort)] : []),
    ip, "whoami"
  ];
  return new Promise(resolve => {
    const proc = _nodeChild_process.spawn("ssh", args, { stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "", stderr = "";
    let killed = false;
    const killTimer = setTimeout(() => {
      killed = true;
      try { proc.kill("SIGKILL"); } catch {}
      resolve({ ok: false, reason: "timeout", detail: `ssh did not respond within ${seconds}s`, ip });
    }, seconds * 1000 + 2000);
    proc.stdout.on("data", d => stdout += d);
    proc.stderr.on("data", d => stderr += d);
    proc.stdin.end();
    proc.on("close", code => {
      if (killed) return;
      clearTimeout(killTimer);
      const out = stdout.trim();
      const err = stderr.trim();
      if (code === 0 && out) return resolve({ ok: true, user: out, ip });
      if (/permission denied|publickey|password|authentic/i.test(err))
        return resolve({ ok: false, reason: "auth", detail: err.split("\n")[0] || err, ip });
      if (/no such host|getaddrinfo|unknown host|name or service/i.test(err))
        return resolve({ ok: false, reason: "unreachable", detail: err.split("\n")[0] || err, ip });
      if (/connection refused/i.test(err))
        return resolve({ ok: false, reason: "refused", detail: err.split("\n")[0] || err, ip });
      if (/timed out|no route/i.test(err))
        return resolve({ ok: false, reason: "unreachable", detail: err.split("\n")[0] || err, ip });
      resolve({ ok: false, reason: "ssh-error", detail: err || `ssh exited ${code}`, ip });
    });
    proc.on("error", e => {
      if (killed) return;
      clearTimeout(killTimer);
      resolve({ ok: false, reason: "ssh-missing", detail: e.message, ip });
    });
  });
}

// ---- identity file / fingerprint lookup -------------------------------

// Returns the IdentityFile ssh would use for `host` per `ssh -G`.
function identityFileFor(host) {
  try {
    const r = _nodeChild_process.spawnSync("ssh", ["-G", host], { encoding: "utf8" });
    if (r.status !== 0) return "";
    const m = r.stdout.split("\n").find(l => /^identityfile\s+/i.test(l));
    if (!m) return "";
    let p = m.replace(/^identityfile\s+/i, "").trim();
    if (p.startsWith("~")) p = _nodeOs.homedir() + p.slice(1);
    return p;
  } catch { return ""; }
}

function fingerprintFor(keyPath) {
  if (!keyPath || !_nodeFs.existsSync(keyPath)) return "";
  // ssh-keygen -lf on private key reads the matching .pub.
  const tryRead = (file) => {
    const r = _nodeChild_process.spawnSync("ssh-keygen", ["-lf", file], { encoding: "utf8" });
    if (r.status === 0) {
      const m = r.stdout.match(/SHA256:[A-Za-z0-9+/]+/);
      return m ? m[0] : r.stdout.trim().split(/\s+/)[1] || "";
    }
    return "";
  };
  return tryRead(keyPath) || tryRead(keyPath + ".pub");
}

// ---- verify block -----------------------------------------------------

async function buildVerifyBlock(target, cwd, seconds = 6, sshConfigAlias?: string) {
  const remote = target.remote;
  const profileName = target.name;
  // Prefer resolved identity/user/port over identityFileFor (which only
  // works for ~/.ssh/config host names, not raw IPs).
  const idFile = target.identityFile || identityFileFor(sshConfigAlias || remote);
  const fp     = fingerprintFor(idFile);
  const t = seconds;
  const SEP = "@@ssh-cli-verify@@";
  const q = (v) => "'" + String(v).replace(/'/g, "'\\''") + "'";
  const cmd =
    `PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin ` +
    `printf '%s\\n' "$(whoami)" ${q(SEP)} "$(uname -n)" ${q(SEP)} "$(date -u +%Y-%m-%dT%H:%M:%SZ)" ${q(SEP)} "${q(profileName)}"`;
  let user = "<error>", hostname = "<error>", date = "<error>", aliasEcho = "<error>";
  try {
    const r = await sshExec(remote, cmd, {
      timeoutSeconds: t,
      identityFile: target.identityFile,
      user: target.user,
      port: target.port
    });
    if (r.exitCode === 0) {
      const parts = r.stdout.toString("utf8").trim().split(SEP);
      if (parts.length >= 4) {
        user = parts[0].trim();
        hostname = parts[1].trim();
        date = parts[2].trim();
        aliasEcho = parts[3].trim();
      }
    } else {
      user = `<ssh-exit-${r.exitCode}>`;
    }
  } catch (e: any) {
    user = `<timeout>`;
  }
  // Mismatch detection: profiles.json or ~/.ssh/config can route a
  // familiar name (e.g. "pve-docker") to a different host. If the
  // profile name disagrees with what `uname -n` reports, surface the
  // warning so the agent/user can spot profile-poisoning.
  const mismatch = aliasEcho !== "<error>" &&
                    hostname !== "<error>" &&
                    aliasEcho !== hostname;
  const lines = [
    "verify:",
    `  user:     ${user}`,
    `  hostname: ${hostname}` + (mismatch ? `  <-- MISMATCH (profile name: ${aliasEcho})` : ""),
    `  cwd:      ${cwd || "(remote default ~)"}`,
    `  key:      ${fp || "(no identity file)"}`,
    `  date:     ${date}`,
    mismatch ? `\n  WARNING: profile name '${aliasEcho}' resolved to '${hostname}'.\n           profiles.json or ~/.ssh/config may be pointing to a different host.` : ""
  ];
  return lines.join("\n");
}

// ---- file operations --------------------------------------------------

function inferImageMimeType(path) {
  switch (_nodePath.extname(path).toLowerCase()) {
    case ".jpg": case ".jpeg": return "image/jpeg";
    case ".png": return "image/png";
    case ".gif": return "image/gif";
    case ".webp": return "image/webp";
    default: return null;
  }
}

function createRemoteReadOps(target) {
  return {
    readFile: (absolutePath) => sshOk(target.remote, `cat ${shellQuote(absolutePath)}`, {
      timeoutSeconds: DEFAULT_SSH_TIMEOUT_SECONDS,
      identityFile: target.identityFile,
      user: target.user,
      port: target.port
    }),
    access: (absolutePath) => sshOk(target.remote, `test -r ${shellQuote(absolutePath)}`, {
      timeoutSeconds: DEFAULT_SSH_TIMEOUT_SECONDS,
      identityFile: target.identityFile,
      user: target.user,
      port: target.port
    }).then(() => {}),
    detectImageMimeType: async (absolutePath) => inferImageMimeType(absolutePath)
  };
}

function createRemoteWriteOps(target) {
  const opts = {
    timeoutSeconds: DEFAULT_SSH_TIMEOUT_SECONDS,
    identityFile: target.identityFile,
    user: target.user,
    port: target.port
  };
  return {
    writeFile: async (absolutePath, content) => {
      try {
        await sshOk(target.remote,
          `if [ -L ${shellQuote(absolutePath)} ]; then p=$(readlink -f ${shellQuote(absolutePath)}); echo "SYMLINK $p"; exit 9; fi; exit 0`,
          opts);
      } catch (e) {
        const msg = String((e as any)?.message ?? e);
        if (msg.includes("exit (9)")) {
          throw new Error(`refusing to write through symlink: ${absolutePath}`);
        }
        throw e;
      }
      await sshOk(target.remote, `cat > ${shellQuote(absolutePath)}`, {
        timeoutSeconds: DEFAULT_SSH_TIMEOUT_SECONDS,
        stdin: content,
        identityFile: target.identityFile,
        user: target.user,
        port: target.port
      });
    },
    mkdir: (dir) => sshOk(target.remote, `mkdir -p ${shellQuote(dir)}`, opts).then(() => {})
  };
}

// ssh_edit: pre/post SHA256 comparison to skip push if unchanged.
// We compare the local buffer (after edit) with what we pulled; if equal,
// no ssh push is needed.
function createRemoteEditOps(target, localCwd) {
  const remotePath = path => {
    if (_nodePath.isAbsolute(path)) return path;
    const relative = _nodePath.relative(localCwd, path).split(_nodePath.sep).join("/");
    if (relative.startsWith("../") || relative === "..") {
      throw new Error(`Resolved edit path ${path} escaped the local SSH edit workspace.`);
    }
    if (!relative || relative === ".") return target.remoteCwd;
    return joinRemote(target.remoteCwd, relative);
  };
  const sshOpts = {
    timeoutSeconds: DEFAULT_SSH_TIMEOUT_SECONDS,
    identityFile: target.identityFile,
    user: target.user,
    port: target.port
  };
  return {
    readFile: (absolutePath) => sshOk(target.remote, `cat ${shellQuote(remotePath(absolutePath))}`, sshOpts),
    writeFile: async (absolutePath, content) => {
      await sshOk(target.remote, `cat > ${shellQuote(remotePath(absolutePath))}`, { ...sshOpts, stdin: content });
    },
    access: (absolutePath) => {
      const p = remotePath(absolutePath);
      return sshOk(target.remote, `test -r ${shellQuote(p)} && test -w ${shellQuote(p)}`, sshOpts).then(() => {});
    }
  };
}

function createRemoteBashOps(target) {
  return {
    exec: async (command, cwd, { onData, signal, timeout }) => {
      const script = `cd ${shellQuote(cwd || target.remoteCwd)}\n${command}\n`;
      const { exitCode } = await sshExec(target.remote, "exec bash -se", {
        stdin: script,
        timeoutSeconds: typeof timeout === "number" && timeout > 0 ? timeout : DEFAULT_SSH_TIMEOUT_SECONDS,
        onStdoutData: onData,
        onStderrData: onData,
        identityFile: target.identityFile,
        user: target.user,
        port: target.port
      });
      return { exitCode };
    }
  };
}

// ---- file transfer (scp) ---------------------------------------------

// Run scp between a local path and a remote target path on the active
// SSH host. direction: 'upload' (local -> remote) or 'download'
// (remote -> local). Optional -r for recursive (directory) transfers.
//
// Returns {exitCode, stdout, stderr, elapsedMs, sourceSha256,
// destinationSha256, truncated}. The caller verifies the two hashes
// match when both ends are regular files (recursive directories get
// empty hashes).
// Decide whether scp's `-C` (ssh-stream compression) is worth the CPU.
// Text-like extensions compress well; binaries don't. We never enable
// `-C` for binary types or unknown extensions (compress-then-encrypt
// is slower for already-compressed data).
const COMPRESSIBLE_EXT = new Set([
  "", ".txt", ".log", ".md", ".rst", ".csv", ".tsv", ".json", ".xml",
  ".yaml", ".yml", ".toml", ".ini", ".conf", ".cfg", ".html", ".css",
  ".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs", ".py", ".rb", ".go",
  ".rs", ".java", ".kt", ".scala", ".c", ".h", ".cpp", ".hpp", ".cs",
  ".sh", ".bash", ".zsh", ".fish", ".sql", ".tex", ".mdx", ".vue", ".svelte"
]);
function isCompressiblePath(p) {
  const idx = p.lastIndexOf(".");
  // No extension = unknown, default to compressible (small files win)
  if (idx < 0 || idx < p.lastIndexOf("/")) return true;
  return COMPRESSIBLE_EXT.has(p.slice(idx).toLowerCase());
}

async function scpTransfer(target, direction, source, destination, recursive, timeoutSeconds) {
  const killTimeoutMs = (typeof timeoutSeconds === "number" && timeoutSeconds > 0 ? timeoutSeconds : DEFAULT_SCP_TIMEOUT_SECONDS) * 1000;
  const flags = ["-v"];
  if (recursive) flags.push("-r");
  if (isCompressiblePath(source)) flags.push("-C");
  // Pass ssh options so scp's internal ssh uses BatchMode + publickey.
  flags.push("-o", "BatchMode=yes", "-o", "PreferredAuthentications=publickey");
  if (target.identityFile) flags.push("-o", `IdentityFile=${target.identityFile}`);
  if (target.user) flags.push("-o", `User=${target.user}`);
  if (target.port && target.port !== 22) flags.push("-P", String(target.port));
  let args;
  if (direction === "upload") {
    try {
      await sshOk(target.remote,
        `if [ -L ${shellQuote(destination)} ]; then exit 9; fi; exit 0`,
        { timeoutSeconds: DEFAULT_SSH_TIMEOUT_SECONDS, identityFile: target.identityFile, user: target.user, port: target.port });
    } catch (e: any) {
      const msg = String(e?.message ?? e);
      if (msg.includes("exit (9)")) {
        throw new Error(`refusing to upload through symlink: ${destination}`);
      }
      throw e;
    }
    args = [...flags, source, `${target.remote}:${destination}`];
  } else if (direction === "download") {
    args = [...flags, `${target.remote}:${source}`, destination];
  } else {
    throw new Error(`ssh_scp: invalid direction '${direction}' (must be 'upload' or 'download')`);
  }
  return new Promise((resolve) => {
    const t0 = Date.now();
    const child = _nodeChild_process.spawn("scp", args, { stdio: ["pipe", "pipe", "pipe"] });
    const outChunks: Buffer[] = [];
    const errChunks: Buffer[] = [];
    // Capture progress lines (stderr from -v) so we can summarise.
    // scp -v output ends with a line like:
    //   "Transferred: sent 4056, received 4608 bytes, in 0.5 seconds"
    //   "Bytes per second: sent 7612.8, received 8648.9"
    let sentBytes = null, receivedBytes = null;
    let elapsedSec = null, sentBps = null, receivedBps = null;
    let killed = false;
    const killTimer = setTimeout(() => {
      killed = true;
      try { child.kill("SIGKILL"); } catch {}
    }, killTimeoutMs);
    child.stdout.on("data", d => outChunks.push(d));
    child.stderr.on("data", d => {
      errChunks.push(d);
      const text = d.toString("utf8");
      // Parse transfer-summary lines emitted near the end of scp -v.
      const m1 = text.match(/Transferred:\s*sent\s*(\d+),\s*received\s*(\d+)\s*bytes,\s*in\s*([\d.]+)\s*seconds/);
      if (m1) {
        sentBytes = parseInt(m1[1], 10);
        receivedBytes = parseInt(m1[2], 10);
        elapsedSec = parseFloat(m1[3]);
      }
      const m2 = text.match(/Bytes per second:\s*sent\s*([\d.]+),\s*received\s*([\d.]+)/);
      if (m2) {
        sentBps = parseFloat(m2[1]);
        receivedBps = parseFloat(m2[2]);
      }
    });
    child.stdin.end();
    child.on("error", err => {
      clearTimeout(killTimer);
      resolve({
        exitCode: 127, stdout: Buffer.alloc(0), stderr: Buffer.from(String(err?.message ?? err)),
        elapsedMs: Date.now() - t0, sourceSha256: "", destinationSha256: "", truncated: false, args
      });
    });
    child.on("close", async code => {
      clearTimeout(killTimer);
      if (killed) {
        resolve({
          exitCode: 124, stdout: Buffer.concat(outChunks), stderr: Buffer.concat(errChunks),
          elapsedMs: Date.now() - t0, sourceSha256: "", destinationSha256: "", truncated: false, args
        });
        return;
      }
      const outCap = 10 * 1024 * 1024;
      let stdout = Buffer.concat(outChunks);
      let stderr = Buffer.concat(errChunks);
      let truncated = false;
      if (stdout.length > outCap) { stdout = stdout.subarray(0, outCap); truncated = true; }
      if (stderr.length > outCap) { stderr = stderr.subarray(0, outCap); truncated = true; }
      // Compute SHA-256 of source + destination AFTER transfer so the
      // caller can verify integrity. Async fs operations.
      const srcSha = await sha256FileAsync(direction === "upload" ? source : destination);
      const dstSha = await sha256FileAsync(direction === "upload" ? destination : source);
      resolve({
        exitCode: code ?? 0, stdout, stderr,
        elapsedMs: Date.now() - t0,
        sourceSha256: srcSha, destinationSha256: dstSha, truncated,
        sentBytes, receivedBytes, elapsedSec, sentBps, receivedBps, args
      });
    });
  });
}

// Promise-based SHA-256 of a file. Returns "" if the file does not
// exist or cannot be read (e.g. after scp failed mid-transfer).
async function sha256FileAsync(path) {
  try {
    const buf = await _nodeFs.promises.readFile(path);
    return _nodeCrypto.createHash("sha256").update(buf).digest("hex");
  } catch {
    return "";
  }
}

// ---- ssh_edit wrapper with SHA256 unchanged-detection -----------------

// pi-coding-agent's createEditToolDefinition reads, applies edits, writes.
// We compare SHA256 of the post-edit content with the pre-pull SHA256;
// equal -> no push. This requires our own pull/push flow, so we override
// the execute body to do pull -> edit -> sha256-compare -> push.

async function execSshEdit(editBase, pi, target, localCwd, params) {
  // Resolve the remote path: pi-coding-agent's edit expects relative or
  // absolute paths against `localCwd`. Map relative ones against the
  // active remote cwd so the file on the remote is in the expected place.
  let absoluteRemote = params.path;
  if (!_nodePath.isAbsolute(absoluteRemote) && !absoluteRemote.startsWith("~")) {
    absoluteRemote = joinRemote(target.remoteCwd, absoluteRemote);
  } else if (absoluteRemote.startsWith("~/")) {
    throw new Error("ssh_edit does not expand ~ paths. Use a path relative to the SSH working directory instead.");
  }

  // Pull current content.
  let beforeSha = "empty";
  let original = "";
  const sshOpts = { timeoutSeconds: DEFAULT_SSH_TIMEOUT_SECONDS, identityFile: target.identityFile, user: target.user, port: target.port };
  try {
    original = (await sshOk(target.remote, `cat ${shellQuote(absoluteRemote)}`, sshOpts)).toString("utf8");
    beforeSha = _nodeCrypto.createHash("sha256").update(original, "utf8").digest("hex");
  } catch (e) {
    original = "";
    beforeSha = _nodeCrypto.createHash("sha256").update("", "utf8").digest("hex");
  }

  // Apply edits via the edit tool against a virtual local file. Use the
  // standard tool so the same edits[] schema works.
  const tmpFile = _nodePath.join(_nodeOs.tmpdir(), `agent-ssh-tools-edit-${process.pid}-${Date.now()}.txt`);
  _nodeFs.writeFileSync(tmpFile, original);

  const transformedParams = {
    ...params,
    path: tmpFile
  };
  const result = await editBase.execute("local", transformedParams, undefined, undefined, undefined);

  const afterContent = _nodeFs.readFileSync(tmpFile, "utf8");
  const afterSha = _nodeCrypto.createHash("sha256").update(afterContent, "utf8").digest("hex");

  try { _nodeFs.unlinkSync(tmpFile); } catch {}

  if (beforeSha === afterSha) {
    // Unchanged: native edit result with diff empty -> renderer shows no diff.
    // Override `details.path` so the renderer shows the real remote path
    // instead of the local tmp file path used internally.
    const details = { ...(result.details ?? {}), unchanged: true, path: absoluteRemote };
    if (typeof details.diff === "string") {
      // Diff text usually starts with "--- <old>" / "+++ <new>" headers;
      // strip those out so the unchanged block is silent.
      details.diff = "";
    }
    return {
      content: result.content ?? [{ type: "text", text: "" }],
      details
    };
  }

  try {
    await sshOk(target.remote,
      `if [ -L ${shellQuote(absoluteRemote)} ]; then exit 9; fi; exit 0`,
      sshOpts);
  } catch (e) {
    const msg = String((e as any)?.message ?? e);
    if (msg.includes("exit (9)")) {
      try { _nodeFs.unlinkSync(tmpFile); } catch {}
      return {
        content: [{ type: "text", text: `refused: ${absoluteRemote} is a symlink — edit aborted` }],
        details: { unchanged: false, error: "symlink", path: absoluteRemote }
      };
    }
    throw e;
  }
  await sshOk(target.remote, `cat > ${shellQuote(absoluteRemote)}`, {
    timeoutSeconds: DEFAULT_SSH_TIMEOUT_SECONDS,
    stdin: Buffer.from(afterContent, "utf8"),
    identityFile: target.identityFile,
    user: target.user,
    port: target.port
  });

  // Return native edit result so renderer shows the diff against the
  // original content. Override path: details.path and any diff header
  // paths to the real remote path so the user never sees the tmp file.
  const details = { ...(result.details ?? {}), unchanged: false, path: absoluteRemote, bytes: afterContent.length };
  if (typeof details.diff === "string") {
    details.diff = details.diff
      .replace(/^--- .*$/m, `--- ${absoluteRemote}`)
      .replace(/^\+\+\+ .*$/m, `+++ ${absoluteRemote}`);
  }
  return {
    content: result.content ?? [{ type: "text", text: `${afterContent.length} bytes` }],
    details
  };
}

// ---- extension entry --------------------------------------------------

function sshToolsExtension(pi) {
  let activeTarget = null;

  // CLI flag detection. Pi's argv parser rejects unknown flags, so
  // the plugin reads an environment variable that wrappers and test
  // harnesses can set:
  //
  //   SSH_CLI_AUTO_ACTIVATE=1 pi -p "ssh_target_select pve-docker"
  //
  // When set, the SSH tools are auto-enabled at session_start so the
  // agent can use them without the user typing /sshactivate first.
  // Target selection still requires ssh_target_select (probe + verify
  // runs as usual). /sshactivate off explicitly overrides.
  const autoActivateFromCli = (() => {
    try {
      const fromEnv = process.env.SSH_CLI_AUTO_ACTIVATE === "1";
      const fromArgv = Array.isArray(process.argv) && process.argv.includes("--ssh-activate");
      return fromEnv || fromArgv;
    } catch {
      return false;
    }
  })();

  // NOTE: we never pass the local process.cwd() to native tool
  // definitions. The local cwd is irrelevant for remote operations —
  // exposing it would leak where this plugin happens to be installed.
  // Use the remote cwd (or `/`) as the tool's cwd so that any local
  // path that ends up in renderResult is sanitised.
  const REMOTE_NEUTRAL_CWD = "/";
  const readBase  = _piCodingAgent.createReadToolDefinition(REMOTE_NEUTRAL_CWD);
  const writeBase = _piCodingAgent.createWriteToolDefinition(REMOTE_NEUTRAL_CWD);
  const editBase  = _piCodingAgent.createEditToolDefinition(REMOTE_NEUTRAL_CWD);
  const bashBase  = _piCodingAgent.createBashToolDefinition(REMOTE_NEUTRAL_CWD);

  const requireActiveTarget = () => {
    if (!activeTarget) {
      throw new Error("No active SSH target. SSH tools are enabled — call ssh_target_select <host> first.");
    }
    return activeTarget;
  };

  const updateStatus = ctx => {
    if (!activeTarget) {
      ctx.ui.setStatus(SSH_STATUS_KEY, undefined);
      return;
    }
    ctx.ui.setStatus(
      SSH_STATUS_KEY,
      ctx.ui.theme.fg("accent", `SSH ${activeTarget.name}:${activeTarget.remoteCwd}`)
    );
  };

  const enableSshTools = () => {
    const next = new Set(pi.getActiveTools());
    for (const name of SSH_TOOL_NAMES) next.add(name);
    pi.setActiveTools(Array.from(next));
  };
  const disableSshTools = () => {
    pi.setActiveTools(pi.getActiveTools().filter(name => !SSH_TOOL_NAMES.includes(name)));
  };

  // Activate (or fail) a target. Returns a structured result so both the
  // /sshactivate command and the ssh_target_select tool can reuse this.
  const activate = async (profile, ctx) => {
    const reasonText = {
      unreachable: "host unreachable",
      refused: "connection refused",
      auth: "authentication failed",
      timeout: "login timed out",
      "ssh-error": "ssh error",
      "ssh-missing": "ssh binary not found"
    };

    // Resolve identity/user/port from sshConfigAlias once. Passed to all
    // sshExec/sshOk calls so the correct key is used from the start.
    let resolvedIdentityFile, resolvedUser, resolvedPort;
    if (profile.sshConfigAlias) {
      try {
        const r = _nodeChild_process.spawnSync("ssh", ["-G", profile.sshConfigAlias], { encoding: "utf8", timeout: 5000 });
        if (r.status === 0) {
          const lines = r.stdout.split("\n").reduce((acc, l) => {
            const kv = l.trim().split(/\s+/);
            if (kv.length >= 2) acc[kv[0].toLowerCase()] = kv.slice(1).join(" ");
            return acc;
          }, {} as Record<string, string>);
          resolvedUser = lines.user;
          resolvedPort = parseInt(lines.port, 10) || 22;
          resolvedIdentityFile = lines.identityfile;
          if (resolvedIdentityFile?.startsWith("~")) resolvedIdentityFile = _nodeOs.homedir() + resolvedIdentityFile.slice(1);
        }
      } catch {}
    }

    ctx.ui.notify(`[ssh-ts] probe START remote=${profile.remote} alias=${profile.sshConfigAlias || "-"}`, "info");
    if (profile._sshTrace) ctx.ui.notify(profile._sshTrace, "info");
    const probeStart = Date.now();
    const r = await probe(profile.remote, undefined, profile.sshConfigAlias);
    ctx.ui.notify(`[ssh-ts] probe END ${Date.now() - probeStart}ms ok=${r.ok} user=${r.user || "-"} ip=${r.ip || "-"} reason=${r.reason || "-"}`, "info");
    if (!r.ok) {
      const ipSuffix = r.ip && r.ip !== profile.remote ? ` (${r.ip})` : "";
      const msg = `SSH mode NOT activated: ${reasonText[r.reason] || r.reason}${ipSuffix} — ${r.detail}`;
      ctx.ui.notify(msg, "warning");
      return { ok: false, reason: r.reason, detail: r.detail, message: msg };
    }
    ctx.ui.notify(`Auth OK as ${r.user} on ${r.ip || profile.remote}`, "info");

    ctx.ui.notify(`[ssh-ts] cwd START ssh=${profile.remote} cmd=pwd`, "info");
    const cwdStart = Date.now();
    const remoteCwd = await (async () => {
      if (profile.cwd && profile.cwd.trim()) return profile.cwd.trim();
      try {
        return (await sshOk(profile.remote, "pwd", {
          timeoutSeconds: 6,
          identityFile: resolvedIdentityFile,
          user: resolvedUser,
          port: resolvedPort
        })).toString("utf8").trim();
      } catch { return ""; }
    })();
    ctx.ui.notify(`[ssh-ts] cwd END ${Date.now() - cwdStart}ms cwd=${JSON.stringify(remoteCwd)}`, "info");

    activeTarget = {
      name: profile.name,
      remote: profile.remote,
      remoteCwd,
      identityFile: resolvedIdentityFile,
      user: resolvedUser,
      port: resolvedPort
    };
    enableSshTools();
    updateStatus(ctx);
    ctx.ui.notify(`SSH mode on: ${activeTarget.name} (${activeTarget.remoteCwd})`, "info");

    // Print the verify block so the agent/user can sanity-check
    // identity, user, hostname, cwd before the first mutation.
    ctx.ui.notify(`[ssh-ts] verifyBlock START remote=${activeTarget.remote} alias=${profile.sshConfigAlias || "-"}`, "info");
    const verifyStart = Date.now();
    let verifyBlock = "";
    try {
      verifyBlock = await buildVerifyBlock(activeTarget, activeTarget.remoteCwd, undefined, profile.sshConfigAlias);
      ctx.ui.notify(`[ssh-ts] verifyBlock END ${Date.now() - verifyStart}ms len=${verifyBlock.length}`, "info");
      ctx.ui.notify(verifyBlock, "info");
    } catch (e) {
      verifyBlock = `(verify-block failed: ${e.message})`;
      ctx.ui.notify(`[ssh-ts] verifyBlock FAILED ${Date.now() - verifyStart}ms err=${e.message}`, "warning");
      ctx.ui.notify(verifyBlock, "warning");
    }

    return {
      ok: true,
      target: activeTarget,
      verifyBlock,
      message: `target set: ${activeTarget.name} (host=${activeTarget.remote} cwd=${activeTarget.remoteCwd})`
    };
  };

  const deactivate = ctx => {
    activeTarget = null;
    disableSshTools();
    updateStatus(ctx);
    ctx.ui.notify("SSH mode off", "info");
  };

  // ---- tools ----------------------------------------------------------

  // Agent-callable target switch. Same probe + verify as the slash
  // command, but exposed as a tool so the agent can change targets
  // without asking the user. Use this when the user tells you to switch
  // systems, or when you discover mid-task that you are on the wrong host.
  pi.registerTool({
    name: "ssh_target_select",
    label: "ssh_target_select",
    description: "Select an SSH target. Probes the host (TCP + ssh BatchMode whoami) and prints a verify block (user, hostname, cwd, key, date). On failure no state changes; on success the other ssh_* tools become usable.",
    promptSnippet: "Switch the active SSH target with probe + verify",
    promptGuidelines: [
      "Call this whenever you need to operate on a remote host. Read the verify block it returns and confirm hostname / user / key / cwd match the user's intent before running ssh_read / ssh_write / ssh_edit / ssh_bash.",
      "If the tool returns an error (unreachable / refused / auth / timeout), do NOT retry without changing something — the verify result is the truth about the current network/auth state.",
      "The argument accepts aliases, profile names, ssh-config Host blocks, and the inline-cwd syntax 'name:/path'."
    ],
    parameters: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target name or alias. Use 'name:/path' to override the cwd."
        }
      },
      required: ["target"]
    },
    async execute(toolCallId, params, signal, onUpdate, ctx) {
      const arg = (params && params.target || "").trim();
      ctx.ui.notify(`[ssh-ts] enter arg=${JSON.stringify(arg)}`, "info");
      if (!arg) {
        ctx.ui.notify(`[ssh-ts] missing target arg`, "warning");
        return {
          content: [{ type: "text", text: "ssh_target_select: missing 'target' argument" }],
          details: { ok: false, reason: "bad-args" }
        };
      }

      ctx.ui.notify(`[ssh-ts] normalizing...`, "info");
      const profile = normalizeTargetArg(arg);
      ctx.ui.notify(`[ssh-ts] normalized name=${profile.name} remote=${profile.remote} alias=${profile.sshConfigAlias || "-"} untrusted=${!!profile.untrusted}`, "info");
      if (!profile.remote) {
        return {
          content: [{ type: "text", text: `ssh_target_select: ${profile.error || "cannot resolve target"}` }],
          details: { ok: false, reason: "bad-args", error: profile.error }
        };
      }
      if (profile.untrusted) {
        // Name did not match profiles, aliases, or ~/.ssh/config.
        // Refuse to probe — a mistyped name like "current" must not
        // result in a connection attempt to an arbitrary host.
        const msg = profile.error
          || `target '${arg}' not found in profiles, aliases, or ~/.ssh/config`;
        ctx.ui.notify(`ssh_target_select: ${msg}`, "warning");
        return {
          content: [{ type: "text", text: `ssh_target_select: ${msg}\n\nAvailable targets: ${sshCliAvailableTargets()}` }],
          details: { ok: false, reason: "unknown-target", error: msg }
        };
      }

      // activate() handles probe + state + verify + UI notifications.
      // We just translate its structured result into the tool response.
      const r = await activate(profile, ctx);
      if (!r.ok) {
        return {
          content: [{ type: "text", text: r.message }],
          details: { ok: false, reason: r.reason, detail: r.detail }
        };
      }
      return {
        content: [{ type: "text", text: `${r.message}\n${r.verifyBlock}` }],
        details: { ok: true, target: r.target }
      };
    },
    renderCall(args, theme) {
      const t = typeof args?.target === "string" ? args.target : "...";
      return new _piTui.Text(
        `${theme.fg("toolTitle", theme.bold("ssh_target_select"))} ${theme.fg("accent", t)}`,
        0, 0
      );
    },
    renderResult: readBase.renderResult
  });

  pi.registerTool({
    name: "ssh_read",
    label: "ssh_read",
    description: "Read a file on the active SSH host. Relative paths are resolved against the active remote working directory.",
    promptSnippet: "Read file contents on the active SSH host",
    promptGuidelines: ["Use ssh_read when the task is on the active SSH host instead of the local machine."],
    parameters: readBase.parameters,
    async execute(toolCallId, params, signal, onUpdate, ctx) {
      const target = requireActiveTarget();
      const abs = _nodePath.isAbsolute(params.path)
        ? params.path
        : joinRemote(target.remoteCwd, params.path);
      const t0 = Date.now();
      const tool = _piCodingAgent.createReadToolDefinition(target.remoteCwd, { operations: createRemoteReadOps(target) });
      const transformed = { ...params, path: abs };
      const result = await tool.execute(toolCallId, transformed, signal, onUpdate, ctx);
      ctx.ui.notify(`$ ssh ${target.remote} read ${abs}  ${Date.now() - t0}ms`, "info");
      return result;
    },
    renderCall(args, theme) {
      const path = typeof args?.path === "string" ? args.path : "...";
      const targetLabel = activeTarget ? activeTarget.name : "inactive";
      return new _piTui.Text(
        `${theme.fg("toolTitle", theme.bold("ssh_read"))} ${theme.fg("accent", path)} ${theme.fg("muted", `[${targetLabel}]`)}`,
        0, 0
      );
    },
    renderResult: readBase.renderResult
  });

  pi.registerTool({
    name: "ssh_write",
    label: "ssh_write",
    description: "Write a text file on the active SSH host. Relative paths are resolved against the active remote working directory.",
    promptSnippet: "Create or overwrite files on the active SSH host",
    promptGuidelines: ["Use ssh_write only for new files or full rewrites on the active SSH host."],
    parameters: writeBase.parameters,
    async execute(toolCallId, params, signal, onUpdate, ctx) {
      const target = requireActiveTarget();
      const abs = _nodePath.isAbsolute(params.path)
        ? params.path
        : joinRemote(target.remoteCwd, params.path);
      const t0 = Date.now();
      const content = typeof params.content === "string" ? params.content : "";
      const size = Buffer.byteLength(content, "utf8");
      if (size > 64 * 1024) {
        ctx.ui.notify(`writing ${(size / 1024).toFixed(1)} KB to ${target.remote}:${abs}...`, "info");
      }
      const tool = _piCodingAgent.createWriteToolDefinition(target.remoteCwd, { operations: createRemoteWriteOps(target) });
      const transformed = { ...params, path: abs };
      const result = await tool.execute(toolCallId, transformed, signal, onUpdate, ctx);
      ctx.ui.notify(`$ ssh ${target.remote} write ${abs}  ${Date.now() - t0}ms`, "info");
      return result;
    },
    renderCall(args, theme) {
      const path = typeof args?.path === "string" ? args.path : "...";
      const targetLabel = activeTarget ? activeTarget.name : "inactive";
      return new _piTui.Text(
        `${theme.fg("toolTitle", theme.bold("ssh_write"))} ${theme.fg("accent", path)} ${theme.fg("muted", `[${targetLabel}]`)}`,
        0, 0
      );
    },
    renderResult: writeBase.renderResult
  });

  pi.registerTool({
    name: "ssh_edit",
    label: "ssh_edit",
    description: "Edit a file on the active SSH host using exact text replacement. Relative paths are resolved against the active remote working directory. The file is skipped if the post-edit content matches the pre-pull content (SHA-256).",
    promptSnippet: "Make precise file edits on the active SSH host",
    promptGuidelines: [
      "Use ssh_edit for precise remote changes.",
      "Each edits[].oldText must match exactly on the remote file.",
      "The push is skipped automatically when the edit produced no change."
    ],
    parameters: editBase.parameters,
    prepareArguments: editBase.prepareArguments,
    async execute(toolCallId, params, signal, onUpdate, ctx) {
      const target = requireActiveTarget();
      const t0 = Date.now();
      ctx.ui.notify(`editing ${target.remote}:${params.path}...`, "info");
      const result = await execSshEdit(editBase, pi, target, process.cwd(), params);
      const details = (result.details ?? {}) as { unchanged?: boolean; path?: string; bytes?: number };
      if (details.unchanged) {
        ctx.ui.notify(`edit ${details.path} — no changes (skipped push)`, "info");
      } else {
        ctx.ui.notify(`$ ssh ${target.remote} edit ${details.path ?? params.path}  ${Date.now() - t0}ms  ${details.bytes ?? "?"}B`, "info");
      }
      return result;
    },
    renderCall(args, theme) {
      const path = typeof args?.path === "string" ? args.path : "...";
      const targetLabel = activeTarget ? activeTarget.name : "inactive";
      return new _piTui.Text(
        `${theme.fg("toolTitle", theme.bold("ssh_edit"))} ${theme.fg("accent", path)} ${theme.fg("muted", `[${targetLabel}]`)}`,
        0, 0
      );
    },
    renderResult(result, _options, theme) {
      // Custom renderer: never expose the internal tmp file path. The
      // native edit renderer reads `context.args.path` and would show
      // `/tmp/agent-ssh-tools-edit-<pid>-<ts>.txt` even though the edit
      // actually landed on the real target file. We render only the
      // remote path + diff body, never the local tmp path.
      const details = (result?.details ?? {}) as { path?: string; diff?: string; unchanged?: boolean };
      const remotePath = details.path ?? "(unknown)";
      const diffText = details.diff ?? "";
      if (details.unchanged || !diffText.trim()) {
        return new _piTui.Text(
          `${theme.fg("muted", "(no changes)")}\n${theme.fg("muted", remotePath)}`,
          0, 0
        );
      }
      // Strip the diff's --- /+++ file header lines that would leak
      // the local tmp path. Then render with the remote path as a
      // visible header.
      const cleanDiff = diffText
        .replace(/^--- .*$/m, "")
        .replace(/^\+\+\+ .*$/m, "")
        .replace(/^\n+/, "");
      const header = `${theme.fg("accent", remotePath)}\n`;
      return new _piTui.Text(`${header}${cleanDiff}`, 0, 0);
    }
  });

  pi.registerTool({
    name: "ssh_bash",
    label: "ssh_bash",
    description: "Execute a bash command on the active SSH host in the active remote working directory.",
    promptSnippet: "Execute bash commands on the active SSH host",
    promptGuidelines: ["Use ssh_bash when the command must run on the active SSH host rather than locally."],
    parameters: bashBase.parameters,
    async execute(toolCallId, params, signal, onUpdate, ctx) {
      const target = requireActiveTarget();
      const cwd = target.remoteCwd;
      const cmd = params.command;
      const fullCmd = cwd ? `cd ${shellQuote(cwd)} && ${cmd}` : cmd;
      const t0 = Date.now();
      // Forward onUpdate so the tool result streams live. sshExec routes
      // it through a 150ms-throttler with a 64KB visible-buffer cap so
      // commands like `docker compose up` (thousands of layer-pull lines)
      // don't flood the TUI. The final result.content below still holds
      // the full output — the throttler only feeds intermediate updates.
      const r = await sshExecVerbose(target.remote, fullCmd, {
        timeoutSeconds: params.timeout ?? 60,
        onUpdate,
        identityFile: target.identityFile,
        user: target.user,
        port: target.port
      });
      const elapsed = Date.now() - t0;
      // Audit log: append-only file with command + target + result. Lets
      // the user audit destructive remote commands after the fact. Path:
      // ~/.config/agent-ssh-tools/audit.log (atomic append via O_APPEND).
      try {
        const auditPath = _nodePath.join(_nodeOs.homedir(), ".config", "agent-ssh-tools", "audit.log");
        _nodeFs.mkdirSync(_nodePath.dirname(auditPath), { recursive: true });
        const stdoutHash = _nodeCrypto.createHash("sha256").update(r.stdout).digest("hex").slice(0, 12);
        const stderrHash = _nodeCrypto.createHash("sha256").update(r.stderr).digest("hex").slice(0, 12);
        const line = [
          new Date().toISOString(),
          target.name,
          target.remote,
          cwd || "/",
          `exit=${r.exit}`,
          `${elapsed}ms`,
          `out=${stdoutHash}`,
          `err=${stderrHash}`,
          JSON.stringify(cmd)
        ].join("\t") + "\n";
        _nodeFs.appendFileSync(auditPath, line, { flag: "a" });
      } catch (e) {
        // Audit failures must not break tool execution.
        ctx?.ui?.notify?.(`audit log write failed: ${(e as any)?.message ?? e}`, "warning");
      }
      // Output only — the renderResult composes the verbose header.
      const parts: string[] = [];
      if (r.stdout.length) parts.push(r.stdout.toString("utf8").trimEnd());
      if (r.stderr.length && r.exit !== 0) parts.push(`[stderr]\n${r.stderr.toString("utf8").trimEnd()}`);
      if (r.truncated) parts.push(`[output truncated — exceeds 10MB cap]`);
      return {
        content: [{ type: "text", text: parts.join("\n\n") }],
        details: {
          exit: r.exit,
          elapsedMs: elapsed,
          cwd,
          host: target.remote,
          cmd,
          truncated: r.truncated
        }
      };
    },
    renderCall(args, theme, context) {
      const command = typeof args?.command === "string" ? args.command : "...";
      const targetLabel = activeTarget ? activeTarget.name : "inactive";
      const text = context.lastComponent ?? new _piTui.Text("", 0, 0);
      text.setText(
        `${theme.fg("toolTitle", theme.bold("ssh_bash"))} ${theme.fg("accent", command)} ${theme.fg("muted", `[${targetLabel}]`)}`
      );
      return text;
    },
    renderResult(result, _options, theme) {
      const details = (result?.details ?? {}) as { cwd?: string; host?: string; exit?: number; elapsedMs?: number };
      const host = details.host ?? "?";
      const cwd = details.cwd ?? "";
      const exit = details.exit ?? 0;
      const ms = details.elapsedMs ?? 0;
      const exitLabel = exit === 0 ? theme.fg("success", "ok") : theme.fg("error", `exit ${exit}`);
      const header = theme.fg("muted", `$ ssh ${host}  cwd=${cwd || "/"}  ${exitLabel}  ${ms}ms`);
      const stdout = (result?.content ?? [])
        .map((c: any) => (c.type === "text" ? c.text : ""))
        .join("\n");
      // stdout already contains the command text + output. Trim the
      // duplicated first line if it duplicates the host line.
      const body = stdout.trim();
      return new _piTui.Text(`${header}\n${body}`, 0, 0);
    }
  });

  // ---- ssh_scp (file transfer) --------------------------------------

  pi.registerTool({
    name: "ssh_scp",
    label: "ssh_scp",
    description: "Transfer files between the local machine and the active SSH host via scp. Use direction='upload' to send local->remote, or 'download' for remote->local. Set recursive=true for directories. The target param is optional — defaults to the currently-active ssh target.",
    promptSnippet: "Transfer files between local and active remote host",
    promptGuidelines: [
      "Use ssh_scp when the user wants to move a file/directory between this machine and the active SSH host.",
      "Prefer ssh_scp over ssh_bash 'cat < local | ssh remote cat >' pipelines — scp handles binary data, permissions, partial failures.",
      "Direction accepts aliases: upload/push/send/to  → local→remote; download/pull/get/fetch/from → remote→local.",
      "Target param is optional — omit it to use the currently-active target.",
      "Source/destination paths must NOT contain newlines or shell metacharacters (whitelisted).",
      "After transfer, check details.sha256_match to confirm integrity."
    ],
    parameters: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "SSH target name (profile/alias/ssh-config host). Optional — defaults to active target."
        },
        direction: {
          type: "string",
          description: "'upload'/'push'/'send'/'to' = local source → remote destination. 'download'/'pull'/'get'/'fetch'/'from' = remote source → local destination. Defaults to 'upload' if source is local and destination is remote (heuristic).",
          default: "upload"
        },
        source: {
          type: "string",
          description: "Source path (local for upload, remote for download)"
        },
        destination: {
          type: "string",
          description: "Destination path (remote for upload, local for download)"
        },
        recursive: {
          type: "boolean",
          description: "Set true to transfer directories (scp -r)",
          default: false
        },
        timeoutSeconds: {
          type: "number",
          description: "Override scp kill timeout in seconds (default 600). Set higher for very large files."
        }
      },
      required: ["source", "destination"]
    },
    async execute(toolCallId, params, signal, onUpdate, ctx) {
      const target = requireActiveTarget();
      // Resolve target: explicit param overrides; otherwise use active target.
      const requestedTarget = params.target || target.name;
      if (params.target && params.target !== target.name) {
        ctx.ui.notify(
          `ssh_scp: target arg '${params.target}' != active target '${target.name}'. ` +
          `Use ssh_target_select to switch. Aborting.`,
          "warning"
        );
        return {
          content: [{ type: "text", text: `target mismatch: requested '${params.target}', active '${target.name}'` }],
          details: { ok: false, error: "target-mismatch" }
        };
      }
      // Normalize direction aliases: upload/push/send/to ↔ download/pull/get/fetch/from
      const dirRaw = String(params.direction || "upload").toLowerCase().trim();
      const dirMap: Record<string, string> = {
        "upload": "upload", "push": "upload", "send": "upload", "to": "upload", "up": "upload",
        "download": "download", "pull": "download", "get": "download", "fetch": "download",
        "from": "download", "down": "download"
      };
      const direction = dirMap[dirRaw];
      if (!direction) {
        return {
          content: [{ type: "text", text:
            `ssh_scp: invalid direction '${params.direction}'. Use 'upload' or 'download' ` +
            `(aliases: push/send/to ↔ pull/get/fetch/from).` }],
          details: { ok: false, error: "invalid-direction" }
        };
      }
      // Heuristic default: if direction arg is omitted but paths look like
      // local→remote, infer upload. Detection: source exists on local fs.
      // This never overrides an explicit direction.
      // (Heuristic intentionally skipped — explicit > smart. User can pass 'upload' or 'download'.)
      // Whitelist remote paths (local paths must also be safe — we never
      // want to pass them through a shell that could be hijacked).
      const sourceSafe = isSafeTargetString(params.source);
      const destSafe = isSafeTargetString(params.destination);
      if (!sourceSafe || !destSafe) {
        ctx.ui.notify(
          `ssh_scp: source or destination contains unsafe characters ` +
          `(allowed: A-Z a-z 0-9 . _ @ - / :)`,
          "warning"
        );
        return {
          content: [{ type: "text", text: `unsafe path characters` }],
          details: { ok: false, error: "unsafe-path" }
        };
      }
      // For upload: confirm source exists locally before invoking scp
      // (scp's error message 'No such file or directory' without the
      // filename is ambiguous and hard to debug).
      if (direction === "upload") {
        try {
          const st = _nodeFs.statSync(params.source);
          if (!st.isFile() && !st.isDirectory()) {
            return {
              content: [{ type: "text", text:
                `ssh_scp: source '${params.source}' is not a regular file or directory` }],
              details: { ok: false, error: "source-not-file" }
            };
          }
          // If local source is a directory, recursive must be true.
          if (st.isDirectory() && !params.recursive) {
            ctx.ui.notify(`ssh_scp: source is a directory — auto-setting recursive=true`, "info");
            params = { ...params, recursive: true };
          }
        } catch (e: any) {
          return {
            content: [{ type: "text", text:
              `ssh_scp: local source not found: ${params.source} (${e?.code ?? e?.message ?? e})` }],
            details: { ok: false, error: "source-missing", source: params.source }
          };
        }
      }
      const t0 = Date.now();
      let r;
      try {
        r = await scpTransfer(
          target, params.direction, params.source, params.destination, !!params.recursive, params.timeoutSeconds
        );
      } catch (e: any) {
        return {
          content: [{ type: "text", text: String(e?.message ?? e) }],
          details: { ok: false, error: "scp-failed" }
        };
      }
      // Verify hashes: src and dst should match for regular files
      const sha256Match = r.sourceSha256 && r.destinationSha256 && r.sourceSha256 === r.destinationSha256;
      // Audit log
      try {
        const auditPath = _nodePath.join(_nodeOs.homedir(), ".config", "agent-ssh-tools", "audit.log");
        _nodeFs.mkdirSync(_nodePath.dirname(auditPath), { recursive: true });
        const line = [
          new Date().toISOString(),
          "scp",
          target.name,
          target.remote,
          params.direction,
          `exit=${r.exitCode}`,
          `${r.elapsedMs}ms`,
          `src=${r.sourceSha256}`,
          `dst=${r.destinationSha256}`,
          `match=${sha256Match ? "yes" : "no"}`,
          JSON.stringify(params.source),
          "->",
          JSON.stringify(params.destination)
        ].join("\t") + "\n";
        _nodeFs.appendFileSync(auditPath, line, { flag: "a" });
      } catch { /* audit failures must not break tool */ }
      const parts = [];
      // Surface the actual scp command in the result so debugging is
      // trivial: copy-paste the scp line and it works.
      parts.push(`$ scp ${r.args.join(" ")}`);
      if (r.exitCode !== 0) {
        parts.push(`[scp ${direction} failed exit=${r.exitCode}]`);
        // scp emits diagnostics on stderr ('debug1: ...', 'scp: No such
        // file...'). Always surface stderr in failure cases so the agent
        // sees the actual error instead of a generic exit-code message.
        if (r.stderr.length) {
          const stderrText = r.stderr.toString("utf8").trimEnd();
          // Keep stderr to last ~4KB to avoid flooding output
          const tail = stderrText.length > 4096
            ? "…\n" + stderrText.slice(stderrText.length - 4096)
            : stderrText;
          parts.push(tail);
        }
      } else {
        parts.push(`scp ${params.direction} ok  ${r.elapsedMs}ms`);
        // Speed/progress from scp -v summary line. Falls back gracefully
        // if scp didn't emit the line (older versions or no -v flag).
        if (r.sentBytes !== null && r.receivedBytes !== null) {
          parts.push(`bytes  sent=${r.sentBytes}  received=${r.receivedBytes}`);
        }
        if (r.sentBps !== null && r.receivedBps !== null) {
          parts.push(`speed  sent=${r.sentBps.toFixed(0)}B/s  received=${r.receivedBps.toFixed(0)}B/s`);
        }
        if (r.elapsedSec !== null) {
          parts.push(`time   ${r.elapsedSec.toFixed(2)}s`);
        }
        if (r.sourceSha256 && r.destinationSha256) {
          parts.push(`sha256  src=${r.sourceSha256.slice(0,12)}  dst=${r.destinationSha256.slice(0,12)}  ${sha256Match ? "MATCH" : "MISMATCH"}`);
        }
        if (r.truncated) parts.push(`[output truncated — exceeds 10MB cap]`);
      }
      return {
        content: [{ type: "text", text: parts.join("\n") }],
        details: {
          ok: r.exitCode === 0,
          direction: params.direction,
          source: params.source,
          destination: params.destination,
          host: target.remote,
          elapsed_ms: r.elapsedMs,
          sent_bytes: r.sentBytes,
          received_bytes: r.receivedBytes,
          sent_bps: r.sentBps,
          received_bps: r.receivedBps,
          transfer_time_seconds: r.elapsedSec,
          sha256_match: sha256Match,
          sha256_source: r.sourceSha256,
          sha256_destination: r.destinationSha256
        }
      };
    },
    renderCall(args, theme) {
      const dir = typeof args?.direction === "string" ? args.direction : "?";
      const src = typeof args?.source === "string" ? args.source : "...";
      const dst = typeof args?.destination === "string" ? args.destination : "...";
      const targetLabel = activeTarget ? activeTarget.name : "inactive";
      return new _piTui.Text(
        `${theme.fg("toolTitle", theme.bold("ssh_scp"))} ${theme.fg("accent", dir)} ${theme.fg("muted", `${src} -> ${dst} [${targetLabel}]`)}`,
        0, 0
      );
    },
    renderResult(result, _options, theme) {
      const text = result?.content?.[0]?.text ?? "";
      return new _piTui.Text(text, 0, 0);
    }
  });

  // ---- /sshactivate command -------------------------------------------

  // The slash command is the user's grant of permission for the agent to
  // perform remote operations. It does NOT select a target — that is the
  // agent's job via `ssh_target_select` (which probes + verifies before
  // committing). With no argument the command only enables the ssh_*
  // tools; with a target argument it is a convenience shortcut that
  // enables tools AND sets the target (equivalent to /sshactivate +
  // ssh_target_select).

  pi.registerCommand("sshactivate", {
    description: "Enable SSH tools (no target preselected): /sshactivate, /sshactivate <host>[:/path], /sshactivate off, /sshactivate status",
    getArgumentCompletions: prefix => {
      const { merged } = refreshProfiles();
      const options = ["off", "status", ...merged.map(p => p.name)];
      const filtered = options.filter(o => o.startsWith(prefix));
      return filtered.length > 0 ? filtered.map(o => ({ value: o, label: o })) : null;
    },
    handler: async (args, ctx) => {
      const input = args.trim();

      if (input === "status") {
        // Show all three states clearly: off / enabled-no-target / active
        const sshToolsActive = (pi.getActiveTools() || []).includes(SSH_TOOL_NAMES[0]);
        if (activeTarget) {
          ctx.ui.notify(
            `SSH: ACTIVE  target=${activeTarget.name}  remote=${activeTarget.remote}  cwd=${activeTarget.remoteCwd}  tools=on`,
            "info"
          );
        } else if (sshToolsActive) {
          ctx.ui.notify(
            "SSH: tools enabled, no target selected — call ssh_target_select <host>",
            "info"
          );
        } else {
          ctx.ui.notify(
            "SSH: off — run /sshactivate to enable tools, /sshactivate <host> for one-shot",
            "info"
          );
        }
        return;
      }

      if (input === "off") {
        if (!activeTarget) {
          ctx.ui.notify("SSH already off (no target was active)", "info");
          return;
        }
        const prev = activeTarget.name;
        deactivate(ctx);
        ctx.ui.notify(`SSH mode off (was: ${prev}). Reload picks it up again or use /sshactivate.`, "info");
        return;
      }

      // Convenience form: /sshactivate <host> enables tools AND sets the
      // target in one step (probe + verify runs as part of activate).
      // Equivalent to bare /sshactivate followed by ssh_target_select.
      if (input) {
        const profile = normalizeTargetArg(input);
        if (profile.untrusted) {
          ctx.ui.notify(`sshactivate: ${profile.error}\nAvailable: ${sshCliAvailableTargets()}`, "warning");
          return;
        }
        await activate(profile, ctx);
        return;
      }

      // Default form: /sshactivate with no argument enables the ssh_*
      // tools so the agent can call ssh_target_select to pick the host.
      // No probe runs — the agent chooses the target.
      enableSshTools();
      ctx.ui.setStatus(SSH_STATUS_KEY, ctx.ui.theme.fg("muted", "SSH (no target — agent picks)"));
      ctx.ui.notify("SSH tools enabled. The agent will pick the target via ssh_target_select.", "info");
    }
  });

  // ---- lifecycle -------------------------------------------------------

  pi.on("session_start", async (_event, ctx) => {
    activeTarget = null;
    if (autoActivateFromCli) {
      // CLI auto-activation: keep tools enabled across sessions. Status
      // marks this so the user can see why the tools are on without
      // having typed /sshactivate.
      enableSshTools();
      ctx.ui.setStatus(
        SSH_STATUS_KEY,
        ctx.ui.theme.fg("accent", "SSH (auto via SSH_CLI_AUTO_ACTIVATE=1)")
      );
      ctx.ui.notify(
        "SSH tools auto-enabled via SSH_CLI_AUTO_ACTIVATE=1. Call ssh_target_select <host> to pick a target.",
        "info"
      );
    } else {
      disableSshTools();
      ctx.ui.setStatus(SSH_STATUS_KEY, undefined);
    }
  });

  pi.on("before_agent_start", async event => {
    if (!activeTarget) return;
    return {
      systemPrompt: event.systemPrompt +
        `\n\nSSH mode is active for this turn.\n` +
        `Remote host: ${activeTarget.remote}\n` +
        `Remote working directory: ${activeTarget.remoteCwd}\n` +
        `Use ssh_read, ssh_write, ssh_edit, and ssh_bash for remote work. ` +
        `Local read/write/edit/bash still operate on the local machine.\n` +
        `Relative paths in ssh_* tools resolve against the remote working directory, ` +
        `not the local one. Before any mutation, re-read the verify-block posted ` +
        `by /ssh and confirm hostname / user / key match expectations.`
    };
  });
}

export default sshToolsExtension;

/* agent-ssh-tools v0.5.0 */