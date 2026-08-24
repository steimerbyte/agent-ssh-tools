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
const SSH_TOOL_NAMES = ["ssh_target_select", "ssh_read", "ssh_write", "ssh_edit", "ssh_bash"];
const SSH_CONFIG_PATH = _nodePath.join(_nodeOs.homedir(), ".ssh", "config");
const PROFILES_FILE = _nodePath.join(_nodeOs.homedir(), ".config", "agent-ssh-tools", "profiles.json");
const DEFAULT_PROBE_SECONDS = 6;
const DEFAULT_SSH_TIMEOUT_SECONDS = 30;

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

function parseSshConfigProfiles() {
  if (!_nodeFs.existsSync(SSH_CONFIG_PATH)) return [];
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
  return Array.from(profiles.values()).sort((a, b) => a.name.localeCompare(b.name));
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
//   4. raw arg as fallback
// Inline ":path" syntax sets an inline cwd that always wins.
function normalizeTargetArg(arg) {
  const trimmed = (arg || "").trim();
  if (!trimmed) return { name: "", remote: "", cwd: undefined };

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

  // ssh-config match wins over same-name profile (Host block is the
  // canonical source for host/port/identity), but cwd from profile is
  // ignored when inline cwd is given.
  const sshCfg = parseSshConfigProfiles().find(p => p.name === resolved);

  const prof = profiles[resolved];
  let remote, cwd;
  if (sshCfg) {
    remote = sshCfg.remote;
    cwd    = inlineCwd || (prof ? prof.cwd : undefined);
  } else if (prof) {
    remote = prof.host || resolved;
    cwd    = inlineCwd || prof.cwd;
  } else {
    remote = resolved;
    cwd    = inlineCwd;
  }

  return { name: resolved, remote, cwd };
}

// ---- ssh wrappers -----------------------------------------------------

function sshExec(remote, command, options = {}) {
  return new Promise((resolve, reject) => {
    const args = [];
    if (typeof options.timeoutSeconds === "number" && options.timeoutSeconds > 0) {
      args.push("-o", `ConnectTimeout=${options.timeoutSeconds}`);
    }
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

    child.stdout.on("data", d => { stdoutChunks.push(d); options.onStdoutData?.(d); });
    child.stderr.on("data", d => { stderrChunks.push(d); options.onStderrData?.(d); });
    child.on("error", err => {
      if (killTimer) clearTimeout(killTimer);
      reject(err);
    });
    child.on("close", exitCode => {
      if (killTimer) clearTimeout(killTimer);
      if (killed) {
        reject(new Error(`timeout:${options.timeoutSeconds}`));
        return;
      }
      resolve({
        stdout: Buffer.concat(stdoutChunks),
        stderr: Buffer.concat(stderrChunks),
        exitCode
      });
    });
  });
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
async function probe(remote, seconds = DEFAULT_PROBE_SECONDS) {
  // DNS lookup for error messages (best-effort, may throw).
  let ip = remote;
  try { ip = (await _nodeDns.promises.lookup(remote)).address; } catch {}

  // Step 1: TCP connect on :22.
  const portOk = await new Promise(resolve => {
    const sock = _nodeNet.createConnection({ host: ip, port: 22, family: 4 });
    let done = false;
    const finish = v => { if (!done) { done = true; resolve(v); } };
    sock.setTimeout(seconds * 1000);
    sock.once("connect", () => { sock.destroy(); finish(true); });
    sock.once("timeout", () => { sock.destroy(); finish("timeout"); });
    sock.once("error", e => finish(e.code || "error"));
  });
  if (portOk !== true) {
    const reason = portOk === "timeout" || /timeout/i.test(String(portOk))
      ? "unreachable" : "unreachable";
    const detail = portOk === "timeout"
      ? `no TCP response on ${ip}:22 within ${seconds}s`
      : `TCP connect to ${ip}:22 failed: ${portOk}`;
    return { ok: false, reason, detail, ip };
  }

  // Step 2: ssh whoami to confirm banner + auth.
  const args = [
    "-o", `ConnectTimeout=${seconds}`,
    "-o", "BatchMode=yes",
    "-o", "PreferredAuthentications=publickey",
    remote, "whoami"
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

async function buildVerifyBlock(remote, cwd, seconds = 6) {
  const idFile = identityFileFor(remote);
  const fp     = fingerprintFor(idFile);
  const t      = seconds;
  const [u, hn, dt] = await Promise.all([
    sshExec(remote, "whoami",         { timeoutSeconds: t }).catch(e => ({ stdout: Buffer.from(`<error:${e.message}>`), stderr: Buffer.alloc(0), exitCode: -1 })),
    sshExec(remote, "hostname",       { timeoutSeconds: t }).catch(e => ({ stdout: Buffer.from(`<error:${e.message}>`), stderr: Buffer.alloc(0), exitCode: -1 })),
    sshExec(remote, "date -u +%Y-%m-%dT%H:%M:%SZ", { timeoutSeconds: t }).catch(e => ({ stdout: Buffer.from(`<error:${e.message}>`), stderr: Buffer.alloc(0), exitCode: -1 }))
  ]);
  const user     = u.stdout.toString("utf8").trim();
  const hostname = hn.stdout.toString("utf8").trim();
  const date     = dt.stdout.toString("utf8").trim();
  const lines = [
    "verify:",
    `  user:     ${user}`,
    `  hostname: ${hostname}`,
    `  cwd:      ${cwd || "(remote default ~)"}`,
    `  key:      ${fp || "(no identity file)"}${idFile ? `  (${idFile})` : ""}`,
    `  date:     ${date}`
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
    readFile: (absolutePath) => sshOk(target.remote, `cat ${shellQuote(absolutePath)}`, { timeoutSeconds: DEFAULT_SSH_TIMEOUT_SECONDS }),
    access:   (absolutePath) => sshOk(target.remote, `test -r ${shellQuote(absolutePath)}`, { timeoutSeconds: DEFAULT_SSH_TIMEOUT_SECONDS }).then(() => {}),
    detectImageMimeType: async (absolutePath) => inferImageMimeType(absolutePath)
  };
}

function createRemoteWriteOps(target) {
  return {
    writeFile: async (absolutePath, content) => {
      await sshOk(target.remote, `cat > ${shellQuote(absolutePath)}`, {
        timeoutSeconds: DEFAULT_SSH_TIMEOUT_SECONDS,
        stdin: content
      });
    },
    mkdir: (dir) => sshOk(target.remote, `mkdir -p ${shellQuote(dir)}`, { timeoutSeconds: DEFAULT_SSH_TIMEOUT_SECONDS }).then(() => {})
  };
}

// ssh_edit: pre/post SHA256 comparison to skip push if unchanged.
// We compare the local buffer (after edit) with what we pulled; if equal,
// no ssh push is needed.
function createRemoteEditOps(target, localCwd) {
  const remotePath = path => {
    // If absolute, treat as already-on-remote.
    if (_nodePath.isAbsolute(path)) return path;
    // Otherwise resolve relative to the local cwd used for the edit workspace
    // and then map to remote cwd via joinRemote. The pi-coding-agent's edit
    // tool runs with localCwd, so any relative path it gives is relative to
    // that. Mapping preserves intent.
    const relative = _nodePath.relative(localCwd, path).split(_nodePath.sep).join("/");
    if (relative.startsWith("../") || relative === "..") {
      throw new Error(`Resolved edit path ${path} escaped the local SSH edit workspace.`);
    }
    if (!relative || relative === ".") return target.remoteCwd;
    return joinRemote(target.remoteCwd, relative);
  };

  return {
    readFile: (absolutePath) => sshOk(target.remote, `cat ${shellQuote(remotePath(absolutePath))}`, { timeoutSeconds: DEFAULT_SSH_TIMEOUT_SECONDS }),
    writeFile: async (absolutePath, content) => {
      await sshOk(target.remote, `cat > ${shellQuote(remotePath(absolutePath))}`, {
        timeoutSeconds: DEFAULT_SSH_TIMEOUT_SECONDS,
        stdin: content
      });
    },
    access: (absolutePath) => {
      const p = remotePath(absolutePath);
      return sshOk(target.remote, `test -r ${shellQuote(p)} && test -w ${shellQuote(p)}`, { timeoutSeconds: DEFAULT_SSH_TIMEOUT_SECONDS }).then(() => {});
    }
  };
}

function createRemoteBashOps(target) {
  return {
    exec: async (command, cwd, { onData, signal, timeout }) => {
      const script = `cd ${shellQuote(cwd || target.remoteCwd)}\n${command}\n`;
      const { exitCode } = await sshExec(target.remote, "exec bash -se", {
        stdin: script,
        timeoutSeconds: timeout,
        onStdoutData: onData,
        onStderrData: onData
      });
      return { exitCode };
    }
  };
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
  try {
    original = (await sshOk(target.remote, `cat ${shellQuote(absoluteRemote)}`, { timeoutSeconds: DEFAULT_SSH_TIMEOUT_SECONDS })).toString("utf8");
    beforeSha = _nodeCrypto.createHash("sha256").update(original, "utf8").digest("hex");
  } catch (e) {
    // Missing file -> start with blank content (sha256 of empty string).
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
    return {
      content: [{ type: "text", text: `No changes — ${absoluteRemote} was already up to date.` }],
      details: { unchanged: true }
    };
  }

  // Push via the same ssh transport.
  await sshOk(target.remote, `cat > ${shellQuote(absoluteRemote)}`, {
    timeoutSeconds: DEFAULT_SSH_TIMEOUT_SECONDS,
    stdin: Buffer.from(afterContent, "utf8")
  });

  return {
    content: [{ type: "text", text: `pushed ${absoluteRemote} (${afterContent.length} bytes)` }],
    details: { unchanged: false, bytes: afterContent.length }
  };
}

// ---- extension entry --------------------------------------------------

function sshToolsExtension(pi) {
  let activeTarget = null;

  // CLI flag detection. When the user invokes `pi -p "..." --ssh-activate`
  // (or any other pi command with this flag), the SSH tools are enabled
  // automatically at session_start so the agent can use them without
  // the user having to type /sshactivate first. Useful for automated
  // test runs and agent harnesses that already know the target.
  //
  // Note: this only enables the tools. Target selection still happens
  // via ssh_target_select — the agent must pick the host explicitly
  // so the verify-block runs and the connection is probed.
  const autoActivateFromCli = (() => {
    try {
      return Array.isArray(process.argv) && process.argv.includes("--ssh-activate");
    } catch {
      return false;
    }
  })();

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

    // Probe BEFORE setting any state. If probe fails, the user/agent sees
    // a clear categorized error and activeTarget stays null.
    const r = await probe(profile.remote);
    if (!r.ok) {
      const ipSuffix = r.ip && r.ip !== profile.remote ? ` (${r.ip})` : "";
      const msg = `SSH mode NOT activated: ${reasonText[r.reason] || r.reason}${ipSuffix} — ${r.detail}`;
      ctx.ui.notify(msg, "warning");
      return { ok: false, reason: r.reason, detail: r.detail, message: msg };
    }

    const remoteCwd = await (async () => {
      if (profile.cwd && profile.cwd.trim()) return profile.cwd.trim();
      try {
        return (await sshOk(profile.remote, "pwd")).toString("utf8").trim();
      } catch { return ""; }
    })();

    activeTarget = { name: profile.name, remote: profile.remote, remoteCwd };
    enableSshTools();
    updateStatus(ctx);
    ctx.ui.notify(`SSH mode on: ${activeTarget.name} (${activeTarget.remoteCwd})`, "info");

    // Print the verify block so the agent/user can sanity-check
    // identity, user, hostname, cwd before the first mutation.
    let verifyBlock = "";
    try {
      verifyBlock = await buildVerifyBlock(activeTarget.remote, activeTarget.remoteCwd);
      ctx.ui.notify(verifyBlock, "info");
    } catch (e) {
      verifyBlock = `(verify-block failed: ${e.message})`;
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
      if (!arg) {
        return {
          content: [{ type: "text", text: "ssh_target_select: missing 'target' argument" }],
          details: { ok: false, reason: "bad-args" }
        };
      }

      const profile = normalizeTargetArg(arg);
      if (!profile.remote) {
        return {
          content: [{ type: "text", text: `ssh_target_select: cannot resolve target '${arg}'` }],
          details: { ok: false, reason: "bad-args" }
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
    renderResult(result, theme) {
      const text = result?.content?.[0]?.text || "";
      return new _piTui.Text(text, 0, 0);
    }
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
      // Map relative path against remote cwd.
      const abs = _nodePath.isAbsolute(params.path)
        ? params.path
        : joinRemote(target.remoteCwd, params.path);
      const transformed = { ...params, path: abs };
      const tool = _piCodingAgent.createReadToolDefinition(target.remoteCwd, { operations: createRemoteReadOps(target) });
      return tool.execute(toolCallId, transformed, signal, onUpdate, ctx);
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
      const transformed = { ...params, path: abs };
      const tool = _piCodingAgent.createWriteToolDefinition(target.remoteCwd, { operations: createRemoteWriteOps(target) });
      return tool.execute(toolCallId, transformed, signal, onUpdate, ctx);
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
      return execSshEdit(editBase, pi, target, process.cwd(), params);
    },
    renderCall(args, theme) {
      const path = typeof args?.path === "string" ? args.path : "...";
      const targetLabel = activeTarget ? activeTarget.name : "inactive";
      return new _piTui.Text(
        `${theme.fg("toolTitle", theme.bold("ssh_edit"))} ${theme.fg("accent", path)} ${theme.fg("muted", `[${targetLabel}]`)}`,
        0, 0
      );
    },
    renderResult: editBase.renderResult
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
      const tool = _piCodingAgent.createBashToolDefinition(target.remoteCwd, { operations: createRemoteBashOps(target) });
      return tool.execute(toolCallId, params, signal, onUpdate, ctx);
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
    renderResult: bashBase.renderResult
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
        if (!activeTarget) {
          ctx.ui.notify("SSH tools enabled. No target selected yet — agent must call ssh_target_select.", "info");
          return;
        }
        ctx.ui.notify(`SSH mode: ${activeTarget.name} (${activeTarget.remote}:${activeTarget.remoteCwd})`, "info");
        return;
      }

      if (input === "off") {
        if (!activeTarget) {
          ctx.ui.notify("SSH mode is already off", "info");
          return;
        }
        deactivate(ctx);
        return;
      }

      // Convenience form: /sshactivate <host> enables tools AND sets the
      // target in one step (probe + verify runs as part of activate).
      // Equivalent to bare /sshactivate followed by ssh_target_select.
      if (input) {
        await activate(normalizeTargetArg(input), ctx);
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
      // CLI auto-activation: keep tools enabled across sessions so the
      // agent can immediately use ssh_target_select. The status line
      // marks this so the user can see why the tools are on without
      // having typed /sshactivate.
      enableSshTools();
      ctx.ui.setStatus(
        SSH_STATUS_KEY,
        ctx.ui.theme.fg("accent", "SSH (auto via --ssh-activate)")
      );
      ctx.ui.notify(
        "SSH tools auto-enabled via --ssh-activate. Call ssh_target_select <host> to pick a target.",
        "info"
      );
    } else {
      disableSshTools();
      updateStatus(ctx);
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