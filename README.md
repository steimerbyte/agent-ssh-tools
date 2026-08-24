# agent-ssh-tools

> **Agent-Safety SSH Extension for Pi** — verified activation, read/write/edit/exec
> tools, and guard-rails that prevent AI agents from mutating the wrong host.

## Install

```sh
pi install npm:@ogulcancelik/agent-ssh-tools
```

## What this plugin does

The plugin activates four tools and one slash command:

| Tool / Command | Purpose |
|----------------|---------|
| `ssh_read` | Read a file on the active remote |
| `ssh_write` | Write a file on the active remote |
| `ssh_edit` | Edit a file with exact text replacement |
| `ssh_bash` | Run a shell command on the active remote |
| `/ssh <name[:/path]>` | Activate a target with probe + verify |
| `/ssh off` | Deactivate |
| `/ssh status` | Show current target |

---

## What was added (vs. a basic SSH plugin)

A bare-bones SSH plugin lets an agent run commands on remote hosts. That is
not enough when the agent acts autonomously — it might activate the
wrong host, edit the wrong file, or silently fail and then assume
success. This plugin adds seven guard-rails.

### Feature 1 — Probe-before-activate

`/ssh <host>` runs two checks before changing any state:

1. **TCP-connect** to port 22 with a 6-second timeout.
2. **`ssh BatchMode whoami`** to confirm SSH banner + authentication both succeed.

Failures are categorized clearly:

| Reason | Meaning |
|--------|---------|
| `unreachable` | No TCP response on port 22 (no route, host down, firewall) |
| `refused` | TCP reached the host but nothing is listening on 22 |
| `auth` | SSH handshake worked but authentication failed |
| `timeout` | Connection took longer than the bound |
| `ssh-error` | ssh(1) reported some other failure |
| `ssh-missing` | No `ssh` binary on PATH |

`activeTarget` stays `null` on any failure. The agent cannot accidentally
run a command on a target it never properly connected to.

### Feature 2 — Verify block after activation

After a successful activation the plugin prints:

```
verify:
  user:     root
  hostname: web01.example.com
  cwd:      /var/www
  key:      SHA256:dL8XuLs6rIr9oU654W7PcQUriY77b+FEVb88yJp+jyg  (/home/steimerbyte/.ssh/id_ed25519)
  date:     2026-08-24T16:54:28Z
```

Each field exists because each one has burned someone in the past:

| Field | What the agent must verify |
|-------|----------------------------|
| `user` | Is this the user the task assumes? Wrong user = wrong permissions. |
| `hostname` | Is this the host the task targets? Mixing `web01` and `web02` is the most common mistake. |
| `cwd` | Is this where the user expects the operation to land? |
| `key` | Does the fingerprint match the identity you expect? Surprising key = wrong `~/.ssh/config` Host block. |
| `date` | Is the remote clock roughly now? Stale date = possible wrong network. |

The key fingerprint comes from `ssh-keygen -lf` on the IdentityFile that
`ssh -G <host>` would actually use — a mismatch means the agent is using
a different SSH key than expected.

### Feature 3 — Profile + alias resolver

Define reusable targets and short names in
`~/.config/agent-ssh-tools/profiles.json`:

```json
{
  "profiles": {
    "web01":   { "host": "web01.example.com", "cwd": "/var/www" },
    "prod-db": { "host": "postgres.internal",  "cwd": "/etc/postgresql" }
  },
  "aliases": {
    "prod":  "web01",
    "stage": "web01-staging:/opt/app",
    "pg":    "prod-db"
  }
}
```

Resolution order:
1. `aliases[arg]`
2. `profiles[arg]`
3. `~/.ssh/config` `Host <arg>` block
4. Raw `<arg>` passed to ssh(1) as fallback

### Feature 4 — Inline cwd via `name:/path` syntax

`/ssh web01:/etc/nginx` overrides any stored cwd for this session.
Aliases can embed inline paths: `"stage": "web01-staging:/opt/app"` opens
the connection as `web01-staging` but starts in `/opt/app` on the remote.

### Feature 5 — SHA-256 unchanged-detection in `ssh_edit`

Before pushing, the plugin compares SHA-256 of the post-edit content with
the pre-pull SHA-256. **Equal → no push.** Two benefits:
- An `edits[]` entry that didn't match anything is a no-op even at the
  remote layer.
- The agent can re-run the same edit safely without churn.

### Feature 6 — Bounded sshExec timeouts

`sshExec(remote, command, { timeoutSeconds })` spawns ssh with
`-o ConnectTimeout=N` and additionally kills the child with `SIGKILL`
if it has not exited by `timeoutSeconds`. Default: **30 s for file
operations**, **6 s for the probe**.

### Feature 7 — Relative paths resolve against remote cwd

`ssh_read web01 nginx.conf`, `ssh_write web01 site.conf`, and
`ssh_edit web01 site.conf` resolve relative paths against the **active
remote cwd**, not the local process cwd.

---

## Config

| File | Purpose |
|------|---------|
| `~/.config/agent-ssh-tools/profiles.json` | profiles + aliases |
| `~/.ssh/config` | auto-discovered hosts (read-only) |

---

## Inspiration and credits

The four-tool pattern (`ssh_read`/`ssh_write`/`ssh_edit`/`ssh_bash`) and
the `/ssh` activation command come from
[**ogulcancelik/pi-ssh-tools**](https://github.com/ogulcancelik/pi-ssh-tools),
created by **Can Çelik** (`@ogulcancelik`).

The agent-safety layer — probe-before-activate, verify block,
SHA-256 unchanged-detection, profile + alias resolver, inline cwd,
bounded timeouts, and relative-path-against-remote — was added on top
because real AI agents routinely mis-target hosts, mis-name files, and
re-run edits without realizing the first run already succeeded.

## License

MIT — see [LICENSE](LICENSE).
