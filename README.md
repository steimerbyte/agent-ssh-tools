# agent-ssh-tools

> **Agent-Safety SSH Extension for Pi** — verified activation, read/write/edit/exec
> tools, and guard-rails that prevent AI agents from mutating the wrong host.

## Install

```sh
pi install npm:@ogulcancelik/agent-ssh-tools
```

## Tools and commands

The plugin registers five tools and one slash command:

| Tool / Command | Purpose |
|----------------|---------|
| `ssh_target_select` | Agent-callable target switch with probe + verify block |
| `ssh_read` | Read a file on the active remote |
| `ssh_write` | Write a file on the active remote |
| `ssh_edit` | Edit a file with exact text replacement (SHA-256 unchanged-detection) |
| `ssh_bash` | Run a shell command on the active remote |
| `/sshactivate <name[:/path]>` | User-initiated activation with probe + verify |
| `/sshactivate off` | Deactivate |
| `/sshactivate status` | Show current target |

## Workflow

```
user types /sshactivate web01
     │
     ▼
plugin runs probe (TCP-connect + ssh BatchMode whoami)
     │
     ├── fail ──► categorized error, no state change
     │
     └── ok ───► activeTarget set, verify block printed
                 │
                 ▼
         ssh_* tools enabled for the agent
                 │
                 ▼
   agent calls ssh_read / ssh_write / ssh_edit / ssh_bash directly
                 │
                 ▼
   agent calls ssh_target_select <other-host> to switch mid-task
```

The slash command and the agent-callable tool use **the same `activate()`**
helper internally, so behavior is identical: same probe, same verify
block, same error categorization.

---

## What this extension adds on top of a basic SSH plugin

A bare-bones SSH plugin lets an agent run commands on remote hosts. That is
not enough when the agent is acting autonomously — it might activate the
wrong Host block, edit the wrong file, or silently fail and then assume
success. This extension bakes in seven guard-rails so the agent is forced
to confirm it is on the right system before any mutation lands.

### 1. Probe-before-activate

`/sshactivate <host>` and `ssh_target_select <host>` both run two checks
before changing any state:

1. **TCP-connect** to port 22 with a 6-second timeout.
2. **`ssh BatchMode whoami`** to confirm the SSH banner exchange and
   authentication both succeed.

Failures are categorized so the agent (and the user) can tell what went
wrong:

| Reason | Meaning |
|--------|---------|
| `unreachable` | No TCP response on port 22 (no route, host down, firewall) |
| `refused` | TCP reached the host but nothing is listening on 22 |
| `auth` | SSH handshake worked but authentication failed |
| `timeout` | The connection took longer than the bound |
| `ssh-error` | ssh(1) reported some other failure |
| `ssh-missing` | No `ssh` binary on PATH |

`activeTarget` stays `null` on any failure and the `ssh_*` tools stay
disabled. The agent cannot accidentally run a command on a target it never
properly connected to.

### 2. Verify block after activation

After a successful activation the plugin prints:

```
verify:
  user:     root
  hostname: web01.example.com
  cwd:      /var/www
  key:      SHA256:dL8XuLs6rIr9oU654W7PcQUriY77b+FEVb88yJp+jyg  (/home/steimerbyte/.ssh/id_ed25519)
  date:     2026-08-24T16:54:28Z
```

This block is the agent's only chance to notice a mistake before the first
mutation. Each field exists because each one has burned someone in the past:

| Field | What the agent must verify |
|-------|----------------------------|
| `user` | Is this the user the task assumes? Wrong user = wrong permissions. |
| `hostname` | Is this the host the task targets? Mixing `web01` and `web02` is the most common mistake. |
| `cwd` | Is this where the user expects the operation to land? |
| `key` | Does the fingerprint match the identity you expect? Surprising key = wrong `~/.ssh/config` Host block. |
| `date` | Is the remote clock roughly now? Stale date = possible MITM or wrong network. |

The key fingerprint comes from `ssh-keygen -lf` on the IdentityFile that
`ssh -G <host>` would actually use, so a mismatch here means the agent
is using a different SSH key than expected — common when `~/.ssh/config`
has multiple Host blocks with similar names that resolve to the same IP.

### 3. Profile + alias resolver

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

Hosts from `~/.ssh/config` are auto-discovered (wildcards `*` / `?` and
negations `!` skipped) and appear in `/sshactivate` completion unless a
profile with the same name is defined.

Resolution order:
1. `aliases[arg]`
2. `profiles[arg]` (uses `host`, `cwd` from the profile)
3. `~/.ssh/config` `Host <arg>` block
4. Raw `<arg>` passed to ssh(1) as a fallback

### 4. Inline cwd via `name:/path` syntax

`/sshactivate web01:/etc/nginx` (or `ssh_target_select web01:/etc/nginx`)
overrides any stored cwd for this session. The inline path always wins.
Aliases can also embed an inline path: `stage: web01-staging:/opt/app`
opens the connection as `web01-staging` but starts the agent in `/opt/app`
on the remote.

### 5. SHA-256 unchanged-detection in `ssh_edit`

Before pushing, the plugin compares SHA-256 of the post-edit content with
the pre-pull SHA-256. **Equal → no push.** Two benefits:
- An `edits[]` entry that didn't match anything is a no-op even at the
  remote layer (no spurious mtime change).
- The agent can re-run the same edit safely without churn.

The pull-edit-push flow uses a local tmp file in `os.tmpdir()` so the
remote file is only written when the edit actually changed something.

### 6. Bounded sshExec timeouts

`sshExec(remote, command, { timeoutSeconds })` spawns ssh with
`-o ConnectTimeout=N` and additionally kills the child with `SIGKILL`
if it has not exited by `timeoutSeconds`. The default is **30 seconds for
file operations** and **6 seconds for the probe**, so a slow network
never freezes the agent.

### 7. Relative paths resolve against remote cwd

`ssh_read web01 nginx.conf`, `ssh_write web01 site.conf`, and
`ssh_edit web01 site.conf` resolve relative paths against the **active
remote cwd**, not the local process cwd. Matches the intuition: "I said
`nginx.conf`, I meant `nginx.conf` on the remote, in the active dir".

---

## Config

| File | Purpose |
|------|---------|
| `~/.config/agent-ssh-tools/profiles.json` | profiles + aliases |
| `~/.ssh/config` | auto-discovered hosts (read-only) |

## Inspiration

This extension was inspired by the original `pi-ssh-tools` plugin (the
four-tool pattern of `ssh_read`/`ssh_write`/`ssh_edit`/`ssh_bash` plus
the user-initiated activation command comes from there). The agent-safety
layer — probe-before-activate, verify block, SHA-256 unchanged-detection,
agent-callable target switch — was added because real AI agents routinely
mis-target hosts, mis-name files, and re-run edits without realizing the
first run already succeeded. None of that is a critique of the original;
the safety layer is meant to be added on top of any working SSH plugin.

## License

MIT — see [LICENSE](LICENSE).