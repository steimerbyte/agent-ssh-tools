# ssh-cli-pi

Pi coding-agent SSH extension — drop-in replacement for `pi-ssh-tools` with
hardened connection semantics and explicit agent safety checks.

## Install

```sh
pi install npm:@ogulcancelik/ssh-cli-pi
```

Or, if you have the original plugin installed, remove it first:

```sh
pi remove pi-ssh-tools  # exact name may vary in your install
pi install npm:@ogulcancelik/ssh-cli-pi
```

The plugin activates four tools:

| Tool | Purpose |
|------|---------|
| `ssh_read` | Read a file on the active remote |
| `ssh_write` | Write a file on the active remote |
| `ssh_edit` | Edit a file with exact text replacement |
| `ssh_bash` | Run a shell command on the active remote |

And one slash command:

| Command | Purpose |
|---------|---------|
| `/ssh` | Toggle SSH mode interactively |
| `/ssh <name[:/path]>` | Activate a target |
| `/ssh off` | Deactivate |
| `/ssh status` | Show current target |

## What changed vs. the original pi-ssh-tools

### 1. Probe-before-activate

`/ssh <host>` runs a TCP-connect to port 22 and an `ssh BatchMode whoami`
before any state changes. If the host is unreachable, refuses, times out, or
fails authentication, the agent sees a categorized error:

```
SSH mode NOT activated: host unreachable (192.0.2.1) — no TCP response on 192.0.2.1:22 within 6s
```

`activeTarget` stays `null` and the four SSH tools remain disabled. **No more
"silent activation with broken connection"** — the agent will fail loudly on
the first tool call instead of confusing the user.

### 2. Verify block after activation

After successful activation the plugin prints:

```
verify:
  user:     root
  hostname: web01.example.com
  cwd:      /var/www
  key:      SHA256:dL8XuLs6rIr9oU654W7PcQUriY77b+FEVb88yJp+jyg  (/home/steimerbyte/.ssh/id_ed25519)
  date:     2026-08-24T16:54:28Z
```

Agents must read this and confirm user/hostname/cwd/key match expectations
before any mutation. The key fingerprint comes from `ssh-keygen -lf` on the
IdentityFile that `ssh -G <host>` would use, so a mismatch here means the
agent is using the wrong key — common when `~/.ssh/config` has multiple Host
blocks with similar names.

### 3. Inline cwd always wins

`/ssh web01:/var/log` overrides any profile-stored cwd for this session.
This also matches the same syntax used by `ssh(1)` and avoids the trap of
"profile.cwd says `/var/www` but I needed `/var/log`".

### 4. profiles.json with aliases

Define reusable targets and short names:

```json
{
  "profiles": {
    "web01":  { "host": "web01.example.com", "cwd": "/var/www" },
    "prod-db":{ "host": "postgres.internal",  "cwd": "/etc/postgresql" }
  },
  "aliases": {
    "prod":   "web01",
    "stage":  "web01-staging:/opt/app",
    "pg":     "prod-db"
  }
}
```

File: `~/.config/ssh-cli-pi/profiles.json`. Aliases and explicit profile names
are auto-completed by `/ssh`. Inline cwd in aliases is preserved.

### 5. SHA-256 unchanged-detection in `ssh_edit`

Before pushing, the plugin compares SHA-256 of the post-edit content with the
pre-pull SHA-256. Equal → no push. Avoids spurious writes when an `edits[]`
entry didn't match anything (which already would have been a no-op in the edit
tool) and lets agents re-run an edit safely without state churn.

### 6. Bounded ssh timeouts

`sshExec()` accepts `timeoutSeconds` and kills the child with `SIGKILL` on
expiry. The default for all file operations is 30 seconds. The probe uses a
6-second ConnectTimeout so a slow network doesn't freeze the agent.

### 7. Relative-path resolution against remote cwd

`ssh_read`, `ssh_write`, `ssh_edit` now map relative paths against the
active **remote** cwd instead of the local process cwd. This matches the
intuition ("I said `nginx.conf`, I meant `nginx.conf` on the remote, in the
active dir").

## Config

| File | Purpose |
|------|---------|
| `~/.config/ssh-cli-pi/profiles.json` | profiles + aliases |
| `~/.ssh/config` | auto-discovered hosts (read-only) |

## Resolution order

```
/ssh <arg>
     │
     ▼
 ┌─────────────────┐
 │ aliases[arg]?   │──yes──► use, optionally with inline :/path
 └────────┬────────┘
          │ no
          ▼
 ┌─────────────────┐
 │ profiles[arg]?  │──yes──► use profile.host, optional profile.cwd
 └────────┬────────┘
          │ no
          ▼
 ┌─────────────────┐
 │ ~/.ssh/config   │──yes──► use as raw ssh target
 │  Host arg       │
 └────────┬────────┘
          │ no
          ▼
 ┌─────────────────┐
 │ raw arg → ssh   │──always──► may fail at ssh(1)
 └─────────────────┘
```

Inline `:path` after any of the above always overrides the resulting cwd.

## License

MIT — see [LICENSE](LICENSE).