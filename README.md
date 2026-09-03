# agent-ssh-tools

> **Agent-Safety SSH Extension for Pi / omp** — verified activation,
> read/write/edit/exec/scp tools, and guard-rails that prevent AI agents
> from mutating the wrong host.

## Install

```sh
pi install npm:@steimerbyte/agent-ssh-tools
```

## Tools and commands

The plugin registers six tools and one slash command:

| Tool / Command | Purpose |
|----------------|---------|
| `ssh_target_select` | Agent-callable target switch with probe + verify block |
| `ssh_read` | Read a file on the active remote |
| `ssh_write` | Write a file on the active remote |
| `ssh_edit` | Edit a file with exact text replacement (SHA-256 unchanged-detection) |
| `ssh_bash` | Run a shell command on the active remote |
| `ssh_scp` | Transfer files between local and the active remote (upload/download) |
| `/sshactivate <name[:/path]>` | User-initiated activation with probe + verify |
| `/sshactivate off` | Deactivate |
| `/sshactivate status` | Show current target |

## Workflow

```
user types /sshactivate                (grant permission — no host chosen)
     │
     ▼
plugin enables ssh_* tools
activeTarget stays null
     │
     ▼
agent calls ssh_target_select web01   (probe + verify + set)
     │
     ├── fail ──► categorized error, ssh_* tools still enabled
     │            agent can try a different host
     │
     └── ok ───► activeTarget set, verify block printed
                agent calls ssh_read / ssh_write / ssh_edit / ssh_bash / ssh_scp
                 │
                 ▼
       agent calls ssh_target_select web02 to switch mid-task
```

The slash command and the agent-callable tool use **the same `activate()`**
helper internally, so behavior is identical: same probe, same verify
block, same error categorization.

`/sshactivate <host>` is a convenience shortcut that combines the bare
`/sshactivate` + `ssh_target_select <host>` in one step. Use it when the
user already knows the host; use bare `/sshactivate` when the agent
should pick.

### Why the split?

`/sshactivate` is the user's **permission** to allow remote operations.
`ssh_target_select` is the agent's **choice** of which host to operate
on, with probe + verify to catch mistakes. Combining the two would mean
the user has to commit to a host at the moment of permission; separating
them lets the user say "yes, you may work remotely" and let the agent
choose the right target based on the task.

---

## What this extension adds on top of a basic SSH plugin

A bare-bones SSH plugin lets an agent run commands on remote hosts. That is
not enough when the agent is acting autonomously — it might activate the
wrong Host block, edit the wrong file, or silently fail and then assume
success. This extension bakes in seven guard-rails so the agent is forced
to confirm it is on the right system before any mutation lands.

### 1. Probe-before-activate

`ssh_target_select <host>` (and the convenience shortcut
`/sshactivate <host>`) run two checks before changing any state:

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
  key:      SHA256:abc123…  (/home/<user>/.ssh/id_<algo>)
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

`/sshactivate web01:/etc/nginx` (convenience form) or
`ssh_target_select web01:/etc/nginx` (agent-callable tool) override any
stored cwd for this session. The inline path always wins.
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

| File / Variable | Purpose |
|-----------------|---------|
| `~/.config/agent-ssh-tools/profiles.json` | profiles + aliases |
| `~/.ssh/config` | auto-discovered hosts (read-only) |
| `SSH_CLI_AUTO_ACTIVATE=1` (env) | Auto-enable SSH tools at session start so the agent can use them without typing `/sshactivate`. The target still has to be picked via `ssh_target_select` (probe + verify run as usual). `/sshactivate off` overrides. |
| `--ssh-activate` (CLI flag) | Same effect as the env var; passed to `pi`/`omp` at startup. |

## Sandbox layout

Seit dem Refactor arbeitet die Extension komplett entkoppelt vom
System-/User-`openssh-client`-Setup. Alle persistenten SSH-Daten liegen
in einer eigenen Sandbox-Root, der ssh-agent wird pro omp-Session neu
gestartet, und `ssh`/`scp`/`ssh-add` sehen nur noch eine Allowlist-env.

### Sandbox-Root

Standardpfad: **`~/.local/share/agent-ssh-tools/`**. Überschreibbar
über `AGENT_SSH_ROOT` (siehe [Configuration](#configuration)).
Das Root-Verzeichnis wird mit Mode `0700` angelegt und ist selbst
rekursiv anlegbar (`mkdir -p` + private-Permissions auf jedem Level).

### Verzeichnis-Layout

```
$AGENT_SSH_ROOT/
├── ssh/
│   ├── agent/                  # unix-socket-Verzeichnis für den extension-eigenen ssh-agent
│   ├── identity/<name>         # private Keys, Mode 0600
│   ├── identity/<name>.pub     # public Keys
│   ├── known_hosts             # sandbox-private known_hosts
│   └── config                  # sandbox-private ssh-config (via `ssh -G` ausgewertet)
├── state/
│   ├── profiles.json           # Profil-Mapping (Host + Aliases + cwd)
│   ├── agent-bootstrap.log     # Debug-Log der ssh-agent-Initialisierung
│   └── audit.log               # append-only Audit-Log aller Remote-Ops
├── tmp/<uuid>/                 # Scratch-Verzeichnisse pro Operation, Mode 0700
│                               # (0600 auf Files), werden nach der Op wieder entfernt
└── lock/<name>.lock            # File-Locks (mkdir+rename-Pattern) für concurrent Ops
```

### Modi & Permissions

| Pfad | Mode | Wer |
|------|------|-----|
| `$AGENT_SSH_ROOT` | `0700` | dir |
| `$AGENT_SSH_ROOT/ssh/` | `0700` | dir |
| `$AGENT_SSH_ROOT/ssh/identity/<name>` | `0600` | file |
| `$AGENT_SSH_ROOT/ssh/identity/<name>.pub` | `0644` | file |
| `$AGENT_SSH_ROOT/ssh/known_hosts` | `0600` | file |
| `$AGENT_SSH_ROOT/ssh/config` | `0600` | file |
| `$AGENT_SSH_ROOT/ssh/agent/` | `0700` | dir (sockets) |
| `$AGENT_SSH_ROOT/state/` | `0700` | dir |
| `$AGENT_SSH_ROOT/state/profiles.json` | `0600` | file |
| `$AGENT_SSH_ROOT/state/agent-bootstrap.log` | `0600` | file |
| `$AGENT_SSH_ROOT/state/audit.log` | `0600` | file |
| `$AGENT_SSH_ROOT/tmp/<uuid>/` | `0700` | dir |
| `$AGENT_SSH_ROOT/tmp/<uuid>/*` | `0600` | file |
| `$AGENT_SSH_ROOT/lock/` | `0700` | dir |

### Lebenszyklus

- **Bootstrap** (einmal pro omp-Session, idempotent):
  1. `$AGENT_SSH_ROOT` sicherstellen (mkdir mit Mode `0700`, sonst mkPrivate).
  2. ssh-agent unter `$AGENT_SSH_ROOT/ssh/agent/` starten, Export-Lines parsen.
  3. IdentityFile aus Sandbox `ssh/config` (bzw. `ssh -G <host>`) auflösen,
     `ssh-add` aufrufen — Fallback-Liste aus `AGENT_SSH_FALLBACK_KEYS`,
     dann notfalls aus `$HOME/.ssh/`.
  4. Audit-Log-Eintrag mit `envHash` (siehe unten).
  5. Cleanup-Hook registrieren (`session_end` / `shutdown` → agent killen,
     socket unlinken, lockfiles freigeben).

- **Pro Operation** (`ssh_read`, `ssh_write`, `ssh_edit`, `ssh_bash`, `ssh_scp`):
  1. `withProfileLock(<profil>)` — File-Lock auf `$AGENT_SSH_ROOT/lock/<profil>.lock`.
  2. `ssh-agent alive?` checken, sonst re-bootstrap.
  3. `sandboxEnv()` bauen (Allowlist, siehe unten) und `ssh`/`scp` damit spawnen.
  4. Audit-Log-Append mit Host, Command-Hash, Exit, envHash.

- **Session-Ende**:
  Agent wird via Hook beendet, Socket gelöscht, Lockfiles entfernt.
  Tmp-Verzeichnisse werden schon pro Op aufgeräumt.

### Was sich bewusst **nicht** ändert

Die Binaries `ssh`, `scp`, `ssh-agent`, `ssh-add`, `ssh-keygen` werden
weiterhin vom System gespawnt — der Refactor isoliert die **Daten**,
nicht die Werkzeuge. Wenn die Binaries auch noch sandboxed werden
sollen, ist das ein eigenes Spec.

---

## Configuration

| Variable / Datei | Default | Effekt |
|------------------|---------|--------|
| `~/.config/agent-ssh-tools/profiles.json` | — | profiles + aliases (siehe [Profile + alias resolver](#3-profile--alias-resolver)) |
| `~/.ssh/config` | — | auto-discovered Hosts (read-only; nur gelesen, nie geschrieben) |
| `AGENT_SSH_ROOT` | `~/.local/share/agent-ssh-tools/` | Sandbox-Wurzelverzeichnis. Alle persistenten Daten (Sandbox-Layout oben) liegen relativ darunter. |
| `AGENT_SSH_IMPORT_FROM_HOME` | `false` | Einmaliger Import-Trigger. Wenn `1`, kopiert die Extension beim ersten Bootstrap `~/.ssh/config`, `~/.ssh/known_hosts` und referenzierte IdentityFiles nach `$AGENT_SSH_ROOT/ssh/`. Original bleibt unangetastet. Siehe [Migration from ~/.ssh/](#migration-from-ssh). |
| `AGENT_SSH_STRICT_HOSTKEY` | `yes` | Wert für `StrictHostKeyChecking`: `yes` = unknown host → fail closed; `accept-new` = erstes Mal akzeptieren und loggen; `no` = nicht empfohlen. |
| `AGENT_SSH_FALLBACK_KEYS` | leer | Komma-separierte Liste absoluter Pfade zu privaten Keys, die beim Bootstrap zusätzlich versucht werden, wenn das aufgelöste IdentityFile nicht lädt. Beispiel: `AGENT_SSH_FALLBACK_KEYS=/home/me/.ssh/id_ed25519,/home/me/.ssh/work_key`. |
| `SSH_CLI_AUTO_ACTIVATE=1` | unset | Auto-enable SSH tools beim Session-Start, ohne dass der User `/sshactivate` tippt. Target muss weiterhin via `ssh_target_select` gewählt werden (Probe + Verify laufen wie üblich). `/sshactivate off` überschreibt. |
| `--ssh-activate` (CLI-Flag) | — | Gleicher Effekt wie `SSH_CLI_AUTO_ACTIVATE=1`; an `pi`/`omp` beim Start übergeben. |

### Was die alten SSH-Agent-Env-Vars machen

`SSH_AUTH_SOCK` und `SSH_AGENT_PID` werden vom Refactor **nicht mehr**
aus der Parent-Shell gelesen oder gesetzt. Die Extension startet
ihren eigenen ssh-agent unter `$AGENT_SSH_ROOT/ssh/agent/` und
propagiert `SSH_AUTH_SOCK`/`SSH_AGENT_PID` **nur** über `sandboxEnv()`
an ihre eigenen Child-Prozesse — `process.env` der omp-Node-Runtime
wird nicht mehr mutiert. Es ist also OK und sogar erwünscht, dass
`echo $SSH_AUTH_SOCK` in der User-Shell nach dem Start leer ist.

---

## Migration from ~/.ssh/

Bestehende Setups, die `~/.ssh/config` / `~/.ssh/known_hosts` und
diverse IdentityFiles parallel zum agent-ssh-tools-Sandbox-Betrieb
verwendet haben, können in einem einmaligen Schritt in die Sandbox
überführt werden. Der Original-`~/.ssh/` wird dabei **nie**
verändert oder gelöscht.

### Schritt-für-Schritt

1. **Audit-Logs sichern (optional).** Die alten Audit-Logs liegen
   unter `~/.config/agent-ssh-tools/audit.log` (bisheriger Pfad) —
   bei Bedarf vorher wegkopieren, sie bleiben vom Refactor unberührt:
   ```sh
   cp -p ~/.config/agent-ssh-tools/audit.log \
         ~/.config/agent-ssh-tools/audit.log.pre-sandbox
   ```

2. **omp-Session mit Import-Flag starten.** Beim ersten Bootstrap mit
   `AGENT_SSH_IMPORT_FROM_HOME=1` zeigt die Extension einen Consent-Banner
   und kopiert dann:
   - `~/.ssh/config` → `$AGENT_SSH_ROOT/ssh/config`
   - `~/.ssh/known_hosts` → `$AGENT_SSH_ROOT/ssh/known_hosts`
   - alle in `profiles.json` referenzierten `IdentityFile`-Pfade →
     `$AGENT_SSH_ROOT/ssh/identity/<basename>`
   ```sh
   AGENT_SSH_IMPORT_FROM_HOME=1 omp
   ```

3. **Sandbox-Inhalt verifizieren.** Die folgenden Pfade müssen jetzt
   vorhanden sein:
   ```sh
   ls -la "$AGENT_SSH_ROOT/ssh/"
   #   drwx------  agent/  identity/  known_hosts  config
   ls -la "$AGENT_SSH_ROOT/ssh/identity/"
   #   -rw-------  <key>
   #   -rw-r--r--  <key>.pub
   ```
   Im Audit-Log erscheint ein Eintrag `migration: imported N files from
   $HOME/.ssh/` (siehe nächste Sektion).

4. **omp normal starten und `ssh_target_select` testen.** Ab sofort
   ohne `AGENT_SSH_IMPORT_FROM_HOME`:
   ```sh
   omp
   # im Prompt:
   /sshactivate web01
   # oder agent-getrieben:
   #   ssh_target_select web01
   ```
   Der Probe-Run verifiziert TCP + Auth gegen `web01` und gibt den
   Verify-Block aus — wenn der erscheint, ist die Sandbox voll
   funktionsfähig.

### Was passiert mit der alten Bootstrap-Pipeline?

Der frühere Pfad `~/.config/agent-ssh-tools/agent-bootstrap.log`
wandert nach `$AGENT_SSH_ROOT/state/agent-bootstrap.log`. Alte
Log-Einträge aus der Vor-Refactor-Phase bleiben am alten Pfad
erhalten und werden **nicht** migriert.

### Was passiert mit `SSH_AUTH_SOCK` in der User-Shell?

Nichts — und genau das ist gewollt. Die Extension liest oder setzt
diese Variable **nicht** mehr aus der Parent-Shell. Siehe Hinweis
am Ende der [Configuration](#configuration)-Sektion.

---

## SSH agent bootstrap (sandbox-owned)

Seit dem Refactor startet die Extension ihren eigenen ssh-agent
unter `$AGENT_SSH_ROOT/ssh/agent/` — **unabhängig davon, was in der
Parent-Shell als `SSH_AUTH_SOCK` gesetzt ist**. Der bisherige erste
Bootstrap-Schritt ("lies inherited env") entfällt komplett: die
Extension vertraut der User-Shell nicht mehr.

### Pipeline

Der Bootstrap läuft **einmal pro omp-Session** und ist danach
idempotent (cache-key: `$AGENT_SSH_ROOT + pid + session-id`).

1. **Sandbox-Root sicherstellen.** `$AGENT_SSH_ROOT` mit Mode `0700`
   anlegen, falls fehlend. Falls `AGENT_SSH_IMPORT_FROM_HOME=1`
   gesetzt: einmaliger Import aus `~/.ssh/` (siehe [Migration from
   ~/.ssh/](#migration-from-ssh)).
2. **`ssh-agent -s` starten.** Unter `$AGENT_SSH_ROOT/ssh/agent/`
   spawnen, Export-Lines parsen (`SSH_AUTH_SOCK=…; export
   SSH_AGENT_PID=…;`). Socket und PID landen in
   `process.env` der omp-Runtime **nicht** mehr — nur in der
   sandbox-scoped Variablen der Extension.
3. **Identity laden.** `IdentityFile` aus `$AGENT_SSH_ROOT/ssh/config`
   via `ssh -G <host>` auflösen und `ssh-add`n. Wenn das fehlschlägt,
   wird die `AGENT_SSH_FALLBACK_KEYS`-Liste (komma-separiert)
   versucht; danach notfalls die Hardcoded-Defaults
   `~/.ssh/id_ed25519` → `~/.ssh/id_rsa` → `~/.ssh/HPE_Pvt_key`
   (nur lesend, niemals kopierend — das wäre Aufgabe des
   Migrations-Flags). Passphrase-Fehler werden gefangen und
   übersprungen, sodass die Session nie auf einem fehlenden
   Pinentry hängt.
4. **Audit-Log-Eintrag.** Siehe [Audit log](#audit-log) unten.
5. **Cleanup-Hook.** `pi.on('session_end' | 'shutdown')` beendet den
   Agent und entfernt den Socket.

Jeder `ssh` / `scp` Child-Spawn erhält das `sandboxEnv()`-Allowlist-Env
(siehe unten) statt `process.env`. Damit bleiben z.B. `AWS_*`,
`GITHUB_TOKEN`, `OMP_INTERNAL_*` für die Child-Prozesse unsichtbar.

### sandboxEnv() — Allowlist

Das an `ssh`/`scp` übergebene `env` enthält **nur** diese Variablen:

| Variable | Wert |
|----------|------|
| `PATH` | unverändert |
| `LANG` | unverändert |
| `TERM` | unverändert |
| `TZ` | unverändert |
| `HOME` | `$AGENT_SSH_ROOT` |
| `USER` | unverändert |
| `LOGNAME` | unverändert |
| `SSH_AUTH_SOCK` | sandbox-socket |
| `SSH_AGENT_PID` | sandbox-agent-pid |

Alles andere aus `process.env` wird bewusst weggelassen. So leak-en
weder Cloud-Provider-Credentials noch Tokens an den Remote-Prozess.

### Was ist mit `SSH_AUTH_SOCK` in der User-Shell?

**Nichts** — und genau das ist die Idee. Die Extension liest oder
setzt `SSH_AUTH_SOCK` / `SSH_AGENT_PID` in der omp-Node-Runtime nicht
mehr; sie propagiert sie nur noch über das sandboxEnv()-Objekt an
eigene Child-Prozesse. Es ist also OK und erwünscht, dass
`echo $SSH_AUTH_SOCK` in der User-Shell nach dem Start leer ist.

### Debug log

Jeder Bootstrap-Schritt hängt eine Zeile an
`$AGENT_SSH_ROOT/state/agent-bootstrap.log` mit aufgelöstem Socket,
versuchtem Key und finaler Identity-Anzahl. Live mitschneiden:

```sh
tail -f "${AGENT_SSH_ROOT:-$HOME/.local/share/agent-ssh-tools}/state/agent-bootstrap.log"
```

### Post-quantum key exchange warning is cosmetic

OpenSSH 9+ gibt ein `** WARNING: connection is not using a
post-quantum key exchange algorithm.`-Banner aus, wenn keine Seite
einen hybriden ML-KEM / Curve25519-Kex anbietet. Dieses Banner
bedeutet **nicht**, dass die Authentifizierung fehlgeschlagen ist —
die Verbindung authentifiziert weiterhin über den klassischen
Algorithmus. Bei einem fehlgeschlagenen Probe den echten Auth-Fehler
findet sich in `notify`-Output und `agent-bootstrap.log`.

### Concurrent Ops

Zwei parallele `ssh_bash` auf dasselbe Profil werden über File-Locks
serialisiert: `withProfileLock(<profil>)` legt ein Lockfile unter
`$AGENT_SSH_ROOT/lock/<profil>.lock` an (mkdir + Random-Suffix-Rename,
kein extra npm-Dep — pure `fs.mkdirSync` recursive + race-Check).
Nach der Op wird das Lock freigegeben; bei Session-Crash räumt der
Cleanup-Hook die Lockfiles auf.

### Hardcoded Fallbacks (Konsistenz mit Spec)

Falls weder das aufgelöste IdentityFile noch `AGENT_SSH_FALLBACK_KEYS`
erfolgreich laden, versucht die Extension **lesend** (nie kopierend)
aus `~/.ssh/`:
`~/.ssh/id_ed25519` → `~/.ssh/id_rsa` → `~/.ssh/HPE_Pvt_key`.

---

## Profile-Schema (kompatibel, ergänzt)

Das bestehende Schema bleibt rückwärtskompatibel; pro Profil können
zwei optionale Felder ergänzt werden:

| Feld | Typ | Bedeutung |
|------|-----|-----------|
| `identityFile` | `string` | Relativer Pfad zu `$AGENT_SSH_ROOT/ssh/identity/`. Beispiel: `"identity/work_key"` |
| `knownHosts` | `string` | Relativ (zu `$AGENT_SSH_ROOT/ssh/`) oder absolut. Beispiel: `"known_hosts"` oder `"/etc/ssh/known_hosts"` |
| `preloadKnownHosts` | `string` | Optionaler read-once Pfad; wird beim Bootstrap einmal in die Sandbox kopiert. Sinnvoll für Hosts, die vor dem ersten Connect verifiziert werden müssen. |

Beispiel:

```json
{
  "profiles": {
    "web01": {
      "host": "web01.example.com",
      "cwd": "/var/www",
      "identityFile": "identity/work_ed25519",
      "knownHosts": "known_hosts"
    }
  }
}
```

---

## StrictHostKeyChecking

Default ist `yes` (über `AGENT_SSH_STRICT_HOSTKEY=accept-new` auf
`accept-new` umschaltbar). Die Sandbox-`known_hosts` startet leer —
beim ersten Connect gilt:

| Modus | Verhalten |
|-------|-----------|
| `yes` (Default) | unknown host → **fail closed**, kein auto-add |
| `accept-new` | erster Connect → akzeptieren + Audit-Log-Eintrag |
| `no` | nicht empfohlen, explizit setzen wenn bewusst gewünscht |

Für Hosts, die schon vor dem ersten Connect verifiziert werden sollen,
einen Profil-Eintrag mit `preloadKnownHosts: "<pfad>"` setzen — die
Extension liest die Datei beim Bootstrap einmal und kopiert sie in
`$AGENT_SSH_ROOT/ssh/known_hosts`.

---

## Audit log

Jede Remote-Operation (`ssh_bash`, `ssh_scp`, sowie zukünftig
`ssh_read`/`ssh_write`/`ssh_edit`) hängt eine Zeile an
`$AGENT_SSH_ROOT/state/audit.log`. Das Format ist TSV mit einem
festen Schema, append-only (`O_APPEND`), sodass concurrent Ops die
Datei nicht zerschießen.

Beispiel-Eintrag (`ssh_bash` auf `web01`):

```
2026-09-03T10:42:18.123Z	envHash=a1b2c3d4e5f6	sandboxRoot=agent-ssh-tools	web01	web01.example.com	/var/www	exit=0	312ms	out=8b3c1e9a4f1d	err=000000000000	["systemctl","status","nginx"]
```

Felder:

| Spalte | Bedeutung |
|--------|-----------|
| `timestamp` | ISO-8601 UTC, ms-genau |
| `envHash=<hash>` | SHA-256-Truncat über `sandboxEnv()`-Variablen + Werte — **ohne Secrets** |
| `sandboxRoot=<basename>` | Basename des Sandbox-Roots (z.B. `agent-ssh-tools`); verhindert Pfadlecks wenn Logs geteilt werden |
| `target.name` | Profil- oder Aliasname (z.B. `web01`, oder `"scp"`/`"migration"`) |
| `target.remote` | aufgelöster `user@host` (oder `-` für Migration) |
| `cwd` | entferntes cwd zum Zeitpunkt der Op (oder `direction` für scp, oder `-` für Migration) |
| `exit=N` | Exit-Status (`N` oder `signal=…`) |
| `elapsed` | Dauer der Op als `<N>ms` |
| `out=<hash>` | SHA-256-Truncat (12 Zeichen) der stdout-Bytes (bzw. `out=imported` für Migration) |
| `err=<hash>` | SHA-256-Truncat (12 Zeichen) der stderr-Bytes (bzw. `err=Nfiles` für Migration) |
| `cmd` (oder scp-Felder) | Tool-spezifisch: command-Array (JSON) für `ssh_bash`, bzw. `match=<yes\|no>` + `src=<sha>` + `dst=<sha>` + JSON-Pfade für `ssh_scp` |

Der `envHash` macht reproduzierbar, welche Umgebung eine Op gesehen
hat, ohne dass die Werte selbst ins Log landen. Beispiel:

```sh
# nur die Hash-Spalten ausgeben, ohne das volle Env zu verraten:
awk -F'\t' '/^[^#]/ {print $1, $2, $3, $9, $10}' \
```


Migrationen landen **nicht** im Audit-Log, sondern im Bootstrap-Log
`$AGENT_SSH_ROOT/state/agent-bootstrap.log` (Plain-Text, eine Zeile pro
Bootstrap-Event). Beispiel:

```
migration: imported 7 files from $HOME/.ssh/ (skipped 0)
```

## Credits

The original `pi-ssh-tools` plugin — including the four-tool pattern of
`ssh_read` / `ssh_write` / `ssh_edit` / `ssh_bash` and the user-initiated
activation command — was written by **ogulcancelik (Can Celik)**. This
project is a fork of that original work, continued and extended by
**steimerbyte**.

The agent-safety layer — probe-before-activate, verify block, SHA-256
unchanged-detection, agent-callable target switch — was added because
real AI agents routinely mis-target hosts, mis-name files, and re-run
edits without realizing the first run already succeeded. None of that
is a critique of the original; the safety layer is meant to be added on
top of any working SSH plugin.

## License

MIT — see [LICENSE](LICENSE).