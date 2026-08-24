# SSH-Plugin Test-Prompt Template

Kopiere diesen Block und passe nur die fett-markierten Stellen an.
Die Reihenfolge ist wichtig — so bekommst du verwertbare Outputs.

---

## Template

```
# Test plan: <FEATURE_NAME>

Verify the **agent-ssh-tools v<VERSION>** plugin on pve-docker
(192.168.179.78). This is v<X.Y.Z> of the plugin on GitHub:
https://github.com/steimerbyte/agent-ssh-tools

## Setup
- Plugin must already be installed via `pi install git:github.com/steimerbyte/agent-ssh-tools@v<X.Y.Z>`
- User has already typed `/sshactivate` (permission granted; tools enabled)
- Working directory on the remote is `/root`
- Test directory will be `/tmp/ssh-tool-test` on the remote

## Test sequence (in this order)

1. **Target selection probe**:
   - Tool call: ssh_target_select pve-docker
   - Expected: returns a verify-block with `user:`, `hostname:`, `cwd:`, `key:`, `date:`
     fields filled in (NOT `<error>`)
   - If user/hostname/date show `<error>` -> STOP, that's a regression

2. **Non-destructive file ops**:
   - Tool calls: ssh_bash -- "mkdir -p /tmp/ssh-tool-test"
   - Tool calls: ssh_write /tmp/ssh-tool-test/retest.txt with content "line1\nline2\n"
   - Tool calls: ssh_read /tmp/ssh-tool-test/retest.txt
   - Expected: write returns success with byte count; read returns "line1\nline2\n"

3. **Edit roundtrip**:
   - Tool calls: ssh_edit /tmp/ssh-tool-test/retest.txt with edits:
     [{oldText: "line2", newText: "line2-edited"}]
   - Tool calls: ssh_read /tmp/ssh-tool-test/retest.txt
   - Expected: read shows "line2-edited"; the diff in the edit result
     must show the **remote path** `/tmp/ssh-tool-test/retest.txt`, NOT
     any `/tmp/agent-ssh-tools-edit-...` path

4. **Verbose envelope check**:
   - Look at the tool-result area, NOT just the notify stream
   - Each tool result should show timing + exit code somewhere visible
     (either in content or as a header line)
   - Verbose output should mention the REMOTE path/host, not local
     details like cwd, tmp file paths, or buffer names

5. **Cleanup**:
   - Tool calls: ssh_bash -- "rm -rf /tmp/ssh-tool-test && echo done"
   - Expected: stdout "done", exit 0

## What to report back

For each test step, report:
- PASS / FAIL with one-line reason
- The exact tool-call output you saw (verbatim)
- Anything that looked like an internal-leak (e.g. a path starting
  with `/tmp/agent-ssh-tools-edit-`)

If ANY step fails, stop and report — do NOT retry. The plugin
author needs the exact error to fix the regression.
```

---

## Warum genau diese Struktur

| Was ich vermeide | Warum |
|---|---|
| "Teste mal das Plugin" | Agent interpretiert das frei, macht beliebige Calls |
| "Mach einen Quick-Test" | "Quick" suggeriert dass Tiefe egal ist |
| Lange Prosa-Beschreibung | LLM kann Schlüssel-Constraints übersehen |

| Was ich forciere | Warum |
|---|---|
| **Versionsnennung** | Reproduzierbar — du weißt welcher Commit getestet wurde |
| **Konkrete Tool-Namen** | Keine "ssh-befehl" oder "tool"-" Halluzinationen |
| **Erwartete Outputs** | Agent kann PASS/FAIL entscheiden ohne zu raten |
| **Stop-Bedingung** | Bei Fehler nicht retryen — der Bug ist der Punkt |
| **Was zu berichten** | Verhindert "looks fine" Halluzinationen ohne Beweis |

## Bonus-Tests für Edge-Cases

Falls du nach dem Smoke-Test noch was tiefer prüfen willst:

**Newline-Injection-Test** (Sicherheit, v0.6.0+):
```
ssh_target_select 'evil
command'
Expected: error message about "unsafe characters", NO probe attempted
```

**Unknown-Target-Test** (Sicherheit, v0.5.1+):
```
ssh_target_select totally-not-a-host
Expected: error message "target not found in profiles..." + list of
available targets. NO probe attempted.
```

**Connection-Pooling-Test** (Performance, nur sinnvoll wenn implementiert):
```
ssh_target_select pve-docker; then 5x ssh_read of different files
Expected: total time < 3s (vs ~5s without pooling)
```

**SHA-256-Unchanged-Detection** (Edit-Feature, v0.2.0+):
```
ssh_edit file with edits that produce identical content
Expected: result says "unchanged" or "no changes", NO ssh push performed
```

## Was du nicht im Test-Prompt brauchst

- Erklärungen was ssh-target_select macht — der Agent hat Skill/Context
- Doku-Verweise auf pi.dev — lenkt vom Test ab
- Bitte um "schöne Formatierung" — lenkt vom Inhalt ab

## Schnellversion (für eilige Checks)

Falls du nur einen Smoke-Test willst ohne ganzen Plan:

```
Tool calls in this exact order on pve-docker:
1. ssh_target_select pve-docker
2. ssh_bash -- "mkdir -p /tmp/quick-test"
3. ssh_write /tmp/quick-test/x.txt with content "abc"
4. ssh_read /tmp/quick-test/x.txt
5. ssh_edit /tmp/quick-test/x.txt replacing "abc" with "xyz"
6. ssh_read /tmp/quick-test/x.txt  (must show "xyz")
7. ssh_bash -- "rm -rf /tmp/quick-test"

For each tool-call, paste the visible output verbatim.
Report PASS or FAIL with the exact failure reason.
Do NOT retry on failure.
```

Das ist 80% des Wertes vom Full-Template für 20% der Textmenge.