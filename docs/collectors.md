# Collectors

Collectors are the only layer allowed to know what an operating system sounds
like. Everything downstream sees `BehaviorEvent` and nothing else.

## The front door: jsonl

```bash
bad collect --platform jsonl --source agent-events.jsonl --output events.jsonl
```

The `jsonl` collector ingests events that are already normalized: one
`BehaviorEvent` JSON object per line. This is the path for agents, EDRs and
monitoring tools. They collect, they normalize, we do the math. It is also
the path that makes the whole package testable on any OS, because CI does not
own a Mac, a Windows box and a time machine.

It is also the only door input dynamics come through. BAD does not sample
the keyboard or the mouse, because a tool that is not an agent does not get
to install a keylogger, and that is what raw input capture is no matter how
noble the readme sounds. An agent emits periodic `input` aggregates (typing
counts and intervals, mouse distance and direction changes, see
[Event Schema](schema.md)) and BAD turns them into features. Timing and
motion only, ever: the moment a sampler proposes sending keystroke content,
decline, and then reconsider your sampler vendor.

## Linux: systemd journal

```bash
bad collect --platform linux --output events.jsonl --since "1 hour ago"
```

Reads `journalctl --output json`, which also carries auditd records when the
box runs auditd and systemd. If it runs neither, the machine is a lifestyle
choice and we respect that from afar.

What gets mapped:

| Source | event_type | action |
|---|---|---|
| auditd `EXECVE` | process | exec |
| auditd `USER_CMD` | shell | command |
| auditd `USER_LOGIN` / `USER_AUTH` | auth | login / auth |
| `sshd` entries | auth | login |
| `sudo` entries | privilege | sudo |

sshd never structured its logs and never will, so success/failure is read
from the prose: failure markers ("Failed", "Invalid", "res=failed") flip
`success` to false, everything else reads as success, because in this
industry absence of failure is as good as success ever gets.

Requires `journalctl` on PATH and a user allowed to read the journal, which
is most users on most boxes and nobody on a properly paranoid one.

## Windows: Security event log

```powershell
bad collect --platform windows --output events.jsonl
```

Runs `Get-WinEvent` through `ConvertTo-Json`, because PowerShell is the one
scripting runtime guaranteed to live on every Windows box whether we like it
or not.

What gets mapped:

| Event ID | event_type | action | success |
|---|---|---|---|
| 4624 (logon) | auth | login | true |
| 4625 (failed logon) | auth | login | false |
| 4688 (process creation) | process | exec | null |

Structured `Properties` array indices are used instead of the human-readable
message, because non-English locales shuffle the prose and localized brittle
is worse than documented brittle. Indices follow Microsoft's layouts:
4624/4625 read TargetUserName at 5 and ProcessName at 18; 4688 reads
SubjectUserName at 1, NewProcessName at 5, ParentProcessName at 9.

## macOS: unified log

```bash
bad collect --platform macos --output events.jsonl
```

Reads `log show --style ndjson`. The unified log is very thorough and very
chatty, so only processes we actually understand get mapped, and everything
else gets skipped. Guessing is for weathermen.

| Process | event_type | action |
|---|---|---|
| `sshd` | auth | login |
| `sudo` | privilege | sudo |

The unified log does not hand us a user per message, so `user_id` stays
"unknown" rather than parsing identity out of free text. Blaming the wrong
employee from a regex is how tools end up on the news.

Want richer macOS telemetry? The real answer is the Endpoint Security
framework, which requires entitlements Apple does not hand out like candy.
Run an ES agent that emits normalized JSONL and feed it through the jsonl
collector. Same pipeline, better data.

## Adding your own

Implement `Collector.collect()` to yield `BehaviorEvent` objects, and add a
branch to `build_collector()`. That is the entire ceremony. Keep the parse
logic a pure function (dict in, event or None out) and the I/O in a thin
subprocess wrapper: plumbing is where bugs breed, we keep it starving.

And keep the golden rule: entries you cannot identify get skipped, not
guessed. Silence beats fiction.