# Local testing and baselines

How to test BAD on a real machine, and how long to wait before the model
stops being a coin with a slogan.

## Testing on a Linux machine

You are presumably on systemd, so the Linux collector will actually do
something. Here is the honest sequence.

### 0. Prerequisites

The journal needs to be readable by your user (or run collect with sudo
for the full firehose):

```bash
sudo usermod -aG systemd-journal ghost   # then relogin
```

For the good telemetry (process exec, user commands) you want auditd
running, since `EXECVE` and `USER_CMD` events come from audit records
relayed through journald. Without it you only get sshd and sudo entries,
which is thin gruel:

```bash
sudo pacman -S audit   # if not present
sudo systemctl enable --now auditd
```

### 1. Collect

```bash
bad collect --platform linux --output events.jsonl --since "3 days ago"
wc -l events.jsonl     # gut check: did we actually catch anything?
```

If that number is embarrassingly small, do some normal activity: open
terminals, ssh somewhere, run a few sudo commands, browse with things that
log. You are feeding the dog you will later ask to bite.

### 2. Train

```bash
bad train --input events.jsonl --output model.joblib
```

### 3. Score and watch

```bash
bad score --input events.jsonl --model model.joblib --threshold 0.65
```

Or the live loop, shipping to syslog where you can watch alerts land:

```bash
bad monitor --input events.jsonl --model model.joblib --siem syslog
journalctl -f | grep SIEM_ALERT
```

### 4. The fun part: provoke it

Train on your normal behavior, then in a five minute window do something a
normal you would not do: hammer sudo with wrong passwords, run an nmap
sweep, fail ssh into localhost twenty times, spawn a pile of unusual
processes. Then score the fresh window. If the model does not perk up,
your threshold is too high or your baseline was too thin. Both are fixable
and both are your fault, which is the good news.

## How long for an accurate baseline

The model needs **windows, not time**. It trains on behavior buckets
(default 300 seconds, minimum 5 events each). The math:

| Training set | Verdict |
|---|---|
| Under ~200 qualifying windows | Coin with a slogan. Flags Tuesdays as suspicious |
| 200 to 2000 windows | Workable baseline for a single user on a single box |
| 2000+ windows | Stable. Boring user, reliable model |

Translating that into wall clock time for a single user workstation:

- **Busy interactive box with auditd on**: 1 to 3 days of collection
- **Quiet workstation, sshd/sudo only**: 3 to 7 days, and lower `--min-events`
  or widen the window, because a quiet user produces starved 300 second
  windows that get dropped
- **A multi-user server** (the real target market): half a day to a day of
  solid traffic

And the part everyone forgets: human behavior runs on a **weekly cycle**. A
model that has only seen weekdays will happily flag your Saturday as an
intrusion. For a genuinely accurate personal baseline, capture at least
one full week, ideally two, then train on everything. On a fleet of
servers the cycle matters less and you get there much faster.

### Tuning a sparse machine

```bash
bad train --input events.jsonl --output model.joblib --window-seconds 3600 --min-events 3
```

Wider window, lower floor, same pipeline. Retraining is cheap (seconds),
so the sane workflow is: collect continuously, retrain daily on a rolling
one or two weeks, and let the model keep up with your bad habits as they
evolve. The model does not judge. It just counts.