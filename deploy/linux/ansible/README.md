# BAD ansible role

Installs BAD on Linux fleet-wide: journal group membership, auditd, config
template, binary, and a validation handler that refuses to let a broken
config survive the play. It installs no daemon and schedules nothing, because
BAD runs when something runs it. The schedule (if you want one) is yours: an
example systemd timer lives in docs/deployment.md.

Honesty first: this role is written to spec and reviewed, but has not been
run against a real fleet by this project. Start with `--check --diff`, then
one sacrificial machine, then the fleet.

## Using the role

The role is this folder, so point `roles:` or `role_path` at it:

```yaml
# playbook.yml
- hosts: monitored
  become: true
  roles:
    - role: ../deploy/linux/ansible
      vars:
        bad_service_user: badsvc
        bad_version: "latest"       # pin for a fleet: "0.2.0"
        bad_siem_kind: "syslog"
        bad_input_dynamics_enabled: true
```

Every default lives in `defaults/main.yml`. The config template renders from
`config.example.toml` structure, so what lands in `/etc/bad/config.toml`
matches the documented example, keys and comments included. An admin who
reads the file on a managed host sees the same file the docs promised.

## Dry run first

```bash
ansible-playbook playbook.yml --check --diff
```

The template, user, file and package modules all support check mode, so you
see exactly what would change without changing it. Read the diff before the
fleet does. The role ships no molecule suite, on the theory that a role with
one task file, one handler and one template is easier to read than a molecule
harness is to maintain. If your shop requires molecule, this role is small
enough that a scenario around it is an afternoon.

## Validation behavior

- `bad check-config` runs as a task AND as a handler. A bad template fails
  the play immediately; a binary or config change re-validates at handler
  time. Belt and suspenders is not paranoia when the belt is free.
- The play fails if the binary cannot run. A deploy log entry is a better
  place to learn that than a 3 AM scheduled run.

## Shops without Ansible

`deploy/linux/install.sh` is the same steps as a plain shell script. Ansible
is a convenience, not a requirement, and a rumor in some shops.