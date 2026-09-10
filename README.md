# Wazuh Domain Impersonation Monitor

A lightweight, industry-neutral domain impersonation and typosquatting monitor designed to feed suspicious lookalike-domain findings into Wazuh.

This project can be used by dealerships, healthcare organizations, law firms, manufacturers, schools, financial institutions, MSPs, SaaS companies, nonprofits, or any organization that wants basic external brand/domain monitoring without adding a separate commercial platform.

## What it does

The monitor:

- Protects one or more legitimate domains.
- Generates likely typo/lookalike variants.
- Checks DNS A, AAAA, and MX records.
- Checks Certificate Transparency data using `api.ctlogs.dev`.
- Scores similarity against the legitimate domain.
- Supports an allowlist for approved aliases and redirects.
- Stores state to suppress duplicate alerts.
- Writes one-line JSON events for Wazuh ingestion.
- Uses `systemd` for scheduled execution.
- Produces Wazuh alerts for new or changed suspicious domains.

## Architecture

```text
Protected Domain(s)
        |
        v
Candidate Lookalike Generation
        |
        v
DNS Checks + Certificate Transparency
        |
        v
Similarity / Allowlist / State Comparison
        |
        v
JSON Event Log
        |
        v
Wazuh Logcollector
        |
        v
Custom Rules
        |
        v
Dashboard / Alert / Email
```

## Important limitation

This is a lightweight defensive monitor, not a full commercial brand-protection service.

It only evaluates domain variants that it generates. It does not continuously enumerate every newly registered domain on the Internet, and a matching domain is not proof of malicious activity.

Treat findings as indicators requiring investigation.

## Requirements

Tested for deployment on Ubuntu with Wazuh Manager.

Install:

```bash
sudo apt update
sudo apt install python3-venv -y
```

Create the project and log directories:

```bash
sudo mkdir -p /opt/domain-monitor
sudo mkdir -p /var/log/domain-monitor
```

Copy these files into `/opt/domain-monitor`:

```text
domain-monitor.py
requirements.txt
config.example.json
```

Create the virtual environment:

```bash
cd /opt/domain-monitor
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Configuration

Copy the example:

```bash
cp config.example.json config.json
```

Edit it:

```bash
nano config.json
```

Example:

```json
{
  "company_name": "YOUR ORGANIZATION NAME",
  "legitimate_domains": [
    "yourcompany.com"
  ],
  "allowed_domains": [
    "your-known-redirect-domain.com"
  ],
  "similarity_threshold": 80,
  "log_file": "/var/log/domain-monitor/domain-monitor.json",
  "alternate_tlds": [
    "net",
    "org",
    "co",
    "shop",
    "store",
    "info",
    "online",
    "us"
  ],
  "candidate_prefixes": [
    "www-",
    "secure-",
    "official-"
  ],
  "candidate_suffixes": [
    "-login",
    "-secure",
    "-support",
    "-portal",
    "-account",
    "-payments",
    "-billing",
    "-official",
    "-online"
  ],
  "character_substitutions": {
    "o": "0",
    "i": "1",
    "l": "1",
    "e": "3"
  }
}
```

### Configuration guidance

`legitimate_domains` contains the domains being protected.

`allowed_domains` contains known-good alternate domains, redirects, or aliases that should not generate spoofing alerts.

`candidate_suffixes` is intentionally configurable. Organizations can add industry-specific terms such as:

```text
-patient
-claims
-student
-payroll
-vendor
-customer
-helpdesk
-remote
-cloud
-auth
```

Do not commit your production `config.json`.

## Manual test

Activate the virtual environment:

```bash
source /opt/domain-monitor/venv/bin/activate
```

Validate syntax:

```bash
python -m py_compile /opt/domain-monitor/domain-monitor.py
```

Run:

```bash
python /opt/domain-monitor/domain-monitor.py
```

Inspect the JSON log:

```bash
cat /var/log/domain-monitor/domain-monitor.json
```

## Wazuh integration

Add the contents of:

```text
wazuh/ossec-localfile.xml
```

inside the main `<ossec_config>` block in:

```text
/var/ossec/etc/ossec.conf
```

Validate logcollector configuration:

```bash
sudo /var/ossec/bin/wazuh-logcollector -t
```

No output generally means the configuration parsed successfully.

Add the rules from:

```text
wazuh/local_rules.xml
```

to your existing:

```text
/var/ossec/etc/rules/local_rules.xml
```

Important: do not nest a new `<group name="...">` block inside an existing Wazuh rule group.

Choose local rule IDs that do not conflict with your environment.

Validate:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
```

Restart:

```bash
sudo systemctl restart wazuh-manager
```

## Test the Wazuh rule

Run:

```bash
sudo /var/ossec/bin/wazuh-logtest
```

Paste:

```json
{"event_type":"domain_spoof","company":"Example Organization","legitimate_domain":"yourcompany.com","suspicious_domain":"yourcompany-secure.com","similarity":95.5,"severity":"high","dns_resolves":true,"certificate_found":true,"certificate_count":1,"source":"domain-monitor"}
```

A high-severity event should match the high-risk child rule.

## Dedicated service account

Create a locked service account:

```bash
sudo useradd --system \
  --home /opt/domain-monitor \
  --shell /usr/sbin/nologin \
  domainmon
```

Set ownership:

```bash
sudo chown -R domainmon:domainmon /opt/domain-monitor
sudo chown -R domainmon:domainmon /var/log/domain-monitor
```

## systemd service

Copy:

```text
systemd/domain-monitor.service
systemd/domain-monitor.timer
```

to:

```text
/etc/systemd/system/
```

Reload systemd:

```bash
sudo systemctl daemon-reload
```

Enable the timer:

```bash
sudo systemctl enable --now domain-monitor.timer
```

Verify:

```bash
systemctl list-timers --all | grep domain-monitor
```

Manual test:

```bash
sudo systemctl start domain-monitor.service
journalctl -u domain-monitor.service -n 30 --no-pager
```

Because the service is `Type=oneshot`, it is normal for it to become inactive after a successful run.

## Deduplication

The monitor stores previous findings in:

```text
/opt/domain-monitor/seen-domains.json
```

A new Wazuh event is generated when:

- a domain is first discovered,
- DNS state changes,
- A/AAAA/MX data changes,
- certificate status changes,
- certificate count changes,
- severity changes.

Unchanged findings are not repeatedly written to the Wazuh log.

## Detection strategy

The default candidate generator currently includes:

- alternate TLDs,
- configurable prefixes,
- configurable suffixes,
- pluralization,
- single-character deletion,
- adjacent-character swaps,
- simple character substitutions,
- one generic hyphen insertion for longer names.

This is intentionally conservative to reduce noise.

For broader coverage, organizations may extend the generator with:

- homoglyph detection,
- additional keyboard-adjacent typos,
- IDN/punycode checks,
- domain-registration feeds,
- search engine monitoring,
- HTML/title similarity,
- favicon or screenshot comparison.

## Security considerations

- Run the monitor under a dedicated non-login service account.
- Keep `config.json` and state files out of source control.
- Review findings before treating them as malicious.
- DNS resolution and certificate issuance are indicators, not proof of fraud.
- Back up Wazuh configuration before editing `ossec.conf` or `local_rules.xml`.
- Monitor the `systemd` unit for failures.
- Consider outbound firewall restrictions if your environment requires them.

## Rollback

Disable the timer:

```bash
sudo systemctl disable --now domain-monitor.timer
```

Remove the localfile stanza from Wazuh and remove the custom rules added for this project.

Validate:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
sudo /var/ossec/bin/wazuh-logcollector -t
```

Restart:

```bash
sudo systemctl restart wazuh-manager
```

## License

MIT
