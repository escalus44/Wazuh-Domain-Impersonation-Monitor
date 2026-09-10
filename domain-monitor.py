#!/usr/bin/env python3

import json
from datetime import datetime, timezone
from pathlib import Path

import requests
import dns.resolver
from rapidfuzz import fuzz


CONFIG_FILE = Path("/opt/domain-monitor/config.json")
STATE_FILE = Path("/opt/domain-monitor/seen-domains.json")


def load_config():
    with CONFIG_FILE.open("r", encoding="utf-8") as f:
        return json.load(f)


def load_state():
    if not STATE_FILE.exists():
        return {}

    try:
        with STATE_FILE.open("r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def save_state(state):
    with STATE_FILE.open("w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, sort_keys=True)


def normalize_domain(domain):
    return domain.lower().strip().rstrip(".")


def generate_candidates(domain, config):
    domain = normalize_domain(domain)

    if "." not in domain:
        return set()

    name, tld = domain.rsplit(".", 1)
    candidates = set()

    alternate_tlds = config.get(
        "alternate_tlds",
        ["net", "org", "co", "shop", "store", "info", "online", "us"]
    )

    prefixes = config.get(
        "candidate_prefixes",
        ["www-", "secure-", "official-"]
    )

    suffixes = config.get(
        "candidate_suffixes",
        [
            "-login",
            "-secure",
            "-support",
            "-portal",
            "-account",
            "-payments",
            "-billing",
            "-official",
            "-online"
        ]
    )

    substitutions = config.get(
        "character_substitutions",
        {
            "o": "0",
            "i": "1",
            "l": "1",
            "e": "3"
        }
    )

    for alt_tld in alternate_tlds:
        candidates.add(f"{name}.{alt_tld}")

    for prefix in prefixes:
        candidates.add(f"{prefix}{name}.{tld}")

    for suffix in suffixes:
        candidates.add(f"{name}{suffix}.{tld}")

    # Common hyphen variants for compound domains.
    # Insert hyphens at likely word boundaries for longer names.
    if len(name) >= 8:
        midpoint = len(name) // 2
        candidates.add(f"{name[:midpoint]}-{name[midpoint:]}.{tld}")

    # Pluralized domain.
    candidates.add(f"{name}s.{tld}")

    # One-character deletion variants.
    for i in range(len(name)):
        if len(name) > 3:
            candidates.add(f"{name[:i]}{name[i+1:]}.{tld}")

    # Adjacent character swap variants.
    for i in range(len(name) - 1):
        if name[i] != name[i + 1]:
            swapped = (
                name[:i]
                + name[i + 1]
                + name[i]
                + name[i + 2:]
            )
            candidates.add(f"{swapped}.{tld}")

    # Simple character substitutions.
    for original, replacement in substitutions.items():
        if original in name:
            candidates.add(
                f"{name.replace(original, replacement, 1)}.{tld}"
            )

    candidates.discard(domain)

    return candidates


def resolve_domain(domain):
    result = {
        "domain": domain,
        "resolves": False,
        "a": [],
        "aaaa": [],
        "mx": []
    }

    try:
        answers = dns.resolver.resolve(domain, "A", lifetime=3)
        result["a"] = sorted(str(answer) for answer in answers)
        result["resolves"] = True
    except Exception:
        pass

    try:
        answers = dns.resolver.resolve(domain, "AAAA", lifetime=3)
        result["aaaa"] = sorted(str(answer) for answer in answers)
        result["resolves"] = True
    except Exception:
        pass

    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=3)
        result["mx"] = sorted(
            str(answer.exchange).rstrip(".")
            for answer in answers
        )
        result["resolves"] = True
    except Exception:
        pass

    return result


def check_ctlogs(domain):
    url = f"https://api.ctlogs.dev/v1/domain/{domain}"

    headers = {
        "User-Agent": "WazuhDomainMonitor/1.0"
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=15
        )
        response.raise_for_status()

        data = response.json()
        rows = data.get("rows", [])

        return {
            "certificate_found": len(rows) > 0,
            "certificate_count": len(rows)
        }

    except Exception as exc:
        return {
            "certificate_found": False,
            "certificate_count": 0,
            "error": str(exc)
        }


def similarity_score(candidate, legitimate):
    return fuzz.ratio(candidate, legitimate)


def write_wazuh_event(log_file, event):
    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    with log_path.open("a", encoding="utf-8") as f:
        f.write(
            json.dumps(event, separators=(",", ":"))
            + "\n"
        )


def build_state_record(
    legitimate,
    candidate,
    score,
    severity,
    dns_result,
    ct_result
):
    return {
        "legitimate_domain": legitimate,
        "similarity": round(score, 1),
        "severity": severity,
        "dns_resolves": dns_result["resolves"],
        "a_records": dns_result["a"],
        "aaaa_records": dns_result["aaaa"],
        "mx_records": dns_result["mx"],
        "certificate_found": ct_result["certificate_found"],
        "certificate_count": ct_result["certificate_count"]
    }


def meaningful_change(old, new):
    monitored_fields = [
        "severity",
        "dns_resolves",
        "a_records",
        "aaaa_records",
        "mx_records",
        "certificate_found",
        "certificate_count"
    ]

    for field in monitored_fields:
        if old.get(field) != new.get(field):
            return True

    return False


def main():
    config = load_config()
    state = load_state()

    legitimate_domains = {
        normalize_domain(domain)
        for domain in config.get("legitimate_domains", [])
    }

    allowed_domains = {
        normalize_domain(domain)
        for domain in config.get("allowed_domains", [])
    }

    threshold = config.get("similarity_threshold", 80)

    log_file = config.get(
        "log_file",
        "/var/log/domain-monitor/domain-monitor.json"
    )

    print("[*] Domain Monitor starting")

    alerts_written = 0
    unchanged = 0

    for legitimate in sorted(legitimate_domains):

        candidates = generate_candidates(legitimate, config)

        for candidate in sorted(candidates):

            candidate = normalize_domain(candidate)

            if candidate in legitimate_domains:
                continue

            if candidate in allowed_domains:
                continue

            score = similarity_score(candidate, legitimate)

            if score < threshold:
                continue

            dns_result = resolve_domain(candidate)
            ct_result = check_ctlogs(candidate)

            if not (
                dns_result["resolves"]
                or ct_result["certificate_found"]
            ):
                continue

            severity = "medium"

            if (
                dns_result["resolves"]
                and ct_result["certificate_found"]
            ):
                severity = "high"

            current = build_state_record(
                legitimate,
                candidate,
                score,
                severity,
                dns_result,
                ct_result
            )

            previous = state.get(candidate)

            should_alert = False
            change_type = "new"

            if previous is None:
                should_alert = True

            elif meaningful_change(previous, current):
                should_alert = True
                change_type = "changed"

            if should_alert:

                event = {
                    "timestamp": datetime.now(
                        timezone.utc
                    ).isoformat(),
                    "event_type": "domain_spoof",
                    "change_type": change_type,
                    "company": config.get(
                        "company_name",
                        "Unknown"
                    ),
                    "legitimate_domain": legitimate,
                    "suspicious_domain": candidate,
                    "similarity": round(score, 1),
                    "severity": severity,
                    "dns_resolves": dns_result["resolves"],
                    "a_records": dns_result["a"],
                    "aaaa_records": dns_result["aaaa"],
                    "mx_records": dns_result["mx"],
                    "certificate_found": ct_result["certificate_found"],
                    "certificate_count": ct_result["certificate_count"],
                    "source": "domain-monitor"
                }

                write_wazuh_event(log_file, event)

                print(
                    f"[ALERT] {candidate} "
                    f"change={change_type} "
                    f"severity={severity}"
                )

                alerts_written += 1

            else:
                print(f"[UNCHANGED] {candidate}")
                unchanged += 1

            current["last_checked"] = (
                datetime.now(timezone.utc).isoformat()
            )

            if previous is None:
                current["first_seen"] = current["last_checked"]
            else:
                current["first_seen"] = previous.get(
                    "first_seen",
                    current["last_checked"]
                )

            state[candidate] = current

    save_state(state)

    print()
    print(f"[*] Alerts written: {alerts_written}")
    print(f"[*] Unchanged findings: {unchanged}")


if __name__ == "__main__":
    main()
