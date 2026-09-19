# ShopNest CTI Exercise — Student Log Analysis

A hands-on **Cyber Threat Intelligence (CTI) / Log Analysis** classroom exercise built
around three realistic Linux server log files.

You are given ~3 months of logs (16 Jun – 18 Sep 2026, all timestamps **UTC**) from the
infrastructure of a fictional online retailer, **ShopNest** (`shopnest.com`), and are
asked to analyse them like a real threat-hunting / incident-response analyst:

build the normal baseline first, filter out the noise, spot the anomaly, reconstruct the
full attack chain by **correlating evidence across all three files**, and write an
intelligence report.

> This is a training exercise. All IP addresses, hostnames, domains, and data are
> fictional (`Documentation` ranges per RFC 5737 / RFC 6598). No real systems or personal
> data are involved.

---

## Repository contents

```
├── README.md                  ← you are here
├── student_worksheet.md       ← the 40-question task sheet (start here)
├── shopnest_access.log         Apache web server access log (~24k requests)
├── shopnest_syslog.log         Linux host syslog / auth / cron / sudo / fail2ban  (~8.5k events)
└── shopnest_firewall.log       UFW / iptables netfilter log  (~11k accept + block packets)
```

| File | Source system | What it records |
|---|---|---|
| `shopnest_access.log` | Apache web server | Every HTTP request to the storefront and admin backend (combined log format) |
| `shopnest_syslog.log` | Ubuntu server | SSH, sudo, cron, DNS (dnsmasq), user/group changes, fail2ban bans |
| `shopnest_firewall.log` | UFW firewall | Inbound accepts & blocks, outbound connections |

The **answer key is intentionally not included** — it is held by the instructor GCN.

---

## How to use

1. Read `student_worksheet.md` first. It explains the method and contains all tasks.
2. Open the three `.log` files in any text editor capable of handling a few megabytes
   (VS Code, Notepad++, Sublime, `less`, `nano`, …).
3. Use `grep` / `Select-String` / `awk` / your favourite log-analysis tool to hunt.
   No special software or libraries are required — the whole exercise works with
   plain text tools.

Suggested first steps from the worksheet:

```
# top source IPs in the web log
awk '{print $1}' shopnest_access.log | sort | uniq -c | sort -rn

# what services appear in syslog
grep -oE '^[A-Za-z]{3} +[0-9]+ [0-9:]+ [^ ]+ [^ ]+' shopnest_syslog.log \
  | awk -F'[][:]' '{print $4}' | sort | uniq -c | sort -rn

# outbound destinations in the firewall log
grep 'OUT=eth0' shopnest_firewall.log | grep -oE 'DST=[0-9.]+' | sort | uniq -c
```

---

## Learning objectives

- Read and interpret **Apache combined**, **syslog**, and **netfilter/UFW** formats
- Establish a traffic **baseline** and separate noise (crawlers, scanners, brute-force
  bots, uptime monitors) from **real malice**
- Reconstruct a complete **intrusion kill chain** by correlating events across logs
- Recognize **false positives** and **failed attacks**
- Extract **Indicators of Compromise (IOCs)** and write **detection rules**
- Produce an **executive incident report**

---

## Getting help during the exercise

- Search online for the *format* of each log type (e.g. "Apache combined log format") —
  this is expected and encouraged.
- Do **not** search for the fictional IPs/domains outside the logs: they are made up and
  will not exist anywhere else. Analyse the evidence in front of you.
- If you get stuck on a task, go back and re-read Part 2 (baseline) of the worksheet.
  Most "attacks" cannot be recognised without knowing what normal looks like first.

---

## Notes for instructors

- Full analysis, kill-chain timeline, IOC table, and answer key are distributed separately
  (not committed to this repository) so that students cannot be spoiled.
- The generator used to produce the logs is also kept out of the repo for the same reason.
- Roughly **2–4 hours** of classroom time covers the full worksheet; Parts 1–2 can be
  trimmed for a shorter lab.

---

## Disclaimer & license

This is synthetic data created for training. All trademarks belong to their owners.
