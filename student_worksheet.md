# ShopNest Cyber Threat Intelligence Exercise — Student Worksheet

**Case:** SDW3-NEST-2026-083 · **Data window:** 16 Jun – 18 Sep 2026 (all timestamps UTC)
**Artifacts to analyze:**

| File                    | Source system | About                                                             |
|-------------------------|---------------|-------------------------------------------------------------------|
| `shopnest_access.log`   | Web server    | Every HTTP request to the storefront + admin backend              |
| `shopnest_syslog.log`   | Linux host    | System events: SSH, sudo, cron, DNS, user/group changes, fail2ban |
| `shopnest_firewall.log` | Firewall      | Accepted / blocked connections, inbound & outbound                |

---

## How to work

- Read the files with any editor or `grep`/`Select-String`; the logs are plain text.
- Work in order: your answer to later questions depends on earlier ones.
- Every claim you make must be backed by at least one **exact log line**. Quote it (copy the full line) and give its source file.
- When you see something suspicious, always check: *is there a matching event in the other two files at the same time?* 
  A single-file anomaly is weak evidence; a three-file correlation is proof.
- Your submitted report will be graded on **evidence quality** 
  (correct lines, correct correlation, correct reasoning), not on guessing.

**Cheat sheet of useful commands** (adapt to your OS):
grep "sqlmap" shopnest_access.log
grep "CommandLine" shopnest_syslog.log
grep "198.51.100.0/24"                         # any IOC you collect
cut -d' ' -f1,2 shopnest_syslog.log | sort | uniq -c     # count lines per minute
awk '{print $1}' shopnest_access.log | sort | uniq -c | sort -rn   # top source IPs

---

## Part 1 — Know your logs (15 min)

1. For each of the three files:
   - What software/system produced it?
   - What is its line format? (describe every field you can identify)
   - What is the date range and roughly how many lines?

2. Produce a "top 5" list for the access log: the five source IPs with the most requests.
   Do any surprise you? (Keep this list — you'll need it in Part 5.)

3. Produce the same "top 5" list for the syslog file, this time broken down by **program**
   (the part right after the hostname, e.g. `sshd[1234]`, `CRON[999]`). Which identity
   appears most, and which appear rarely?

4. In the firewall log, list the distinct *destination* IPs that the server connects **out to**.
   How many distinct outbound destinations are there? Write them down.

---

## Part 2 — Establish the baseline (45 min)

The single most important skill is knowing what **normal** looks like before hunting for evil.

5. Find the recurring request that happens roughly every 20 minutes, all day, for the whole window. 
   Find who sends it and why. Is it malicious?

6. A human administrator uses this server every workday. Determine:
   - their **source IP** and **SSH key type/fingerprint**,
   - the hours during which they normally connect,
   - what kind of **web pages** they normally visit in the admin panel.

   > Hint: cross-reference beneficial insights in Q2/Q3: the admins' SSH session and their
   > web traffic come from the same IP.

7. Find a week-long **gap** in that administrator's activity (no SSH, no web admin).
   Give the exact start and end dates of the gap. What normal life event explains it?

8. Identify at least **four** categories of *background internet noise* that show up over and over but are NOT attacks on this site. 
   For each: name the category, an example IP, and the evidence line you found. 
   Categories to look for: 
   - search-engine crawlers,
   - security research scanners (Censys/Shodan/masscan/Shadowserver), 
   - web-optimization tools, 
   - uptime monitors, and 
   - SSH brute-force botnets.

9. The firewall blocks UDP/TCP port bursts from brute-force botnets on ports 22, 3389, 445, 3306, 8443, and others. 
   Pick **two** example IPs and quote their blocked traffic. 
   Then find which local service **recognizes and bans** repeated SSH failures — what does the ban line look like?

10. On **15 Aug** the server briefly returned HTTP **503** responses to customers. 
    What legitimate maintenance event caused it? Find the matching evidence in the syslog file.

---

## Part 3 — Find the incident (3–4 hours)

Do not skip Part 2 first. Now hunt for behaviour that **breaks the baseline**.

### 3a. Discovery & exploitation

11. On **30 Jul**, shortly after 08:00 UTC, someone requests several unusual admin/debug pages that a normal visitor wouldn't. 
    - Which source IP? (Note the User-Agent — what web browser is it? Look it up.)
    - What pages did they request, and what port probes appear in the firewall log for the same IP at the same time? List every probe.
    - Reason: is a defensive/monitoring system relevant here? Who is this actor?

12. On **3–4 Aug**, one IP generates a huge burst of requests to a single page with strange query strings. 
    - Which IP, which page, how many requests per day on each day?
    - The requests' `User-Agent` — what tool is it? What does that tool do?
    - Quote **three** different payloads from those query strings (e.g. a `SLEEP`, a `UNION SELECT`, an `EXTRACTVALUE`, and a boolean-style probe).
    - Do you see HTTP **500** responses mixed with 200s on that page *only during the burst*?
      What does a 500 from this page actually mean here?
    - What web application vulnerability is being exercised? Which parameter holds the flaw?
    - This is stage "initial access" — estimate exactly when the funnel started and ended.

### 3b. Account takeover & admin access

13. On **5 Aug at 13:12 UTC**, the *same source IP* from 3a appears somewhere it has never been before. 
    Where? List the exact sequence of requests (with status codes) from that IP between 13:12 and 13:14.

14. Look at **which data pages** that IP browsed in `/admin/` right after login. 
    What four pieces of sensitive information would have been visible? 
    Why do we conclude the logins were *not* the legitimate admin (cross-reference Q6/Q7)?

15. Can you prove (or argue) that the attacker used credentials from the database dump in 3a to get in? 
    Write the reasoning, quoting the relevant `CONCAT` payload from Part 3a.

### 3c. Web shell & command execution

16. On **5 Aug, 14:02–14:03 UTC**, a request uploads a file via a surprising admin function.
    - Which endpoint, and with what query parameter? Which filename is being implied?
    - What kind of file is it really? What would an auditor verify to catch this (extension, MIME type, magic bytes, file size)?
    - A minute later the same file is requested again with **`act=phpinfo`**. What did that confirm to the attacker?

17. From **14:05** the attacker starts sending **`cmd=`** parameters to the uploaded file.
    Over the next hours, quote the commands that let you prove each of these facts:
    - they are running as `www-data`,
    - they know the OS/kernel,
    - they enumerated web roots and the passwd database.

    For each answered command, quote the exact request line.

18. Where does the uploaded file live (full path on disk), and how does its filename help it hide in plain sight?

### 3d. Privilege escalation

19. At **14:41:22** the attacker runs `sudo -l`. 
    Find this exact moment in the **syslog**: quote the line showing `www-data` issuing `sudo -l` and the *user* it requested.

20. At **14:46:33–34** two things happen almost simultaneously: 
    a request in the access log and a line in the syslog. 
    Quote **both**.
    - Parse the Python one-liner: 
      what does it do *at the OS level*? 
      What single privilege does it grant?
    - Immediately after, the attacker runs `id` again. 
      Compare the output (uid) — now what user are they?
    - Root cause in config: what **one misconfiguration** made this possible? 
      Where would an auditor find that line (which file), and what should it be changed to?

### 3e. Data theft (staging)

21. Between **15:20 and 15:27** the attacker stages the stolen data. 
    Reconstruct the exact sequence of `cmd=` operations and for each state what it did:
    - create the working directory,
    - dump three database tables (name them) you now see, one at a time,
    - combine them into a single archive — give the archive's **full path and filename**,
    - check its size.

22. Which database credentials were used for the dumps? 
    State what that implies about account security/secret management on this host.

### 3f. Exfiltration & C2

23. At **17:28:44** a DNS resolver on the host resolves an unusual name. 
    Quote the syslog line. 
    What is suspicious about the domain name relative to what ShopNest actually does?

24. At **17:29:20** find the `curl` command in the access log. 
    Decode it **exactly**: what HTTP method, which URL, which `-F file=@…` argument, and what was `-o` / `-w` used for?

25. In the **firewall log**, reconstruct the full outbound TCP session that occurred between 17:29:20 and 17:35:52 on 5 Aug:
    - the destination IP and port,
    - the source ports used,
    - the TCP flag sequence you can observe (SYN, SYN/ACK, ACK, … FIN),
    - which of those events line up with the `curl` and which with a *second* connection at 17:31:40.

26. Search the whole firewall log for **any earlier** connection to that destination IP.
    Repeat for the destination IP itself. What conclusion can you draw about the 
    hypothesis "this is a routine service the server already talks to"?

### 3g. Persistence

27. At **17:31:40** the attacker writes a file inside `/etc/cron.d/`. 
    - Quote the exact `cmd=` request in the access log.
    - Decode the shell command it executes: 
      write out what the final line in `/etc/cron.d/…` will be (do NOT run it), including the schedule.
    - What does `curl … | sh` mean as opposed to just downloading a file?

28. From midnight on **6 Aug** the syslog shows the same mysterious command **every hour**.
    - Quote one execution line (with timestamp).
    - Count how many times it fired over the observation window (e.g. `grep -c`).
    - Does the firewall log show a matching hourly **outbound** beacon? Quote one. 
      Compare: is it exactly hourly? any jitter?

29. On **6 Aug, 09:40 UTC** another persistence mechanism is added.
    - Quote the syslog lines for every step (account creation, group, shell, password).
    - What is the account name, UID, and what **elevated group** was it added to?
    - Cross-correlate: does the attacker use this account for anything else you can see? 
      What does an incident responder do about this account *today*?

30. Does the attacker return later? Find evidence of activity on **7 Aug**, **12 Aug**,
    **27 Aug** and **10 Sep**, and classify each: check-in, data access, or modification.
    - In particular the **12 Aug** admin action edits a specific product. 
    - Which product id? 
    - Why might changing *price data* matter to the attacker's motive? 
      (Fraud / resell / hiding an action — argue which.)

---

## Part 4 — Separate the incident from the noise (45 min)

31. During the observation window a *different* IP performs **sqlmap** attacks — and fails.
    - Which IP, what tool/version in the UA, which target page did they hammer?
    - What HTTP status code did they get on **every** attempt? 
      Quote examples. Why does a 400 prove the attack failed here (think: what does the parameter do)?
    - Compare and contrast against the successful actor from Part 3a in a small table
      (IP, tool signature, page, status codes, outcome, follow-on activity).
    - Lesson: why is "somebody ran sqlmap" NOT the same as "we were breached"?

32. On **18 Aug, 12:31** a request looks like a SQL injection payload. 
    - Quote the request. Which IP? Way too rare to be a scanner, right?
    - Read it as a human: what is the customer actually searching for?
    - Note the referer. Explain what happens when a naive SIEM rule flags *any* request containing a single quote.

33. The uptime monitor from Q5 — could *it* be false? It only calls `/heartbeat.php`.
    Give one reason its traffic cannot exfiltrate the data you found in Part 3.

34. List everything that is **bystander/noise/false-positive** and everything that is
    **incident**, in two columns, with your one-line justification each. 
    (This answer is a central part of your grade.)

---

## Part 5 — Intelligence product (write it up)

35. **IOC table.** Extract and table every Indicator of Compromise you found, with columns:
    Type (IP / domain / file / account / cron / hash), Value, Role (what it did),
    Evidence (file:line or quoted line).

36. **Kill chain map.** Put the incident on a timeline grid:

    Stage                 | Date      |     Time (UTC)  |  Evidence summary (file + line number) |
    Reconnaissance        |           |                 |                                        |
    Exploitation (SQLi)   |           |                 |                                        |
    …
    
    Cover at least: recon, exploitation, account takeover, web shell, privilege escalation,
    data staging, exfiltration, persistence, operator return visits.

37. **Attribution.** 
    - In 3–5 sentences write your assessment: 
      is the actor likely opportunistic or targeted? 
      Criminal or state? 
      How confident, and *why* (say which evidence drives your confidence). 
      Flag the limits of log-only attribution.

38. **Detection rules.** Write at least one detection rule each for:
    a. sqlmap/web-shell User-Agents + error-burst pattern,
    b. admin-panel login from an unexpected source IP,
    c. outbound connection to an IP never seen in the baseline (egress anomaly),
    d. `curl … | sh` pattern in cron output,
    e. `python3 -c` executed as the web user.
    Use pseudo-SIEM (any syntax you like) *and* a comment of why the rule won't false-positive all over the baseline you built in Part 2.

39. **Executive incident report.** One page, three sections:
    - *Summary* (2–3 sentences: what happened, when, who, what was taken),
    - *Impact* (which data classes, how many rows affected approx, reputational/legal exposure for an e-commerce entity),
    - *Recommended actions* (5–8 concrete steps, ordered: contain → eradicate → recover → prevent).

40. **Lessons learned.** List the top 5 *root-cause-level* fixes (not patching band-aids) that would have prevented or cut this attack short. 
    For each fix, name the exact stage of the kill chain it would have stopped.

---

## Grading rubric (what "good" looks like)

| Criteria         | Weak                                  | Strong  |
|------------------|---------------------------------------|-----------------------------------------|
| Evidence quoting | Paraphrases                           | Quotes exact lines + file/line refs     |
| Correlation      | Treats one log in isolation           | Proves events in ≥2 logs at same time   |
| Baseline         | Skips noise analysis                  | Shows noise first, then filters it      |
| False positives  | Ignores the 400-sqlmap & quote-search | Explicitly classifies them              |
| IOCs             | Lists IPs only                        | Full typed IOC table with roles         |
| Reporting        | Bullet dump                           | Structured, prioritized, decision-ready |

**Submission:** one `Day4_LASTNAME_FIRSTNAME_incident_report.md` containing answers to all 40 questions.