# Study plan: AppSec + AI security, paired with Sluice

Goal: Burp Suite Certified Practitioner (BSCP), then live AI-feature bug
bounties. Each week pairs PortSwigger Web Security Academy topics with the
Sluice milestone that builds the same idea, so learning and building feed
each other. Assumes about 10 hours a week: roughly 6 on labs, 4 on Sluice.

Rule for every lab: solve it in Burp first, then replay the same traffic
through Sluice and note what Sluice could not do. That list is the next
Sluice backlog.

| Week | Academy (labs) | Sluice | Output |
| --- | --- | --- | --- |
| 1 | [Threat modeling](https://owasp.org/www-community/Threat_Modeling) basics; [Access control](https://portswigger.net/web-security/access-control) (IDOR) | M4 start: Send to Repeater, edit and resend | One threat model of the payments ledger: trust boundaries, data flows |
| 2 | Access control, practitioner labs | M4: Copy as curl, response timing | Write-up: "IDOR is a missing check at a trust boundary" |
| 3 | [Authentication](https://portswigger.net/web-security/authentication) | M4: Intercept toggle (hold, edit, forward, drop) | Demo clip: intercepting a login |
| 4 | [Business logic](https://portswigger.net/web-security/logic-flaws); [Information disclosure](https://portswigger.net/web-security/information-disclosure) | M4: match-and-replace; M5 start: passive leak rules | Sluice flags a leaked key or stack trace in a lab |
| 5 | [SSRF](https://portswigger.net/web-security/ssrf) | M5: passive header and cookie rules | Write-up: SSRF and cloud metadata |
| 6 | [SQL injection](https://portswigger.net/web-security/sql-injection) | M5: Fuzzer (sniper mode) | Fuzzer finds an injection point in a lab |
| 7 | [XSS](https://portswigger.net/web-security/cross-site-scripting) | M5: Hex view, cluster-bomb mode | Semgrep: first custom rule ([docs](https://semgrep.dev/docs/writing-rules/overview)) on a C# or TS sink |
| 8 | [Web LLM attacks](https://portswigger.net/web-security/llm-attacks); [OWASP LLM Top 10](https://genai.owasp.org/llm-top-10/); [Gandalf](https://gandalf.lakera.ai/) | M6 start: LLM endpoint detection, SSE reassembly | Write-up: indirect prompt injection through a web feature |
| 9–10 | Revisit weak topics; [request smuggling](https://portswigger.net/web-security/request-smuggling) (ties to the M1 parser) | M6: payload sets against DVAP | Pick first live program (HackerOne/Bugcrowd, AI in scope) |
| 11–12 | BSCP practice exams ([certification](https://portswigger.net/web-security/certification)) | M6.5: indirect injection lab | Book the BSCP exam |

Start here: the [Academy learning paths](https://portswigger.net/web-security/learning-paths)
page, Access control, first three apprentice labs.

Not in scope for now: network pentest, SOC/blue team, malware RE, ML math.
Sluice's background-traffic view (M3.5) and transparent capture (M9) wait
until after M6.5 for that reason.
