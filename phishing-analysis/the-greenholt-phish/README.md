\# The Greenholt Phish — Phishing Email Investigation



\## 1. Investigation Overview



| Field | Details |

|---|---|

| Platform | TryHackMe |

| Learning Path | SOC Level 1 |

| Module | Phishing Analysis |

| Room | The Greenholt Phish |

| Analyst | Erick Hambardzumyan |

| Investigation Date | November 18, 2026 |

| Incident Type | Phishing — Malicious Attachment |

| Severity | High |

| Verdict | True Positive |

| Confidence | High |

| Investigation Status | Completed |

| Recommended Disposition | Escalate to Tier 2 |

| Endpoint Compromise | Not Established |



\## 2. Executive Summary



A suspicious email claiming to contain confirmation of a

$149,650 SWIFT financial transfer was investigated to

determine whether it represented a phishing attempt.



The investigation consisted of email header analysis,

sender authentication analysis, social engineering

analysis, static attachment analysis, and open-source

threat intelligence gathering.



Analysis revealed an SPF authentication failure,

inconsistent sender and Reply-To domains, and a suspicious

attachment presented as a financial payment receipt.



Although the attachment had a .CAB extension and contained

the term PDF in its filename, file signature analysis

identified it as a RAR version 5 archive.



A VirusTotal hash lookup revealed that 49 of 64 security

vendors classified the attachment as malicious, with

detections associated with trojan and ransomware categories.



Based on the collected evidence, the email was classified

as a True Positive phishing incident with High severity

and High confidence.



No evidence of successful payload execution or endpoint

compromise was established.



\## 3. Investigation Objectives



\- Examine suspicious email metadata and content.

\- Identify sender inconsistencies and potential impersonation.

\- Evaluate email authentication mechanisms.

\- Identify relevant sending infrastructure.

\- Analyze attachment metadata and actual file type.

\- Calculate cryptographic file hashes.

\- Conduct IP and file reputation analysis.

\- Identify indicators of compromise (IOCs).

\- Map observed behavior to MITRE ATT\&CK.

\- Recommend appropriate incident response actions.



\## 4. Tools Used



| Tool | Purpose |

|---|---|

| Mozilla Thunderbird | Email and raw header analysis |

| Linux File Manager | Attachment metadata inspection |

| Linux Terminal | Static file analysis |

| file | File signature and type identification |

| md5sum | MD5 hash calculation |

| sha256sum | SHA-256 hash calculation |

| AbuseIPDB | Public IP reputation analysis |

| VirusTotal | File hash reputation and malware classification |

| MITRE ATT\&CK | Adversary technique mapping |



\## 5. Investigation Process



\### 5.1 Initial Email Triage



\*\*Methodology:\*\*



The suspicious email was examined in Thunderbird to

identify its sender, recipient, subject, message content,

and attachment.



\*\*Findings:\*\*



| Attribute | Observed Value |

|---|---|

| Sender Display Name | Mr. James Jackson |

| Sender Address | info\[@]mutawamarine\[.]com |

| Recipient | webmaster\[@]redacted\[.]org |

| Claimed Organization | SEC Marine Services PTE LTD |

| Claimed Department | Accounts Payable |

| Email Date | June 10, 2020 (UTC) |

| Email Theme | SWIFT financial transfer |

| Claimed Transfer Amount | $149,650 USD |

| Attachment Present | Yes |



\*\*Analysis:\*\*



The sender claimed that a financial transfer had been

successfully completed and that a payment receipt was

attached to the email.



The financial nature of the message, substantial transfer

amount, and suspicious attachment warranted further

investigation.



\*\*Supporting Evidence:\*\*



!\[Initial Email](screenshots/01-initial-email.png)



\### 5.2 Email Header Analysis



\*\*Methodology:\*\*



The raw email headers were examined to identify sender

metadata, reply destinations, mail routing information,

and spam filtering results.



\*\*Findings:\*\*



| Header Field | Observed Value |

|---|---|

| From | info\[@]mutawamarine\[.]com |

| Reply-To | info.mutawamarine\[@]mail\[.]com |

| Return-Path | info\[@]mutawamarine\[.]com |

| Public Sending IP Candidate | 192\[.]119\[.]71\[.]157 |

| Sending Hostname | hwsrv-737338.hostwindsdns\[.]com |

| Private IP 1 | 10.201.192.162 |

| Private IP 2 | 10.197.41.148 |

| X-Spam-Status | No |

| Reported Spam Score | -0.5 |

| Spam Threshold | 5.0 |



\*\*Analysis:\*\*



The From and Reply-To addresses use different domains,

indicating that responses would be directed to a mailbox

different from the apparent sender.



This discrepancy may represent an attempt to redirect

communication to an alternative mailbox.



The Received headers identified a public sending server

IP address associated with Hostwinds infrastructure.



Two RFC 1918 private IP addresses were also identified.

These appear to represent internal mail processing and

relay infrastructure and were excluded from public

reputation analysis.



The exact originating endpoint could not be established

because portions of the email headers were redacted.



The spam filtering headers indicated that the message

was not classified as spam by the recorded filtering

system. The reported score was below the configured

spam threshold.



This demonstrates the importance of validating suspicious

messages rather than relying solely on automated

spam classifications.



\*\*Supporting Evidence:\*\*



!\[Email Headers Part 1](screenshots/02-email-headers-p1.png)



!\[Email Headers Part 2](screenshots/02-email-headers-p2.png)



\### 5.3 Email Authentication Analysis



\*\*Methodology:\*\*



The Received-SPF and Authentication-Results headers

were examined to assess sender authentication.



| Mechanism | Result | Interpretation |

|---|---|---|

| SPF | Fail | Evaluated sending server was not authorized for the envelope sender domain |

| DKIM | Not Available | No verification result was observed |

| DMARC | Unknown | Authentication status could not be established |



\*\*Analysis:\*\*



The SPF failure indicates that the connecting server

evaluated by the receiving mail infrastructure was

not authorized to send email for the checked domain.



This finding, combined with the inconsistent From and

Reply-To domains, increases suspicion of unauthorized

sender activity.



The SPF-evaluated IP address was redacted. Therefore,

the failure cannot be directly attributed to the

identified public sending IP.



SPF failure alone does not conclusively establish

malicious intent. However, it contributes to the

overall phishing assessment when combined with the

remaining evidence.



\*\*Supporting Evidence:\*\*



!\[Email Authentication Results](screenshots/03-authentication-results.png)



\### 5.4 Email Body and Social Engineering Analysis



\*\*Methodology:\*\*



The email subject, message content, claimed identity,

financial details, and attachment naming convention

were examined to identify social engineering techniques.



\*\*Findings:\*\*



\- The sender impersonated or presented themselves

&#x20; as an accounts payable representative.

\- The message claimed that a SWIFT financial transfer

&#x20; had been successfully completed.

\- The claimed transfer amount was $149,650 USD.

\- Transaction details and a reference number were

&#x20; included to establish credibility.

\- The attachment was presented as a payment receipt.

\- The attachment filename contained the term PDF.



\*\*Analysis:\*\*



The message uses financial pretexting to establish

a seemingly legitimate business context.



The inclusion of transaction details, bank charges,

a reference number, and a professional signature

may increase the perceived authenticity of the email.



The substantial payment amount could exploit the

recipient's curiosity or desire to verify the transaction.



The likely attacker objective was to persuade the

recipient to open the attached archive under the

assumption that it contained a legitimate payment receipt.



This objective is inferred from the available evidence.

Successful recipient interaction was not established.



\### 5.5 Attachment Analysis



\#### Attachment Metadata



\*\*Methodology:\*\*



The attachment was saved within the authorized lab

environment and its file properties were examined

without executing its contents.



| Attribute | Finding |

|---|---|

| Filename | SWT\_#09674321\_\_\_PDF\_\_.CAB |

| File Extension | .CAB |

| File Manager Classification | Microsoft Cabinet Archive |

| Reported MIME Type | application/vnd.ms-cab-compressed |

| Actual File Type | RAR archive data, v5 |

| File Size | 409,868 bytes |

| MD5 | f4dd3456cdb1976a145c1179a4d461ec |

| SHA-256 | 2e91c533615a9bb8929ac4bb76707b2444597ce063d84a4b33525e25074fff3f |



\*\*Supporting Evidence:\*\*



!\[Attachment Properties](screenshots/05-attachment-details.png)



\#### File Signature Analysis



The Linux file utility was used to determine the

attachment's actual file type.



Command:



&#x20;   file \*.CAB



Result:



&#x20;   RAR archive data, v5



\*\*Analysis:\*\*



Three different file identities were identified:



\- Apparent document type: PDF.

\- Declared file extension: CAB.

\- Actual file signature: RAR version 5 archive.



The discrepancy between the filename, extension,

and actual file signature indicates potential

file masquerading.



The file manager initially classified the attachment

as a Microsoft Cabinet archive. However, the Linux

file utility identified it as a RAR archive based

on its contents.



This highlights the importance of verifying file

signatures rather than trusting file extensions

or graphical file classifications.



\#### Cryptographic Hash Calculation



The attachment's MD5 and SHA-256 hashes were calculated

to uniquely identify the sample for threat intelligence

analysis.



Commands:



&#x20;   md5sum \*.CAB

&#x20;   sha256sum \*.CAB



\*\*MD5:\*\*



&#x20;   f4dd3456cdb1976a145c1179a4d461ec



\*\*SHA-256:\*\*



&#x20;   2e91c533615a9bb8929ac4bb76707b2444597ce063d84a4b33525e25074fff3f



The calculated hashes were collected without

executing the attachment.



\*\*Supporting Evidence:\*\*



!\[File Signature and Hash Analysis](screenshots/06-file-hash.png)



\### 5.6 Threat Intelligence Analysis



\#### IP Reputation Analysis



\*\*Tool:\*\* AbuseIPDB



\*\*Investigated Artifact:\*\* 192\[.]119\[.]71\[.]157



| Attribute | Finding |

|---|---|

| Abuse Confidence Score | 0% |

| Abuse Reports | None |

| ISP | Hostwinds Seattle |

| Usage Type | Data Center / Web Hosting / Transit |

| ASN | AS54290 |

| Country | United States |

| City | Dallas, Texas |

| Associated Domain | hostwinds\[.]com |

| Reputation Classification | Neutral Activity |



\*\*Analysis:\*\*



The investigated IP address was associated with

commercial hosting infrastructure.



AbuseIPDB returned an abuse confidence score of 0%

and no recorded abuse reports at the time of analysis.



These results did not independently establish

malicious activity associated with the IP address.



However, the absence of abuse reports does not

guarantee that the IP address is safe.



The original email dates back to June 2020, while

the reputation analysis was conducted in November 2026.



IP address reassignment and changes in infrastructure

reputation limit the historical relevance of the

observed results.



The IP address was therefore retained as a contextual

investigative artifact rather than a confirmed

malicious indicator.



\*\*Supporting Evidence:\*\*



!\[AbuseIPDB Results](screenshots/04-ip-reputation.png)



\#### Attachment Reputation Analysis



\*\*Tool:\*\* VirusTotal



The calculated SHA-256 hash was searched in VirusTotal

to identify existing malware analysis results.



| Attribute | Finding |

|---|---|

| Detection Ratio | 49/64 |

| Detection Percentage | 76.56% |

| Popular Threat Label | trojan.msil/loki |

| Threat Categories | Trojan, Ransomware |

| Family Labels | msil, loki, agensla |

| Identified File Type | RAR Archive |

| Reputation Assessment | Malicious |



\*\*Selected Vendor Detections:\*\*



| Security Vendor | Detection |

|---|---|

| BitDefender | Gen:Variant.Ransom.Loki.8140 |

| Avast | Win32:MalwareX-gen \[Pws] |

| ClamAV | Legacy.Trojan.Agent-1388784 |

| Antiy-AVL | Trojan/MSIL.Kryptik |

| Cynet | Malicious (score: 99) |



\*\*Analysis:\*\*



VirusTotal reported that 49 of 64 security vendors

flagged the attachment as malicious.



Multiple vendors associated the sample with trojan,

ransomware, and password-stealing malware detections.



The VirusTotal file classification also corroborated

the RAR archive identification obtained from the

Linux file utility.



The detection consensus provides strong evidence

that the attachment is malicious.



However, vendor classifications vary, and the exact

malware family and runtime capabilities cannot be

conclusively established through reputation analysis

alone.



No dynamic malware analysis was performed.



\*\*Supporting Evidence:\*\*



!\[VirusTotal Threat Intelligence](screenshots/07-virustotal-threat-intelligence.png)



\## 6. Indicators of Compromise (IOCs)



| Indicator Type | Indicator | Assessment |

|---|---|---|

| Sender Email | info\[@]mutawamarine\[.]com | Suspicious |

| Reply-To Email | info.mutawamarine\[@]mail\[.]com | Suspicious |

| IP Address | 192\[.]119\[.]71\[.]157 | Contextual artifact |

| Hostname | hwsrv-737338.hostwindsdns\[.]com | Contextual artifact |

| Domain | mutawamarine\[.]com | Requires further investigation |

| Filename | SWT\_#09674321\_\_\_PDF\_\_.CAB | Malicious attachment |

| MD5 | f4dd3456cdb1976a145c1179a4d461ec | Malicious file identifier |

| SHA-256 | 2e91c533615a9bb8929ac4bb76707b2444597ce063d84a4b33525e25074fff3f | Malicious file identifier |



The file hashes represent the investigated malicious

attachment. Other extracted artifacts are suspicious

or contextual and should not automatically be

classified as malicious.



\## 7. MITRE ATT\&CK Mapping



| Technique ID | Technique | Tactic | Supporting Evidence |

|---|---|---|---|

| T1566.001 | Spearphishing Attachment | Initial Access | Phishing email containing a malicious archive |

| T1036 | Masquerading | Defense Evasion | Discrepancy between apparent PDF identity, CAB extension, and actual RAR file signature |



\### Potential Subsequent Technique



T1204.002 — User Execution: Malicious File



The recipient would potentially need to interact with

malicious content to enable further execution.



This technique was not observed and is therefore

documented as a potential subsequent attack stage

rather than confirmed adversary behavior.



\## 8. Findings and Final Verdict



| Assessment | Result |

|---|---|

| Verdict | True Positive |

| Severity | High |

| Confidence | High |

| Attack Vector | Phishing Email Attachment |

| Suspected Objective | Malicious Payload Delivery |

| Endpoint Compromise | Not Established |

| Recommended Disposition | Escalate to Tier 2 |



\### Key Findings



1\. The email contained a financial transfer pretext

&#x20;  designed to establish credibility.

2\. The From and Reply-To addresses used different domains.

3\. SPF authentication failed.

4\. The recorded spam filter did not classify the

&#x20;  message as spam.

5\. The attachment was presented as a payment receipt.

6\. The attachment had a CAB extension but was

&#x20;  identified as a RAR version 5 archive.

7\. VirusTotal reported 49 of 64 malicious detections.

8\. The sending IP had no current AbuseIPDB reports,

&#x20;  but this did not establish historical legitimacy.



\### Severity Justification



The incident was assigned High severity due to the

delivery of a malicious attachment with potential

trojan and ransomware capabilities.



The deceptive attachment naming convention,

authentication failure, social engineering content,

and strong antivirus detection consensus create

a significant potential security risk.



Critical severity was not assigned because successful

payload execution, unauthorized access, and endpoint

compromise were not established.



This severity assessment represents an analyst judgment

for the training scenario rather than an organization-

specific severity policy.



\### Confidence Justification



High confidence was assigned because multiple independent

forms of evidence support the phishing classification,

including attachment file signature analysis,

email authentication results, social engineering

indicators, and VirusTotal detection results.



\### Potential Impact



If malicious content from the attachment were executed,

potential consequences could include:



\- Malware infection.

\- Credential theft.

\- Unauthorized system access.

\- Ransomware infection.

\- Data encryption or exposure.

\- Additional endpoint compromise.



These are potential impacts based on the observed

threat classifications, not confirmed outcomes.



\### Investigation Limitations



\- Portions of the original email headers were redacted.

\- Historical IP reputation could not be established.

\- DKIM verification results were unavailable.

\- DMARC status was unknown.

\- The attachment was not executed.

\- Dynamic malware analysis was not performed.

\- The exact malware family was not independently verified.

\- Recipient interaction and endpoint compromise

&#x20; were not established.



\### Conclusion



The investigation identified a phishing email using

financial social engineering and file masquerading

to deliver a malicious archive.



The attachment's actual file type and strong malware

detection consensus provide sufficient evidence

to classify the incident as a True Positive.



The incident warrants High severity classification

and escalation for containment and further investigation

in a real-world SOC environment.



\## 9. Recommended Incident Response Actions



\### Immediate Containment



\- Quarantine the identified phishing email.

\- Search for and remove additional copies from

&#x20; organizational mailboxes.

\- Block the confirmed malicious file hashes.

\- Prevent recipients from accessing the attachment.

\- Escalate the incident to Tier 2 for further analysis.



\### Further Investigation



\- Determine whether any recipients opened the archive

&#x20; or executed its contents.

\- Search email gateway logs for related messages.

\- Review endpoint detection and response telemetry.

\- Search for the malicious hashes across endpoints.

\- Investigate suspicious process and network activity.

\- Determine whether credentials or sensitive data

&#x20; were exposed.

\- Assess sending infrastructure before applying

&#x20; broad IP or domain blocks.



\### Prevention and Remediation



\- Isolate affected endpoints if compromise is suspected.

\- Reset exposed credentials if credential theft is suspected.

\- Improve archive and attachment inspection policies.

\- Detect discrepancies between file extensions

&#x20; and file signatures.

\- Review SPF, DKIM, and DMARC enforcement.

\- Improve phishing detection rules.

\- Conduct targeted phishing awareness training.



These actions are recommendations for a real-world

SOC environment. They were not executed during

this training investigation.



\## 10. Lessons Learned



\- Email authentication failures should be evaluated

&#x20; alongside other investigative evidence.

\- From and Reply-To discrepancies can indicate

&#x20; suspicious communication redirection.

\- Email headers provide useful infrastructure

&#x20; and routing information.

\- Private IP addresses are not suitable for

&#x20; public IP reputation lookups.

\- A clean reputation score does not guarantee

&#x20; that infrastructure is trustworthy.

\- Historical context is essential when interpreting

&#x20; current threat intelligence results.

\- File extensions and graphical classifications

&#x20; should not be trusted without verification.

\- File signature analysis can expose masqueraded files.

\- Hash-based reputation lookups allow investigation

&#x20; without executing suspicious attachments.

\- Malware vendor labels do not independently prove

&#x20; specific runtime capabilities.

\- Confirmed malicious email delivery does not

&#x20; establish successful endpoint compromise.



\## 11. Skills Demonstrated



\- Phishing Email Investigation

\- SOC Alert Triage

\- Email Header Analysis

\- SPF, DKIM, and DMARC Analysis

\- Social Engineering Analysis

\- Static File Analysis

\- File Signature Identification

\- Cryptographic Hash Calculation

\- Open-Source Threat Intelligence

\- IP and File Reputation Analysis

\- IOC Identification

\- MITRE ATT\&CK Mapping

\- Incident Severity Classification

\- Incident Response Recommendations

\- Technical Security Reporting



\## 12. References



\- \[TryHackMe — The Greenholt Phish](https://tryhackme.com/room/phishingemails5fgjlzxc)

\- \[AbuseIPDB](https://www.abuseipdb.com/)

\- \[VirusTotal](https://www.virustotal.com/)

\- \[RFC 1918 — Private Address Space](https://datatracker.ietf.org/doc/html/rfc1918)

\- \[MITRE ATT\&CK — T1566.001](https://attack.mitre.org/techniques/T1566/001/)

\- \[MITRE ATT\&CK — T1036](https://attack.mitre.org/techniques/T1036/)

\- \[MITRE ATT\&CK — T1204.002](https://attack.mitre.org/techniques/T1204/002/)

\- \[NIST — Incident Response Recommendations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)



\---



\## Disclaimer



This investigation was conducted in an authorized

cybersecurity training environment for educational

and professional development purposes.



The investigation focuses on defensive security

practices, analytical reasoning, threat intelligence,

and incident response methodology.



