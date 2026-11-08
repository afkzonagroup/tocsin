# Legal mapping

What Tocsin implements, where it comes from, and how the text was read. The texts were read on EUR-Lex on 8 November 2026 in English. Quotations are from the official English versions. EU legislation may be reused with acknowledgement of the source (Commission Decision 2011/833/EU).

This document is not legal advice. National transposition laws decide the details of reporting in each Member State.

## Sources

| Act | Link | Status checked on 8 Nov 2026 |
|---|---|---|
| Directive (EU) 2022/2555 (NIS2) | [EUR-Lex CELEX 32022L2555](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32022L2555) | In force. Member States apply their measures from 18 October 2024 (Art 41(1)). The only corrigendum covering the English text (OJ L, 22.12.2023) changes Article 19(1) and does not touch Article 6 or 23. EUR-Lex lists two amendment *proposals*, COM(2025) 837 and COM(2026) 13. They are not law; Tocsin follows the text in force. |
| Commission Implementing Regulation (EU) 2024/2690 | [EUR-Lex CELEX 32024R2690](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R2690) | In force since 7 November 2024. Its three corrigenda concern the Polish, Swedish and Dutch versions only. |
| Regulation (EEC, Euratom) No 1182/71 | [EUR-Lex CELEX 31971R1182](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:31971R1182) | Read for the interpretation of time periods (see below). |

## Article 23 NIS2: reporting stages

| Stage | Official text (Art 23(4)) | Tocsin |
|---|---|---|
| Early warning | "(a) without undue delay and in any event within 24 hours of becoming aware of the significant incident, an early warning, which, where applicable, shall indicate whether the significant incident is suspected of being caused by unlawful or malicious acts or could have a cross-border impact" | Deadline: aware + 24 h. Elements: suspected unlawful or malicious acts; possible cross-border impact (both "where applicable"). |
| Incident notification | "(b) without undue delay and in any event within 72 hours of becoming aware of the significant incident, an incident notification, which, where applicable, shall update the information referred to in point (a) and indicate an initial assessment of the significant incident, including its severity and impact, as well as, where available, the indicators of compromise" | Deadline: aware + 72 h. Elements: initial assessment (severity, impact), IoCs where available, update of the point (a) information. |
| Trust service providers | "By way of derogation from the first subparagraph, point (b), a trust service provider shall, with regard to significant incidents that have an impact on the provision of its trust services, notify the CSIRT or, where applicable, the competent authority, without undue delay and in any event within 24 hours of becoming aware of the significant incident." | Notification deadline aware + 24 h when the incident affects a trust service. If that impact is not yet answered, Tocsin uses the earlier deadline and says so. |
| Intermediate report | "(c) upon the request of a CSIRT or, where applicable, the competent authority, an intermediate report on relevant status updates" | Recorded per request. No deadline unless the request sets one. Element: relevant status updates. |
| Final report | "(d) a final report not later than one month after the submission of the incident notification under point (b), including the following: (i) a detailed description of the incident, including its severity and impact; (ii) the type of threat or root cause that is likely to have triggered the incident; (iii) applied and ongoing mitigation measures; (iv) where applicable, the cross-border impact of the incident" | Deadline: notification **submission** + one calendar month. Before the notification is submitted, the date is shown as an estimate from the notification deadline. Elements (i)-(iv) exactly. |
| Progress report | "(e) in the event of an ongoing incident at the time of the submission of the final report referred to in point (d), Member States shall ensure that entities concerned provide a progress report at that time and a final report within one month of their handling of the incident." | If handling has not concluded by the final-report deadline: progress report due then, final report due one month after handling concluded. Point (e) lists no content; Tocsin asks for a "progress status" and labels it as its own minimum. |

Every stage: "without undue delay" (Art 23(1) and 23(4)). The hour and month limits are outer limits.

Other parts of Article 23 used:

- **Art 23(1), first subparagraph**: notification goes to "its CSIRT or, where applicable, its competent authority". Tocsin has no built-in recipients; you configure yours. The same sentence requires information "enabling the CSIRT or, where applicable, the competent authority to determine any cross-border impact". Tocsin asks for cross-border details and the Member States concerned.
- **Art 23(1), second sentence**: "Where appropriate, entities concerned shall notify, without undue delay, the recipients of their services of significant incidents that are likely to adversely affect the provision of those services." Tocsin asks whether recipients are likely to be affected, shows a reminder without a date, and records communications.
- **Art 23(2)**: communication of measures or remedies to recipients potentially affected by a significant cyber threat, and where appropriate of the threat itself. Recorded as a communication of kind "cyber threat (Art 23(2))".
- **Art 23(3)**: "An incident shall be considered to be significant if: (a) it has caused or is capable of causing severe operational disruption of the services or financial loss for the entity concerned; (b) it has affected or is capable of affecting other natural or legal persons by causing considerable material or non-material damage." For entities outside IR 2024/2690, Tocsin asks these two questions and does not decide them.
- **Art 23(5)-(11)** are duties of authorities and the Commission. Not implemented.

## Article 6 NIS2: definitions used

- (6) "incident": "an event compromising the availability, authenticity, integrity or confidentiality of stored, transmitted or processed data or of the services offered by, or accessible via, network and information systems".
- (8) "incident handling": "any actions and procedures aiming to prevent, detect, analyse, and contain or to respond to and recover from an incident". Used for "handling concluded".
- (11) "significant cyber threat", (5) "near miss": not recorded as incidents.
- (19)-(21), (24)-(25), (28)-(33), (39)-(40): definitions of the service types (DNS service provider, TLD name registry, trust service provider, online marketplace, online search engine, cloud computing service, data centre service, content delivery network, social networking services platform, managed service provider, managed security service provider). The user chooses the type; Tocsin does not classify entities.

## Implementing Regulation (EU) 2024/2690: significant incidents

The Regulation applies to the "relevant entities" of its Article 1: DNS service providers, TLD name registries, cloud computing service providers, data centre service providers, content delivery network providers, managed service providers, managed security service providers, providers of online marketplaces, of online search engines and of social networking services platforms, and trust service providers. Recital 30: the criteria "should be considered exhaustive, without prejudice to Article 5 of Directive (EU) 2022/2555".

"More than" and "exceeds" are strict. "Whichever number is smaller / lower" is computed exactly with integers (count × 20 > total for 5 %, × 100 for 1 %, × 1000 for 0,1 %).

### Article 3(1): every relevant entity

| Point | Criterion (official text, shortened only where marked …) | Tocsin |
|---|---|---|
| (a) | "direct financial loss for the relevant entity that exceeds EUR 500 000 or 5 % of the relevant entity's total annual turnover in the preceding financial year, whichever is lower" | Loss in cents vs. configured turnover. Without turnover, a loss above EUR 500 000 is "met" and anything lower is "unknown". |
| (b) | "the exfiltration of trade secrets as set out in Article 2 point (1), of Directive (EU) 2016/943" | Yes/no question. |
| (c) | "the death of a natural person" | Yes/no question. |
| (d) | "considerable damage to a natural person's health" | Yes/no question (recital 37 hint). |
| (e) | "a successful, suspectedly malicious and unauthorised access to network and information systems occurred, which is capable of causing severe operational disruption" | Two yes/no questions, both must be yes. |
| (f) | "the incident meets the criteria set out in Article 4" | Recurring-incident check across the register. |
| (g) | "the incident meets one or more of the criteria set out in Articles 5 to 14" | Per service type, below. |

All of (a)-(e) say "has caused or is capable of causing". The questions use the same words.

**Art 3(2)**: "Scheduled interruptions of service and planned consequences of scheduled maintenance operations carried out by or on behalf of the relevant entities shall not be considered to be significant incidents." Asked as a question; "yes" makes the outcome "not significant".

**Art 3(3)**: how to count users (contract customers, and persons associated with business customers). Shown as help text. Recital 32: if users cannot be counted, use the estimate of the possible maximum.

### Article 4: recurring incidents

"Incidents that individually are not considered a significant incident within the meaning of Article 3, shall be considered collectively as one significant incident where they meet all of the following criteria: (a) they have occurred at least twice within 6 months; (b) they have the same apparent root cause; (c) they collectively meet the criteria set out in Article 3(1)(a)."

### Articles 5 to 14: by service type

| Article | Type | Thresholds in Tocsin |
|---|---|---|
| 5 | DNS | (a) completely unavailable > 30 min; (b) average response time > 10 s for a period > 1 h; (c) integrity, confidentiality or authenticity of data for the authoritative service compromised, **except** where fewer than 1 000 domain names, no more than 1 % of those managed, are incorrect because of misconfiguration |
| 6 | TLD name registry | (a) authoritative service completely unavailable (any duration); (b) average response time > 10 s for > 1 h; (c) data related to the technical operation of the TLD compromised |
| 7 | Cloud | (a) completely unavailable > 30 min; (b) availability limited for > 5 % of EU users or > 1 000 000 (smaller), for > 1 h; (c) data compromised as a result of a suspectedly malicious action; (d) data compromised with impact on > 5 % or > 1 000 000 EU users (smaller) |
| 8 | Data centre | (a) a data centre service completely unavailable (any duration); (b) availability limited > 1 h; (c) data compromised by suspectedly malicious action; (d) physical access to a data centre compromised |
| 9 | CDN | as Article 7 |
| 10 | Managed (security) service | as Article 7 |
| 11 | Online marketplace | (a) completely unavailable for > 5 % or > 1 000 000 EU users (smaller); (b) > 5 % or > 1 000 000 EU users (smaller) impacted by limited availability; (c) as 7(c); (d) as 7(d) |
| 12 | Online search engine | as Article 11 |
| 13 | Social networking platform | as Article 11 |
| 14 | Trust service | (a) completely unavailable > 20 min; (b) unavailable to users or relying parties > 1 h "calculated on a calendar week basis"; (c) > 1 % or > 200 000 users or relying parties (smaller) impacted by limited availability; (d) physical access to restricted areas, or its protection, compromised; (e) data compromised with impact on > 0,1 % or > 100 users or relying parties (smaller) |

Measurements follow recitals 34 (duration from disruption to recovery; if the start is unknown, from detection or earliest log record), 35 (complete unavailability), 36 (what counts as direct financial loss) and 38 (limited availability: considerably slower than average, or not all functionalities).

## Interpretation choices

These are the readings Tocsin uses. Where a reading is uncertain, Tocsin picks the one that gives the **earlier** deadline or reports **more**, because reporting early is never a breach.

1. **Becoming aware.** The clocks start when the user records awareness. Recital 31 IR 2024/2690: an entity is aware "when, after such initial assessment, that entity has a reasonable degree of certainty that a significant incident has occurred". Tocsin does not set this time itself.
2. **Hours are elapsed time.** 24 h and 72 h are added as exact milliseconds to the stored UTC instant. Across a daylight-saving change the wall-clock deadline moves by one hour (e.g. aware 28 March 12:00 EET → early warning due 29 March 13:00 EEST).
3. **"One month" is a calendar month in the configured time zone.** Same day and same wall-clock time in the next month. If that day does not exist, the last day of the month is used: 31 January → 28 February (29 in leap years); 31 March → 30 April. If the resulting wall-clock time happens twice (clocks go back), the first occurrence is used. If it does not exist (clocks skip it), it is read with the offset in force after the change, which is the earlier of the two possible instants: 02:30 on the day clocks jump from 02:00 to 03:00 becomes 01:30 local time.
4. **Regulation 1182/71 is not applied.** That Regulation (Art 3) would exclude the hour or day of the triggering event and let month periods end at the end of the last day. It addresses acts of the Council and Commission; NIS2 obligations reach entities through national law, which has its own rules. Tocsin's deadlines are therefore the same as or earlier than a 1182/71 reading. National transposition law decides how its periods are counted. It cannot give more time than the Directive's outer limits, but under Article 5 NIS2 (minimum harmonisation) it may set stricter requirements, including shorter deadlines; check it.
5. **Final report before the notification is sent.** Point (d) counts from the *submission* of the notification. Until it is submitted, Tocsin shows the final-report date as an estimate counted from the notification deadline.
6. **Progress report.** Shown as due only when handling has not concluded by the final-report deadline (or a progress report was already sent). "Handling" uses the Article 6(8) definition.
7. **"Within 6 months" (IR Art 4).** The later incident occurred no later than six calendar months after the earlier one, boundary included. "Same apparent root cause" is your label (`rootCauseKey`).
8. **Unknown trust-service impact.** For trust service providers, the 24-hour notification deadline applies unless you answer that the incident does not affect the provision of trust services.
9. **Exceeding a share.** "More than 5 % … or more than 1 million …, whichever number is smaller" is "more than the smaller of the two numbers", computed without rounding.

## How the deadlines are tested

The deadline code (`src/stages/deadlines.ts`, `src/time/`) is checked against a second calculator written separately from the readings above (`test/oracle/deadline-oracle.ts`). It has its own calendar-month and time-zone arithmetic.

`test/deadline-oracle.test.ts` compares the two over 20,000 generated incidents in nine time zones. These include 30-minute daylight-saving changes (Lord Howe), negative daylight-saving time (Dublin), changes at midnight (Santiago) and UTC+12:45 (Chatham).

The awareness times cluster 24 hours, 72 hours and about one month before clock changes, and around month ends and 29 February. The generated incidents cover:
- submissions on time and late;
- awareness times corrected after reports were sent;
- trust service providers with each possible answer;
- progress reports, handling concluded or not;
- intermediate requests.

All cases agree. The disagreements found while building the oracle came from impossible generated states, such as a final report submitted before handling concluded, which Tocsin refuses. None was a different reading of the law.

The test fails if:
- the notification deadline changes by one hour;
- calendar months are counted in UTC;
- an unanswered trust-service question stops counting as yes.

## What is not covered

- National rules: reporting portals, forms, languages, extra fields, sector rules and any national thresholds for entities outside IR 2024/2690.
- Other reporting regimes that may apply to the same incident: personal-data breach notification under Articles 33 and 34 GDPR, Regulation (EU) 2022/2554 (DORA) for financial entities (see Article 4 NIS2 on sector-specific acts), Directive (EU) 2022/2557 (CER), and sector rules.
- Whether an organisation is an essential or important entity (Articles 2 and 3 NIS2).
- Voluntary notifications (Article 30) and near misses.
