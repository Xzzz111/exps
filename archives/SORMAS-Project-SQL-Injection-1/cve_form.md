## CVE Submission Form

- **Vulnerability type info:** SQL Injection
- **Vendor of the product(s) info:** SORMAS Foundation
- **Affected product(s)/code base info:**
  - Product: SORMAS (SORMAS-Project)
  - Version: development branch up to commit 14dbe7eea5b6a7c27552b4d46d0cc40912e59a70 (no fix available)
- **Has vendor confirmed or acknowledged the vulnerability:** No
- **Attack type info:** Remote
- **Impact info:** Information Disclosure
- **Affected component(s):** `sormas-backend/src/main/java/de/symeda/sormas/backend/caze/CaseStatisticsFacadeEjb.java`, `sormas-ui/src/main/java/de/symeda/sormas/ui/statistics/StatisticsView.java`, `sormas-ui/src/main/java/de/symeda/sormas/ui/statistics/StatisticsFilterSimpleTextElement.java`
- **Attack vector(s):** Authenticated users can inject SQL through the “Residence → City/Postcode” filters in the statistics dashboard (or equivalent Vaadin RPC requests), causing the backend to append attacker-controlled predicates to native queries.
- **Suggested description of the vulnerability for use in the CVE info:** A SQL injection vulnerability in the statistics module of SORMAS up to commit 14dbe7eea5b6a7c27552b4d46d0cc40912e59a70 allows authenticated users to craft city or postal code filters that are concatenated into native SQL without parameterization, enabling privilege bypass and disclosure of arbitrary data.
- **Discoverer(s)/Credits info:** sh7err
- **Reference(s) info:**
  - https://github.com/sormas-foundation/SORMAS-Project
- **Additional information:** Preliminary CVSS v3.1 base score 8.2 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N); no vendor fix available at submission time.

