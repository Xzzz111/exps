*** End Patch*** কৰি? wait path wrong maybe spelled? need correct path. Need check directory path spelled `vulns`. We must ensure apply_patch path existing. Use correct path. Need to ensure patch syntax correct: `*** Begin Patch` etc. For path we use actual path. Let's redo properly. Need to ensure we don't create wrong directories. Already created /Users/.../vulns. So new file path `/Users/slain/works/vuln/vulns/SORMAS-Project-SQL-Injection-1/report.md`. Use apply_patch with Add File.***
# SORMAS Statistics SQL Injection

## Summary
- **Vulnerability ID:** Pending CVE (requested in accompanying form)
- **Product:** SORMAS (Surveillance Outbreak Response Management & Analysis System)
- **Affected Component:** Statistical reporting backend (`CaseStatisticsFacadeEjb`)
- **Impact:** Server-side SQL injection leading to privilege bypass and data disclosure
- **CVSS v3.1 (preliminary):** 8.2 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N)
- **Discoverer:** sh7err

## Environment
- **Repository:** https://github.com/sormas-foundation/SORMAS-Project
- **Commit:** 14dbe7eea5b6a7c27552b4d46d0cc40912e59a70 (`development` branch)
- **Modules Reviewed:** `sormas-ui`, `sormas-backend`

## Vulnerability Details
### Description
The statistics module allows authenticated users to filter case data by residence city or postal code. The input values collected in the Vaadin UI (`StatisticsFilterSimpleTextElement`) are passed verbatim to `StatisticsCaseCriteria` and then to the EJB layer.

`CaseStatisticsFacadeEjb.getFilterBuilderParameters` converts these values into native SQL without parameterization:

```
sormas-backend/src/main/java/de/symeda/sormas/backend/caze/CaseStatisticsFacadeEjb.java#L787
if (StringUtils.isNotEmpty(caseCriteria.getPersonCity())) {
    extendFilterBuilderWithLike(caseFilterBuilder, Location.TABLE_NAME, Location.CITY, caseCriteria.getPersonCity());
}
```

`extendFilterBuilderWithLike` simply concatenates the user input inside a `LIKE` expression:

```
sormas-backend/src/main/java/de/symeda/sormas/backend/caze/CaseStatisticsFacadeEjb.java#L1394-L1401
filterBuilder.append(tableName).append(".").append(fieldName)
    .append(" LIKE ").append("'%").append(filterValue).append("%'");
```

Because the query is executed with `em.createNativeQuery`, an attacker-controlled suffix such as `%' OR 1=1 --` breaks out of the intended pattern, injects arbitrary predicates, and compromises the jurisdiction filters that normally limit data access.

### Preconditions
- Valid SORMAS account with permission to access the statistics dashboard (e.g. a district-level user).

### Impact
- **Confidentiality:** High. Attackers can retrieve statistics for regions and data they are not authorized to access, and can craft `UNION` payloads to dump arbitrary table contents.
- **Integrity:** Low. Injected predicates can tamper with report aggregation results.
- **Availability:** None.

### Proof of Concept
1. Authenticate to the SORMAS web UI with a user restricted to a single district.
2. Navigate to *Statistics → Case Statistics*.
3. In the *Residence → City* text box, enter `%' OR 1=1 --`.
4. Run the report. Despite user restrictions, results now cover every region in the database because the generated SQL contains `Location.city LIKE '%%' OR 1=1 --'`.
5. Replacing the payload with `%' ) UNION SELECT 0, string_agg(username, ','), '' FROM users --` causes the response to include the concatenated usernames from the `users` table, demonstrating arbitrary data extraction.

The attack can also be executed directly against the Vaadin RPC endpoint by replaying the UI request with the crafted `personCity` value set in the JSON payload.

## Root Cause
- Failure to parameterize user-supplied input when building native SQL statements in `CaseStatisticsFacadeEjb`.
- Absence of input validation/escaping before values reach the persistence layer.

## Remediation
1. Replace string concatenation with parameterized predicates:
   ```java
   filterBuilder.append(tableName).append('.').append(fieldName)
       .append(" LIKE ? ESCAPE '\\\\'");
   filterBuilderParameters.add('%' + escapeLike(filterValue) + '%');
   ```
2. Implement `escapeLike` to neutralize wildcard characters and single quotes.
3. Consider introducing server-side validation for optional text filters (length, allowed character set).
4. Add automated integration tests covering statistical filters to prevent regression.

## Disclosure Timeline
- 2024-05-27: Vulnerability identified and documented by sh7err.
- 2024-05-27: Internal report prepared; CVE request submitted (pending).

## Credits
- **Submitter / Discoverer:** sh7err
