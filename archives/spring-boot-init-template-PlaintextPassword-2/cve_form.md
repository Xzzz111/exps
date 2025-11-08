# CVE Request Form – spring-boot-init-template Plaintext Password Storage

**Vulnerability type info**: Plaintext Storage of Passwords (CWE-256)

**Vendor of the product(s) info**: AntonyCheng (spring-boot-init-template project maintainer)

**Affected product(s)/code base info**:
- Product: spring-boot-init-template
- Version: v2.2.1-jdk17-pre (latest main branch). No patched version is published.

**Has vendor confirmed or acknowledged the vulnerability**: No

**Attack type info**: Local (requires read access to the application database, backups, or logs)

**Impact info**: Information Disclosure, Escalation of Privileges (attackers can log in as any user once passwords are revealed)

**Affected component(s)**: `AuthServiceImpl.register/login`, `UserServiceImpl.addUser/resetPassword/updatePassword/importUser`, database schema `t_user` initialized in `sql/db/init_db.sql`

**Attack vector(s)**: An adversary who obtains a copy of the database (through SQL injection, backup exposure, insider access, etc.) reads the `t_user.user_password` column and retrieves every user’s real password because no hashing or salting is performed anywhere in the code base.

**Suggested description of the vulnerability for use in the CVE info**:
`spring-boot-init-template v2.2.1-jdk17-pre stores all user passwords in plaintext and validates them through direct string comparison. Anyone who gains access to the database or backups immediately obtains the real passwords for every account, enabling credential theft and privilege escalation. The project provides no option to hash passwords.`

**Discoverer(s)/Credits info**: sh7err@vEcho

**Reference(s) info**:
https://github.com/AntonyCheng/spring-boot-init-template

**Additional information**: The default SQL seed data also hard-codes plaintext passwords (`xAXL594fo95Auh35w1kzIA==`), demonstrating that this behavior is intentional in the current release.

