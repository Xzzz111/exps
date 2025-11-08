# Vulnerability Report – Plaintext Password Storage in spring-boot-init-template

## Summary
The Spring Boot starter project `spring-boot-init-template` (version v2.2.1-jdk17-pre) persists user passwords in plaintext and validates logins through raw string comparison. Because there is no hashing or salting anywhere in the registration, import, or update flows, compromise of the application database or logs immediately reveals every user’s real password. This contradicts security best practices and enables trivial credential theft.

- **Submitter**: sh7err@vEcho
- **CWE**: CWE-256 – Plaintext Storage of a Password
- **Severity**: High

## Product & Component
- **Product**: spring-boot-init-template
- **Version**: v2.2.1-jdk17-pre
- **Components**:
  - `src/main/java/top/sharehome/springbootinittemplate/service/impl/AuthServiceImpl.java` (`register`, `login`, `checkEmailCode`)
  - `src/main/java/top/sharehome/springbootinittemplate/service/impl/UserServiceImpl.java` (`addUser`, `resetPassword`, `updatePassword`, `importUser`)
  - Seed data in `sql/db/init_db.sql` stores default passwords as the literal string `xAXL594fo95Auh35w1kzIA==`.

None of these locations call a password encoder or hashing utility; the values taken from HTTP bodies are saved directly in `t_user.user_password`.

## Technical Details
1. User registration and import invoke `new User().setPassword(authRegisterDto.getPassword())` and persist the entity with MyBatis. There is no intermediary hashing step.
2. During login, `AuthServiceImpl.login` executes:

```java
if (!Objects.equals(userInDatabase.getPassword(), authLoginDto.getPassword())) {
    // treat as wrong password
}
```

This direct string comparison confirms that stored values are expected to match the raw password typed by the user.
3. Password resets (`UserServiceImpl.resetPassword`, `updatePassword`, bulk import) follow the same pattern and therefore keep plaintext secrets in the database.
4. By inspecting the `t_user` table (e.g., via `SELECT user_account, user_password FROM t_user;`) an attacker immediately learns every user’s password and can re-use them on other services.

## Proof of Concept
1. Register a new user with password `P@ssw0rd!` through `/auth/register`.
2. Query the database: `SELECT user_password FROM t_user WHERE user_account='test';`.
3. The result returns exactly `P@ssw0rd!`, demonstrating plaintext storage. The login logic also compares this literal string.

## Impact
- Total compromise of every account once the database, a backup, or a log statement is leaked.
- Offline brute-force attacks are trivial because the attacker already holds the plaintext; no hashing cost exists.
- Violates compliance requirements (e.g., GDPR, PCI DSS) and exposes users who reuse credentials elsewhere.

## Remediation
- Introduce a strong password hashing mechanism such as BCrypt, Argon2, or PBKDF2 via Spring Security’s `PasswordEncoder`.
- Hash passwords before persistence in every code path (registration, import, reset, admin edits) and use `passwordEncoder.matches()` during authentication.
- Immediately force password rotation and purge existing plaintext values after deploying the fix.

## References
- Project repository: https://github.com/AntonyCheng/spring-boot-init-template

