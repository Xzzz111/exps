# Orion-ops user update endpoint allows horizontal privilege abuse

# NAME OF AFFECTED PRODUCT(S)

- Orion-ops (server component)

## Vendor Homepage

- https://github.com/lijiahangmax/orion-ops

# AFFECTED AND/OR FIXED VERSION(S)

## submitter

- sh7err@vEcho

## VERSION(S)

- <= master commit 5925824997a3109651bbde07460958a7be249ed1 (no official fix published)

## Software Link

- https://github.com/lijiahangmax/orion-ops

# PROBLEM TYPE

## Vulnerability Type

- Improper authorization leading to horizontal privilege escalation (CWE-269)

## Root Cause

- `UserController#update` exposes `POST /orion/api/user/update` without `@RequireRole`. It sets `request.id` to either the caller-provided value or the current user ID. Because the controller does not override attacker-supplied IDs, `UserServiceImpl#updateUser` happily updates any user record. The service only protects the `roleType` field (requiring administrator status for role changes), but it still lets the caller set `status`, `nickname`, `phone`, and `email`. A regular account can therefore disable administrator accounts or tamper with their metadata simply by posting another user’s ID.

## Impact

- Any authenticated user can disable other accounts, including administrators, by setting their status to “disabled”, effectively causing a denial of service for legitimate operators. Attackers can also overwrite contact details or execute phishing/social-engineering attacks using the impersonated data.

# DESCRIPTION

- Orion-ops intends `/user/update` to let users edit their own profile. However, the implementation never enforces that invariant. The controller trusts the supplied `id` and the service layer does not compare it to `Currents.getUserId()`. Therefore, any session can update any row in `user_info`, with only the `roleType` field being guarded. This contradicts the intended design and gives low-privilege users leverage to lock out administrators or tamper with audit-relevant information.

# Code Analysis

- `orion-ops-api/orion-ops-web/src/main/java/cn/orionsec/ops/controller/UserController.java:86-128`
- `orion-ops-api/orion-ops-service/src/main/java/cn/orionsec/ops/service/impl/UserServiceImpl.java:141-214`

# Proof of Concept

1. Authenticate as a normal user (role = developer or operator).
2. Send `POST /orion/api/user/update` with body `{"id":1,"status":2}` where `1` is the administrator account ID and `2` represents “disabled”.
3. The API returns success and the admin can no longer log in because their account was disabled by the attacker.

# Suggested Remediation

- Require administrator privileges for modifying any account other than the caller’s own record.
- In the service layer, enforce `request.id == Currents.getUserId()` for non-admin sessions before applying updates.
- Split the API into “self profile update” and “administrative user management” endpoints with explicit authorization checks.
