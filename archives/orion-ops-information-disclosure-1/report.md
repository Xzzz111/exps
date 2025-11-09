# Orion-ops machine key API exposes private keys

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

- Improper authorization leading to sensitive information disclosure (CWE-285)

## Root Cause

- The authenticated REST endpoints `POST /orion/api/machine-key/list`, `POST /orion/api/machine-key/detail`, and `POST /orion/api/file-download/token`/`GET /orion/api/file-download/{token}/exec` are reachable to every logged-in user. `MachineKeyController` never enforces `@RequireRole`, so any session can enumerate every stored SSH key ID and the corresponding internal file path. `FileDownloadServiceImpl#getDownloadToken` accepts any key ID and returns a short-lived download token without checking whether the requester is the owner of the underlying machine (`Currents.getUserId()` is written to Redis but never revalidated). `execDownload` simply streams the referenced file back to the caller. As a result, a low-privileged account can download every SSH private key that administrators imported.

## Impact

- Attackers can download all registered SSH private keys, impersonate the automation server when connecting to production hosts, bypass any protections implemented by Orion-ops, and pivot further inside the victim infrastructure.

# DESCRIPTION

- Orion-ops uses the `MachineKeyController` to manage SSH key material that is later injected into deployment workflows. The controller exposes listing and detail endpoints without narrowing the caller’s role. In the download path, `FileDownloadServiceImpl` trusts the provided `id` and never checks that the requesting user actually owns, uploaded, or has any relationship with that key. The download tokens are therefore unscoped and reusable by any session. This behavior is inconsistent with the intent of storing sensitive SSH credentials on the server side and results in total disclosure of the stored secrets.

# Code Analysis

- `orion-ops-api/orion-ops-web/src/main/java/cn/orionsec/ops/controller/MachineKeyController.java:87-109`
- `orion-ops-api/orion-ops-service/src/main/java/cn/orionsec/ops/service/impl/FileDownloadServiceImpl.java:93-205`

# Proof of Concept

1. Authenticate as any non-admin user (e.g., demo account).
2. Request `POST /orion/api/machine-key/list {"page":1,"limit":50}` to collect key IDs.
3. Generate a download token with `POST /orion/api/file-download/token {"id":<keyId>,"type":"SECRET_KEY"}`.
4. Download the private key via `GET /orion/api/file-download/<token>/exec`.

# Suggested Remediation

- Gate all machine key management APIs behind administrator-only roles.
- When issuing download tokens, verify that the requesting user is allowed to access the specific key (e.g., owns the machine that references it) and enforce that check again inside `execDownload`.
- Consider encrypting stored keys with a hardware-backed secret so that the API layer never returns raw key material to clients.
