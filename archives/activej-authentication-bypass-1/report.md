# ActiveJ FileSystemServlet remote authentication bypass enables arbitrary file operations

# NAME OF AFFECTED PRODUCT(S)

- ActiveJ

## Vendor Homepage

- [ActiveJ](https://activej.io)

# AFFECTED AND/OR FIXED VERSION(S)

## submitter

- sh7err@vEcho

## VERSION(S)

- 6.0-SNAPSHOT (master branch, prior to any fix)
- Historical releases that include `extra/launchers/fs-gui/src/main/java/io/activej/fs/http/FileSystemServlet.java` (e.g., 6.0.0, 5.x) are expected to be impacted because the servlet never enforced authentication. No patched release is available.

## Software Link

- [https://github.com/activej/activej](https://github.com/activej/activej)

# PROBLEM TYPE

## Vulnerability Type

- Missing authentication for critical function / Improper access control

## Root Cause

- The `FileSystemServlet.create(...)` routing exposes every filesystem management primitive (`upload`, `append`, `download`, `list`, `info`, `copy`, `move`, `delete`, etc.) directly to HTTP clients without any authentication, authorization, or origin validation. The servlet even advertises itself as safe for "publicly available servers" but never validates the caller. Any remote party that can reach the listening port gains full control over the configured `IFileSystem` backend.

## Impact

- Remote attackers can upload, overwrite, download, list, copy, move, or delete arbitrary files inside the configured ActiveFs storage namespace. This allows theft of sensitive data, destruction or corruption of stored artifacts, staging of malware, and complete loss of availability for downstream consumers.

# DESCRIPTION

- While reviewing ActiveJ's filesystem HTTP launcher, a critical authentication bypass was identified in `extra/launchers/fs-gui/src/main/java/io/activej/fs/http/FileSystemServlet.java`. The servlet routes unauthenticated HTTP verbs such as `POST /upload/*`, `POST /append/*`, `GET /download/*`, `GET /list`, `GET /info/*`, `POST /copy`, `POST /move`, and `DELETE /delete/*` directly to the injected `IFileSystem` instance. There is no session requirement, no token verification, and no optional filter to enforce ACLs. The associated GUI (`FileSystemGuiServlet`) simply re-uses parts of this servlet and likewise omits authentication. Because the default launchers bind this servlet straight to `HttpServer` without any protective middleware (see `FileSystemGuiModule`), the design intent of "publicly available server" is defeated: anyone on the network can fully manage the server-side filesystem.

# **Code Analysis**

- `FileSystemServlet` constructor comment (lines 39-48) claims the servlet may be launched as a publicly available server, yet no auth checks exist in `RoutingServlet.builder(...)` (lines 60-156). All handlers directly call the supplied `IFileSystem` APIs such as `fs.upload(decodePath(request))` or `fs.delete(decodePath(request))`.
- `decodePath` (lines 166-177) merely URL-decodes paths; no caller identification is made before dispatching to the filesystem. Errors return HTTP 500/400 rather than blocking access.
- `FileSystemGuiServlet` (lines 31-83) embeds the same unauthenticated upload/download routes into `/api/*`, again without credentials. `FileSystemGuiModule` wires this servlet into `HttpServer` with no security configuration, so default launchers expose the issue out of the box.

# No login or authorization is required to exploit this vulnerability

# Vulnerability details and POC

## Vulnerability type:

- Authentication bypass leading to unrestricted file management

## Vulnerability location:

- `extra/launchers/fs-gui/src/main/java/io/activej/fs/http/FileSystemServlet.java` (`create`, `decodePath`, routing handlers)

## Example exploitation steps (no existing session needed):

```
# Upload arbitrary content
curl -X POST --data-binary '@/etc/passwd' http://TARGET:8080/upload/malicious.txt

# List every file under the storage root
curl 'http://TARGET:8080/list?glob=**'

# Delete application artifacts
curl -X DELETE http://TARGET:8080/delete/config/app.properties
```

Each request returns HTTP 200 and the backend `IFileSystem` reflects changes immediately, proving full read/write/delete control to anonymous users.

# Attack results

- Anonymous network attackers can steal snapshots, overwrite backups, drop ransomware payloads, or wipe the entire object store. Because ActiveFs can back production data pipelines, this directly threatens confidentiality, integrity, and availability.

# Suggested repair

1. Introduce mandatory authentication/authorization hooks inside `FileSystemServlet` (e.g., token-based, mTLS, or delegated filters) before invoking any `IFileSystem` method.
2. Provide configuration options in launchers to enforce credentials by default and document that the servlet must not be exposed publicly without an auth layer.
3. Consider rate limiting and audit logging to detect abuse once authentication is in place.
