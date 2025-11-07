# Minum Arbitrary File Read via Static Directory Symlink Bypass

# NAME OF AFFECTED PRODUCT(S)

- Minum Web Framework

## Vendor Homepage

- [https://github.com/byronka/minum](https://github.com/byronka/minum)

# AFFECTED AND/OR FIXED VERSION(S)

## submitter

- sh7err@vEcho

## VERSION(S)

- Tested on 8.3.0 (latest at time of writing); earlier versions inherit the same logic.

## Software Link

- [https://github.com/byronka/minum](https://github.com/byronka/minum)

# PROBLEM TYPE

## Vulnerability Type

- Directory Traversal / Arbitrary File Read via Symlink

## Root Cause

- The static file handler trusts `FileUtils.checkFileIsWithinDirectory` to prevent path escape. That helper resolves paths with `toRealPath(LinkOption.NOFOLLOW_LINKS)` and therefore does **not** follow symbolic links during validation. Later, the actual file access routines (`Files.isRegularFile` and `RandomAccessFile` inside `FileReader.readFile`) follow symbolic links by default. An attacker can place a symlink inside the static directory that points outside the allowed tree and request it over HTTP to read arbitrary files.

## Impact

- Unauthenticated attackers that can create or control symbolic links under the application’s static directory can read any file accessible to the Minum process (configuration, credentials, source code, etc.), resulting in a severe information disclosure.

# DESCRIPTION

`WebFramework.readStaticFile` is responsible for serving static resources. It first calls `checkForBadFilePatterns` to ensure the path only contains whitelisted characters, then calls `FileUtils.checkFileIsWithinDirectory(path, constants.staticFilesDirectory)` and finally reads the resolved file via `Files`/`RandomAccessFile`.

`checkFileIsWithinDirectory` resolves the static directory root with `toRealPath(LinkOption.NOFOLLOW_LINKS)` and resolves the user path with the same option before checking `startsWith`. Because the `NOFOLLOW_LINKS` flag is present, symbolic links **inside** the static directory are treated as ordinary folders during validation, so a path like `static/leak/passwd` (where `leak` is a symlink to `/`) still appears under `static`. When the file is later opened without `NOFOLLOW_LINKS`, the symlink is followed and the contents of `/passwd` (or any other target) are served to the client.

This breaks the design goal of constraining static responses to the configured directory and yields a trivial arbitrary file read primitive.

# **Code Analysis**

- `FileUtils.checkFileIsWithinDirectory` (`src/main/java/com/renomad/minum/utils/FileUtils.java:169-180`): uses `Path.of(directoryPath).toRealPath(LinkOption.NOFOLLOW_LINKS)` and compares `fullRealPath.startsWith(directoryRealPath)`, so symlinks inside the static tree are not dereferenced during validation.
- `WebFramework.readStaticFile` (`src/main/java/com/renomad/minum/web/WebFramework.java:497-540`): after the above check succeeds, it resolves the user path and reads bytes via `FileReader`, which ultimately instantiates a `RandomAccessFile` that follows symlinks.

# No login or authorization is required to exploit this vulnerability (static assets are typically world-accessible).

# Vulnerability details and POC

## Vulnerability type

- Directory traversal through symlink inside the static directory.

## Vulnerability location

- `WebFramework.readStaticFile()` path validation (`src/main/java/com/renomad/minum/web/WebFramework.java:497-540`).
- `FileUtils.checkFileIsWithinDirectory()` (`src/main/java/com/renomad/minum/utils/FileUtils.java:169-180`).

## Proof of Concept

1. On the target host (or deployment pipeline), create a symbolic link inside the configured static directory that points outside of it. The default directory is `static/` relative to the working directory.

```bash
$ cd /path/to/app
$ ln -s /etc static/leak
```

2. Request any file through the web server by referencing the symlink. Example HTTP request for `/etc/passwd`:

```
GET /leak/passwd HTTP/1.1
Host: victim.example
Connection: close
```

3. The server responds with `200 OK` and the body contains the chosen external file, proving arbitrary file read.

The attack works for any readable file, including application secrets, templates, or SSH keys, as long as the Minum process can read them.

# Attack results

- Confidential files outside the intended static root become accessible without authentication.
- Depending on deployment, leaking configuration and credentials may enable further compromise of databases or other services.

# Suggested repair

1. **Follow symlinks during validation**: remove `LinkOption.NOFOLLOW_LINKS` when resolving the candidate file, or resolve the final path (including symlinks) before the `startsWith` comparison.
2. **Reject symlinks altogether**: walk every path segment (e.g., via `Files.readAttributes(..., LinkOption.NOFOLLOW_LINKS)`) and fail if any component is a symbolic link.
3. **Add regression tests**: include a unit/integration test that mounts a symlink inside the static directory and asserts the request is rejected (e.g., returns 400/404).

Implementing any of these mitigations will restore the intended confinement of static resources and prevent arbitrary file reads.
