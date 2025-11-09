# AIAS Training Platform ZipUtil arbitrary file write (Zip Slip)

# NAME OF AFFECTED PRODUCT(S)

- AIAS Training Platform (part of the AIAS project)

## Vendor Homepage

- [AIAS Project](http://aias.top/)

# AFFECTED AND/OR FIXED VERSION(S)

## submitter

- sh7err@vEcho

## VERSION(S)

- <= v0.23.0 (current master, no fix available)

## Software Link

- [AIAS repository](https://gitee.com/mymagicpower/AIAS)

# PROBLEM TYPE

## Vulnerability Type

- Zip Slip / Path Traversal leading to arbitrary file write and remote code execution

## Root Cause

- `/api/train/trigger` ultimately calls `top.aias.training.common.utils.ZipUtil.unZipTrainingData()` (lines 35-109). The function concatenates `entry.getName()` directly onto the destination directory without sanitizing `..`, absolute paths, or drive prefixes, and immediately writes files via `createNewFile` + `FileOutputStream`. Because the controller never canonicalizes the final path, attackers can supply crafted archive entries such as `../../../../tmp/evil.sh`, causing files to be created outside the intended `dataRootPath` extraction directory.

## Impact

- An authenticated or unauthenticated user who can upload a training dataset archive can write arbitrary files as the application user. By planting executables or overwriting configuration/cron files, this escalates to remote code execution and complete server compromise.

# DESCRIPTION

The AIAS training service accepts ZIP uploads under `/api/localStorage/file` and starts model training by invoking `/api/train/trigger`. `TrainController.trigger()` trusts the stored file metadata, derives a per-run `dataRootPath`, and passes both the OS information and archive path to `ZipUtil.unZipTrainingData()`. Because the unzipping utility does not enforce canonical paths or restrict traversal sequences, an attacker-controlled archive can escape the sandbox directory and overwrite arbitrary files on the host. This behavior contradicts the module's intention of isolating uploads under the generated UUID directory.

# Code Analysis

Relevant excerpt (`2_training_platform/train-platform/src/main/java/top/aias/training/common/utils/ZipUtil.java`):

```
filename = filePath + File.separator + filename;
File file = new File(filename);
...
file.createNewFile();
is = zipFile.getInputStream(entry);
fos = new FileOutputStream(file);
```

`filename` is never canonicalized, so entries such as `../../../../etc/crontab` escape `filePath`.

# Authentication / Authorization

- No additional privilege is needed beyond being able to upload a ZIP dataset and trigger training. The default deployment exposes these APIs without authentication, so exploitation can be remote and unauthenticated.

# Vulnerability details and POC

## Vulnerability type

- Zip Slip (path traversal during archive extraction)

## Vulnerability location

- `top.aias.training.common.utils.ZipUtil#unZipTrainingData`
- Trigged by `/api/train/trigger`

## Proof of Concept

1. Craft `evil.zip` with an entry named `../../../../tmp/reverse.sh` containing arbitrary shell commands.
2. Upload the ZIP via `POST /api/localStorage/file` and note the returned `id`.
3. Invoke `POST /api/train/trigger` with body `{"id": <storedId>}`.
4. After the request completes, `/tmp/reverse.sh` exists and contains attacker-controlled content outside the training data directory.

Executing the planted script via cron or another privileged mechanism results in remote code execution.

# Suggested remediation

1. When resolving each `ZipEntry`, obtain its canonical path and ensure it starts with the intended extraction directory. Reject entries containing `..`, absolute paths, or drive letters.
2. Consider reusing the hardened `ZipUtils` implementations already present in other AIAS modules, which strip directory names.
3. Delete temporary files after training completes and run the service under a low-privilege account to limit blast radius.
