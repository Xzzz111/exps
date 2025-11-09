* Vulnerability type info 
Zip Slip / Path Traversal leading to arbitrary file write

* Vendor of the product(s) info
AIAS Project (aias.top)

Affected product(s)/code base info
* Product* Version
AIAS Training Platform <= 0.23.0 (no fixed version announced)

Optional
Has vendor confirmed or acknowledged the vulnerability No

Attack type info 
Remote

Impact info
Code Execution

Affected component(s)
`2_training_platform/train-platform/src/main/java/top/aias/training/common/utils/ZipUtil.java`, `top.aias.training.controller.TrainController`

Attack vector(s)
An attacker uploads a crafted ZIP dataset containing entries such as `../../../../tmp/evil.sh` via `/api/localStorage/file` and then calls `/api/train/trigger`; the traversal entries are written outside the intended extraction directory, resulting in arbitrary file overwrite.

Suggested description of the vulnerability for use in the CVE info
AIAS Training Platform <= 0.23.0 contains a Zip Slip vulnerability in `ZipUtil.unZipTrainingData`, where archive entry names are concatenated to the extraction path without canonicalization. By uploading a crafted ZIP and triggering training, a remote attacker can write files outside the data directory and achieve code execution.

Discoverer(s)/Credits info
sh7err@vEcho

Reference(s) info
https://gitee.com/mymagicpower/AIAS

Additional information
The project currently ships multiple hardened Zip utilities in other modules; reusing those mitigations or adding canonical path checks would close the issue.
