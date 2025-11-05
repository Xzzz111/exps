## CVE Request Form

* **Vulnerability type info**  
Path Traversal (Zip Slip leading to arbitrary file write)

* **Vendor of the product(s) info**  
Vaadin Ltd.

* **Affected product(s)/code base info**  
Vaadin Flow automatic Node.js installer / frontend toolchain bootstrap

* **Product**  
Vaadin Flow

* **Version**  
24.3.0 - 25.0-SNAPSHOT (latest as of 2025-02-XX); no fixed version released

* **Has vendor confirmed or acknowledged the vulnerability**  
No

* **Attack type info**  
Remote

* **Impact info**  
Code Execution

* **Affected component(s)**  
flow-server/src/main/java/com/vaadin/flow/server/frontend/installer/DefaultArchiveExtractor.java, flow-server/src/main/java/com/vaadin/flow/server/frontend/installer/NodeInstaller.java

* **Attack vector(s)**  
An attacker provides a crafted Node.js ZIP archive via a malicious or compromised `nodeDownloadRoot` mirror (or by intercepting the download), embedding traversal sequences such as `../..` to force Vaadin Flow to write files outside the intended installation directory during automated toolchain setup.

* **Suggested description of the vulnerability for use in the CVE info**  
Vaadin Flow from version 24.3.0 through 25.0-SNAPSHOT contains a ZIP extraction flaw in `DefaultArchiveExtractor`. When unpacking Node.js distributions, ZIP entries are written without canonical path validation, allowing crafted archives with `../` sequences to escape the target directory. An attacker controlling the download source can write arbitrary files on the developer or CI host, achieving remote code execution. Tar/GZip extraction validates paths, but the ZIP code path lacks equivalent checks. No patched version is available at the time of reporting.

* **Discoverer(s)/Credits info**  
sh7err (independent security researcher)

* **Reference(s) info**  
https://github.com/vaadin/flow/blob/main/flow-server/src/main/java/com/vaadin/flow/server/frontend/installer/DefaultArchiveExtractor.java  
https://github.com/vaadin/flow/blob/main/flow-server/src/main/java/com/vaadin/flow/server/frontend/installer/NodeInstaller.java

* **Additional information**  
The SHA256 verification file is fetched from the same untrusted mirror as the archive, so integrity checks do not prevent exploitation. Mitigation requires canonical path checks for ZIP entries and updated releases for supported branches.

