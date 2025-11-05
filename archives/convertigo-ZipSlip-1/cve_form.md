* Vulnerability type info 
Directory Traversal (Zip Slip) leading to Arbitrary File Write

* Vendor of the product(s) info
Convertigo SA

Affected product(s)/code base info
* Product* Version
Convertigo Low Code Platform (engine module) — 8.x and prior (no fixed version available yet)

Has vendor confirmed or acknowledged the vulnerability
No

Attack type info 
Remote

Impact info
Code Execution

Affected component(s)
engine/src/com/twinsoft/convertigo/engine/util/ZipUtils.java:expandZip,
engine/src/com/twinsoft/convertigo/engine/DatabaseObjectsManager.java:deployProject,
engine/src/com/twinsoft/convertigo/engine/admin/services/UploadService.java,
engine/src/com/twinsoft/convertigo/engine/admin/services/projects/Deploy.java

Attack vector(s)
An authenticated admin uploads a specially crafted .car/.zip project archive via `/admin/services/projects/Deploy`, causing traversal during extraction and arbitrary file placement.

Suggested description of the vulnerability for use in the CVE info
Convertigo's project deployment pipeline expands uploaded archives without sanitizing entry paths. Crafted project archives containing traversal sequences can escape the target directory during extraction, allowing authenticated administrators to write arbitrary files and execute code on the server (Zip Slip / CWE-22).

Discoverer(s)/Credits info
sh7err

Reference(s) info
https://github.com/convertigo/convertigo

Additional information
A proof-of-concept archive demonstrating the traversal can place a JSP web shell into the application webroot, resulting in remote command execution under the Convertigo service account.

