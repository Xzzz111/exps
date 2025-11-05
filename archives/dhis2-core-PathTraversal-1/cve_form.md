## CVE Submission Form

* **Vulnerability type info**  
Path Traversal / Arbitrary File Read

* **Vendor of the product(s) info**  
DHIS2 (University of Oslo)

* **Affected product(s)/code base info**  
DHIS2 Core (server)

* **Product Version**  
- dhis2-core commit 5a9b5335e29947ecad6b9f74ef69b073f727a730 (latest `master`, 2025-11-04).  
- All deployments using the filesystem file store provider are believed to be affected.  
- No fixed version is available at the time of reporting.

* **Has vendor confirmed or acknowledged the vulnerability**  
No

* **Attack type info**  
Network

* **Impact info**  
Information Disclosure

* **Affected component(s)**  
`dhis-web-api` `AppController#getResourcePath`, `dhis-services/dhis-service-core` `DefaultAppManager` & `JCloudsAppStorageService`, `dhis-support/dhis-support-external` `DefaultLocationManager`

* **Attack vector(s)**  
An authenticated user (or anyone allowed to load app resources) requests `/api/apps/{appKey}/../../../../etc/passwd` or similar; the server opens and returns the referenced OS file because the path is never normalized or bounds-checked when the filesystem blob provider is used.

* **Suggested description of the vulnerability for use in the CVE info**  
DHIS2 Core fails to sanitize user-controlled paths in the `/api/apps/{appKey}/**` resource handler when operating with the filesystem file store provider. A remote authenticated attacker can traverse out of the app directory and read arbitrary files from the DHIS2 host, leading to disclosure of sensitive data such as configuration files and credentials.

* **Discoverer(s)/Credits info**  
s1ain

* **Reference(s) info**  
N/A (coordinated disclosure, no public advisory yet)

* **Additional information**  
Tested on dhis2-core commit 5a9b5335e29947ecad6b9f74ef69b073f727a730 (2025-11-04). The issue occurs specifically when `FILESTORE_PROVIDER=filesystem`, which is the default for on-prem installations per documentation.
