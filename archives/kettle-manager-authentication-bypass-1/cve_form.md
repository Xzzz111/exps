* Vulnerability type info 
Authentication Bypass via Default Credentials
* Vendor of the product(s) info
Trimdata / Benma666 (kettle-manager maintainers)
Affected product(s)/code base info
kettle-manager (a.k.a. 数据大师 / sjds)
* Product* Version
kettle-manager 0.2.6-SNAPSHOT (current master). No fixed version available.

Has vendor confirmed or acknowledged the vulnerability No
Attack type info 
Remote network attack
Impact info
Code Execution
Information Disclosure
Denial of Service
Escalation of Privileges
Affected component(s)
Spring Boot security configuration (`src/main/resources/application.yaml`, `doc/docker/sjsj/conf/application-private.yaml`)
Attack vector(s)
An unauthenticated attacker sends any HTTP request to the service, supplies the bundled Basic Auth credentials `jingma/jingma`, and obtains administrator-level access to all APIs.
Suggested description of the vulnerability for use in the CVE info
The default kettle-manager distribution configures Spring Security with hard-coded credentials `jingma/jingma` in both the main and Docker deployment configuration files. Every stock deployment therefore exposes a publicly known administrator account that grants full control of the platform to any remote unauthenticated attacker.
Discoverer(s)/Credits info
sh7err@vEcho
Reference(s) info
https://github.com/majinju/kettle-manager

Additional information
The credentials are embedded in multiple configuration files and automatically loaded because Spring Security starter is present; there is no mechanism to randomize or disable the account without modifying source code.

