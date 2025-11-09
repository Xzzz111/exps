* Vulnerability type info 
Information Disclosure (Exposed Monitoring Console)
* Vendor of the product(s) info
Trimdata / Benma666
Affected product(s)/code base info
kettle-manager (数据大师 / sjds)
* Product* Version
kettle-manager 0.2.6-SNAPSHOT (default configuration). No fix available.

Has vendor confirmed or acknowledged the vulnerability No
Attack type info 
Remote network attack
Impact info
Information Disclosure
Affected component(s)
Alibaba Druid StatView servlet configuration (`src/main/resources/application.yaml`, `doc/docker/sjsj/conf/application-private.yaml`)
Attack vector(s)
An unauthenticated user browses to `/sjsj-ht/druid/login.html` and logs in with the bundled credentials `jingma/jingma`, gaining full access to the Druid monitoring interface and its SQL/connection telemetry.
Suggested description of the vulnerability for use in the CVE info
kettle-manager exposes the Druid database monitoring console to all remote users and protects it with a hard-coded username/password pair (`jingma/jingma`). This allows any unauthenticated attacker to view SQL statements, connection details, and runtime metrics from production deployments.
Discoverer(s)/Credits info
sh7err@vEcho
Reference(s) info
https://github.com/majinju/kettle-manager

Additional information
The `allow` whitelist is empty, so the servlet accepts requests from any IP address. The same weak credentials are present in both the main configuration and the Docker deployment files.

