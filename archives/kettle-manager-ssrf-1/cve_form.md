* Vulnerability type info 
Server-Side Request Forgery (SSRF)
* Vendor of the product(s) info
Trimdata / Benma666
Affected product(s)/code base info
kettle-manager (数据大师 / sjds)
* Product* Version
kettle-manager 0.2.6-SNAPSHOT (default XXL-JOB configuration). No fix available.

Has vendor confirmed or acknowledged the vulnerability No
Attack type info 
Remote network attack
Impact info
Information Disclosure
Other (Network pivoting)
Affected component(s)
XXL-JOB executor configuration (`src/main/resources/application-xxljob.yaml`) and `httpJobHandler` implementation (`src/main/java/cn/benma666/sjsj/demo/job/XxxJob.java:145-234`)
Attack vector(s)
An unauthenticated attacker sends a crafted POST request to the XXL-JOB executor `/run` endpoint on port 9998, selecting the `httpJobHandler` and supplying an arbitrary target URL. The handler retrieves the remote resource and logs the response, which the attacker reads via the `/log` endpoint to obtain the forged response.
Suggested description of the vulnerability for use in the CVE info
kettle-manager deploys the XXL-JOB executor without an access token, exposing demo handler `httpJobHandler` that performs arbitrary outbound HTTP requests and stores the response in executor logs. Any unauthenticated remote attacker can abuse this to carry out SSRF attacks against internal services and cloud metadata endpoints.
Discoverer(s)/Credits info
sh7err@vEcho
Reference(s) info
https://github.com/majinju/kettle-manager
https://www.xuxueli.com/xxl-job/

Additional information
Because `xxljob.accessToken` is empty, all executor management APIs are callable without credentials. The same configuration is shipped both in the repository and the Docker deployment scripts.

