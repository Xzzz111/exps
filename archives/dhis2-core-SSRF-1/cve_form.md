## CVE Submission Form

* **Vulnerability type info**  
Server-Side Request Forgery (SSRF)

* **Vendor of the product(s) info**  
DHIS2 (University of Oslo)

* **Affected product(s)/code base info**  
DHIS2 Core (server)

* **Product Version**  
- dhis2-core commit 5a9b5335e29947ecad6b9f74ef69b073f727a730 (latest `master`, 2025-11-04).  
- All versions that ship with the default configuration `route.remote_servers_allowed=https://*` are believed to be affected.  
- No fixed version is available.

* **Has vendor confirmed or acknowledged the vulnerability**  
No

* **Attack type info**  
Network

* **Impact info**  
Information Disclosure (and potential lateral movement/pivoting)

* **Affected component(s)**  
Configuration key `route.remote_servers_allowed`; `RouteService#postConstruct`, `RouteService#validateRoute`, `/api/routes` REST endpoints

* **Attack vector(s)**  
An authenticated user with `F_ROUTE_PUBLIC_ADD` creates a route whose URL points to an arbitrary HTTPS endpoint (e.g., `https://169.254.169.254/latest/meta-data/**`). Because the default allowlist regex is `https://*`, the server accepts it. Subsequent requests to `/api/routes/{uid}/run/...` proxy the attacker’s request through the DHIS2 server to the internal target, returning the response to the attacker.

* **Suggested description of the vulnerability for use in the CVE info**  
DHIS2 Core’s Route feature trusts a default allowlist of `https://*`, effectively granting unrestricted outbound HTTPS access. Any authenticated user with route-management rights can register a route to internal services and retrieve their responses via `/api/routes/{id}/run/**`, enabling SSRF against the DHIS2 host environment.

* **Discoverer(s)/Credits info**  
sh7err

* **Reference(s) info**  
N/A (private report)

* **Additional information**  
The issue was reproduced on dhis2-core commit 5a9b5335e29947ecad6b9f74ef69b073f727a730. The warning emitted by `RouteService#validateHost` when wildcards are used is purely informational and does not mitigate the issue.
