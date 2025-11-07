# CVE Submission Form – zdh_web Authentication Bypass

* **Vulnerability type info**
Authentication Bypass / Missing Authorization

* **Vendor of the product(s) info**
zdh_web project maintainers (GitHub: zhaoyachao)

* **Affected product(s)/code base info**
  * Product: zdh_web
  * Version: <= master commit 63125e22e7afa0e1649d0d154562823b5fd4c5c9 (no fixed version available)

* **Has vendor confirmed or acknowledged the vulnerability**
No

* **Attack type info**
Network

* **Impact info**
Escalation of Privileges; Other (business process/approval tampering)

* **Affected component(s)**
`src/main/java/com/zyc/zdh/api/ProcessFlowApi.java`, `src/main/java/com/zyc/zdh/config/ShiroConfig.java`

* **Attack vector(s)**
An unauthenticated attacker sends a crafted POST request to `/api/process_status_by_flow_status` with the `id` of an existing approval node and an arbitrary `status` value. Because `/api/**` is whitelisted and the handler omits `check_aksk`, the request succeeds without credentials, allowing the attacker to approve, reject, or revoke any workflow item.

* **Suggested description of the vulnerability for use in the CVE info**
`ProcessFlowApi.process_flow_status` in zdh_web accepts unauthenticated POST requests and updates approval flow records without enforcing product `ak/sk` validation. Because `/api/**` routes are marked anonymous in Shiro, remote attackers can change the status of arbitrary approval nodes and bypass the intended approval controls.

* **Discoverer(s)/Credits info**
sh7err@vEcho

* **Reference(s) info**
https://github.com/zhaoyachao/zdh_web

* **Additional information**
Confirmed on commit 63125e22e7afa0e1649d0d154562823b5fd4c5c9.
