# CVE Submission Form – zdh_web SQL Injection

* **Vulnerability type info**
SQL Injection

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
Information Disclosure; Other (permission bypass within data marketplace)

* **Affected component(s)**
`src/main/java/com/zyc/zdh/controller/ZdhDataWareController.java`, `src/main/java/com/zyc/zdh/dao/IssueDataMapper.java`

* **Attack vector(s)**
A logged-in user submits a crafted `label_params` value such as `test'),1=1#` to the `POST /data_ware_house_list6` endpoint. The controller forwards the string directly to the mapper, which interpolates it via `${label_name}` inside a `FIND_IN_SET` clause, allowing the attacker to inject arbitrary SQL conditions and read otherwise unauthorized data.

* **Suggested description of the vulnerability for use in the CVE info**
The `data_ware_house_list6` endpoint in zdh_web passes unsanitized `label_params` input into `IssueDataMapper.selectByParams`, where MyBatis `${}` substitution places the value inside a `FIND_IN_SET` expression. Malicious payloads can break out of the quoted string and inject arbitrary SQL, enabling data disclosure and permission bypass.

* **Discoverer(s)/Credits info**
sh7err@vEcho

* **Reference(s) info**
https://github.com/zhaoyachao/zdh_web

* **Additional information**
Confirmed on commit 63125e22e7afa0e1649d0d154562823b5fd4c5c9; no vendor advisory at the time of writing.
