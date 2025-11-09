# CVE Request Form

* Vulnerability type info 
URL Redirection to Untrusted Site (Open Redirect)

* Vendor of the product(s) info
Zanata Project (maintained by Red Hat/community)

* Affected product(s)/code base info
Zanata Platform — web-based translation management server

* Product* Version
Product: Zanata Platform
Version: <= Git commit 68c80db891bc816f737fbfd1c77b6f68fb295143 (no official fix available)

Has vendor confirmed or acknowledged the vulnerability
No

Attack type info 
Remote

Impact info
Other (forced navigation / phishing after authentication)

Affected component(s)
`server/zanata-war/src/main/webapp/account/login.xhtml`, `server/services/src/main/java/org/zanata/security/UserRedirectBean.java`, `server/services/src/main/java/org/zanata/action/OpenIdAction.java`, `server/services/src/main/java/org/zanata/servlet/KLoginServlet.java`, `server/services/src/main/java/org/zanata/util/UrlUtil.java`

Attack vector(s)
An attacker sends a victim a Zanata login URL such as `/account/login.xhtml?continue=https%3A%2F%2Fevil.example` or `/account/klogin?continue=https%3A%2F%2Fevil.example`; once the victim completes OpenID/SAML or Kerberos authentication, the server redirects the browser to the attacker-supplied absolute URL.

Suggested description of the vulnerability for use in the CVE info
"Zanata Platform trusts the `continue` query parameter captured on the login/Kerberos entry points and redirects to it verbatim after authentication. Because the value is never validated to ensure it is a same-origin path, attackers can craft login URLs that bounce authenticated users to arbitrary domains, enabling phishing and credential theft."

Discoverer(s)/Credits info
sh7err@vEcho

Reference(s) info
https://github.com/zanata/zanata-platform

Additional information
Proof-of-concept URLs:
1. `https://<zanata>/account/login.xhtml?continue=https%3A%2F%2Fevil.example%2Flanding`
2. `https://<zanata>/account/klogin?continue=https%3A%2F%2Fevil.example%2Ftickets`
