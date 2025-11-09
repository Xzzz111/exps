# Zanata Platform Open Redirect via `continue` Parameters

# NAME OF AFFECTED PRODUCT(S)

- Zanata Platform (web-based translation management server)

## Vendor Homepage

- [Zanata Project](https://github.com/zanata/zanata-platform)

# AFFECTED AND/OR FIXED VERSION(S)

## submitter

- sh7err@vEcho

## VERSION(S)

- Source build from `zanata-platform` Git repository commit `68c80db891bc816f737fbfd1c77b6f68fb295143` (latest master at audit time)

## Software Link

- [https://github.com/zanata/zanata-platform](https://github.com/zanata/zanata-platform)

# PROBLEM TYPE

## Vulnerability Type

- Improper validation of redirect (`continue`) parameter leading to open redirect / CWE-601

## Root Cause

- Login-related flows trust and replay the caller-supplied `continue` query parameter without verifying that it references an in-application path. `account/login.xhtml` binds the value to `userRedirect.encodedUrl`, and `UserRedirectBean.setUrl` simply stores the decoded value (see `server/services/src/main/java/org/zanata/security/UserRedirectBean.java:88-134`). Subsequent components (`OpenIdAction.handleRedirect` in `server/services/src/main/java/org/zanata/action/OpenIdAction.java:48-63` and the Kerberos `KLoginServlet` in `server/services/src/main/java/org/zanata/servlet/KLoginServlet.java:47-104`) call `urlUtil.redirectToInternal(userRedirect.getUrl())` or `resp.sendRedirect(continueUrl)` with the attacker-provided URL. `UrlUtil.redirectToInternal` (lines 269-304 in `server/services/src/main/java/org/zanata/util/UrlUtil.java`) simply appends the JSF window id to any string and forwards it to `FacesContext.redirect` without domain validation.

## Impact

- Any unauthenticated remote attacker can trick users into logging in via a crafted Zanata login/OpenID/Kerberos link and get the server to redirect the victim’s browser to an arbitrary attacker-controlled domain immediately after a successful authentication. This creates high-value phishing and credential-harvesting opportunities and allows chaining with downstream OAuth/OpenID clients.

# DESCRIPTION

During an audit of the Zanata Platform web application, an open redirect vulnerability was identified in the handling of the `continue` parameter of the login view. The login JSF page (`server/zanata-war/src/main/webapp/account/login.xhtml:10-14`) copies the `continue` query parameter into `UserRedirectBean`. `UserRedirectBean` does not restrict the stored URL to local paths and it is later replayed verbatim after successful authentication by multiple entry points: the OpenID callback (`OpenIdAction.handleRedirect`) and the Kerberos ticket endpoint (`KLoginServlet`). `UrlUtil.redirectToInternal` treats any string as trusted and sends a 302 redirect without checking the host, so any absolute URL supplied via `continue` will be honored after successful login. No authentication bypass is required; victims only need to finish a legitimate login flow.

# **Code Analysis**

1. **Parameter capture:**
   - `server/zanata-war/src/main/webapp/account/login.xhtml:10-14` binds `?continue=` to `#{userRedirect.encodedUrl}`.
2. **Storage without validation:**
   - `server/services/src/main/java/org/zanata/security/UserRedirectBean.java:88-134` decodes the URL and assigns it to `this.url` without ensuring it is inside `contextPath`.
3. **Unsafe usage (OpenID path):**
   - `server/services/src/main/java/org/zanata/action/OpenIdAction.java:48-63` redirects authenticated users using `urlUtil.redirectToInternal(userRedirect.getUrl())` when `userRedirect.isRedirect()`.
4. **Unsafe usage (Kerberos path):**
   - `server/services/src/main/java/org/zanata/servlet/KLoginServlet.java:86-103` calls `resp.sendRedirect(continueUrl)` when the Kerberos login completes.

# No additional privileges are required beyond luring a user to a crafted login link

# Vulnerability details and POC

## Vulnerability type:

- Open redirect / improper validation of redirect parameter

## Vulnerability location:

- `continue` query parameter on `/account/login.xhtml` (OpenID/SAML flows)
- `continue` query parameter on `/account/klogin` (Kerberos login servlet)

## Proof of Concept 1 – OpenID/SAML flow

1. Host a malicious landing page at `https://evil.example/postLogin`.
2. Send the victim the following Zanata login link (URL-encoded attacker domain):
   ```
   https://<zanata-host>/account/login.xhtml?continue=https%3A%2F%2Fevil.example%2FpostLogin
   ```
3. After the victim completes OpenID/SAML authentication, `OpenIdAction.handleRedirect` issues a 302 redirect to `https://evil.example/postLogin?dswid=<window-id>`, loading attacker-controlled content in the same browser session.

## Proof of Concept 2 – Kerberos flow

1. Craft a Kerberos login URL:
   ```
   https://<zanata-host>/account/klogin?continue=https%3A%2F%2Fevil.example%2Fticket
   ```
2. When the victim’s browser performs SPNEGO negotiation with Zanata, `KLoginServlet.performRedirection` executes `resp.sendRedirect(continueUrl)` and immediately sends the victim to `https://evil.example/ticket` after the ticket is accepted.

# Attack results

- Successful exploitation forces users to leave the trusted Zanata origin right after authenticating, enabling phishing, credential theft, or malicious OAuth flows.

# Suggested repair

1. Accept only relative paths that reside within the Zanata context when capturing `continue`. Reject or sanitize any absolute URLs or values pointing outside the deployment host.
2. When a fully qualified URL is required, enforce a strict allow list of approved domains instead of trusting user input.
3. For consistency, make `UserRedirectBean.setUrl` normalize inputs to context-relative values and make `KLoginServlet` reuse the same validation helper before calling `sendRedirect`.
