# MyBatis JPetStore 6 AccountActionBean signon Session Fixation

# NAME OF AFFECTED PRODUCT(S)

- MyBatis JPetStore Demo 6

## Vendor Homepage

- [MyBatis](https://www.mybatis.org/)

# AFFECTED AND/OR FIXED VERSION(S)

## submitter

- sh7err@vEcho

## VERSION(S)

- 6.1.1-SNAPSHOT (latest master, no fix available)

## Software Link

- [https://github.com/mybatis/jpetstore-6](https://github.com/mybatis/jpetstore-6)

# PROBLEM TYPE

## Vulnerability Type

- Session Fixation / Improper Session Management

## Root Cause

- The login handler `AccountActionBean.signon()` (file `src/main/java/org/mybatis/jpetstore/web/actions/AccountActionBean.java:149-176`) authenticates a user but never regenerates the HTTP session identifier and continues to use the attacker-supplied `JSESSIONID`. The application also allows URL-based session tracking (see `web.xml` mapping of Stripes and JSP pages using `;jsessionid=` by default), so an adversary can pre-establish a session ID, deliver it via a crafted link, and take over the victim’s authenticated session once they log in.

## Impact

- Attackers can hijack authenticated sessions after the victim signs in, obtaining the victim’s identity and full privileges without needing to steal cookies post-login.

# DESCRIPTION

- Classic session fixation occurs when a web app fails to assign a fresh session ID after successful authentication. In JPetStore 6, the login flow merely stores the populated `AccountActionBean` into whatever session is currently attached to the request (`context.getRequest().getSession()`) and sets `accountBean` attributes. Because there is no `changeSessionId()`/`invalidate()` call, the session ID remains under attacker control. By emailing or hosting a link such as `https://host/jpetstore/actions/Account.action;jsessionid=FIXED?signonForm=`, the attacker causes the victim to reuse the attacker’s session. Once the victim logs in, the attacker reuses `FIXED` to access any authenticated page (orders, account edit, checkout, etc.).

# CODE ANALYSIS

- `src/main/java/org/mybatis/jpetstore/web/actions/AccountActionBean.java:149-176` (signon success path never regenerates session ID)
- `src/main/java/org/mybatis/jpetstore/web/actions/AccountActionBean.java:180-188` (only signoff invalidates the session, confirming no regeneration happens elsewhere)
- `src/main/webapp/WEB-INF/web.xml` (standard configuration with URL session tracking enabled)

# Vulnerability details and POC

## Vulnerability type:

- Session fixation leading to privilege escalation

## Vulnerability location:

- Login endpoint `/jpetstore/actions/Account.action` (signon event)

## Attack steps:

1. Attacker visits the site and records their unauthenticated `JSESSIONID=XYZ`.
2. Attacker sends the victim a link `https://target/jpetstore/actions/Account.action;jsessionid=XYZ?signonForm=`.
3. Victim logs in normally; the server keeps `JSESSIONID=XYZ` while marking the session as authenticated.
4. Attacker reuses `JSESSIONID=XYZ` to access authenticated resources (`/actions/Order.action?listOrders`, `/actions/Account.action?editAccountForm`, etc.), fully impersonating the victim.

# Attack results

- Session hijack with the victim’s privileges, exposing personal data, order history, and ability to place or modify orders.

# Suggested repair

1. On successful authentication, call `request.changeSessionId()` (Servlet 3.1+) or `session.invalidate(); request.getSession(true);` before storing authentication state.
2. Disable URL-based session tracking (`<context-param><param-name>disableURLRewriting</param-name><param-value>true</param-value></context-param>` or equivalent) so session IDs cannot be fixed via the URL.
3. Set the session cookie attributes `HttpOnly`, `Secure`, and optionally `SameSite` to reduce secondary theft vectors.
