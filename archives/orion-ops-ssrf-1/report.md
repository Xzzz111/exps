# Orion-ops direct connectivity test allows SSRF and internal port scanning

# NAME OF AFFECTED PRODUCT(S)

- Orion-ops (server component)

## Vendor Homepage

- https://github.com/lijiahangmax/orion-ops

# AFFECTED AND/OR FIXED VERSION(S)

## submitter

- sh7err@vEcho

## VERSION(S)

- <= master commit 5925824997a3109651bbde07460958a7be249ed1 (no official fix published)

## Software Link

- https://github.com/lijiahangmax/orion-ops

# PROBLEM TYPE

## Vulnerability Type

- Server-Side Request Forgery / Internal network probing (CWE-918)

## Root Cause

- The endpoints `POST /orion/api/machine/direct-test-connect` and `POST /orion/api/machine/direct-test-ping` are meant for administrators to verify reachability of managed hosts, but `MachineInfoController` does not enforce any role checks. The controller forwards user-supplied `host`, `sshPort`, `username`, `password`, or `keyId` directly to `MachineInfoServiceImpl.testConnect`. The service builds an SSH connection using those exact parameters via `SessionHolder#getSession` and reports timeout vs. success. Because user input is never validated against a whitelist of managed machines, any authenticated session can coerce the Orion-ops server into initiating arbitrary TCP connections to internal addresses.

## Impact

- An attacker can map the internal network reachable from the Orion-ops server, discover open ports, and target services that are otherwise inaccessible from the attacker’s location. With further refinement, the same primitive can be combined with protocol smuggling to interact with internal systems.

# DESCRIPTION

- Orion-ops exposes convenience APIs that test SSH reachability. These APIs are not restricted to administrators and accept arbitrary destination parameters. `MachineInfoServiceImpl#testConnectMachine` executes `session.connect(timeout)` against any user-provided host and port, including internal-only services. The server then discloses whether the attempt timed out or failed due to authentication. This behavior directly contradicts the intended design of only testing enrolled machines and effectively turns the Orion-ops server into an SSRF proxy.

# Code Analysis

- `orion-ops-api/orion-ops-web/src/main/java/cn/orionsec/ops/controller/MachineInfoController.java:128-166`
- `orion-ops-api/orion-ops-service/src/main/java/cn/orionsec/ops/service/impl/MachineInfoServiceImpl.java:320-505`

# Proof of Concept

1. Authenticate as any non-admin user.
2. Send `POST /orion/api/machine/direct-test-connect` with body `{"host":"10.0.0.1","sshPort":22,"username":"x","password":"x","authType":1}`.
3. Observe the JSON response: a fast “success” indicates the port is open, while an error or timeout indicates otherwise. Repeat against different internal addresses to map the network.

# Suggested Remediation

- Restrict the direct test endpoints to administrators and ensure the target host must be an existing machine entry owned by that user.
- Reject private or non-routable addresses unless explicitly whitelisted.
- Consider performing connectivity checks asynchronously on the managed agent rather than from the management server.
