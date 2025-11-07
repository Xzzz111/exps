# Unauthenticated Approval Flow Manipulation in zdh_web

- **Submitter:** sh7err@vEcho
- **Project:** zdh_web (github.com/zhaoyachao/zdh_web)
- **Tested Version:** master @ `63125e22e7afa0e1649d0d154562823b5fd4c5c9`
- **Vulnerability Class:** Authentication/Authorization Bypass

## Summary
The REST endpoint `POST /api/process_status_by_flow_status` is exposed without any authentication or product `ak/sk` validation. Any unauthenticated user on the network can change the status of arbitrary approval flow nodes (approve, reject, revoke) by supplying the `id` of the flow item. This violates the design requirement that API clients must authenticate with per-product tokens before they can drive approval workflows.

## Technical Details
1. `ShiroConfig` marks every URL under `/api/**` as `anon`, meaning Shiro performs no session checks for those routes.
2. Unlike the other API methods in `ProcessFlowApi`, the `process_flow_status` handler never invokes `check_aksk` or any authentication helper before updating the database.
3. The implementation simply updates the row identified by `id` and sets downstream nodes visible when `status=success`.

Because there is no middleware intercepting the request (Annotational AOP layers are not applied to `com.zyc.zdh.api`), any unauthenticated HTTP client can drive the workflow to any state.

Relevant code excerpts:
- `src/main/java/com/zyc/zdh/config/ShiroConfig.java`, lines 283-314 (`/api/**` => `anon`).
- `src/main/java/com/zyc/zdh/api/ProcessFlowApi.java`, lines 150-170 (no call to `check_aksk`).

## Proof of Concept
```
POST /api/process_status_by_flow_status HTTP/1.1
Host: <zdh_host>
Content-Type: application/x-www-form-urlencoded
Content-Length: 64

id=1637727192999&status=success&product_code=demo&ak=0&sk=0
```
No authentication cookies or ak/sk tokens are required. The server returns a `200` JSON payload containing the updated `ProcessFlowInfo`. Observing the database or the UI confirms that the approval status switched to `success` and downstream nodes became visible.

## Impact
Attackers can fully bypass the approval flow to force any task into an approved state, or mark it rejected/revoked at will. This undermines all business-process controls that rely on the approval module, enabling unauthorized data releases, configuration changes, or task executions. Because the endpoint is network-accessible and requires only the flow item ID (guessable or enumerable), exploitation is trivial.

## Suggested Remediation
1. Apply the same `check_aksk(product_code, ak, sk)` validation used by the other API methods before mutating approval records.
2. Remove `/api/**` from the anonymous filter chain or introduce a dedicated signature-based authentication filter for the API namespace.
3. Consider recording the acting identity for audit purposes and validating that the caller is assigned to the specific approval node.

## Timeline
- 2025-02-14 – Vulnerability discovered during code audit.

## References
- https://github.com/zhaoyachao/zdh_web/blob/63125e22e7afa0e1649d0d154562823b5fd4c5c9/src/main/java/com/zyc/zdh/api/ProcessFlowApi.java
