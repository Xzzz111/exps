# NutzBoot Web3j transfer endpoint allows unauthorized ETH transfers

# NAME OF AFFECTED PRODUCT(S)

- NutzBoot (Web3j starter + demo module)

## Vendor Homepage

- [Nutz Framework](https://nutz.io)

# AFFECTED AND/OR FIXED VERSION(S)

## submitter

- sh7err@vEcho

## VERSION(S)

- 2.6.0-SNAPSHOT (current `dev` branch)
- Any deployment that exposes `EthModule.sendTransaction`

## Software Link

- [https://github.com/nutzam/nutzboot](https://github.com/nutzam/nutzboot)

# PROBLEM TYPE

## Vulnerability Type

- Missing authentication on financial transaction API / improper access control

## Root Cause

- `EthModule.sendTransaction(String from, String to, @Param("wei") double wei)` (`nutzboot-demo/.../EthModule.java:89-120`) is registered at `@At("/web3j/eth/sendTransaction/?/?")`, lacks `@POST`, CSRF protection, or any authorization guard, and directly signs a transaction using the locally stored account password and `personalSendTransaction`. Any HTTP client that can reach the endpoint can trigger a transfer between arbitrary addresses as long as `wei` is between 0.01 and 100.

## Impact

- An unauthenticated attacker can drain the server's configured Ethereum wallets or transfer arbitrary values to attacker-controlled addresses.

# DESCRIPTION

The same Web3j demo module that loads wallet credentials also provides a convenience endpoint to trigger transfers. The method performs the following steps:

1. Accepts `from` and `to` path segments and a `wei` query parameter.
2. Ensures the amount is 0.01–100 ether.
3. Fetches the `Web3jAccount` matching the `from` name and obtains its stored password.
4. Calls `web3jAdmin.personalSendTransaction(...)`, which unlocks the account and sends the transaction.

No user identity is checked, and the route is accessible with an ordinary GET request. Consequently, anyone can spend the funds of any configured account by making a single HTTP call.

# CODE ANALYSIS

- `nutzboot-demo/nutzboot-demo-simple/nutzboot-demo-simple-web3j/src/main/java/io/nutz/demo/simple/module/EthModule.java:89-120`
- `nutzboot-starter/nutzboot-starter-web3j/src/main/java/org/nutz/boot/starter/web3/Web3jStarter.java:79-112`

# VULNERABILITY DETAILS AND POC

## Vulnerability location

- `GET /web3j/eth/sendTransaction/{from}/{to}?wei=<amount>`

## Steps to Reproduce

1. Start the demo Web3j application with at least one locally configured account (e.g., name `dev`).
2. Issue the following request without any authentication or CSRF token:
   ```bash
   curl "http://<host>:<port>/web3j/eth/sendTransaction/dev/0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef?wei=1.5"
   ```
3. The server signs and broadcasts the transfer using the saved password and returns the transaction hash, moving 1.5 ether from the `dev` account to the attacker-controlled address.

# SUGGESTED REPAIR

1. Remove this helper API from public deployments, or at minimum require strong authentication/authorization, rate limiting, and audit logging.
2. Restrict the HTTP method to POST and enforce CSRF tokens or HMAC signatures.
3. Perform server-side validation of destination addresses and introduce an approval workflow for outgoing transfers.
4. Avoid storing wallet passwords in process memory; require operators to unlock the account manually before each transfer.
