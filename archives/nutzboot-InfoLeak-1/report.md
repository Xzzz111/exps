# NutzBoot Web3j `local/accounts` API leaks wallet passwords

# NAME OF AFFECTED PRODUCT(S)

- NutzBoot (Web3j starter + demo module)

## Vendor Homepage

- [Nutz Framework](https://nutz.io)

# AFFECTED AND/OR FIXED VERSION(S)

## submitter

- sh7err@vEcho

## VERSION(S)

- 2.6.0-SNAPSHOT (current `dev` branch; no patch available)
- Any deployment that exposes `EthModule` from `nutzboot-demo-simple-web3j`

## Software Link

- [https://github.com/nutzam/nutzboot](https://github.com/nutzam/nutzboot)

# PROBLEM TYPE

## Vulnerability Type

- Sensitive information disclosure / credential leakage

## Root Cause

- `EthModule.localeAccounts` (`nutzboot-demo/.../EthModule.java:68-82`) returns the injected `Map<String, Web3jAccount> web3jCredentials` directly as JSON. The view annotation `@Ok("json:{compact:false,quoteName:true, ignoreNull:true, locked:'credentials'}")` only hides the `credentials` field, but the `Web3jAccount` class (`nutzboot-starter-web3j/.../Web3jAccount.java`) still exposes `password`. `Web3jStarter.loadCredentials()` populates that `password` property with the keystore passphrase read from configuration. The endpoint does not enforce any authentication or access control, so every caller receives plaintext wallet passwords.

## Impact

- Anyone with network access to `/web3j/local/accounts` can download all locally configured Ethereum addresses together with their wallet passwords, enabling immediate theft of keys or unauthorized signing via other RPC interfaces.

# DESCRIPTION

The NutzBoot Web3j starter autoloads keystore files and their passphrases into `Web3jAccount` objects. The demo `EthModule` exposes two diagnostic APIs at `/web3j/remote/accounts` and `/web3j/local/accounts`. While intended for monitoring, the implementation fails to protect sensitive data.

`EthModule.localeAccounts(Boolean updateBalance)` iterates over `web3jCredentials`, optionally refreshes balances, and returns `new NutMap("ok", true).setv("data", web3jCredentials)`. There is no authentication annotation, and the route is declared with `@At("/web3j")`, so regular GET requests can reach it.

`Web3jAccount` contains getters for `name`, `address`, `password`, `credentials`, and `banlance`. The JSON view locks only the `credentials` field, leaving `password` untouched. Therefore, the serialized response contains entries such as:
```json
{
  "ok": true,
  "data": {
    "dev": {
      "name": "dev",
      "address": "0x...",
      "password": "superSecret",
      "banlance": "0x..."
    }
  }
}
```
Because these passwords are sufficient to unlock the keystore, any visitor can steal the wallet funds or use the credentials in other attack chains.

# CODE ANALYSIS

- `nutzboot-demo/nutzboot-demo-simple/nutzboot-demo-simple-web3j/src/main/java/io/nutz/demo/simple/module/EthModule.java:68-82`
- `nutzboot-starter/nutzboot-starter-web3j/src/main/java/org/nutz/boot/starter/web3/Web3jAccount.java`
- `nutzboot-starter/nutzboot-starter-web3j/src/main/java/org/nutz/boot/starter/web3/Web3jStarter.java:79-112`

# VULNERABILITY DETAILS AND POC

## Vulnerability location

- `GET /web3j/local/accounts`

## Steps to Reproduce

1. Start the demo Web3j application with at least one account configured via `web3j.accounts.<name>.password`.
2. Request the local accounts endpoint without any authentication:
   ```bash
   curl http://<host>:<port>/web3j/local/accounts?updateBalance=false
   ```
3. Observe that the JSON response contains the plaintext password and address for every configured account.

## Impact demonstration

With the revealed password, an attacker can load the same keystore file (often deployed alongside the app) or reuse the `personal_sendTransaction` RPC to drain funds.

# SUGGESTED REPAIR

1. Never include `password` (or other secrets) in API responses. Use DTOs that omit sensitive fields or extend the `locked` attribute to include `password`.
2. Protect `/web3j/local/accounts` behind authentication/authorization, and disable it entirely in production builds.
3. Store wallet passphrases in a secure secret vault rather than embedding them in configuration files that are loaded into memory and leaked via serialization.
