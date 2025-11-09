# AIAS Platform multiple URL-based inference endpoints SSRF / Local File Read

# NAME OF AFFECTED PRODUCT(S)

- AIAS Training & API Platform (REST services exposed under `/api`)

## Vendor Homepage

- [AIAS Project](http://aias.top/)

# AFFECTED AND/OR FIXED VERSION(S)

## submitter

- sh7err@vEcho

## VERSION(S)

- <= v0.23.0 (current master, no fix available)

## Software Link

- [AIAS repository](https://gitee.com/mymagicpower/AIAS)

# PROBLEM TYPE

## Vulnerability Type

- Server-Side Request Forgery (SSRF) and Local File Read via unrestricted URL fetching

## Root Cause

- Numerous controllers accept a user-supplied URL and immediately pass it to libraries such as `ImageFactory.fromUrl`, `AudioFactory.fromUrl`, or a home-grown `ImageUtil.getImageByUrl` helper (e.g., `2_training_platform/train-platform/src/main/java/top/aias/training/controller/InferController.java:46-135`, `3_api_platform/api-platform/src/main/java/top/aias/platform/controller/AsrController.java:46-214`, `4_web_app/image_search/.../SearchController.java:119-136`). These APIs call `new URL(url).openStream()` without validating the scheme, host, or destination IP, allowing attackers to coerce the server into fetching arbitrary internal or local resources.

## Impact

- Remote attackers can scan or interact with services on the internal network (e.g., cloud metadata endpoints, management planes) and retrieve their responses. Because `java.net.URL` also supports the `file:` scheme, attackers can read local files such as `/etc/passwd`, and the response is often returned in the API output or error message. Depending on the targeted endpoint, this may reveal credentials, configuration secrets, or otherwise facilitate further compromise.

# DESCRIPTION

The affected modules were designed to simplify workflows by letting users supply a URL instead of uploading media files. However, the implementation blindly trusts the entire URL string. There is no allowlist, no IP range filtering, and no scheme restrictions. As a result, calling `/api/inference/featureForImageUrl?url=file:/etc/passwd` makes the training service open the local password file, while `/api/asr/enAsrForAudioUrl?url=http://127.0.0.1:2375/version` forces the ASR service to query the Docker API on localhost. The resulting bytes are fed into the AI pipeline and often echoed back to the caller, enabling practical SSRF and local file disclosure.

# Code Analysis

Example (`4_web_app/image_search/image_search/image-search/aiplatform-system/src/main/java/me/calvin/modules/search/common/utils/ImageUtil.java` lines 87-95):

```
public static byte[] getImageByUrl(String strUrl) {
    URL url = new URL(strUrl);
    HttpURLConnection conn = (HttpURLConnection) url.openConnection();
    conn.setRequestMethod("GET");
    InputStream inStream = conn.getInputStream();
    return readInputStream(inStream);
}
```

The helper honors any scheme supported by `java.net.URL`, so `file:/etc/passwd` and `http://169.254.169.254/latest/meta-data/` both succeed.

# Authentication / Authorization

- The impacted endpoints are exposed as public REST APIs and do not enforce authentication by default. Therefore exploitation is remote and unauthenticated.

# Vulnerability details and POC

## Vulnerability type

- Server-Side Request Forgery / Local File Read

## Vulnerability location

- `top.aias.training.controller.InferController#featureForImageUrl`, `#compareForImageUrls`
- `top.aias.platform.controller.AsrController#enAsrForAudioUrl`, `#zhAsrForAudioUrl`
- `me.calvin.modules.search.rest.SearchController#searchImageByUrl` (uses `ImageUtil.getImageByUrl`)

## Proof of Concept

1. SSRF: `GET /api/asr/enAsrForAudioUrl?url=http://127.0.0.1:2375/version`
   - The ASR service fetches Docker’s unauthenticated API on localhost and returns its JSON response as the transcription result.
2. Local File Read: `GET /api/inference/featureForImageUrl?url=file:/etc/passwd`
   - `ImageFactory.fromUrl` opens the passwd file. The bytes are interpreted as an image, often causing an error whose message leaks the file content base64-encoded in the JSON response. Even when parsing fails, the request still discloses whether the file exists and reads it into memory.

# Suggested remediation

1. Restrict supported schemes to `http`/`https` and validate destinations against a configurable allowlist of trusted domains.
2. Resolve hostnames to IPs and block private, loopback, link-local, and multicast ranges to prevent internal access.
3. Consider removing server-side URL fetching altogether in favor of direct client uploads, or proxy all downloads through a hardened sandbox service with strict egress controls.
