* Vulnerability type info 
Server-Side Request Forgery / Local File Read via unrestricted URL fetch

* Vendor of the product(s) info
AIAS Project (aias.top)

Affected product(s)/code base info
* Product* Version
AIAS API & Training Platform <= 0.23.0 (no fix available)

Optional
Has vendor confirmed or acknowledged the vulnerability No

Attack type info 
Remote

Impact info
Information Disclosure

Affected component(s)
`2_training_platform/train-platform/src/main/java/top/aias/training/controller/InferController.java`, `3_api_platform/api-platform/src/main/java/top/aias/platform/controller/AsrController.java`, `4_web_app/image_search/image_search/image-search/aiplatform-system/src/main/java/me/calvin/modules/search/common/utils/ImageUtil.java`

Attack vector(s)
The APIs expose endpoints such as `/api/inference/featureForImageUrl`, `/api/asr/enAsrForAudioUrl`, and `/api/search/url` that accept attacker-supplied URLs and fetch them with `java.net.URL#openStream`. By pointing these parameters to internal hosts, cloud metadata services, or `file:/` URIs, an attacker can force the server to retrieve and return sensitive resources.

Suggested description of the vulnerability for use in the CVE info
AIAS Platform <= 0.23.0 exposes multiple URL-based inference endpoints that forward a user-controlled URL to `ImageFactory.fromUrl`, `AudioFactory.fromUrl`, or `ImageUtil.getImageByUrl` without scheme or address validation. Remote attackers can abuse these endpoints to perform SSRF against internal services or read arbitrary local files.

Discoverer(s)/Credits info
sh7err@vEcho

Reference(s) info
https://gitee.com/mymagicpower/AIAS

Additional information
Blocking private/loopback networks and limiting schemes to http/https would mitigate the issue; ideally the services should require file uploads rather than server-side downloads.
