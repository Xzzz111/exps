* Vulnerability type info 
Resource exhaustion / temporary file leak leading to DoS

* Vendor of the product(s) info
Auties00

Affected product(s)/code base info
Cobalt

* Product Version
<= 0.1.0 (no fixed version available)

Has vendor confirmed or acknowledged the vulnerability
No

Attack type info 
Remote

Impact info
Denial of Service

Affected component(s)
src/main/java/com/github/auties00/cobalt/media/MediaConnection.java (MediaConnection#upload)

Attack vector(s)
An attacker who can trigger media uploads can repeatedly request uploads of large payloads; the library leaves each payload as an undeleted temp file, exhausting disk space.

Suggested description of the vulnerability for use in the CVE info
Cobalt's MediaConnection#upload stores every encrypted payload in a temp file but never deletes it, allowing a remote user who can trigger uploads to accumulate unlimited `upload*.tmp` files and exhaust disk storage, resulting in denial of service.

Discoverer(s)/Credits info
sh7err@vEcho

Reference(s) info
https://github.com/Auties00/Cobalt

Additional information
No official patch is available as of this report; mitigations include deleting the temp file in a finally block or streaming the payload directly.
