# CVE Report – Cobalt Temporary File Exhaustion DoS

- **Submitter:** sh7err@vEcho
- **Product:** Cobalt (WhatsApp automation client)
- **Affected Version:** <= 0.1.0 (master branch commit a19a9f0)
- **Vulnerability Class:** Resource Exhaustion / Denial of Service

## Summary
Cobalt's media uploading pipeline leaves every encrypted payload on disk as a temporary file under the system TMP directory. The files are never deleted after the HTTP request completes, regardless of success or failure. An attacker who can request repeated media uploads (e.g., through a bot endpoint built on top of Cobalt) can continuously trigger uploads to accumulate unbounded `upload*.tmp` files until disk space is exhausted, taking down the host process and potentially the entire system.

## Impact
- Persistent disk consumption until available space is depleted
- Denial of service for the Cobalt process (I/O failures, crashes) and for other co-located services sharing the disk
- Works with default configuration; no special privileges required beyond the ability to ask Cobalt to upload media

## Technical Details
The method `MediaConnection#upload` creates a temp file for every upload:
```java
var tempFile = Files.createTempFile("upload", ".tmp");
try (uploadStream; var outputStream = Files.newOutputStream(tempFile)) {
    uploadStream.transferTo(outputStream);
}
...
var request = HttpRequest.newBuilder()
        .uri(uri)
        .POST(HttpRequest.BodyPublishers.ofFile(tempFile))
        .build();
client.send(request, HttpResponse.BodyHandlers.ofByteArray());
```
(see `src/main/java/com/github/auties00/cobalt/media/MediaConnection.java`, lines 37-111)

There is no `finally` block nor any call to `Files.delete*` or `File#deleteOnExit`. A repository-wide search shows no cleanup routine for `upload*.tmp`. Consequently, every upload permanently leaves a full copy of the payload in `/tmp` (or the platform temp folder). Because uploads are attacker-controlled in many Cobalt deployments, a malicious client can loop over uploads of large payloads to fill the disk.

## Proof of Concept
```java
var media = Files.createTempFile("large", ".bin");
Files.write(media, new byte[100 * 1024 * 1024]);
while (true) {
    whatsapp.mediaConnection().get().upload(provider, Files.newInputStream(media));
}
```
Observe `/tmp/upload*.tmp` increasing without bound via `ls -lh /tmp/upload*`.

## Mitigations
- Delete the temporary file in a `finally` block (`Files.deleteIfExists(tempFile)`).
- Prefer `HttpRequest.BodyPublishers.ofInputStream` to stream the encrypted payload directly without materializing it on disk.

## References
- Vulnerable source file: `src/main/java/com/github/auties00/cobalt/media/MediaConnection.java`
