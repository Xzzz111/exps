# CVE Report – Cobalt Session Store Permission Disclosure

- **Submitter:** sh7err@vEcho
- **Product:** Cobalt (WhatsApp automation client)
- **Affected Version:** <= 0.1.0 (master branch commit a19a9f0)
- **Vulnerability Class:** Information Disclosure / Credential Exposure

## Summary
Cobalt serializes every WhatsApp session to `~/.cobalt/<type>/<uuid>/store.proto` using default filesystem permissions and without encrypting sensitive fields. On typical Linux/Unix systems the default `umask 022` results in directories readable by every local user (755) and files readable by every local user (644). Because the serialized protobuf includes Noise/Signal identity key pairs, signed pre-keys, device identities, and backup tokens, any local unprivileged user can copy those files and fully impersonate the victim’s WhatsApp account.

## Impact
- Complete compromise of WhatsApp identities and conversation history stored in the protobuf
- Ability for a local attacker to clone the session, decrypt media, and send messages as the victim
- Persistence across application restarts because the attacker keeps a copy of the serialized keys

## Technical Details
`ProtobufStoreSerializer` always writes files underneath `DEFAULT_SERIALIZER_PATH = ~/.cobalt/`:
```java
private Path getSessionFile(WhatsAppClientType clientType, String uuid, String fileName) {
    var result = getSessionDirectory(clientType, uuid).resolve(fileName);
    Files.createDirectories(result.getParent());
    return result;
}
```
`s getSessionDirectory` simply calls `Files.createDirectories(result.getParent())` with no POSIX permission mask or encryption. The subsequent `Files.newOutputStream` in `encodeStore`, `serializeChat`, etc., writes plaintext protobufs.

The `WhatsappStore` model confirms that highly sensitive credentials are serialized verbatim:
```java
@ProtobufProperty(index = 41, type = ProtobufType.INT32)
final Integer registrationId;
@ProtobufProperty(index = 42, type = ProtobufType.MESSAGE)
final SignalIdentityKeyPair noiseKeyPair;
@ProtobufProperty(index = 44, type = ProtobufType.MESSAGE)
final SignalIdentityKeyPair identityKeyPair;
@ProtobufProperty(index = 47, type = ProtobufType.MESSAGE)
final SignalSignedKeyPair signedKeyPair;
```
(see `src/main/java/com/github/auties00/cobalt/store/WhatsappStore.java`, lines 563-640)

Because no warning or hardening is applied, a local co-tenant only needs filesystem read access to the victim’s home directory (default on multi-user systems) to copy the `.proto` files and replay them with `WhatsappStoreSerializer` to hijack the account.

## Proof of Concept
```
$ ls -l ~/.cobalt/web/<uuid>/store.proto
-rw-r--r-- 1 victim victim 131072 Apr 16 10:55 store.proto
$ cp ~/.cobalt/web/<uuid>/store.proto /tmp/
$ java -jar cobalt.jar --load-store /tmp/store.proto
```
The resulting client connects as the victim because all key material was present in the file.

## Mitigations
- Explicitly set `0700`/`0600` permissions when creating directories and files (POSIX or platform-specific ACLs).
- Encrypt sensitive fields inside the protobuf using a user-supplied passphrase or OS keyring.
- Document the requirement to run Cobalt under a dedicated user account whose home directory is not world-readable.

## References
- Vulnerable source: `src/main/java/com/github/auties00/cobalt/store/ProtobufStoreSerializer.java`
- Sensitive data structure: `src/main/java/com/github/auties00/cobalt/store/WhatsappStore.java`
