* Vulnerability type info 
Insecure default permissions / plaintext credential storage

* Vendor of the product(s) info
Auties00

Affected product(s)/code base info
Cobalt

* Product Version
<= 0.1.0 (no fixed version available)

Has vendor confirmed or acknowledged the vulnerability
No

Attack type info 
Local

Impact info
Information Disclosure

Affected component(s)
src/main/java/com/github/auties00/cobalt/store/ProtobufStoreSerializer.java; src/main/java/com/github/auties00/cobalt/store/WhatsappStore.java

Attack vector(s)
Any local user on a multi-user system can read `~/.cobalt/*/*.proto` because they are created with default 755/644 permissions and contain unencrypted Noise/Signal key material; copying the files lets the attacker impersonate the victim.

Suggested description of the vulnerability for use in the CVE info
Cobalt persists WhatsApp session protobufs under `~/.cobalt/` without setting restrictive permissions or encrypting the serialized keys, so on systems with default umask 022 any local user can read Noise/Signal private keys and clone the victim's WhatsApp session.

Discoverer(s)/Credits info
sh7err@vEcho

Reference(s) info
https://github.com/Auties00/Cobalt

Additional information
Mitigations include forcing 0700/0600 permissions for session directories/files and encrypting the serialized key material with a user-controlled secret.
