# 3DSRelay

A proof-of-concept offline messenger for the Nintendo 3DS. Nearby consoles exchange encrypted messages over local wireless (UDS ad-hoc) and relay them hop-by-hop, so a message can reach a recipient who isn't directly in range as long as a chain of devices connects them. It needs no internet, cell service, or access point.

The app presents itself on the Home Menu as a FAT32 disk diagnostics tool.

> This is an experimental project for learning and demonstration. The protocol is custom and has **not** been independently audited or reviewed. Don't rely on it where your safety depends on it. See [Limitations](#limitations).

---

## Getting started

### Install

1. Copy `3DSRelay.cia` to the SD card and install it with FBI or another CIA installer.
2. Optionally copy a signed update package to `sdmc:/3ds/3DSRelay.update`. A device that holds one will seed it to nearby devices over the mesh.
3. It appears on the Home Menu as **FAT32 File System Diagnostics**.

### Unlock and set up identity

1. Launch **FAT32 File System Diagnostics**. It opens to a locked screen styled as a disk scanner.
2. Enter the unlock combination on the buttons (default: Up, Down, Up, Down, Left, Right). The combo is hashed and only checked once you've entered the full length, so the screen gives no feedback as you go.
3. Enter your alias. It is mixed into key derivation and is required every session.
4. Enter a passphrase. The alias and passphrase together derive your keypairs.

Your passphrase is never written to disk. The alias is stored in the config, and the identity seed is stored encrypted (it can only be decrypted with the key derived from your alias + passphrase). The derived keypairs themselves live only in RAM.

**Fumbled the combo?** Press **SELECT** to clear the in-progress entry. A wrong button stays in the buffer until the sequence reaches full length and then fails as a whole, so SELECT lets you start over cleanly. The entry also clears itself after 5 seconds of inactivity.

**Change the combo:** under **System Settings → Change Access Pattern**, press buttons to record a new sequence (up to 16), **START** to save, **SELECT** to cancel.

### Add a contact

Open **Add Contact** and either **Scan QR Code** (point the outer camera at the other person's code) or **Enter Key Manually** (their alias and 64-char public-key hex). Show your own code under **Show My Public Key**, which also displays a short fingerprint you can read out to verify in person.

The handshake is mutual: a contact becomes usable only once **both** consoles have added each other. After you add someone they show as `[Pending]`; once their handshake arrives back the entry becomes `[Active]` and can be messaged. Handshakes are resent in the background for a while, so the order in which you scan each other doesn't matter.

If someone adds you first, a **Contact Request** screen shows their alias and fingerprint — **A** to accept, **B** to reject. An unsolicited handshake registers nothing until you accept it.

### Messaging

- **Compose Private Msg** — pick a confirmed recipient under **Select Recipient**, then type. The message is encrypted so only that contact can read it. Pending contacts can't be selected.
- **Compose Broadcast Msg** — a signed, public message readable by everyone in range.
- Undelivered messages are held and relayed by intermediate consoles, so a recipient who isn't reachable now may receive a message later once a path exists. There is no delivery guarantee or acknowledgement.

### Updates

A device holding a newer signed package seeds it to nearby devices, which verify the signature and payload hash before installing through the system AM service. The app checks for a staged update at startup and via **Check for Updates** in settings. Transfers are batched and resumable: if the link drops mid-download, progress is saved and a later check continues from where it stopped.

### Controls

| Context | Button | Action |
| --- | --- | --- |
| Locked | unlock combo | Enter the sequence to unlock |
| Locked | SELECT | Clear the in-progress combo |
| Any menu | D-pad Up/Down | Move selection |
| Any menu | A | Select / confirm |
| Submenu | B | Back |
| Main menu | START | Exit |
| Contact request | A / B | Accept / reject |
| QR scan | A / B | Capture a frame / cancel |
| Pattern setup | any buttons | Record (START save, SELECT cancel) |

With the lid closed the app keeps relaying: sleep is suppressed, the screens blank to save power, and it re-locks when the lid reopens.

### Clearing data

- **Three completed-but-wrong unlock attempts** clear the keys and contacts from RAM and force you to re-enter your passphrase. This does **not** delete anything from the SD card — your encrypted identity and saved contacts are reloaded on the next successful unlock.
- **System Settings → Panic Wipe Staging** and **Lock & Exit** both run a scrub that zeroes the keys in RAM and deletes the contacts file and packet cache from the SD card.

---

## How it works

### Mesh networking

Consoles find each other over UDS (Nintendo's local wireless) using a fixed comm ID. Packets propagate epidemically: each node stores what it receives and rebroadcasts it to peers it meets, and a TTL field caps the number of hops. Range is whatever UDS local wireless reaches (roughly tens of metres line-of-sight), extended only by relaying through other devices.

### Connection handling

The link is torn down only after several consecutive failed health checks rather than on a single bad read, so it survives brief radio gaps. A client that ends up alone in a network (its host vanished) treats that as a dead link and re-scans, or becomes a host itself, so an isolated console recovers on its own. The link is also serviced during long blocking operations such as a QR scan. A small random delay before each transmission reduces collisions when several consoles send at once.

### Rate limiting

Each packet carries a proof-of-work nonce whose SHA-256 hash must meet a difficulty target. The difficulty is intentionally low (mining averages only a few hundred hashes) so it stays fast on the hardware — it is a mild speed bump against flooding, not a serious anti-abuse or anti-Sybil mechanism. A signature cache rejects duplicate packets before the check runs.

### Cryptography

- **Primitives** come from TweetNaCl: Ed25519 signatures and `crypto_box` (Curve25519 + XSalsa20-Poly1305) for encryption. ChaCha20 is used for at-rest encryption. The *protocol* that combines them is custom.
- **Identity**: the alias and passphrase are run through PBKDF2-HMAC-SHA256 (25,000 iterations — a compromise for the 3DS's slow CPU, lower than current desktop recommendations) to derive a key that protects a random identity seed; the seed deterministically produces the Ed25519 and Curve25519 keypairs. Mixing the alias into derivation means a different alias yields different keys and fails the integrity check.
- **Messages**: private messages use `crypto_box`; broadcasts and handshakes are signed with Ed25519. Update manifests are signed with a developer key whose public half is embedded in the app.
- **Contact trust**: the QR card carries an alias and a public key but no signature, so adding a contact is trust-on-first-use — verify the fingerprint in person if it matters. A contact's alias is pinned to its key on first add and not overwritten afterward.

### OTA updates

`3DSRelay.update` is a signed manifest (version, payload size, SHA-256, Ed25519 signature) followed by the CIA payload. The downloader requests blocks in batches; the seeder streams them from one open handle, paced for the receive queue. A per-block bitmap is saved next to the partial file so an interrupted transfer resumes from the missing blocks, and the downloader re-acquires any peer advertising the same version and hash if the seeder drops. The wire format is unchanged, so a seeder still answers single-block requests from older peers.

### Persistence

SD writes (config, contacts, packet cache) use a write-temp-then-rename pattern to avoid corruption from power loss or a crash.

---

## Limitations

This is a proof of concept, not a hardened secure messenger. Known limits:

- **Not audited.** The cryptographic primitives are standard, but the surrounding protocol is custom and has had no external review.
- **Metadata is exposed.** It is not anonymous. Anyone in range can observe ciphertext, ephemeral keys, packet timing, and the sender of a broadcast. Epidemic relaying makes traffic analysis easier, not harder.
- **The unlock combo is weak.** It is a short button sequence with a small keyspace — a shoulder-surf/quick-lock deterrent, not a strong password. The 3-attempt RAM scrub limits online guessing but the secret itself is low-entropy.
- **Contact exchange is trust-on-first-use.** The QR card is unsigned, so an attacker who controls what code you scan can substitute their own key. The fingerprint check is the only defence.
- **The disguise is cosmetic.** The name and icon present as a disk tool and the UI uses diagnostic-sounding labels, but anyone who gets past the lock sees a messenger. It is not steganographic or undetectable.
- **Rate limiting is light** (see above) and the PBKDF2 iteration count is modest for the hardware.
- **No delivery guarantees.** Messages may never arrive if no path forms before they age out of the relay buffers.

---

## Build

Requires devkitARM, libctru, and makerom.

```
make clean && make
```

Pack a signed update:

```
make update SIGNING_KEY=<private_key_hex>
```

This reads the version from source and produces `3DSRelay.update`.

## Credits

- [TweetNaCl](https://tweetnacl.cr.yp.to/)
- [Smaz](https://github.com/antirez/smaz)
- [QR Code generator](https://www.nayuki.io/page/qr-code-generator-library)
- [quirc](https://github.com/dlbeer/quirc)
- [devkitARM](https://devkitpro.org/) / [libctru](https://github.com/devkitPro/libctru)
