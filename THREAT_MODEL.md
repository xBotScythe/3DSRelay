# Threat model

This is a proof of concept, not a finished secure messenger. Before trusting it with anything that matters, here's an honest account of what it protects, what it doesn't, and who it can and can't keep out. The crypto building blocks are standard, but the way they're wired together is homemade and hasn't been reviewed by anyone outside this project.

## What it's actually trying to protect

Mostly one thing: a private message should only be readable by the person you sent it to.

After that, roughly in order: your identity keys (the secret keys derived from your alias and passphrase), what's saved on your SD card (your encrypted identity and your contacts), and the link between a contact's name and their real keys.

One thing it deliberately does **not** protect is the fact that you're communicating at all — who's talking, when, and that you're part of the network. This is not an anonymity tool, and the rest of this document keeps coming back to that.

## Who might come after you, and how it holds up

### Someone listening on the radio nearby

Anyone with the right gear, within wireless range, can hear everything on the air: the encrypted messages, the temporary keys attached to them, the timing, and what type each packet is. They can also read any broadcast and see who sent it, because broadcasts are public on purpose.

What they *can't* do is read your private messages. Those are sealed to the recipient's key, so a sniffer just sees noise.

The honest catch: they can still tell that communication is happening, roughly when, and that you're involved. Relaying actually makes this easier to watch, not harder, because copies of your traffic get passed around. Same-size packets and a small random delay before each send round off the sharpest edges, but none of that is anonymity — don't treat it as such.

### Someone flooding or replaying packets

An attacker in range can try to jam the mesh by injecting junk or replaying old packets. Two things push back: every packet has to carry a small proof-of-work stamp before anyone processes or forwards it, and a cache of recently-seen packets drops exact replays.

Be clear about how strong this is: the proof-of-work is a speed bump, not a wall. It's tuned low so it runs on 2011 hardware, which means a determined attacker with real hardware can still flood you. It raises the cost of being annoying, but it does not stop a serious annoyance.

Tampering is handled better: change any byte of a packet and its proof-of-work (and signature, if it has one) stops checking out. That part is covered by the tests.

### Someone trying to impersonate a contact

When you add someone, you're trusting that the key you got really belongs to them. The QR code is a *signed* card now: it bundles the alias, the encryption key, and the signing key with a signature over them, so the scanner rejects a card that's been corrupted or has mismatched keys.

What that buys you: you can't be tricked into pasting one person's encryption key under someone else's identity, and the fingerprint you read out loud now covers a consistent identity. What it does **not** buy you: protection against someone who just makes their own signed card and hands it to you instead of the real person's. The only defense against that is checking the fingerprint with the other person face-to-face. Once you've added someone, their name stays pinned to that key and isn't silently overwritten later.

### Someone who steals the device

If someone gets their hands on your console, locked or not:

Your identity seed on the SD card is encrypted with a key derived from your alias and passphrase (PBKDF2, 25,000 rounds — modest, but the CPU is slow). The passphrase itself is never written down anywhere, and the actual keys only exist in RAM while you're unlocked. Your contacts and your saved message history are also encrypted on disk, under a separate storage key, so a raw SD card does not leak them, including broadcast text.

The unlock combo, though, is a deterrent and nothing more. It's a short button sequence with a small number of possibilities, which is fine against someone glancing over your shoulder or grabbing the device for a minute, useless against someone willing to sit and guess. Three full wrong attempts wipe the keys from memory. Lock & Exit just clears RAM and closes the app — your encrypted files stay on the card and come back when you unlock. Panic Wipe is the one that goes further and deletes the contacts and packet files outright.

And the disguise is just paint. The app shows up as "FAT32 File System Diagnostics" and talks like a disk tool, but the 3DS has no secure hardware to actually hide behind. Anyone who gets past the lock sees a messenger. It's plausible cover for a casual glance, not protection against someone who knows what they're looking at or who images the SD card.

### A poisoned update

Updates spread device-to-device over the mesh, so in principle someone could try to feed you a malicious one. Every update is signed with a developer key whose public half is baked into the app, and a console checks both that signature and the payload's hash before installing anything. A forged or altered package gets rejected. The private signing key stays with the developer.

## Where it falls short
- **It's not anonymous.** Traffic analysis is easy here, by design. If hiding *that* you communicate matters, this isn't the tool.
- **Flood protection is light.** The proof-of-work is a nuisance to attackers, not a real defense, and there's no meaningful Sybil resistance.
- **Messages can just not arrive.** If no chain of devices ever connects you to the recipient before the message ages out, it's gone, with no acknowledgement either way.
- **Nobody has audited the protocol.** The pieces are standard; the assembly is custom and unreviewed.
- **A stolen passphrase loses everything.** It recovers your long-term identity. Per-message temporary keys limit the damage but don't undo it.

## What's actually been tested

A test suite runs on a normal computer (no 3DS needed) on every push, and covers the parts that don't depend on the hardware: the proof-of-work (including that relaying a packet doesn't break it and that tampering does), packet de-duplication, the hashing and compression, that every packet type is the same size on the wire, and that the encrypted storage round-trips and refuses a wrong key. The radio layer, the camera and QR scanning, and the on-device key handling can only really be checked on actual hardware.
