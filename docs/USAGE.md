# How to use `@snazzah/davey`
Hi, this package has helper functions and methods to handle the [DAVE protocol](https://daveprotocol.com/).
If you plan on implementing this as a dependency, it is still your library's job to manage the session flow, use the appropriate functions when handling certain events, and handle session transitions. If you want an example of an implementation, [here is my PR to the dysnomia library (an eris fork)](https://github.com/projectdysnomia/dysnomia/pull/196) that should handle everything, this is roughly what this document is based off of.

> [!NOTE]  
> To double check my work, check the [whitepaper](https://daveprotocol.com/). If there is a mistake in this document or something that isn't right, let me know!

# Prerequisites
Your library should:
- Use Voice Gateway V8
- Use the new encryption modes (`aead_xchacha20_poly1305_rtpsize` & `aead_aes256_gcm_rtpsize`). If you aren't currently, then voice connections aren't even working for you right now.
- Be able to differentiate between binary and plaintext messages when receiving WebSocket messages.
- Handle voice op codes `CLIENTS_CONNECT` (11) and `CLIENT_DISCONNECT` (13)

# Implementation
Make sure to have `@snazzah/davey` as a peer/optional dependency. It should be at least at version `0.2.0`.

Then, add these voice opcodes to any enum/mapping you have these for:
```ts
DAVE_PREPARE_TRANSITION:        21;
DAVE_EXECUTE_TRANSITION:        22;
DAVE_TRANSITION_READY:          23;
DAVE_PREPARE_EPOCH:             24;
MLS_EXTERNAL_SENDER:            25;
MLS_KEY_PACKAGE:                26;
MLS_PROPOSALS:                  27;
MLS_COMMIT_WELCOME:             28;
MLS_ANNOUNCE_COMMIT_TRANSITION: 29;
MLS_WELCOME:                    30;
MLS_INVALID_COMMIT_WELCOME:     31;
```

You should also add two properties, one for knowing what protocol version is being used in the session `daveProtocolVersion`, and one for the session, `daveSession`. Might be good to let developers access that property.

Add the `max_dave_protocol_version` property to the `IDENTIFY` opcode, using `Davey.DAVE_PROTOCOL_VERSION` (the maximum supported protocol version):
```ts
this.sendWS(VoiceOPCodes.IDENTIFY, {
	max_dave_protocol_version: Davey?.DAVE_PROTOCOL_VERSION ?? 0,
	...
});
```

Very cool, now Discord knows you like DAVE, now time to handle it...

## Session Transitions
During the voice session, every time someone joins or leaves, you'll need to transition the MLS group to another epoch. You won't have to deal with the exchanging secrets and epoch stuff, but you *do* have to tell the session about transitions with `daveSession.prepareTransition` and `daveSession.executeTransition`.

[In my PR](https://github.com/projectdysnomia/dysnomia/pull/196), I've stored pending transitions in `#davePendingTransitions`, noted if the last transition was a downgrade with `#daveDowngraded` and executed them with `#executePendingTransition` which consists of this:
```ts
#executePendingTransition(transitionId: number) {
	// If we didn't expect the transition, warn about it.
  if(!this.#davePendingTransitions.has(transitionId)) {
    return this.emit("warn", `Received execute transition, but we don't have a pending transition for ${transitionId}`);
  }

  // ID 0 already gets executed by davey in `prepareTransition`
  if(transitionId !== 0) {
    try {
      this.daveSession?.executeTransition(transitionId);
    } catch(e) {
      this.emit("warn", `Failed to execute DAVE transition: ${e}`);
    }
  }

  const oldVersion = this.daveProtocolVersion;
  this.daveProtocolVersion = this.#davePendingTransitions.get(transitionId);

  // Handle upgrades & defer downgrades
  if(oldVersion !== this.daveProtocolVersion && this.daveProtocolVersion === 0) {
    // We've downgraded to transport-only encryption, sad.
    this.#daveDowngraded = true;
    this.emit("debug", "DAVE protocol downgraded");
  } else if(transitionId > 0 && this.#daveDowngraded) {
    // We've upgraded from transport-only encryption, cool.
    this.#daveDowngraded = false;
    this.daveSession?.setPassthroughMode(false, 10);
    this.emit("debug", "DAVE protocol upgraded");
  }

  this.emit("debug", `DAVE transition executed (v${oldVersion} -> v${this.daveProtocolVersion}, id: ${transitionId})`);

  this.#davePendingTransitions.delete(transitionId);
	return true;
}
```

Note that `setPassthroughMode` function. It's used to let other clients to send unencrypted voice frames to us and "passthrough" the MLS decryption. Enabling it allows unencrypted frames until it's disabled. What if a packet is a little late? In this case, when we upgrade from a previously-downgraded session, we disable passthrough mode with a 10 second expiry, so clients can still passthrough packets for 10 seconds, and after that, their unencrypted packets won't be allowed anymore. This 10 second rule is carried out through pretty much every transition. The package handles the keys for joins and leaves mid-encrypted session as long as you prepare and execute transitions. However during upgrades and downgrades, you'll have to handle passthrough mode (as you see here) and we'll get to handling that more later.

## Handling Voice Events

Now we need to update the voice WebSocket handler to get all the new events down.

#### `SESSION_DESCRIPTION`
During `SESSION_DESCRIPTION`, note down the returned protocol version from `dave_protocol_version`, and set `#daveDowngraded` if it's `0`. This is where your session should be initialized. [In my PR](https://github.com/projectdysnomia/dysnomia/pull/196), I made a function to create/reinitialize the DAVE session since we may need to re-init the session depending on what the voice server tells us, so in this case, a `#reinitDaveSession` function would work. (with it using the version we just got from this event)

```ts
#reinitDaveSession() {
	if(this.daveProtocolVersion > 0) {
		// We have a DAVE session to handle...
		if(this.daveSession) {
			// The package has a `reinit` function to pretty much wipe all decryptors and redo everything, so you don't need to remake the class. You'll see why you need to keep the class anyways.
			this.daveSession.reinit(this.daveProtocolVersion, this.userId, this.channelId);
			this.emit("debug", `DAVE session reinitialized for protocol version ${this.daveProtocolVersion}`);
		} else {
			this.daveSession = new DAVESession(this.daveProtocolVersion, this.userId, this.channelId);
			this.emit("debug", `DAVE session initialized for protocol version ${this.daveProtocolVersion}`);
		}

		// When upgrading, unencrypted packets are still sent until the transition is executed
		if(this.#daveDowngraded) {
			this.daveSession.setPassthroughMode(true);
		}

		// Generate a key package and send it to the voice server
		this.sendWSBinary(VoiceOPCodes.MLS_KEY_PACKAGE, this.daveSession.getSerializedKeyPackage());
	} else {
		// This purges the group internally, but you still have decryptors
		this.daveSession?.reset();
		if(this.daveSession) {
			// Allow clients to passthrough after downgrading
			this.daveSession.setPassthroughMode(true);
			this.emit("debug", "DAVE session reset");
		}
	}
}
```

#### `MLS_EXTERNAL_SENDER`
Now that we have something initialized, an `MLS_EXTERNAL_SENDER` event would usually follow.

 > [!IMPORTANT]  
> This is a binary event, so make sure to handle those properly! As a quick reminder, this is how you can easily get the starting values you need:
> ```ts
> const seq = message.readUInt16BE(0);
> const op = message.readUInt8(2);
> ```
> You'll need to set the sequence number from these binary messages too.

In this event handling, send the external sender to the session class:

```ts
this.daveSession.setExternalSender(m.subarray(3));
```

That's it for this one, the other binary messages are pretty simple to handle too.

#### `MLS_PROPOSALS`
Here's what to do when handling `MLS_PROPOSALS`:

```ts
const optype = m.readUInt8(3);
const {commit, welcome} = this.daveSession.processProposals(optype, m.subarray(4), recognizedUserIds);
if(commit) {
	// This sends a binary message to the voice server, pretty much the same as `Buffer.concat([optype, buffer])` with optype being a uint8
	this.sendWSBinary(VoiceOPCodes.MLS_COMMIT_WELCOME, welcome ? Buffer.concat([commit, welcome]) : commit);
}
```

`daveSession.processProposals` needs the proposals op type (either being APPEND/0 or REVOKE/1) and the proposals (or proposal refs if revoke). Both `commit` and `welcome` are optional. If an in-flight proposal was revoked (a user joins then leaves before being in the MLS group) then a commit could be `null`, meaning we don't need to create a commit for them. `welcome` can also be `null` if the resulting commit doesn't add new members to the MLS group. So we handle that here.

Also for `recognizedUserIds`, you don't *have* to have this, its an optional argument, but you should for security purposes. This should be the set of user IDs you received through `CLIENTS_CONNECT` **and your own user ID**, so make sure to maintain that in your library code.

#### `MLS_ANNOUNCE_COMMIT_TRANSITION`
Here's where you actually process those commits you've made. It can either be your own or someone else's. The package will handle both cases.
```ts
const transitionId = message.readUInt16BE(3);
try {
	// The commit is ignored if there's no established group or queued proposals (e.g. while resetting)
	if (!this.daveSession.processCommit(message.subarray(5))) return;
	// Prepare the new keys, these are used once the transition is executed (or right away for transition ID 0)
	this.daveSession.prepareTransition(transitionId, this.daveSession.protocolVersion);
	// We note our pending transition because `DAVE_EXECUTE_TRANSITION` will follow
	// except on reinitializing transitions (transition ID 0)
	if (transitionId !== 0) {
    this.#davePendingTransitions.set(transitionId, this.daveProtocolVersion);
		this.sendWS(VoiceOPCodes.DAVE_TRANSITION_READY, {transition_id: transitionId});
	}
	this.emit("debug", `MLS commit processed (transition id: ${transitionId})`);
} catch(e) {
	// In the event this *does* error, you'll need to tell the voice server something went wrong and recover
	this.emit("warn", `MLS commit errored: ${e}`);
	this.#recoverFromInvalidCommit(transitionId, data.user_id, data.channel_id);
}
```

`#recoverFromInvalidCommit` just consists of this:
```ts
#recoverFromInvalidCommit(transitionId: number) {
	this.sendWS(VoiceOPCodes.MLS_INVALID_COMMIT_WELCOME, {transition_id: transitionId});
	this.#reinitDaveSession(this.userId, this.channelId);
}
```
We send a WebSocket message saying that commit sucked, and reinitialize our session.

#### `MLS_WELCOME`
This is pretty much the previous event. except we are joining the group and need to process a welcome.
```ts
const transitionId = m.readUInt16BE(3);
try {
	this.daveSession.processWelcome(m.subarray(5), recognizedUserIds);
	this.daveSession.prepareTransition(transitionId, this.daveSession.protocolVersion);
	if (transitionId !== 0) {
    this.#davePendingTransitions.set(transitionId, this.daveProtocolVersion);
		this.sendWS(VoiceOPCodes.DAVE_TRANSITION_READY, {transition_id: transitionId});
	}
	this.emit("debug", `MLS welcome processed (transition id: ${transitionId})`);
} catch(e) {
	this.emit("warn", `MLS welcome errored: ${e}`);
	this.#recoverFromInvalidCommit(transitionId, data.user_id, data.channel_id);
}
```

#### `DAVE_PREPARE_TRANSITION`
Here we, well, prepare for a transition. I store the pending transition in the aforementioned `#davePendingTransition` but we also need to handle other cases too!
```ts
this.emit("debug", `Preparing for DAVE transition (${packet.d.transition_id}, v${packet.d.protocol_version})`);
this.#davePendingTransitions.set(packet.d.transition_id, packet.d.protocol_version);

try {
	this.daveSession?.prepareTransition(packet.d.transition_id, packet.d.protocol_version);
} catch(e) {
	this.emit("warn", `Failed to prepare DAVE transition: ${e}`);
}

// When the included transition ID is 0, the transition is for (re)initialization and it can be executed immediately.
if(packet.d.transition_id === 0) {
	this.#executePendingTransition(packet.d.transition_id);
} else {
	// Upon receiving this message, clients enable passthrough mode on their receive-side
	// https://daveprotocol.com/#downgrade-to-transport-only-encryption
	if(packet.d.protocol_version === 0) {
		this.daveSession?.setPassthroughMode(true);
	}
	this.sendWS(VoiceOPCodes.DAVE_TRANSITION_READY, {transition_id: packet.d.transition_id});
}
```


#### `DAVE_EXECUTE_TRANSITION`
Oh hey I guess we have a function for that now, huh?
```ts
this.emit("debug", `Executing DAVE transition (${packet.d.transition_id})`);
this.#executePendingTransition(packet.d.transition_id);
```

#### `DAVE_PREPARE_EPOCH`
This isn't much, we just need to handle for `1` epochs.
```ts
this.emit("debug", `Preparing for DAVE epoch (${packet.d.epoch})`);
// When the epoch ID is equal to 1, this message indicates that a new MLS group is to be created for the given protocol version.
if(packet.d.epoch === 1) {
	this.daveProtocolVersion = packet.d.protocol_version;
	this.#reinitDaveSession(this.userId, this.channelId);
}
```

## Handling Voice Packets
Now that we have WebSocket message exchanging squared away, we should actually start encrypting and decrypting our stuff.

Encrypting voice packets is fairly easy, right before you encrypt your packet with the transport encryption mode, encrypt it with DAVE:
```ts
let frame = unencryptedFrame;
if(this.#daveReady && !unencryptedFrame.equals(SILENCE_FRAME)) {
	// After a welcome, we don't have a key until the transition is executed, so drop the frame to avoid leaking it
	if(!this.daveSession.canEncrypt) {
		return;
	}
	frame = this.daveSession.encryptOpus(unencryptedFrame);
}
```

Here we use a `#daveReady` getter that just consists of this:
```ts
get #daveReady() {
	return this.daveProtocolVersion !== 0 && !this.#daveDowngraded && this.daveSession?.ready;
}
```

This makes sure that if we have downgraded, we stop encrypting. Also we don't encrypt silent frames. The package already filters those (before it didn't) but doing it yourself probably won't hurt. Should also note `daveSession.ready` means that packets are *ready* to be decrypted, and `daveSession.canEncrypt` means we have a key to encrypt with. Checking readiness in general is with `daveSession.status`.

Now time to decrypt other's packets. Remember the 10 second rule? This gets a bit weird since we want to decrypt packets that are late after a decryption. So sometimes, encrypted packets may show up even after we went transport-only. (This is why the session class is kept even after downgrading!) `daveSession.canPassthrough` will tell you if a user's packet can passthrough. This means they also have a decryption key in the session and could decrypt those late packets. Woo!
```ts
if(this.daveSession && userID && !data.equals(SILENCE_FRAME)) {
	try {
		const canDecrypt = this.daveSession.ready && (this.#daveReady || this.daveSession.canPassthrough(userID));
		if(canDecrypt) {
			data = this.daveSession.decrypt(userID, Davey.MediaType.AUDIO, data);
		}
	} catch {
		return this.emit("warn", `Failed to decrypt received E2EE packet from ${userID}`);
	}
}
```

## That's pretty much it!
This should cover what's needed to handle an MLS session with this package. Some cool things you can get from this:
- `daveSession.voicePrivacyCode` will give you... the voice privacy code! It's a getter that will update automatically during session changes.
- `daveSession.getVerificationCode(userId)` gets the verification code of another person. This gives you a promised string.
- `daveSession.getEncryptionStats` and `daveSession.getDencryptionStats(userId)` does exactly that. This was something I took from libdave. Think of this being good for a debug thing.

Hopefully this works for you, and if not, [make a PR/issue](https://github.com/Snazzah/davey) and let me know! I'm not 100% knowledgeable on how to properly handle everything as Discord does, but I can try my best.

If you like my work, [give the repo a star](https://github.com/Snazzah/davey) or [follow me](https://github.com/Snazzah).