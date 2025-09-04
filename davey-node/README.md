# Davey!

[![NPM version](https://img.shields.io/npm/v/@snazzah/davey?maxAge=3600)](https://www.npmjs.com/package/@snazzah/davey) [![install size](https://packagephobia.com/badge?p=@snazzah/davey)](https://packagephobia.com/result?p=@snazzah/davey) [![NPM downloads](https://img.shields.io/npm/dt/@snazzah/davey?maxAge=3600)](https://www.npmjs.com/package/@snazzah/davey) [![discord chat](https://img.shields.io/discord/311027228177727508?logo=discord&logoColor=white&color=5865F2)](https://snaz.in/discord)

A [Discord Audio & Video End-to-End Encryption (DAVE) Protocol](https://daveprotocol.com/) implementation using [OpenMLS](https://openmls.tech/) built with [NAPI-RS](https://napi.rs/).

> Proper documentation does not exist yet, but you can [read the usage document](https://github.com/Snazzah/davey/blob/master/docs/USAGE.md) and review the [type definitions](https://github.com/Snazzah/davey/blob/master/index.d.ts) for available methods.

```ts
import { DAVESession, ProposalsOperationType, MediaType, Codec } from '@snazzah/davey';

const session = new DAVESession(
  1, // dave version
  '158049329150427136', // user id
  '927310423890473011', // channel id
);

// Set the external sender of the session from opcode 25
session.setExternalSender(externalSenderBuffer);

// Get the key package buffer to send to Discord
session.getSerializedKeyPackage();

// Process a proposals
session.processProposals(
  ProposalsOperationType.APPEND, // the type of proposals operation
  proposalsBuffer, // proposals or proposal refs buffer
  recognizedUserIds, // an array of user IDs in the session, optional but recommended
);

// Process a commit
session.processCommit(commitBuffer);

// Process a welcome
session.processWelcome(welcomeBuffer);

// The current voice privacy code of the session, updated after a commit/welcome
session.voicePrivacyCode; // a 30 digit string or an empty string for not started sessions

// Encrypt/decrypt voice packets
if (session.ready) {
  // Encrypt packets with a specified media type and codec, use this before transport encryption
  session.encrypt(MediaType.AUDIO, Codec.OPUS, packet);
  // Really only opus is supported right now so just use the shorthand method
  session.encryptOpus(packet);
  // Decrypt a packet from a user, use this after transport decryption
  session.decrypt(userId, MediaType.AUDIO, incomingPacket);
}
```

#### References

- [daveprotocol.com](https://daveprotocol.com/)
- [discord/libdave](https://github.com/discord/libdave)
- [Discord Dev Docs - Voice - E2EE](https://discord.com/developers/docs/topics/voice-connections#endtoend-encryption-dave-protocol)
- [NAPI-RS](https://napi.rs/docs/introduction/getting-started)
- [OpenMLS Book](https://book.openmls.tech/introduction.html)
- [Voice Model - High Level Summary - DPP](https://dpp.dev/voice-model.html)
