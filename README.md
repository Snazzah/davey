# davey

This is an attempt to get DAVE protocol working in TypeScript by... reimplementing MLS...

There is [mls-ts](https://gitlab.matrix.org/matrix-org/mls-ts) but the last commit is three years ago and seems to miss some certain things in the RFC (since the RFC was published in July of 2023) so this package is just to make MLS just enough for Discord to be okay with it.

> [!CAUTION]
> This is still an in-progress project. Don't use this in production stuff yet.

Note that:
- This is formed somewhat closely to the C++ libdave library.
- The code may suck quality-wise, but I'm just trying to get it working.
- I'm probably allocating too much stuff.
- I'm open to contributions.
- This may all be in vain! (if someone smarter than me makes a native thing instead)

## TODO
- [ ] Remove noble/curves dependency in favor of webcrypto
- [x] Create session
  - [x] Create key package
  - [x] Store external sender
- [ ] Process proposals
  - [ ] Parse message
    - [ ] Handle additions
    - [ ] Handle revocation
  - [ ] Create MLS message
  - [ ] Create welcome message
- [ ] RatchetTree logic
  - [ ] calculate tree hash

#### References
- [daveprotocol.com](https://daveprotocol.com/)
- [libdave](https://github.com/discord/libdave)
- [Discord Dev Docs - Voice - E2EE](https://discord.com/developers/docs/topics/voice-connections#endtoend-encryption-dave-protocol)