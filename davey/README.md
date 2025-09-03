# davey

A Rust implementation of DAVE.

> [NOTE]
> I needed to fork [`aes-gcm`](https://github.com/RustCrypto/AEADs/tree/master/aes-gcm) and include it inside the crate so I could actually use 8-byte truncated tags as the original crate doesn't let me validate 8-byte tags.

Note that if you want to use this library in your rust project, you have to add the following dependencies to your `Cargo.toml` file:
```toml
[dependencies]
impit = { version = "*" }

[patch.crates-io]
openmls = { git = "https://github.com/Snazzah/openmls.git", rev = "3f237fb29e0d61cedd43223a6d6df1fbc0a042ad" }
openmls_basic_credential = { git = "https://github.com/Snazzah/openmls.git", rev = "3f237fb29e0d61cedd43223a6d6df1fbc0a042ad" }
openmls_rust_crypto = { git = "https://github.com/Snazzah/openmls.git", rev = "3f237fb29e0d61cedd43223a6d6df1fbc0a042ad" }
```

The patched dependencies make it so that `davey` can set the ProposalOrRef type and forcefully only return proposal refs when making commits.