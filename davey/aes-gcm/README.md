This is a light modification of the `aes-gcm` crate. I needed to fork this so I could actually use 8-byte truncated tags as the original crate doesn't let me validate 8-byte tags.

Repository: https://github.com/RustCrypto/AEADs/tree/master/aes-gcm
