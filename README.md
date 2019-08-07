osclientcerts
-----
`osclientcerts` is a PKCS#11 module that will give Firefox the ability to use client authentication certificates stored in OS-specific mechanisms.

Platforms
-----
Currently `osclientcerts` only works on MacOS. Windows support will be coming soon.

Howto
-----
For the time being, this module must be manually compiled and added to Firefox. Clone the repo and run `cargo build` to build (this requires that a rust toolchain be installed, as well as the MacOS development toolchain). Once built, there should be a file `libosclientcerts.dylib` in `target/debug` (or `target/release` for release builds). To add the module to Firefox, open `about:preferences`, search for "Security Devices", and click the corresponding button. Then click "Load" and enter the path to `libosclientcerts.dylib` (or find it using the file picker). Click "OK" (you can also give the module a more descriptive name). Once loaded, the module should allow Firefox to use client authentication certificates that are stored in your keychain or via external tokens supported by MacOS. Please file an issue if you encounter a certificate that should work but doesn't.
