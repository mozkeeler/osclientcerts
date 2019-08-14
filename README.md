osclientcerts
-----
`osclientcerts` is a PKCS#11 module that will give Firefox the ability to use client authentication certificates stored in OS-specific mechanisms.

Support
-----
`osclientcerts` currently has preliminary support for MacOS (using the keychain) and Windows (using CNG). Only RSA and EC keys are supported.

Howto
-----
For the time being, this module must be manually compiled and added to Firefox. Clone the repo and run `cargo build` to build (this requires that a rust toolchain be installed, as well as a platform-specific development toolchain). Once built, there should be a file `libosclientcerts.dylib` (for MacOS) or `osclientcerts.dll` (for Windows) in `target/debug` (or `target/release` for release builds). To add the module to Firefox, open `about:preferences`, search for "Security Devices", and click the corresponding button. Then click "Load" and enter the path to the module library file (or find it using the file picker). Click "OK" (you can also give the module a more descriptive name). Once loaded, the module should allow Firefox to use client authentication certificates that are stored in or accessible from platform-specific mechanisms. Please file an issue if you encounter a certificate that should work but doesn't.
