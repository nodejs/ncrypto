# Node.js crypto (ncrypto) library

The `ncrypto` library extracts the base internal implementation of Node.js crypto operations
that support both `node:crypto` and Web Crypto implementations and makes them available for
use in other projects that need to emulate Node.js' behavior.

## Compatibility

* Build systems: `ncrypto` can be built with either Bazel or CMake.
* SSL libraries: `ncrypto` supports linking to either `boringssl` or `openssl`.

## Build flags

* Bazel: `--@ncrypto//:bssl_libdecrepit_missing=True` 
* CMake: `-DNCRYPTO_BSSL_LIBDECREPIT_MISSING=1`

If linking against `boringssl`, libdecrepit is an optional component that isn't always built. If
this option is set, `ncrypto` will use a built-in replacement for the missing functions.
