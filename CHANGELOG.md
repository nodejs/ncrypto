# Changelog

## [1.1.3](https://github.com/nodejs/ncrypto/compare/v1.1.2...v1.1.3) (2026-02-04)


### Bug Fixes

* unconditionally include vector ([ba39e40](https://github.com/nodejs/ncrypto/commit/ba39e40ed1c1231902a676f53906cdd2f6119648))
* use more strict compiler flags ([fc401e3](https://github.com/nodejs/ncrypto/commit/fc401e387491005bfbe6c48b7296862d07ea85d7))

## [1.1.2](https://github.com/nodejs/ncrypto/compare/v1.1.1...v1.1.2) (2026-02-02)


### Bug Fixes

* handle edge cases and CI builds ([57cae0f](https://github.com/nodejs/ncrypto/commit/57cae0f055ba7c2d060f0ed4e49431e9e56a0a2d))

## [1.1.1](https://github.com/nodejs/ncrypto/compare/v1.1.0...v1.1.1) (2026-02-02)


### Bug Fixes

* re-add more functions that are moved ([2ceab38](https://github.com/nodejs/ncrypto/commit/2ceab38e9caafd49b2f0a722ad76ae68f68fe7b5))
* re-add removed BignumPointer::bitLength() ([0ba85e3](https://github.com/nodejs/ncrypto/commit/0ba85e3c3a3cdd8abcab066b046bbb11c9136bc8))

## [1.1.0](https://github.com/nodejs/ncrypto/compare/1.0.1...v1.1.0) (2026-01-31)


### Features

* sync source code with nodejs/node ([#17](https://github.com/nodejs/ncrypto/issues/17)) ([47c21db](https://github.com/nodejs/ncrypto/commit/47c21db34df5f00eab945e2cd4e3ca6d9d57c793))


### Bug Fixes

* add missing header files during install ([#27](https://github.com/nodejs/ncrypto/issues/27)) ([d714e74](https://github.com/nodejs/ncrypto/commit/d714e745cd54b5f06686e2def826da101ebb2205))
* use BN_GENCB_get_arg accessor for OpenSSL 3.x compatibility ([#16](https://github.com/nodejs/ncrypto/issues/16)) ([afc7e12](https://github.com/nodejs/ncrypto/commit/afc7e12c3f862165d7cfdc10bd971d7115d4fdb5))
