workspace(name = "ncrypto")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "ssl",
    sha256 = "64529449ef458381346b163302523a1fb876e5b667bec4a4bd38d0d2fff8b42b",
    strip_prefix = "boringssl-0.20250818.0",
    type = "tgz",
    urls = ["https://github.com/google/boringssl/archive/refs/tags/0.20250818.0.tar.gz"],
    patches = [
         "@ncrypto//:patches/0001-Expose-libdecrepit-so-NodeJS-can-use-it-for-ncrypto.patch"
    ],
    patch_strip = 1
)
