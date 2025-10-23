#include <ncrypto.h>

#include <gtest/gtest.h>

#include <string>
#include <unordered_set>

using namespace ncrypto;

TEST(basic, cipher_foreach) {
  std::unordered_set<std::string> foundCiphers;

  Cipher::ForEach([&](const char* name) { foundCiphers.insert(name); });

  // When testing Cipher::ForEach, we cannot expect a particular list of ciphers
  // as that depends on openssl vs boringssl, versions, configuration, etc.
  // Instead, we look for a couple of very common ciphers that should always be
  // present.
  ASSERT_TRUE(foundCiphers.count("AES-128-CTR"));
  ASSERT_TRUE(foundCiphers.count("AES-256-CBC"));
}
