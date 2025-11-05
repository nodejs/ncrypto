#include <ncrypto.h>

#include <gtest/gtest.h>
#include <string>

using namespace ncrypto;

// Convenience class for creating buffers in tests
struct TestBuf : public std::string {
  TestBuf(const std::string& constStr)
      : std::string(constStr),
        buf{reinterpret_cast<unsigned char*>(data()), size()} {}
  TestBuf(size_t n) : TestBuf(std::string(n, 0)) {}

  operator Buffer<unsigned char>&() { return buf; }

  Buffer<const unsigned char> asConst() const {
    return Buffer<const unsigned char>{
        .data = reinterpret_cast<const unsigned char*>(data()), .len = size()};
  }

 private:
  Buffer<unsigned char> buf;
};

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

#ifdef OPENSSL_IS_BORINGSSL
TEST(basic, chacha20_poly1305) {
  unsigned char key[] = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03,
                         0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
                         0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
                         0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7};

  auto aead = Aead::CHACHA20_POLY1305;
  auto encryptCtx = AeadCtxPointer::New(aead, true, key, aead.getKeyLength());

  TestBuf input("Hello world");
  TestBuf tag(aead.getMaxTagLength());
  TestBuf nonce(aead.getNonceLength());
  TestBuf aad("I dunno man");
  TestBuf encryptOutput(input.size());

  auto encryptOk = encryptCtx.encrypt(
      input.asConst(), encryptOutput, tag, nonce.asConst(), aad.asConst());
  ASSERT_TRUE(encryptOk);
  ASSERT_NE(input, encryptOutput);

  auto decryptCtx = AeadCtxPointer::New(aead, false, key, aead.getKeyLength());

  TestBuf decryptOutput(encryptOutput.size());

  auto decryptOk = decryptCtx.decrypt(encryptOutput.asConst(),
                                      decryptOutput,
                                      tag.asConst(),
                                      nonce.asConst(),
                                      aad.asConst());
  ASSERT_TRUE(decryptOk);
  ASSERT_EQ(input, decryptOutput);
}

TEST(basic, aead_info) {
  auto aead = Aead::FromName("aEs-256-gcM");  // spongebob does encryption
  ASSERT_EQ(aead.getName(), "aes-256-gcm");
  ASSERT_EQ(aead.getModeLabel(), "gcm");
  ASSERT_EQ(aead.getBlockSize(), 1);
  ASSERT_EQ(aead.getNonceLength(), 12);
  ASSERT_EQ(aead.getMaxTagLength(), 16);
}
#endif
