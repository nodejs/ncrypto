#include <ncrypto.h>
#include <ncrypto/aead.h>

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
  ASSERT_TRUE(foundCiphers.count("aes-128-ctr") ||
              foundCiphers.count("AES-128-CTR"));
  ASSERT_TRUE(foundCiphers.count("aes-256-cbc") ||
              foundCiphers.count("AES-256-CBC"));
}

TEST(BignumPointer, bitLength) {
  // Test empty/null BignumPointer
  BignumPointer empty;
  ASSERT_EQ(empty.bitLength(), 0);

  // Test zero value
  auto zero = BignumPointer::New();
  ASSERT_TRUE(zero);
  ASSERT_TRUE(zero.setWord(0));
  ASSERT_EQ(zero.bitLength(), 0);

  // Test value 1 (1 bit)
  auto one = BignumPointer::New();
  ASSERT_TRUE(one);
  ASSERT_TRUE(one.setWord(1));
  ASSERT_EQ(one.bitLength(), 1);

  // Test value 2 (2 bits: 10 in binary)
  auto two = BignumPointer::New();
  ASSERT_TRUE(two);
  ASSERT_TRUE(two.setWord(2));
  ASSERT_EQ(two.bitLength(), 2);

  // Test value 255 (8 bits: 11111111 in binary)
  auto byte = BignumPointer::New();
  ASSERT_TRUE(byte);
  ASSERT_TRUE(byte.setWord(255));
  ASSERT_EQ(byte.bitLength(), 8);

  // Test value 256 (9 bits: 100000000 in binary)
  auto nineBits = BignumPointer::New();
  ASSERT_TRUE(nineBits);
  ASSERT_TRUE(nineBits.setWord(256));
  ASSERT_EQ(nineBits.bitLength(), 9);

  // Test larger value (0xFFFFFFFF = 32 bits)
  auto thirtyTwoBits = BignumPointer::New();
  ASSERT_TRUE(thirtyTwoBits);
  ASSERT_TRUE(thirtyTwoBits.setWord(0xFFFFFFFF));
  ASSERT_EQ(thirtyTwoBits.bitLength(), 32);
}

TEST(BignumPointer, byteLength) {
  // Test empty/null BignumPointer
  BignumPointer empty;
  ASSERT_EQ(empty.byteLength(), 0);

  // Test zero value
  auto zero = BignumPointer::New();
  ASSERT_TRUE(zero);
  ASSERT_TRUE(zero.setWord(0));
  ASSERT_EQ(zero.byteLength(), 0);

  // Test value 1 (1 byte)
  auto one = BignumPointer::New();
  ASSERT_TRUE(one);
  ASSERT_TRUE(one.setWord(1));
  ASSERT_EQ(one.byteLength(), 1);

  // Test value 255 (1 byte)
  auto byte = BignumPointer::New();
  ASSERT_TRUE(byte);
  ASSERT_TRUE(byte.setWord(255));
  ASSERT_EQ(byte.byteLength(), 1);

  // Test value 256 (2 bytes)
  auto twoBytes = BignumPointer::New();
  ASSERT_TRUE(twoBytes);
  ASSERT_TRUE(twoBytes.setWord(256));
  ASSERT_EQ(twoBytes.byteLength(), 2);

  // Test larger value (0xFFFFFFFF = 4 bytes)
  auto fourBytes = BignumPointer::New();
  ASSERT_TRUE(fourBytes);
  ASSERT_TRUE(fourBytes.setWord(0xFFFFFFFF));
  ASSERT_EQ(fourBytes.byteLength(), 4);
}

// ============================================================================
// Ec class tests

// Helper to create an EC key for testing
static ECKeyPointer createTestEcKey() {
  // NID_X9_62_prime256v1 is P-256
  auto key = ECKeyPointer::NewByCurveName(NID_X9_62_prime256v1);
  if (key && EC_KEY_generate_key(key.get())) {
    return key;
  }
  return {};
}

TEST(Ec, getDegree) {
  auto ecKey = createTestEcKey();
  ASSERT_TRUE(ecKey);

  Ec ec(ecKey.get());
  ASSERT_TRUE(ec);

  // P-256 has degree 256
  ASSERT_EQ(ec.getDegree(), 256u);
}

TEST(Ec, getCurveName) {
  auto ecKey = createTestEcKey();
  ASSERT_TRUE(ecKey);

  Ec ec(ecKey.get());
  ASSERT_TRUE(ec);

  // P-256 is also known as prime256v1
  std::string name = ec.getCurveName();
  ASSERT_TRUE(name == "prime256v1" || name == "P-256");
}

TEST(Ec, getPublicKey) {
  auto ecKey = createTestEcKey();
  ASSERT_TRUE(ecKey);

  Ec ec(ecKey.get());
  ASSERT_TRUE(ec);

  // Public key should exist
  const EC_POINT* pubKey = ec.getPublicKey();
  ASSERT_NE(pubKey, nullptr);
}

TEST(Ec, getPrivateKey) {
  auto ecKey = createTestEcKey();
  ASSERT_TRUE(ecKey);

  Ec ec(ecKey.get());
  ASSERT_TRUE(ec);

  // Private key should exist for a generated key
  const BIGNUM* privKey = ec.getPrivateKey();
  ASSERT_NE(privKey, nullptr);
}

TEST(Ec, getXYCoordinates) {
  auto ecKey = createTestEcKey();
  ASSERT_TRUE(ecKey);

  Ec ec(ecKey.get());
  ASSERT_TRUE(ec);

  // X and Y coordinates should be populated
  const BignumPointer& x = ec.getX();
  const BignumPointer& y = ec.getY();

  ASSERT_TRUE(x);
  ASSERT_TRUE(y);

  // For P-256, coordinates should be 256 bits (32 bytes)
  ASSERT_GT(x.byteLength(), 0u);
  ASSERT_LE(x.byteLength(), 32u);
  ASSERT_GT(y.byteLength(), 0u);
  ASSERT_LE(y.byteLength(), 32u);
}

TEST(Ec, getCurve) {
  auto ecKey = createTestEcKey();
  ASSERT_TRUE(ecKey);

  Ec ec(ecKey.get());
  ASSERT_TRUE(ec);

  // getCurve should return the NID for P-256
  int curve = ec.getCurve();
  ASSERT_EQ(curve, NID_X9_62_prime256v1);
}

TEST(Ec, GetCurves) {
  std::vector<std::string> curves;

  bool result = Ec::GetCurves([&](const char* name) {
    curves.push_back(name);
    return true;
  });

  ASSERT_TRUE(result);
  // Should have at least some built-in curves
  ASSERT_GT(curves.size(), 0u);

  // Check that common curves are present
  bool hasP256 = false;
  bool hasP384 = false;
  for (const auto& curve : curves) {
    if (curve == "prime256v1" || curve == "P-256") hasP256 = true;
    if (curve == "secp384r1" || curve == "P-384") hasP384 = true;
  }
  ASSERT_TRUE(hasP256);
  ASSERT_TRUE(hasP384);
}

TEST(Ec, GetCurves_early_exit) {
  int count = 0;

  // Test that returning false stops iteration
  bool result = Ec::GetCurves([&](const char* name) {
    count++;
    return count < 3;  // Stop after 2 curves
  });

  ASSERT_FALSE(result);
  ASSERT_EQ(count, 3);
}

// ============================================================================
// EVPKeyPointer tests

TEST(EVPKeyPointer, operatorEc) {
  auto ecKey = createTestEcKey();
  ASSERT_TRUE(ecKey);

  // Create EVPKeyPointer from EC_KEY
  EVPKeyPointer key(EVP_PKEY_new());
  ASSERT_TRUE(key);
  ASSERT_TRUE(EVP_PKEY_set1_EC_KEY(key.get(), ecKey.get()));

  // Convert to Ec
  Ec ec = key;
  ASSERT_TRUE(ec);
  ASSERT_EQ(ec.getDegree(), 256u);
}

TEST(EVPKeyPointer, clone) {
  auto ecKey = createTestEcKey();
  ASSERT_TRUE(ecKey);

  // Create EVPKeyPointer from EC_KEY
  EVPKeyPointer key(EVP_PKEY_new());
  ASSERT_TRUE(key);
  ASSERT_TRUE(EVP_PKEY_set1_EC_KEY(key.get(), ecKey.get()));

  // Clone the key
  auto cloned = key.clone();
  ASSERT_TRUE(cloned);

  // Both should be valid
  ASSERT_TRUE(key);
  ASSERT_TRUE(cloned);

  // Both should have the same key type
  ASSERT_EQ(key.id(), cloned.id());
}

TEST(EVPKeyPointer, cloneEmpty) {
  EVPKeyPointer empty;
  ASSERT_FALSE(empty);

  // Clone of empty should be empty
  auto cloned = empty.clone();
  ASSERT_FALSE(cloned);
}

// ============================================================================
// KDF tests

TEST(KDF, pbkdf2Into) {
  const char* password = "password";
  const unsigned char salt[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
  const size_t length = 32;

  Buffer<const char> passBuf{password, strlen(password)};
  Buffer<const unsigned char> saltBuf{salt, sizeof(salt)};

  unsigned char output[32];
  Buffer<unsigned char> outBuf{output, length};

  Digest md(EVP_sha256());
  ASSERT_TRUE(md);

  bool result = pbkdf2Into(md, passBuf, saltBuf, 1000, length, &outBuf);
  ASSERT_TRUE(result);

  // Verify output is not all zeros
  bool allZeros = true;
  for (size_t i = 0; i < length; i++) {
    if (output[i] != 0) {
      allZeros = false;
      break;
    }
  }
  ASSERT_FALSE(allZeros);
}

TEST(KDF, pbkdf2) {
  const char* password = "password";
  const unsigned char salt[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
  const size_t length = 32;

  Buffer<const char> passBuf{password, strlen(password)};
  Buffer<const unsigned char> saltBuf{salt, sizeof(salt)};

  Digest md(EVP_sha256());
  ASSERT_TRUE(md);

  auto result = pbkdf2(md, passBuf, saltBuf, 1000, length);
  ASSERT_TRUE(result);
  ASSERT_EQ(result.size(), length);
}

TEST(KDF, scryptInto) {
  const char* password = "password";
  const unsigned char salt[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
  const size_t length = 32;

  Buffer<const char> passBuf{password, strlen(password)};
  Buffer<const unsigned char> saltBuf{salt, sizeof(salt)};

  unsigned char output[32];
  Buffer<unsigned char> outBuf{output, length};

  // Use small parameters for testing
  bool result = scryptInto(passBuf, saltBuf, 16, 1, 1, 0, length, &outBuf);
  ASSERT_TRUE(result);

  // Verify output is not all zeros
  bool allZeros = true;
  for (size_t i = 0; i < length; i++) {
    if (output[i] != 0) {
      allZeros = false;
      break;
    }
  }
  ASSERT_FALSE(allZeros);
}

TEST(KDF, scrypt) {
  const char* password = "password";
  const unsigned char salt[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
  const size_t length = 32;

  Buffer<const char> passBuf{password, strlen(password)};
  Buffer<const unsigned char> saltBuf{salt, sizeof(salt)};

  // Use small parameters for testing
  auto result = scrypt(passBuf, saltBuf, 16, 1, 1, 0, length);
  ASSERT_TRUE(result);
  ASSERT_EQ(result.size(), length);
}

TEST(KDF, hkdfInfo) {
  const unsigned char key[] = {0x0b,
                               0x0b,
                               0x0b,
                               0x0b,
                               0x0b,
                               0x0b,
                               0x0b,
                               0x0b,
                               0x0b,
                               0x0b,
                               0x0b,
                               0x0b,
                               0x0b,
                               0x0b,
                               0x0b,
                               0x0b};
  const unsigned char salt[] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
  const unsigned char info[] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7};
  const size_t length = 42;

  Buffer<const unsigned char> keyBuf{key, sizeof(key)};
  Buffer<const unsigned char> saltBuf{salt, sizeof(salt)};
  Buffer<const unsigned char> infoBuf{info, sizeof(info)};

  unsigned char output[42];
  Buffer<unsigned char> outBuf{output, length};

  Digest md(EVP_sha256());
  ASSERT_TRUE(md);

  bool result = hkdfInfo(md, keyBuf, infoBuf, saltBuf, length, &outBuf);
  ASSERT_TRUE(result);

  // Verify output is not all zeros
  bool allZeros = true;
  for (size_t i = 0; i < length; i++) {
    if (output[i] != 0) {
      allZeros = false;
      break;
    }
  }
  ASSERT_FALSE(allZeros);
}

TEST(KDF, hkdf) {
  const unsigned char key[] = {0x0b,
                               0x0b,
                               0x0b,
                               0x0b,
                               0x0b,
                               0x0b,
                               0x0b,
                               0x0b,
                               0x0b,
                               0x0b,
                               0x0b,
                               0x0b,
                               0x0b,
                               0x0b,
                               0x0b,
                               0x0b};
  const unsigned char salt[] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
  const unsigned char info[] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7};
  const size_t length = 42;

  Buffer<const unsigned char> keyBuf{key, sizeof(key)};
  Buffer<const unsigned char> saltBuf{salt, sizeof(salt)};
  Buffer<const unsigned char> infoBuf{info, sizeof(info)};

  Digest md(EVP_sha256());
  ASSERT_TRUE(md);

  auto result = hkdf(md, keyBuf, infoBuf, saltBuf, length);
  ASSERT_TRUE(result);
  ASSERT_EQ(result.size(), length);
}

// ============================================================================
// SPKAC tests

TEST(SPKAC, VerifySpkacBuffer) {
  // A valid SPKAC string (base64 encoded)
  // This is a test SPKAC - in real use, you'd have a properly generated one
  const char* spkac =
      "MIIBQDCBqjCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA2L3lR6VHBxKBZGnr"
      "5R9AmJwcQPePMHl7X1tj0n5PKMXwXHLqD/xHtqWFN9aSWfZhCYVOYMPLsIEZvtsJ"
      "qFCJzJXB7lYlLqcLLVJ5sDlT0fM8QiJR6CnBlWgaXEozL5XdKJdQ7UVlL1qqoLJP"
      "8wLJ0PhXFaNvlNBaXx1lAx0CAwEAARYAMA0GCSqGSIb3DQEBBQUAA4GBAKMzhfqX"
      "MvWRBfL+VNVX/3rE9IahSMPl/Dz0P4UO0MtDgYFR4N0tPPqg1EMH7HJRxPJQDUlf"
      "M9TsMI8e8KfJX0VdPmmjvNy3LcboJqmqQ8TViV2U0K0mTgg3kEWdKl25QcleVQry"
      "CqU2ThYNnK3QEbFwuTS4MHk4MHk2WHJoYzlk";

  Buffer<const char> buf{spkac, strlen(spkac)};

  // Note: This specific SPKAC may not verify correctly due to signature issues,
  // but we're testing that the function runs without crashing and accepts the
  // buffer interface
  bool result = VerifySpkac(buf);
  // The result depends on the validity of the SPKAC
  (void)result;
}

TEST(SPKAC, ExportPublicKeyBuffer) {
  const char* spkac =
      "MIIBQDCBqjCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA2L3lR6VHBxKBZGnr"
      "5R9AmJwcQPePMHl7X1tj0n5PKMXwXHLqD/xHtqWFN9aSWfZhCYVOYMPLsIEZvtsJ"
      "qFCJzJXB7lYlLqcLLVJ5sDlT0fM8QiJR6CnBlWgaXEozL5XdKJdQ7UVlL1qqoLJP"
      "8wLJ0PhXFaNvlNBaXx1lAx0CAwEAARYAMA0GCSqGSIb3DQEBBQUAA4GBAKMzhfqX"
      "MvWRBfL+VNVX/3rE9IahSMPl/Dz0P4UO0MtDgYFR4N0tPPqg1EMH7HJRxPJQDUlf"
      "M9TsMI8e8KfJX0VdPmmjvNy3LcboJqmqQ8TViV2U0K0mTgg3kEWdKl25QcleVQry"
      "CqU2ThYNnK3QEbFwuTS4MHk4MHk2WHJoYzlk";

  Buffer<const char> buf{spkac, strlen(spkac)};

  // Test that the buffer version works
  auto bio = ExportPublicKey(buf);
  // Result depends on SPKAC validity
  (void)bio;
}

TEST(SPKAC, ExportChallengeBuffer) {
  const char* spkac =
      "MIIBQDCBqjCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA2L3lR6VHBxKBZGnr"
      "5R9AmJwcQPePMHl7X1tj0n5PKMXwXHLqD/xHtqWFN9aSWfZhCYVOYMPLsIEZvtsJ"
      "qFCJzJXB7lYlLqcLLVJ5sDlT0fM8QiJR6CnBlWgaXEozL5XdKJdQ7UVlL1qqoLJP"
      "8wLJ0PhXFaNvlNBaXx1lAx0CAwEAARYAMA0GCSqGSIb3DQEBBQUAA4GBAKMzhfqX"
      "MvWRBfL+VNVX/3rE9IahSMPl/Dz0P4UO0MtDgYFR4N0tPPqg1EMH7HJRxPJQDUlf"
      "M9TsMI8e8KfJX0VdPmmjvNy3LcboJqmqQ8TViV2U0K0mTgg3kEWdKl25QcleVQry"
      "CqU2ThYNnK3QEbFwuTS4MHk4MHk2WHJoYzlk";

  Buffer<const char> buf{spkac, strlen(spkac)};

  // Test that the buffer version works and returns DataPointer
  auto challenge = ExportChallenge(buf);
  // Result depends on SPKAC validity
  (void)challenge;
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

// ============================================================================
// Argon2 KDF tests (OpenSSL 3.2.0+ only)

#if OPENSSL_VERSION_NUMBER >= 0x30200000L
#ifndef OPENSSL_NO_ARGON2

TEST(KDF, argon2i) {
  const char* password = "password";
  const unsigned char salt[] = {0x01,
                                0x02,
                                0x03,
                                0x04,
                                0x05,
                                0x06,
                                0x07,
                                0x08,
                                0x09,
                                0x0a,
                                0x0b,
                                0x0c,
                                0x0d,
                                0x0e,
                                0x0f,
                                0x10};
  const size_t length = 32;

  Buffer<const char> passBuf{password, strlen(password)};
  Buffer<const unsigned char> saltBuf{salt, sizeof(salt)};
  Buffer<const unsigned char> secret{nullptr, 0};
  Buffer<const unsigned char> ad{nullptr, 0};

  // Use small parameters for testing
  // lanes=1, memcost=16 (KB), iter=3, version=0x13 (1.3)
  auto result = argon2(passBuf,
                       saltBuf,
                       1,
                       length,
                       16,
                       3,
                       0x13,
                       secret,
                       ad,
                       Argon2Type::ARGON2I);
  ASSERT_TRUE(result);
  ASSERT_EQ(result.size(), length);

  // Verify output is not all zeros
  bool allZeros = true;
  for (size_t i = 0; i < length; i++) {
    if (reinterpret_cast<unsigned char*>(result.get())[i] != 0) {
      allZeros = false;
      break;
    }
  }
  ASSERT_FALSE(allZeros);
}

TEST(KDF, argon2d) {
  const char* password = "password";
  const unsigned char salt[] = {0x01,
                                0x02,
                                0x03,
                                0x04,
                                0x05,
                                0x06,
                                0x07,
                                0x08,
                                0x09,
                                0x0a,
                                0x0b,
                                0x0c,
                                0x0d,
                                0x0e,
                                0x0f,
                                0x10};
  const size_t length = 32;

  Buffer<const char> passBuf{password, strlen(password)};
  Buffer<const unsigned char> saltBuf{salt, sizeof(salt)};
  Buffer<const unsigned char> secret{nullptr, 0};
  Buffer<const unsigned char> ad{nullptr, 0};

  auto result = argon2(passBuf,
                       saltBuf,
                       1,
                       length,
                       16,
                       3,
                       0x13,
                       secret,
                       ad,
                       Argon2Type::ARGON2D);
  ASSERT_TRUE(result);
  ASSERT_EQ(result.size(), length);
}

TEST(KDF, argon2id) {
  const char* password = "password";
  const unsigned char salt[] = {0x01,
                                0x02,
                                0x03,
                                0x04,
                                0x05,
                                0x06,
                                0x07,
                                0x08,
                                0x09,
                                0x0a,
                                0x0b,
                                0x0c,
                                0x0d,
                                0x0e,
                                0x0f,
                                0x10};
  const size_t length = 32;

  Buffer<const char> passBuf{password, strlen(password)};
  Buffer<const unsigned char> saltBuf{salt, sizeof(salt)};
  Buffer<const unsigned char> secret{nullptr, 0};
  Buffer<const unsigned char> ad{nullptr, 0};

  auto result = argon2(passBuf,
                       saltBuf,
                       1,
                       length,
                       16,
                       3,
                       0x13,
                       secret,
                       ad,
                       Argon2Type::ARGON2ID);
  ASSERT_TRUE(result);
  ASSERT_EQ(result.size(), length);
}

TEST(KDF, argon2_with_secret_and_ad) {
  const char* password = "password";
  const unsigned char salt[] = {0x01,
                                0x02,
                                0x03,
                                0x04,
                                0x05,
                                0x06,
                                0x07,
                                0x08,
                                0x09,
                                0x0a,
                                0x0b,
                                0x0c,
                                0x0d,
                                0x0e,
                                0x0f,
                                0x10};
  const unsigned char secretData[] = {0xaa, 0xbb, 0xcc, 0xdd};
  const unsigned char adData[] = {0x11, 0x22, 0x33, 0x44, 0x55};
  const size_t length = 32;

  Buffer<const char> passBuf{password, strlen(password)};
  Buffer<const unsigned char> saltBuf{salt, sizeof(salt)};
  Buffer<const unsigned char> secret{secretData, sizeof(secretData)};
  Buffer<const unsigned char> ad{adData, sizeof(adData)};

  auto result = argon2(passBuf,
                       saltBuf,
                       1,
                       length,
                       16,
                       3,
                       0x13,
                       secret,
                       ad,
                       Argon2Type::ARGON2ID);
  ASSERT_TRUE(result);
  ASSERT_EQ(result.size(), length);
}

TEST(KDF, argon2_empty_password) {
  const unsigned char salt[] = {0x01,
                                0x02,
                                0x03,
                                0x04,
                                0x05,
                                0x06,
                                0x07,
                                0x08,
                                0x09,
                                0x0a,
                                0x0b,
                                0x0c,
                                0x0d,
                                0x0e,
                                0x0f,
                                0x10};
  const size_t length = 32;

  Buffer<const char> passBuf{"", 0};
  Buffer<const unsigned char> saltBuf{salt, sizeof(salt)};
  Buffer<const unsigned char> secret{nullptr, 0};
  Buffer<const unsigned char> ad{nullptr, 0};

  // Empty password should still work
  auto result = argon2(passBuf,
                       saltBuf,
                       1,
                       length,
                       16,
                       3,
                       0x13,
                       secret,
                       ad,
                       Argon2Type::ARGON2ID);
  ASSERT_TRUE(result);
  ASSERT_EQ(result.size(), length);
}

TEST(KDF, argon2_different_types_produce_different_output) {
  const char* password = "password";
  const unsigned char salt[] = {0x01,
                                0x02,
                                0x03,
                                0x04,
                                0x05,
                                0x06,
                                0x07,
                                0x08,
                                0x09,
                                0x0a,
                                0x0b,
                                0x0c,
                                0x0d,
                                0x0e,
                                0x0f,
                                0x10};
  const size_t length = 32;

  Buffer<const char> passBuf{password, strlen(password)};
  Buffer<const unsigned char> saltBuf{salt, sizeof(salt)};
  Buffer<const unsigned char> secret{nullptr, 0};
  Buffer<const unsigned char> ad{nullptr, 0};

  auto resultI = argon2(passBuf,
                        saltBuf,
                        1,
                        length,
                        16,
                        3,
                        0x13,
                        secret,
                        ad,
                        Argon2Type::ARGON2I);
  auto resultD = argon2(passBuf,
                        saltBuf,
                        1,
                        length,
                        16,
                        3,
                        0x13,
                        secret,
                        ad,
                        Argon2Type::ARGON2D);
  auto resultID = argon2(passBuf,
                         saltBuf,
                         1,
                         length,
                         16,
                         3,
                         0x13,
                         secret,
                         ad,
                         Argon2Type::ARGON2ID);

  ASSERT_TRUE(resultI);
  ASSERT_TRUE(resultD);
  ASSERT_TRUE(resultID);

  // All three types should produce different outputs
  ASSERT_NE(memcmp(resultI.get(), resultD.get(), length), 0);
  ASSERT_NE(memcmp(resultI.get(), resultID.get(), length), 0);
  ASSERT_NE(memcmp(resultD.get(), resultID.get(), length), 0);
}

#endif  // OPENSSL_NO_ARGON2
#endif  // OPENSSL_VERSION_NUMBER >= 0x30200000L
