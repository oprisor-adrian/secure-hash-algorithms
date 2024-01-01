#include <gtest/gtest.h>

#include <string>

#include <byte_vector.h>

#include "../include/sha1.h"

TEST(TestSHA1, TestDigest) {
  Cryptography::SHA1 sha1;
  ByteUtils::ByteVector output = sha1.Digest({"616263"});
  std::string expected_output = "a9993e364706816aba3e25717850c26c9cd0d89d";
  EXPECT_STREQ(output.ToHex().c_str(), expected_output.c_str());
} 