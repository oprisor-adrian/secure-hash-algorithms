/* 
  Copyright (C) 2024  Oprișor Adrian-Ilie
  
  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.
  
  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <https://www.gnu.org/licenses/>.
   
  Contact: contact@dev-adrian.com
*/
#include <gtest/gtest.h>

#include <string>

#include <byte_vector.h>

#include "../include/sha256.h"

struct TestCase {
  std::string message;
  std::string digest;
};

TEST(TestSHA256, TestDigest) {
  TestCase cases[] = {
    {
      "616263", 
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    },
    {
      "6162636462636465636465666465666765666768666768696768696a68696a6b"
      "696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071",
      "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    },
    {
      "546869732069732061206C6F6E67206C6F6E67206D6573736167652074686174"
      "2077696C6C20626520656E63727970746564207573696E672074686520736563"
      "757265206861736820616C676F726974686D206F6E203235362062697473206F"
      "7574707574206469676573742E",
      "989fc00d54800181c6b628929bd2fe5cc297d72b6a326c1bd91418c17e310c63"
    }
  };
  Cryptography::SHA256 sha256;
  for (std::size_t index = 0; index < 3; index++) {
    ByteUtils::ByteVector output = sha256.Digest(cases[index].message);
    EXPECT_STREQ(output.ToHex().c_str(), cases[index].digest.c_str());
  }
}