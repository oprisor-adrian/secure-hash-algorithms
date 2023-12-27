#include "sha256.h"

#include "byte_vector.h"

namespace Cryptography {

namespace {

const ByteUtils::ByteVector key("428a2f9871374491b5c0fbcfe9b5dba53956c25b"
                                "59f111f1923f82a4ab1c5ed5d807aa9812835b01"
                                "243185be550c7dc372be5d7480deb1fe9bdc06a7"
                                "c19bf174e49b69c1efbe47860fc19dc6240ca1cc"
                                "2de92c6f4a7484aa5cb0a9dc76f988da983e5152"
                                "a831c66db00327c8bf597fc7c6e00bf3d5a79147"
                                "06ca63511429296727b70a852e1b21384d2c6dfc"
                                "53380d13650a7354766a0abb81c2c92e92722c85"
                                "a2bfe8a1a81a664bc24b8b70c76c51a3d192e819"
                                "d6990624f40e3585106aa07019a4c1161e376c08"
                                "2748774c34b0bcb5391c0cb34ed8aa4a5b9cca4f"
                                "682e6ff3748f82ee78a5636f84c878148cc70208"
                                "90befffaa4506cebbef9a3f7c67178f2");
}  // namespace

SHA256::SHA256(const std::string& message) {

}

void SHA256::InitHash() {
  hash_.push_back(ByteUtils::Word("6a09e667"));
  hash_.push_back(ByteUtils::Word("bb67ae85"));
  hash_.push_back(ByteUtils::Word("3c6ef372"));
  hash_.push_back(ByteUtils::Word("a54ff53a"));
  hash_.push_back(ByteUtils::Word("510e527f"));
  hash_.push_back(ByteUtils::Word("9b05688c"));
  hash_.push_back(ByteUtils::Word("1f83d9ab"));
  hash_.push_back(ByteUtils::Word("5be0cd19"));
}

ByteUtils::ByteVector SHA256::PaddMessage(const std::string& message) const {
  ByteUtils::ByteVector padded_message(message);
  padded_message.PushBack(ByteUtils::Word("80", 8));
  std::size_t k = (440 - message.size());
}

ByteUtils::Word SHA256::Choose(const ByteUtils::Word& word1, 
                               const ByteUtils::Word& word2,
                               const ByteUtils::Word& word3) const {
  return (word1 & word2) ^ (~word1 & word3);
}

ByteUtils::Word SHA256::Majority(const ByteUtils::Word& word1,
                                 const ByteUtils::Word& word2,
                                 const ByteUtils::Word& word3) const {
  return (word1 & word2) ^ (word1 & word3) ^ (word2 & word3);
}

ByteUtils::Word SHA256::RotL(const ByteUtils::Word& word, 
                             std::size_t n_bits) const {
  return (word << n_bits) | (word >> (word.Size() * 8 - n_bits));
}

ByteUtils::Word SHA256::RotR(const ByteUtils::Word& word,
                             std::size_t n_bits) const {
  return (word >> n_bits) | (word << (word.Size() * 8 - n_bits));
}

}  // namespace Cryptography