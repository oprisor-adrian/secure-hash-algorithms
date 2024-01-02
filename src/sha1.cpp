#include "sha1.h"

namespace Cryptography {

SHA1::SHA1() {
  InitKey();
}

ByteUtils::ByteVector SHA1::Digest(const ByteUtils::ByteVector& message) {
  ComputeDigest(message);
  ByteUtils::ByteVector digest;
  for (const auto& word : hash_) {
    digest.PushBack(word);
  }
  return digest;
}

void SHA1::InitHash() {
  hash_ = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0};
}

void SHA1::InitKey() {
  for (std::size_t index = 0; index < 20; index++) {
    key_[index] = 0x5a827999;
  }
  for (std::size_t index = 20; index < 40; index++) {
    key_[index] = 0x6ed9eba1;
  }
  for (std::size_t index = 40; index < 60; index++) {
    key_[index] = 0x8f1bbcdc;
  }
  for (std::size_t index = 60; index < 80; index++) {
    key_[index] = 0xca62c1d6;
  }
}

ByteUtils::ByteVector SHA1::PaddMessage(ByteUtils::ByteVector message) {
  std::size_t msg_bits_size = message.Size() * 8;
  message.PushBack(0x80);
  int bits_2_append = (440 - msg_bits_size);
  if (bits_2_append < 0) {
    bits_2_append += 512;
  }
  std::size_t bytes_2_append = (bits_2_append + 7) / 8;
  while (bytes_2_append--) {
    message.PushBack(ByteUtils::Byte(0x00));
  }
  message.PushBack(ByteUtils::Word<64>(msg_bits_size));
  return message;
}

std::vector<ByteUtils::ByteVector> SHA1::ParseMessage(
    const ByteUtils::ByteVector& message) const {
  std::vector<ByteUtils::ByteVector> message_blocks;
  std::size_t no_blocks = (message.Size() + 63) / 64;
  for (std::size_t index = 0; index < no_blocks; index++) {
    std::size_t s_index = index * 64;
    ByteUtils::ByteVector temp = message.Subvector(s_index, 64);
    message_blocks.push_back(temp);
  } 
  return message_blocks;
}

ByteUtils::ByteVector SHA1::ScheduleMessage(
    const ByteUtils::ByteVector& message) const {
  ByteUtils::ByteVector msg_schedule = message.Subvector(0, 64);
  for (std::size_t index = 16; index < 80; index++) {
    auto result = RotL(msg_schedule.GetWord<32>(index-3) ^ 
                       msg_schedule.GetWord<32>(index-8) ^
                       msg_schedule.GetWord<32>(index-14) ^ 
                       msg_schedule.GetWord<32>(index-16),
                       1);
    msg_schedule.PushBack(result);
  }
  return msg_schedule;
}

void SHA1::ComputeHash(const ByteUtils::ByteVector& message) {
  std::array<ByteUtils::Word<32>, 5> working_hash = hash_;
  for (std::size_t index = 0; index < 80; index++) {
    ByteUtils::Word<32> temp;
    if (index < 20) {
      temp = RotL(working_hash[0], 5) + 
             Choose(working_hash[1],
                    working_hash[2],
                    working_hash[3]) +
             working_hash[4] +
             key_[index] + 
             message.GetWord<32>(index);
    }
    if ((index > 19 && index < 40) || index > 59) {
      temp = RotL(working_hash[0], 5) + 
             Parity(working_hash[1],
                    working_hash[2],
                    working_hash[3]) +
             working_hash[4] + 
             key_[index] +
             message.GetWord<32>(index);
    }
    if (index > 39 && index < 60) {
      temp = RotL(working_hash[0], 5) + 
             Majority(working_hash[1],
                      working_hash[2],
                      working_hash[3]) +
             working_hash[4] + 
             key_[index] + 
             message.GetWord<32>(index);
    }
    working_hash[4] = working_hash[3];
    working_hash[3] = working_hash[2];
    working_hash[2] = RotL(working_hash[1], 30);
    working_hash[1] = working_hash[0];
    working_hash[0] = temp;
  }
  for (std::size_t index = 0; index < 5; index++) {
    hash_[index] = working_hash[index] + hash_[index];
  }
}

ByteUtils::Word<32> SHA1::Choose(const ByteUtils::Word<32>& word1,
                                   const ByteUtils::Word<32>& word2,
                                   const ByteUtils::Word<32>& word3) const {
  return (word1 & word2) ^ (~word1 & word3);
}

ByteUtils::Word<32> SHA1::Majority(const ByteUtils::Word<32>& word1,
                                     const ByteUtils::Word<32>& word2,
                                     const ByteUtils::Word<32>& word3) const {
  return (word1 & word2) ^ (word1 & word3) ^ (word2 & word3);
}

ByteUtils::Word<32> SHA1::Parity(const ByteUtils::Word<32>& word1,
                                 const ByteUtils::Word<32>& word2,
                                 const ByteUtils::Word<32>& word3) const {
  return word1 ^ word2 ^ word3;
}

ByteUtils::Word<32> SHA1::RotL(const ByteUtils::Word<32>& word,
                               std::size_t n_pos) const {
  return (word << n_pos) | (word >> (32 - n_pos));
}

}  // namespace Cryptography