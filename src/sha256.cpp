/* 
  Copyright (C) 2023  Oprișor Adrian-Ilie
  
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
#include "sha256.h"

#include <iostream>
#include <vector>

#include "word.h"

namespace Cryptography {

SHA256::SHA256() {
  InitKey();
}

ByteUtils::ByteVector SHA256::ComputeDigest(
    const ByteUtils::ByteVector& message) {
  InitHash();
  ByteUtils::ByteVector message_block = PaddMessage(message);
  ByteUtils::ByteVector shedule = ScheduleMessage(message_block);
  ComputeHash(shedule);
  ByteUtils::ByteVector digest;
  for (const auto& word : hash_) {
    digest.PushBack(word);
  }
  return digest;
}

void SHA256::InitHash() {
  hash_ = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  };
}

void SHA256::InitKey() {
  key_ = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  };
}

ByteUtils::ByteVector SHA256::PaddMessage(ByteUtils::ByteVector message) {
  std::size_t message_size = message.Size() * 8;
  message.PushBack(0x80);
  std::size_t bits_2_append = (440 - message_size);
  std::size_t bytes_2_append = 0;
  if (bits_2_append < 0) {
    bytes_2_append = ((bits_2_append + 512) + 7) / 8;
  } else {
    bytes_2_append = (bits_2_append + 7) / 8;
  }
  while (bytes_2_append--) {
    message.PushBack(ByteUtils::Byte(0x00));
  }
  message.PushBack(ByteUtils::Word<64>(message_size));
  return message;
}

ByteUtils::ByteVector  SHA256::ScheduleMessage(
    const ByteUtils::ByteVector& message) const {
  ByteUtils::ByteVector msg_schedule;    
  for (std::size_t index = 0; index < 16; index++) {
    msg_schedule.PushBack(message.GetWord<32>(index));
  }
  for (std::size_t index = 16; index < 64; index++) {
    auto result = Sigma1(msg_schedule.GetWord<32>(index-2)) + 
                  msg_schedule.GetWord<32>(index-7) + 
                  Sigma0(msg_schedule.GetWord<32>(index-15)) + 
                  msg_schedule.GetWord<32>(index-16); 
    msg_schedule.PushBack(result);
  }
  return msg_schedule;
}

void SHA256::ComputeHash(const ByteUtils::ByteVector& message) {
  std::array<ByteUtils::Word<32>, 8> working_hash = hash_;
  for (std::size_t index = 0; index < 64; index++) {
    auto temp1 = working_hash[7] + 
                 UpperSigma1(working_hash[4]) + 
                 Choose(working_hash[4], working_hash[5], working_hash[6]) +
                 key_[index] + message.GetWord<32>(index);
    auto temp2 = UpperSigma0(working_hash[0]) + 
                 Majority(working_hash[0], working_hash[1], working_hash[2]);
    working_hash[7] = working_hash[6];
    working_hash[6] = working_hash[5];
    working_hash[5] = working_hash[4];
    working_hash[4] = working_hash[3] + temp1;
    working_hash[3] = working_hash[2];
    working_hash[2] = working_hash[1];
    working_hash[1] = working_hash[0];
    working_hash[0] = temp1 + temp2;
  }
  for (std::size_t index = 0; index < 8; index++) {
    hash_[index] = working_hash[index] + hash_[index];
  }
}

ByteUtils::Word<32> SHA256::Choose(const ByteUtils::Word<32>& word1,
                                   const ByteUtils::Word<32>& word2,
                                   const ByteUtils::Word<32>& word3) const {
  return (word1 & word2) ^ (~word1 & word3);
}

ByteUtils::Word<32> SHA256::Majority(const ByteUtils::Word<32>& word1,
                                     const ByteUtils::Word<32>& word2,
                                     const ByteUtils::Word<32>& word3) const {
  return (word1 & word2) ^ (word1 & word3) ^ (word2 & word3);
}

ByteUtils::Word<32> SHA256::RotR(const ByteUtils::Word<32>& word,
                                 std::size_t n_pos) const {
  return (word >> n_pos) | (word << (32 - n_pos));
}

ByteUtils::Word<32> SHA256::Sigma0(const ByteUtils::Word<32>& word) const {
  return RotR(word, 7) ^ RotR(word, 18) ^ (word >> 3);
}

ByteUtils::Word<32> SHA256::Sigma1(const ByteUtils::Word<32>& word) const {
  return RotR(word, 17) ^ RotR(word, 19) ^ (word >> 10);
}

ByteUtils::Word<32> SHA256::UpperSigma0(const ByteUtils::Word<32>& word) const {
  return RotR(word, 2) ^ RotR(word, 13) ^ RotR(word, 22);
}

ByteUtils::Word<32> SHA256::UpperSigma1(const ByteUtils::Word<32>& word) const {
  return RotR(word, 6) ^ RotR(word, 11) ^ RotR(word, 25);
}

}  // namespace Cryptography