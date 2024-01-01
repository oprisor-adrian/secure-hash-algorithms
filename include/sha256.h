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
#ifndef SECURE_HASH_ALGORITHMS_SHA256_H_
#define SECURE_HASH_ALGORITHMS_SHA256_H_

#include <array>
#include <cstdint>
#include <string>

#include <byte_vector.h>
#include <word.h>

#include "sha.h"

namespace Cryptography {

class SHA256: public details::SHA {
  public:
    // Creates a `SHA256` object with the default `key`.
    SHA256();
    // Returns the computed digest as a vector of bytes.
    ByteUtils::ByteVector Digest(const ByteUtils::ByteVector& message) override;
  private:
    void InitHash() override;
    void InitKey() override;
    ByteUtils::ByteVector PaddMessage(ByteUtils::ByteVector message) override;
    std::vector<ByteUtils::ByteVector> ParseMessage(
        const ByteUtils::ByteVector& message) const override;
    ByteUtils::ByteVector ScheduleMessage(
        const ByteUtils::ByteVector& message) const override;
    void ComputeHash(const ByteUtils::ByteVector& message) override;
    ByteUtils::Word<32> Choose(const ByteUtils::Word<32>& word1,
                               const ByteUtils::Word<32>& word2,
                               const ByteUtils::Word<32>& word3) const;
    ByteUtils::Word<32> Majority(const ByteUtils::Word<32>& word1,
                                 const ByteUtils::Word<32>& word2,
                                 const ByteUtils::Word<32>& word3) const;
    ByteUtils::Word<32> RotR(const ByteUtils::Word<32>& word, 
                             std::size_t n_pos) const;
    ByteUtils::Word<32> Sigma0(const ByteUtils::Word<32>& word) const;
    ByteUtils::Word<32> Sigma1(const ByteUtils::Word<32>& word) const;
    ByteUtils::Word<32> UpperSigma0(const ByteUtils::Word<32>& word) const;
    ByteUtils::Word<32> UpperSigma1(const ByteUtils::Word<32>& word) const;
    std::array<ByteUtils::Word<32>, 64> key_;
    std::array<ByteUtils::Word<32>, 8> hash_;
};

}  // namespace Cryptography

#endif // SECURE_HASH_ALGORITHMS_SHA256_H_