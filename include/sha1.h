#ifndef SECURE_HASH_ALGORITHMS_SHA1_H_
#define SECURE_HASH_ALGORITHMS_SHA1_H_

#include <array>

#include <byte_vector.h>
#include <word.h>

#include "sha.h"

namespace Cryptography {

class SHA1: public SHA {
  public:
    // Creates a `SHA1` object with the default `key`.
    SHA1();
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
    ByteUtils::Word<32> Parity(const ByteUtils::Word<32>& word1,
                               const ByteUtils::Word<32>& word2,
                               const ByteUtils::Word<32>& word3) const;
    ByteUtils::Word<32> RotL(const ByteUtils::Word<32>& word, 
                             std::size_t n_pos) const;
    std::array<ByteUtils::Word<32>, 80> key_;
    std::array<ByteUtils::Word<32>, 5> hash_;
};

}  // namespace Cryptography

#endif  // SECURE_HASH_ALGORITHMS_SHA1_H_