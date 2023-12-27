#ifndef SHA256_SHA256_H_
#define SHA256_SHA256_H_

#include <string>
#include <vector>

#include "byte_vector.h"
#include "word.h"

namespace Cryptography {

class SHA256 {
  public:
    SHA256() = default;
    SHA256(const std::string& message);
  private:
    void InitHash();
    ByteUtils::ByteVector PaddMessage(const std::string& message) const;
    ByteUtils::Word Choose(const ByteUtils::Word& word1, 
                           const ByteUtils::Word& word2,
                           const ByteUtils::Word& word3) const;
    ByteUtils::Word Majority(const ByteUtils::Word& word1,
                             const ByteUtils::Word& word2,
                             const ByteUtils::Word& word3) const;
    ByteUtils::Word RotL(const ByteUtils::Word& word, 
                         std::size_t n_bits) const;
    ByteUtils::Word RotR(const ByteUtils::Word& word,
                         std::size_t n_bits) const;
    std::vector<ByteUtils::Word> hash_;
};

}  // namespace Cryptography

#endif // SHA256_SHA256_H_