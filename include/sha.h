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
#ifndef SECURE_HASH_ALGORITHMS_SHA_H_
#define SECURE_HASH_ALGORITHMS_SHA_H_

#include <byte_vector.h>

namespace Cryptography::details {

// The class `SHA` represents a base class 
// for the algorithms from SHA cryptographic family.
class SHA {
  public:
    virtual ~SHA() = default;
    virtual ByteUtils::ByteVector Digest(
        const ByteUtils::ByteVector& message) = 0;
  protected:
    // Prepares the message for future computation.
    std::vector<ByteUtils::ByteVector> Preprocess(
        const ByteUtils::ByteVector& message);
    // Returns the computed digest for a message in hexadecimal format.
    void ComputeDigest(const ByteUtils::ByteVector& message);
    virtual void InitHash() = 0;
    virtual void InitKey() = 0;
    virtual ByteUtils::ByteVector PaddMessage(
        ByteUtils::ByteVector message) = 0;
    virtual std::vector<ByteUtils::ByteVector> ParseMessage(
        const ByteUtils::ByteVector& message) const = 0;
    virtual ByteUtils::ByteVector ScheduleMessage(
        const ByteUtils::ByteVector& message) const = 0;
    virtual void ComputeHash(const ByteUtils::ByteVector& message) = 0;
};

}  // namespace details

#endif  // SECURE_HASH_ALGORITHMS_SHA_H_