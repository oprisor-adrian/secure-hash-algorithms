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
#ifndef SHA_SHA_H_
#define SHA_SHA_H_

#include <byte_vector.h>

namespace Cryptography::details {

// The class `SHA` represents an abstract class 
// for the algorithms from SHA cryptographic family.
class SHA {
  public:
    virtual ByteUtils::ByteVector ComputeDigest(
        const ByteUtils::ByteVector& message) = 0;
    virtual void InitHash() = 0;
    virtual void InitKey() = 0;
    virtual ByteUtils::ByteVector PaddMessage(
        ByteUtils::ByteVector message) = 0;
    virtual ByteUtils::ByteVector ScheduleMessage(
        const ByteUtils::ByteVector& message) const = 0;
    virtual void ComputeHash(const ByteUtils::ByteVector& message) = 0;
};

}  // namespace details

#endif  // SHA_SHA_H_