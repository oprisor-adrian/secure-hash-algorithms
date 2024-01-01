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
#include "sha.h"

#include <iostream>

namespace Cryptography {

void SHA::ComputeDigest(const ByteUtils::ByteVector& message) {
  auto message_blocks = Preprocess(message);
  for (const auto& block : message_blocks) {
    ByteUtils::ByteVector scheduled_block = ScheduleMessage(block); 
    ComputeHash(scheduled_block);
  }
}

std::vector<ByteUtils::ByteVector> SHA::Preprocess(
    const ByteUtils::ByteVector& message) {
  InitHash();
  ByteUtils::ByteVector padded_message = PaddMessage(message);
  return ParseMessage(padded_message);
}

}  // namespace Cryptography