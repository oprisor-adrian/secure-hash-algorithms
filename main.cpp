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
#include <iostream>

#include <byte_vector.h>

#include "sha256.h"

int main() {
  Cryptography::SHA256 sha256;
  ByteUtils::ByteVector result = sha256.ComputeDigest({"616263"});
  std::cout << result.ToHex() << std::endl;
  return 0;
}