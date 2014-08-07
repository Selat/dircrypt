/*
  This file is part of Dircrypt

  Dircrypt is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  Dircrypt is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with Dircrypt.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef CRYPT_H
#define CRYPT_H

#include <stdint.h>

typedef struct Settings Settings;

void CRYPT_Init();
void CRYPT_Quit();

void CRYPT_ReadSettings(Settings* settings);

void CRYPT_Decrypt(uint8_t* data, int size);
void CRYPT_Encrypt(uint8_t* data, int size);
void CRYPT_SetKey(uint8_t* data, int size);
uint8_t* CRYPT_GetKeyHash();

void CRYPT_FillWithNoise(uint8_t* data, int size);

uint8_t* CRYPT_Hash(uint8_t* data, int size);

#endif
