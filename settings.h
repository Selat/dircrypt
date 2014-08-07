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

#ifndef SETTINGS_H
#define SETTINGS_H

#include <inttypes.h>

#define MAX_KEY_LENGTH 1024

typedef struct Settings
{
	char is_encrypt;
	char is_action_set;
	char is_encrypt_all;
	char is_key_set;
	char is_ignore_errors;
	char is_verbose;
	unsigned char random_level;
	uint8_t key[MAX_KEY_LENGTH + 1];
	int key_len;
} Settings;

void SETTINGS_Init(Settings* settings);

#endif
