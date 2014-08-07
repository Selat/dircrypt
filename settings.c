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

#include "settings.h"

void SETTINGS_Init(Settings* settings)
{
	settings->is_encrypt = 0;
	settings->is_action_set = 0;
	settings->is_encrypt_all = 0;
	settings->is_key_set = 0;
	settings->is_ignore_errors = 0;
	settings->is_verbose = 0;
	settings->random_level = 2;
	settings->key_len = 0;
}
