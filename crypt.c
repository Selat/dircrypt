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

#include <stdio.h>

#define GCRYPT_NO_DEPRECATED
#include <gcrypt.h>

#include "crypt.h"
#include "settings.h"

#define GCRY_CHECK(a)							\
	{											\
	gcry_error_t		e = a;					\
	if(e) {										\
		printf("GCRY error: %s\n", gcry_strerror(e));	\
		exit(-1);								\
	}											\
	}

static gcry_cipher_hd_t cipher_handle;
static gcry_md_hd_t hash_handle;
static gcry_random_level_t random_level = GCRY_STRONG_RANDOM;
uint8_t key_hash[32];

void CRYPT_Init()
{
	if(!gcry_check_version(GCRYPT_VERSION)) {
		fputs("libgcrypt version mismatch.\n", stderr);
	}
	GCRY_CHECK(gcry_control(GCRYCTL_DISABLE_SECMEM, 0));
	GCRY_CHECK(gcry_control(GCRYCTL_INITIALIZATION_FINISHED));
	GCRY_CHECK(gcry_cipher_open(&cipher_handle, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_ECB, 0));
	GCRY_CHECK(gcry_md_open(&hash_handle, GCRY_MD_SHA256, 0));
}

void CRYPT_Quit()
{
	gcry_md_close(hash_handle);
	gcry_cipher_close(cipher_handle);
}

void CRYPT_ReadSettings(Settings* settings)
{
	uint8_t* tmp_hash = NULL;
	switch(settings->random_level) {
	case 1:
		random_level = GCRY_WEAK_RANDOM;
		break;
	case 2:
		random_level = GCRY_STRONG_RANDOM;
		break;
	case 3:
		random_level = GCRY_VERY_STRONG_RANDOM;
		break;
	default:
		fprintf(stderr, "Unknown random level.\n");
		break;
	}

	tmp_hash = CRYPT_Hash((settings->key), settings->key_len);
	CRYPT_SetKey(tmp_hash, 32);
	memcpy(key_hash, tmp_hash, 32);
	tmp_hash = CRYPT_Hash(key_hash, 32);
	memcpy(key_hash, tmp_hash, 32);
	if(settings->is_encrypt) {
		CRYPT_Encrypt(key_hash, 32);
	}
}

void CRYPT_Decrypt(uint8_t* data, int size)
{
	GCRY_CHECK(gcry_cipher_decrypt(cipher_handle, data, size, NULL, 0));
}

void CRYPT_Encrypt(uint8_t* data, int size)
{
	GCRY_CHECK(gcry_cipher_encrypt(cipher_handle, data, size, NULL, 0));
}

void CRYPT_SetKey(uint8_t* data, int size)
{
	GCRY_CHECK(gcry_cipher_setkey(cipher_handle, data, size));
}

uint8_t* CRYPT_GetKeyHash()
{
	return key_hash;
}

void CRYPT_FillWithNoise(uint8_t* data, int size)
{
	gcry_randomize(data, size, random_level);
}

uint8_t* CRYPT_Hash(uint8_t* data, int size)
{
	gcry_md_write(hash_handle, data, size);
	return gcry_md_read(hash_handle, GCRY_MD_SHA256);
}
