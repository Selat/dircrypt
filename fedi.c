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

#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <string.h>
#include <ftw.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>

#include "crypt.h"
#include "fedi.h"
#include "settings.h"

#define BLOCK_SIZE 1024

#define SAFE_CALL(a) \
if(a != 0) {                            \
    closeFiles(0, &state);              \
    if(!settings->is_ignore_errors) {   \
        return -1;                      \
    } else {                            \
        return 0;                       \
    }                                   \
}

#define SAFE_READ(data, data_size, n, file)                        \
if(fread(data, data_size, n, file) != n) {                         \
	fprintf(stderr, "%s - ailed to read data!", state->file_name); \
    return -1;                                                     \
}

#define SAFE_WRITE(data, data_size, n, file)                       \
if(fwrite(data, data_size, n, file) != n) {                        \
	fprintf(stderr, "%s - ailed to read data!", state->file_name); \
    return -1;                                                     \
}

typedef struct State
{
	FILE* file_in;
	FILE* file_out;
	char* file_name;
	char* tmp_file_name;
	uint32_t last_block_size;
} State;

State state;

static Settings* settings = NULL;
static char* prog_path = NULL;
static char* working_dir = NULL;

static void fillWorkingDir();
static char* getRealPath(const char* file_name);
static int isProgFile(const char* file_name);

static int processFileHeader(int is_finishing, State* state);
static int processFileData(State* state);
static int openFiles(const char* file_name, State* state);
static int closeFiles(int is_replace_old_file, State* state);
static int callback(const char *file_name, const struct stat *s, int type);

void FEDI_Init(char* prog_name, Settings* _settings)
{
	settings = _settings;
	fillWorkingDir();
	prog_path = getRealPath(prog_name);
	state.file_in = NULL;
	state.file_out = NULL;
	state.file_name = NULL;
	state.tmp_file_name = NULL;
	state.last_block_size = 0;
}

void FEDI_Quit()
{
	closeFiles(0, &state);
	free(state.tmp_file_name);
	free(state.file_name);
	free(prog_path);
	free(working_dir);
}

void FEDI_ProcessPath(char* path)
{
	ftw(path, callback, 1);
}

static void fillWorkingDir()
{
	char* path = getcwd(NULL, 0);
	int path_len = strlen(path);
	working_dir = (char*)malloc(sizeof(char) * (path_len + 2));
	strcpy(working_dir, path);
	if(working_dir[path_len - 1] != '/') {
		working_dir[path_len] = '/';
		working_dir[path_len + 1] = '\0';
	}
	free(path);
}

static char* getRealPath(const char* file_name)
{
	int name_len = strlen(file_name);
	int path_len = strlen(working_dir);
	char* path = NULL;
	char* full_path = NULL;
	path = (char*)malloc(sizeof(char) * (path_len + name_len + 1));
	if(file_name[0] != '/') {
		path = (char*)malloc(sizeof(char) * (path_len + name_len + 1));
		strcpy(path, working_dir);
		strcat(path, file_name);
		full_path = realpath(path, NULL);
		strcpy(path, full_path);
		free(full_path);
		return path;
	} else {
		strcpy(path, file_name);
		return path;
	}
}

static int isProgFile(const char* file_name)
{
	char* full_file_name = getRealPath(file_name);
	if(strcmp(full_file_name, prog_path) == 0) {
		free(full_file_name);
		return 1;
	} else {
		free(full_file_name);
		return 0;
	}
}

static int processFileHeader(int is_finishing, State* state)
{
	uint8_t* key_hash = CRYPT_GetKeyHash();
	FILE* file_in = state->file_in;
	FILE* file_out = state->file_out;
	static uint8_t real_key_hash[32];

	if(settings->is_encrypt) {
		fseek(file_out, 0, SEEK_SET);
		SAFE_WRITE(&(state->last_block_size), sizeof(uint32_t), 1, file_out);
		SAFE_WRITE(key_hash, sizeof(uint8_t), 32, file_out);
	} else if(!is_finishing) {
		SAFE_READ(&(state->last_block_size), sizeof(uint32_t), 1, file_in);
		SAFE_READ(real_key_hash, sizeof(uint8_t), 32, file_in);
		CRYPT_Decrypt(real_key_hash, 32);
		if(memcmp(key_hash, real_key_hash, 32) != 0) {
			fprintf(stderr, "%s - Incorrect key!\n", state->file_name);
			fflush(file_out);
			return -1;
		}
	}
	return 0;
}

static int processFileData(State* state)
{
	static uint8_t block1[BLOCK_SIZE + 1];
	static uint8_t block2[BLOCK_SIZE + 1];
	int len1 = fread(block1, sizeof(uint8_t), BLOCK_SIZE, state->file_in);
	int len2 = 0;
	int cur_block_id = 0;
	while(len1) {
		len2 = fread(block2, sizeof(uint8_t), BLOCK_SIZE, state->file_in);
		if(settings->is_encrypt) {
			if(len2 == 0) {
				CRYPT_FillWithNoise(block1 + len1, BLOCK_SIZE - len1);
			}
			CRYPT_Encrypt(block1, BLOCK_SIZE);
			SAFE_WRITE(block1, sizeof(uint8_t), BLOCK_SIZE, state->file_out);
			state->last_block_size = len1;
		} else {
			CRYPT_Decrypt(block1, BLOCK_SIZE);
			if(len2 != 0) {
				SAFE_WRITE(block1, sizeof(uint8_t), BLOCK_SIZE, state->file_out);
			} else {
				SAFE_WRITE(block1, sizeof(uint8_t), state->last_block_size, state->file_out);
			}
		}
		memcpy(block1, block2, len2);
		len1 = len2;
		++cur_block_id;
	}
	return 0;
}

static int openFiles(const char* file_name, State* state)
{
	int file_name_len = strlen(file_name);
	state->file_name = (char*)malloc(sizeof(char) * (file_name_len + 1));
	state->tmp_file_name = (char*)malloc(sizeof(char) * (file_name_len + 2));
	strcpy(state->file_name, file_name);
	strcpy(state->tmp_file_name, file_name);
	strcat(state->tmp_file_name, "~");

	if(access(file_name, R_OK | W_OK) != 0) {
		fprintf(stderr, "Error: don't have read/write access to %s\n", file_name);
		return -1;
	}
	state->file_in = fopen(state->file_name, "r");
	state->file_out = fopen(state->tmp_file_name, "w");
	if(!state->file_in || !state->file_out) {
		printf("Failed to open file %s\n", file_name);
		return -1;
	}
	return 0;
}

static int closeFiles(int is_replace_old_file, State* state)
{
	if(((state->file_in != NULL) && (state->file_out != NULL))
	   && (fclose(state->file_in) || fclose(state->file_out))) {
		fprintf(stderr, "Failed to close file %s\n", state->file_name);
		return -1;
	}
	if((state->file_name != NULL) && (state->tmp_file_name != NULL)) {
		if(is_replace_old_file) {
			remove(state->file_name);
			rename(state->tmp_file_name, state->file_name);
		} else {
			remove(state->tmp_file_name);
		}
		free(state->file_name);
		free(state->tmp_file_name);
		state->file_name = NULL;
		state->tmp_file_name = NULL;
	}
	return 0;
}

static int callback(const char *file_name, const struct stat *s, int type)
{
	if((type == FTW_F) && !isProgFile(file_name)) {
		if(settings->is_verbose) {
			printf("Processing: %s - ", file_name);
			fflush(stdout);
		}

		SAFE_CALL(openFiles(file_name, &state));
		SAFE_CALL(processFileHeader(0, &state));
		SAFE_CALL(processFileData(&state));
		SAFE_CALL(processFileHeader(1, &state));

		if((closeFiles(1, &state) != 0) && !settings->is_ignore_errors) {
			return -1;
		}

		if(settings->is_verbose) {
			puts("ok!");
		}
	}
	return 0;
}
