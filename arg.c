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
#include <string.h>
#include <stdlib.h>

#include "arg.h"
#include "settings.h"

struct Option
{
	char short_name;
	char* full_name;
	char* description;
	int (*func)(int id, char** argv, Settings* settings);
};

static int helpCommand(int id, char** argv, Settings* settings);
static int forceCommand(int id, char** argv, Settings* settings);
static int randomLevelCommand(int id, char** argv, Settings* settings);
static int actionCommand(int id, char** argv, Settings* settings);
static int keyCommand(int id, char** argv, Settings* settings);
static int ignoreCommand(int id, char** argv, Settings* settings);
static int verboseCommand(int id, char** argv, Settings* settings);

static struct Option options[] = {
	{.short_name = 'h', .full_name = "help", .description = "display this help and exit", .func = helpCommand},
	{.short_name = 'A', .full_name = "all", .description = "encrypt all files, don't exclude [DIRECTORY]/dircrypt", .func = forceCommand},
	{.short_name = 'r', .full_name = "random-level", .description = "set random level (from 1 to 3)", .func = randomLevelCommand},
	{.short_name = 'a', .full_name = "action", .description = "set action (e - encrypt, d - decrypt)", .func = actionCommand},
	{.short_name = 'k', .full_name = "key", .description = "set key", .func = keyCommand},
	{.short_name = 'i', .full_name = "ignore", .description = "continue even if program fails to process some file", .func = ignoreCommand},
	{.short_name = 'v', .full_name = "verbose", .description = "print more information", .func = verboseCommand}
};
static const int options_num = sizeof(options) / sizeof(struct Option);
static char** paths = NULL;
static int paths_num = 0;

void ARG_Parse(int argc, char **argv, Settings* settings)
{
	int i, j, k, param_id;
	int len;
	char is_option_found;
	char *s;
	paths = (char**)malloc(sizeof(char) * (argc - 1));
	for(i = 1; i < argc;) {
		s = argv[i];
		if(s[0] == '-') {
			if(s[1] != '-') {
				len = strlen(s);
				param_id = i + 1;
				for(j = 1; j < len; ++j) {
					is_option_found = 0;
					for(k = 0; k < options_num; ++k) {
						if(s[j] == options[k].short_name) {
							param_id = options[k].func(param_id, argv, settings);
							is_option_found = 1;
							break;
						}
					}
					if(param_id == 0) {
						exit(-1);
					}
					if(!is_option_found) {
						fprintf(stderr, "Unknown option: -%c\n", s[j]);
						exit(-1);
					}
				}
				i = param_id;
			} else {
				is_option_found = 0;
				s += 2;
				for(j = 0; j < options_num; ++j) {
					if(strcmp(s, options[j].full_name) == 0) {
						i = options[j].func(i + 1, argv, settings);
						is_option_found = 1;
					}
				}
				if(i == 0) {
					exit(-1);
				}
				if(!is_option_found) {
					fprintf(stderr, "%s: unrecognized option '--%s'\n", argv[0], s);
					fprintf(stderr, "Try '%s --help' for more information\n", argv[0]);
					exit(-1);
				}
			}
		} else {
			paths[paths_num++] = s;
			++i;
		}
	}
}

void ARG_Quit()
{
	free(paths);
}

int ARG_GetPathsNum()
{
	return paths_num;
}

char* ARG_GetPath(int id)
{
	if((id >= 0) && (id < paths_num)) {
		return paths[id];
	} else {
		return NULL;
	}
}

static int helpCommand(int id, char** argv, Settings* settings)
{
	static char help_message[] =
		"Usage: dircrypt [OPTION]... [DIRECTORY]... [FILE]...\n"
		"Encrypt directories or files (the current directory by default).\n" \
		"Options: ";
	static const int max_width = 25;
	int i, j;
	puts(help_message);
	for(i = 0; i < options_num; ++i) {
		for(j = 0; j < 2; ++j) {
			putc(' ', stdout);
		}
		if(options[i].short_name) {
			printf("-%c, ", options[i].short_name);
		} else {
			printf("     ");
		}
		printf("--%s", options[i].full_name);
		j = 8 + strlen(options[i].full_name);
		while(j++ < max_width) {
			putc(' ', stdout);
		}
		printf("%s\n", options[i].description);
	}
	return 0;
}

static int forceCommand(int id, char** argv, Settings* settings)
{
	settings->is_encrypt_all = 1;
	return id;
}

static int randomLevelCommand(int id, char** argv, Settings* settings)
{
	int level = argv[id][0] - '0';
	if((argv[id][1] != '\0') || (level < 1) || (level > 3)) {
		fprintf(stderr, "Unknown random level: %s\n", argv[id]);
		return 0;
	} else {
		settings->random_level = level;
		return id + 1;
	}
}

static int actionCommand(int id, char** argv, Settings* settings)
{
	int len = strlen(argv[id]);
	char action = argv[id][0];
	if((len > 1) || !((action == 'e') || (action == 'd'))) {
		fprintf(stderr, "Unknown action: %s\n", argv[id]);
		return 0;
	} else if(action == 'e') {
		settings->is_encrypt = 1;
	} else {
		settings->is_encrypt = 0;
	}
	settings->is_action_set = 1;
	return id + 1;
}

static int keyCommand(int id, char** argv, Settings* settings)
{
	strcpy((char*)(settings->key), argv[id]);
	settings->is_key_set = 1;
	settings->key_len = strlen(argv[id]);
	return id + 1;
}

static int ignoreCommand(int id, char** argv, Settings* settings)
{
	settings->is_ignore_errors = 1;
	return id;
}

static int verboseCommand(int id, char** argv, Settings* settings)
{
	settings->is_verbose = 1;
	return id;
}
