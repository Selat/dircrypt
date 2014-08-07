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
#include <inttypes.h>
#include <unistd.h>
#include <signal.h>

#include "arg.h"
#include "crypt.h"
#include "fedi.h"
#include "tty.h"
#include "settings.h"

static Settings settings;

static void terminationHandler(int signum);

void readAction()
{
	int is_read = 0;
	struct termios s;
	TTY_Capture(&s);
	s.c_iflag &= ~(IGNBRK|BRKINT|PARMRK|ISTRIP
	               |INLCR|IGNCR|ICRNL|IXON);
	s.c_oflag &= ~OPOST;
	s.c_lflag &= ~ICANON;
	s.c_cflag |= CS8;
	TTY_SetState(&s);

	printf("Choose action (1 - encrypt, 2 - decrypt): ");
	fflush(stdout);
	while(!is_read) {
		char c;
		int len;
		fflush(stdin);
		len = read(tty, &c, 1);
		if(len == 1) {
			if(c == '1') {
				settings.is_encrypt = 1;
				is_read = 1;
			} else if(c == '2') {
				settings.is_encrypt = 0;
				is_read = 1;
			} else {
				printf("\n\rUnknown command. Try again: ");
				fflush(stdout);
			}
		}
	}
	TTY_Release();
	printf("\n");
}

void readKey()
{
	int len = 1;
	struct termios s;
	TTY_Capture(&s);
	s.c_lflag &= ~ECHO;
	TTY_SetState(&s);
	while(len == 1) {
		printf("\rKey: ");
		fflush(stdout);
		len = read(tty, settings.key, MAX_KEY_LENGTH);
	}
	settings.key_len = len - 1;
	TTY_Release();
	printf("\n");
}

static void terminationHandler(int signum)
{
	FEDI_Quit();
	if(TTY_IsCaptured()) {
		TTY_Release();
	}
	printf("\n");
	exit(0);
}

int main(int argc, char **argv)
{
	int i, num;
	char* path;
	signal(SIGINT, terminationHandler);
	signal(SIGHUP, terminationHandler);
	signal(SIGTERM, terminationHandler);
	signal(SIGQUIT, terminationHandler);
	FEDI_Init(argv[0], &settings);
	SETTINGS_Init(&settings);
	CRYPT_Init();
	ARG_Parse(argc, argv, &settings);
	if(!settings.is_action_set) {
		readAction();
	}
	if(!settings.is_key_set) {
		readKey();
	}
	CRYPT_ReadSettings(&settings);
	if(settings.is_encrypt) {
		puts("Starting encryption...");
	} else {
		puts("Starting decryption...");
	}
	num = ARG_GetPathsNum();
	if(num == 0) {
		FEDI_ProcessPath(".");
	} else {
		for(i = 0; i < num; ++i) {
			path = ARG_GetPath(i);
			FEDI_ProcessPath(path);
		}
	}
	ARG_Quit();
	CRYPT_Quit();
	FEDI_Quit();
	return 0;
}
