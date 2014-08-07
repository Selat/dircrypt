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
#include <fcntl.h>
#include <unistd.h>

#include "tty.h"

int tty = -1;
struct termios tty_start_state;

void TTY_SetState(struct termios* state)
{
	if(tcsetattr(tty, TCSANOW, state) != 0) {
		puts("Failed to set term attributes.");
		exit(-1);
	}
}

void TTY_Capture(struct termios* state)
{
	tty = open("/dev/tty", O_RDWR);
	if(tty < 0) {
		puts("Failed to open /dev/tty.");
		exit(-1);
	}
	if(tcgetattr(tty, &tty_start_state) != 0) {
		puts("Failed to get term attributes.");
		exit(-1);
	}
	*state = tty_start_state;
}

void TTY_Release()
{
	TTY_SetState(&tty_start_state);
	if(close(tty)) {
		puts("Failed to close /dev/tty.");
	}
	tty = -1;
}

int TTY_IsCaptured()
{
	return (tty != -1);
}
