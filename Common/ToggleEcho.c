#include <termios.h>
#include <unistd.h>

#include "ToggleEcho.h"

void toggleEcho(const bool on) {
	struct termios t;
	if (tcgetattr(STDIN_FILENO, &t) != 0) return;

	if (on) {
		t.c_lflag |= ((tcflag_t)ECHO);
		t.c_lflag |= ((tcflag_t)ICANON);
	} else {
		t.c_lflag &= ~((tcflag_t)ECHO);
		t.c_lflag &= ~((tcflag_t)ICANON);
	}

	tcsetattr(STDIN_FILENO, TCSANOW, &t);
}
