#include "Message.h"

int msg_getPadAmount(const int lenContent) {
	return (lenContent % 16 == 0) ? 0 : 16 - (lenContent % 16);
}
