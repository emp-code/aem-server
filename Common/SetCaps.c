#include <sys/capability.h>

#include "SetCaps.h"

int setCaps(const cap_value_t enable) {
	if (!CAP_IS_SUPPORTED(CAP_SETFCAP)) return -1;

	cap_t caps = cap_get_proc();
	if (cap_clear(caps) != 0) {cap_free(caps); return -1;}

	if (enable != 0) {
		if (cap_set_flag(caps, CAP_PERMITTED, 1, &enable, CAP_SET) != 0) {cap_free(caps); return -1;}
		if (cap_set_flag(caps, CAP_EFFECTIVE, 1, &enable, CAP_SET) != 0) {cap_free(caps); return -1;}
	}

	if (cap_set_proc(caps) != 0) {cap_free(caps); return -1;}
	return cap_free(caps);
}
