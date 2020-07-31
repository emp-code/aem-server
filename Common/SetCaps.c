#include <sys/capability.h>

#include "SetCaps.h"

int setCaps(const cap_value_t cap1, const cap_value_t cap2) {
	if (!CAP_IS_SUPPORTED(CAP_SETFCAP)) return -1;

	cap_t caps = cap_get_proc();
	if (cap_clear(caps) != 0) {cap_free(caps); return -1;}

	if (cap1 != 0) {
		const cap_value_t enable[2] = {cap1, cap2};
		if (cap_set_flag(caps, CAP_PERMITTED, cap2 == 0 ? 1 : 2, enable, CAP_SET) != 0) {cap_free(caps); return -1;}
		if (cap_set_flag(caps, CAP_EFFECTIVE, cap2 == 0 ? 1 : 2, enable, CAP_SET) != 0) {cap_free(caps); return -1;}
	}

	if (cap_set_proc(caps) != 0) {cap_free(caps); return -1;}

	return cap_free(caps);
}
