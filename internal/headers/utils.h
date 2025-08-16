#ifndef UTILS_H
#define UTILS_H

#include "bpf_helpers.h"

/* Memory iterators used below. */
#define __it_bwd(x, op) (x -= sizeof(__u##op))

/* Memory operators used below. */
#define __it_xor(a, b, r, op) r |= (*(__u##op *)__it_bwd(a, op)) ^ (*(__u##op *)__it_bwd(b, op))
#define __it_set(a, op) (*(__u##op *)__it_bwd(a, op)) = 0

/* an optimized memcmp implementation from Cilium,
it works by XORing the two inputs at chunks of 8,4 or 2 bytes
limited to 128 bytes comparisons,
It helps the verifier by reduce branching complexity and it is more efficient than single byte comparisons */
static __always_inline bool __bpf_memcmp(const void *x, const void *y, __u64 len) {
    __u64 r = 0;

    if (!__builtin_constant_p(len)) {
        __builtin_trap();
    }

    x += len;
    y += len;

    if (len > 1 && len % 2 == 1) {
        __it_xor(x, y, r, 8);
        len -= 1;
    }

    switch (len) {
	case 128:         __it_xor(x, y, r, 64); __attribute__((fallthrough));
	case 120:jmp_120: __it_xor(x, y, r, 64); __attribute__((fallthrough));
	case 112:jmp_112: __it_xor(x, y, r, 64); __attribute__((fallthrough));
	case 104:jmp_104: __it_xor(x, y, r, 64); __attribute__((fallthrough));
	case 96: jmp_96:  __it_xor(x, y, r, 64); __attribute__((fallthrough));
	case 88: jmp_88:  __it_xor(x, y, r, 64); __attribute__((fallthrough));
	case 80: jmp_80:  __it_xor(x, y, r, 64); __attribute__((fallthrough));
    case 72: jmp_72:  __it_xor(x, y, r, 64); __attribute__((fallthrough));
    case 64: jmp_64:  __it_xor(x, y, r, 64); __attribute__((fallthrough));
    case 56: jmp_56:  __it_xor(x, y, r, 64); __attribute__((fallthrough));
    case 48: jmp_48:  __it_xor(x, y, r, 64); __attribute__((fallthrough));
    case 40: jmp_40:  __it_xor(x, y, r, 64); __attribute__((fallthrough));
    case 32: jmp_32:  __it_xor(x, y, r, 64); __attribute__((fallthrough));
    case 24: jmp_24:  __it_xor(x, y, r, 64); __attribute__((fallthrough));
    case 16: jmp_16:  __it_xor(x, y, r, 64); __attribute__((fallthrough));
    case  8: jmp_8:   __it_xor(x, y, r, 64);
        break;

	case 126: __it_xor(x, y, r, 16); __it_xor(x, y, r, 32); goto jmp_120;
	case 118: __it_xor(x, y, r, 16); __it_xor(x, y, r, 32); goto jmp_112;
	case 110: __it_xor(x, y, r, 16); __it_xor(x, y, r, 32); goto jmp_104;
	case 102: __it_xor(x, y, r, 16); __it_xor(x, y, r, 32); goto jmp_96;
	case 94: __it_xor(x, y, r, 16); __it_xor(x, y, r, 32); goto jmp_88;
	case 86: __it_xor(x, y, r, 16); __it_xor(x, y, r, 32); goto jmp_80;
	case 78: __it_xor(x, y, r, 16); __it_xor(x, y, r, 32); goto jmp_72;
    case 70: __it_xor(x, y, r, 16); __it_xor(x, y, r, 32); goto jmp_64;
    case 62: __it_xor(x, y, r, 16); __it_xor(x, y, r, 32); goto jmp_56;
    case 54: __it_xor(x, y, r, 16); __it_xor(x, y, r, 32); goto jmp_48;
    case 46: __it_xor(x, y, r, 16); __it_xor(x, y, r, 32); goto jmp_40;
    case 38: __it_xor(x, y, r, 16); __it_xor(x, y, r, 32); goto jmp_32;
    case 30: __it_xor(x, y, r, 16); __it_xor(x, y, r, 32); goto jmp_24;
    case 22: __it_xor(x, y, r, 16); __it_xor(x, y, r, 32); goto jmp_16;
    case 14: __it_xor(x, y, r, 16); __it_xor(x, y, r, 32); goto jmp_8;
    case  6: __it_xor(x, y, r, 16); __it_xor(x, y, r, 32);
        break;

	case 124: __it_xor(x, y, r, 32); goto jmp_120;
	case 116: __it_xor(x, y, r, 32); goto jmp_112;
	case 108: __it_xor(x, y, r, 32); goto jmp_104;
	case 100: __it_xor(x, y, r, 32); goto jmp_96;
	case 92: __it_xor(x, y, r, 32); goto jmp_88;
	case 84: __it_xor(x, y, r, 32); goto jmp_80;
	case 76: __it_xor(x, y, r, 32); goto jmp_72;
    case 68: __it_xor(x, y, r, 32); goto jmp_64;
    case 60: __it_xor(x, y, r, 32); goto jmp_56;
    case 52: __it_xor(x, y, r, 32); goto jmp_48;
    case 44: __it_xor(x, y, r, 32); goto jmp_40;
    case 36: __it_xor(x, y, r, 32); goto jmp_32;
    case 28: __it_xor(x, y, r, 32); goto jmp_24;
    case 20: __it_xor(x, y, r, 32); goto jmp_16;
    case 12: __it_xor(x, y, r, 32); goto jmp_8;
    case  4: __it_xor(x, y, r, 32);
        break;

	case 122: __it_xor(x, y, r, 16); goto jmp_120;
	case 114: __it_xor(x, y, r, 16); goto jmp_112;
	case 106: __it_xor(x, y, r, 16); goto jmp_104;
	case 98: __it_xor(x, y, r, 16); goto jmp_96;
	case 90: __it_xor(x, y, r, 16); goto jmp_88;
	case 82: __it_xor(x, y, r, 16); goto jmp_80;
	case 74: __it_xor(x, y, r, 16); goto jmp_72;
    case 66: __it_xor(x, y, r, 16); goto jmp_64;
    case 58: __it_xor(x, y, r, 16); goto jmp_56;
    case 50: __it_xor(x, y, r, 16); goto jmp_48;
    case 42: __it_xor(x, y, r, 16); goto jmp_40;
    case 34: __it_xor(x, y, r, 16); goto jmp_32;
    case 26: __it_xor(x, y, r, 16); goto jmp_24;
    case 18: __it_xor(x, y, r, 16); goto jmp_16;
    case 10: __it_xor(x, y, r, 16); goto jmp_8;
    case  2: __it_xor(x, y, r, 16);
        break;

    case  1: __it_xor(x, y, r, 8);
        break;

    default:
        __builtin_trap();
    }

    return r == 0;
}

static __always_inline void __bpf_memzero(void *d, __u64 len)
{
	if (!__builtin_constant_p(len))
		__builtin_trap();

	d += len;

	if (len > 1 && len % 2 == 1) {
		__it_set(d, 8);
		len -= 1;
	}

	switch (len) {
	case 96:         __it_set(d, 64); __attribute__((fallthrough));
	case 88: jmp_88: __it_set(d, 64); __attribute__((fallthrough));
	case 80: jmp_80: __it_set(d, 64); __attribute__((fallthrough));
	case 72: jmp_72: __it_set(d, 64); __attribute__((fallthrough));
	case 64: jmp_64: __it_set(d, 64); __attribute__((fallthrough));
	case 56: jmp_56: __it_set(d, 64); __attribute__((fallthrough));
	case 48: jmp_48: __it_set(d, 64); __attribute__((fallthrough));
	case 40: jmp_40: __it_set(d, 64); __attribute__((fallthrough));
	case 32: jmp_32: __it_set(d, 64); __attribute__((fallthrough));
	case 24: jmp_24: __it_set(d, 64); __attribute__((fallthrough));
	case 16: jmp_16: __it_set(d, 64); __attribute__((fallthrough));
	case  8: jmp_8:  __it_set(d, 64);
		break;

	case 94: __it_set(d, 16); __it_set(d, 32); goto jmp_88;
	case 86: __it_set(d, 16); __it_set(d, 32); goto jmp_80;
	case 78: __it_set(d, 16); __it_set(d, 32); goto jmp_72;
	case 70: __it_set(d, 16); __it_set(d, 32); goto jmp_64;
	case 62: __it_set(d, 16); __it_set(d, 32); goto jmp_56;
	case 54: __it_set(d, 16); __it_set(d, 32); goto jmp_48;
	case 46: __it_set(d, 16); __it_set(d, 32); goto jmp_40;
	case 38: __it_set(d, 16); __it_set(d, 32); goto jmp_32;
	case 30: __it_set(d, 16); __it_set(d, 32); goto jmp_24;
	case 22: __it_set(d, 16); __it_set(d, 32); goto jmp_16;
	case 14: __it_set(d, 16); __it_set(d, 32); goto jmp_8;
	case  6: __it_set(d, 16); __it_set(d, 32);
		break;

	case 92: __it_set(d, 32); goto jmp_88;
	case 84: __it_set(d, 32); goto jmp_80;
	case 76: __it_set(d, 32); goto jmp_72;
	case 68: __it_set(d, 32); goto jmp_64;
	case 60: __it_set(d, 32); goto jmp_56;
	case 52: __it_set(d, 32); goto jmp_48;
	case 44: __it_set(d, 32); goto jmp_40;
	case 36: __it_set(d, 32); goto jmp_32;
	case 28: __it_set(d, 32); goto jmp_24;
	case 20: __it_set(d, 32); goto jmp_16;
	case 12: __it_set(d, 32); goto jmp_8;
	case  4: __it_set(d, 32);
		break;

	case 90: __it_set(d, 16); goto jmp_88;
	case 82: __it_set(d, 16); goto jmp_80;
	case 74: __it_set(d, 16); goto jmp_72;
	case 66: __it_set(d, 16); goto jmp_64;
	case 58: __it_set(d, 16); goto jmp_56;
	case 50: __it_set(d, 16); goto jmp_48;
	case 42: __it_set(d, 16); goto jmp_40;
	case 34: __it_set(d, 16); goto jmp_32;
	case 26: __it_set(d, 16); goto jmp_24;
	case 18: __it_set(d, 16); goto jmp_16;
	case 10: __it_set(d, 16); goto jmp_8;
	case  2: __it_set(d, 16);
		break;

	case  1: __it_set(d, 8);
		break;

	default:
		/* __builtin_memset() is crappy slow since it cannot
		 * make any assumptions about alignment & underlying
		 * efficient unaligned access on the target we're
		 * running.
		 */
		__builtin_trap();
	}
}

#endif