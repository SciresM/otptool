// Copyright 2010  booto 
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
#ifndef types_h
#define types_h

#include <stdint.h>

typedef int8_t s8;
typedef uint8_t u8;
typedef int16_t s16;
typedef uint16_t u16;
typedef int32_t s32;
typedef uint32_t u32;
typedef int64_t s64;
typedef uint64_t u64;

#endif

// Copyright 2010  booto 
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
#ifndef ec_h
#define ec_h

int check_ec(u8 *ng, u8 *ap, u8 *sig, u8 *sig_hash);
void ec_priv_to_pub(const u8 *k, u8 *Q);
int check_ecdsa(u8 *Q, u8 *R, u8 *S, u8 *hash);
int generate_ecdsa(u8 *R, u8 *S, u8 *k, u8 *hash);

#endif
// Copyright 2010  booto 
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
#ifndef bn_h
#define bn_h


int bn_compare(u8 *a, u8 *b, u32 n);
void bn_sub_modulus(u8 *a, u8 *N, u32 n);
void bn_add(u8 *d, u8 *a, u8 *b, u8 *N, u32 n);
void bn_mul(u8 *d, u8 *a, u8 *b, u8 *N, u32 n);
void bn_exp(u8 *d, u8 *a, u8 *N, u32 n, u8 *e, u32 en);
void bn_inv(u8 *d, u8 *a, u8 *N, u32 n);
#endif
