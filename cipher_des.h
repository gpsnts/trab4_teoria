#ifndef CIPHER_DES_H
#define CIPHER_DES_H

#include <cstdlib>
#include <cstdint>
#include <iostream>
#include "cipher_params.h"

using namespace std;

/*
DES - FLUXO
function DESEncrypt(K,M) // K=48 bits1, M=49 bits {
 1. P-1
 2. Gen de subkeys
 3. Permutacoes K1...K16 to 48 bits;
 4. Subtituicoes
  5. swap(LE16,RE16);
  6. IP-1
}
*/

uint32_t permute(const char *table, uint8_t table_len, uint64_t input, uint8_t input_len);

uint64_t ip(uint64_t M);

uint64_t fp(uint64_t M);

uint64_t *key_schedule(uint32_t K, uint64_t (&subkeys)[ITERATIONS]);

// expand 24 bits
uint64_t Expand(uint32_t R);

// Mapper da S-Box
char S(int sbox, uint8_t input);

// output: 24 bit
uint32_t F(uint64_t K, uint32_t R);

// M: 56 bits
uint64_t des(uint64_t (&subkeys)[ITERATIONS], uint64_t M, int enc);

#endif //CIPHER_DES_H
