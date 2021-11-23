#include "cipher_des.h"

uint32_t permute(const char *table, uint8_t table_len, uint64_t input, uint8_t input_len)
{
  uint32_t res = 0;
  for (uint8_t i = 0; i < table_len; i++)
	{
  	res = (res << 1) | ((input >> (input_len - table[i])) & 0x01); 
  }
  return res;
}

// P1
uint64_t ip(uint64_t M) {
  return permute(IP, sizeof(IP) / sizeof(IP[0]), M, 48);
}

// P-1
uint64_t fp(uint64_t M)
{
	return permute(FP, sizeof(FP) / sizeof(FP[0]), M, 48);
}

uint64_t *key_schedule(uint32_t K, uint64_t (&subkeys)[ITERATIONS])
{
  // PC1 
	// - Como não há spec no trabalho dos init de serem diferentes do "original", resolvi deixar 48 (como é empregado no original) ...
	// 		aqui seria 64 e o último seria 56, digo
  K = permute(PC1, sizeof(PC1) / sizeof(PC1[0]), K, 48);

	// split esq-dir (c | d)
  uint16_t C = (uint16_t) ((K >> 16) & 0x000000000fffffff);
  uint16_t D = (uint16_t) (K & 0x000000000fffffff);

  for (int i = 0; i < ITERATIONS; i++)
	{
  	switch ((int) (LEFT_SHIFTS[i]))
		{
    	// Shift 1 bit
			case 1:
			{
      	C = ((C << 1) & 0x0FFFFFFF) | (C >> 15);
      	D = ((D << 1) & 0x0FFFFFFF) | (D >> 15);
      	break;
      }
			// Shift 2 bits
      case 2:
			{
      	C = ((C << 2) & 0x0FFFFFFF) | (C >> 14);
        D = ((D << 2) & 0x0FFFFFFF) | (D >> 14);
        break;
      }
    }

    uint64_t CD = (((uint64_t) C) << 16) | (uint64_t) D;
        
		// PC2 (o mesmo do PC1 vale aqui (48 porque não foi espeficificado se o "backdoor" se aplica aqui))
    subkeys[i] = permute(PC2, sizeof(PC2) / sizeof(PC2[0]), CD, 48);
  }
  return subkeys;
}

uint64_t Expand(uint32_t R)
{
  return permute(E, sizeof(E) / sizeof(E[0]), R, 32);
}

char S(int sbox, uint8_t input)
{
  char row = (char) (((input & 0x20) >> 4) | (input & 0x01));
  char col = (char) ((input & 0x1E) >> 1);
  return SBOXMAP[sbox][16 * row + col];
}

uint32_t F(uint32_t K, uint32_t R)
{
	// Expande como no "original"
  uint32_t e = Expand(R);
  e ^= K;

  uint32_t output = 0;
  for (int i = 0; i < 8; ++i)
	{
    output <<= 4;
    output |= (uint32_t) S(i, (uint8_t) ((e & 0xFC0000000000) >> 42));
    e <<= 6;
  }

  return (uint32_t) permute(P, sizeof(P) / sizeof(P[0]), output, 32);;
}

uint64_t des(uint64_t (&subkeys)[ITERATIONS], uint64_t M, int enc)
{
	// 1ª etapa: P1
  M = ip(M);

	// Divisao de blocks de 24 bits (24 - L | 24  - R)
  uint32_t L = (uint32_t) (M >> 24) & 0x0FFFFFFFF;
  uint32_t R = (uint32_t) (M & 0x0FFFFFFFF);

	// 2ª etapa: substituicao (Esquerda (L) e direira (R))
  for (int i = 0; i < ITERATIONS; ++i)
	{
    uint32_t oldL = L;
    uint32_t subkey = enc ? subkeys[i] : subkeys[ITERATIONS - i - 1];
    L = R; // LEi = REi-1;
    R = oldL ^ F(subkey, R); // XOR da L (antes do attrib) e subchave
  }

	// 3ª etapa: swap para nao usar o L <-R | R <- OldL ^ R
  M = (((uint64_t) R) << 24) | (uint64_t) L;
  // 4. Aplica a P-1 (FP)
  return fp(M); // 48 bits;
}
