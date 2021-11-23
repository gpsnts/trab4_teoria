#ifndef padding_hpp
#define padding_hpp

#include <cstdlib>
#include <cstdint>
#include <string>

// PKCS5 Padding (https://en.wikipedia.org/wiki/PKCS)

// Espaco para fazer padding
uint64_t get_pad_length(uint64_t data_len);

// pad
uint64_t pad_with_length(uint64_t data, uint64_t pad_len);

// limpa o pad para do dec
uint64_t remove_pad(uint64_t data, uint64_t pad_len);

#endif //padding_hpp
