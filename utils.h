#ifndef utils_hpp
#define utils_hpp

#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <chrono>
#include <random>
#include <cctype>

using namespace std;

// Convesor de valores big-n/lil-endian bytes
uint64_t ntoh64(const uint64_t *input);
uint64_t hton64(const uint64_t *input);

// Print dos hex de input ou gerados
void print_hex_string(string label, uint64_t &input);

// Valores random para caso de nao inputar os mesmo
string DES_random_string(const int len);

// pad data no ultimo block com 0's
uint64_t DES_key_iv_check(const char *data, uint64_t length);

// Validador hex
uint8_t valid_hex_string(string &data, int len);

const string HEX_SET = "0123456789abcdef";

#endif
