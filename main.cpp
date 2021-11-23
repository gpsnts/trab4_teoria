#include "utils.h"

#include <cstdio>
#include <cstdlib>
#include <bitset>

#include "cipher_des.h"
#include "cipher_padding.h"

// input - path do arquivo de input
// output - nome arquivo de ouput
// iv - initial value (valor inicial do cbc)
// enc - enc ou dec

void DES_cbc_encrypt(string input, string output, uint64_t (&subkeys)[ITERATIONS], uint64_t &iv, int enc)
{
	ifstream in;
  ofstream out;

 	in.open(input, ios::binary | ios::in | ios::ate);
 	out.open(output, ios::binary | ios::out);
    
	if (!in)
	{
  	cerr << "Error: missing file " << input << endl;
  	exit(1);
  }

	// Aponta para o final do arquivo para ter nocao do tamanho
  uint64_t len = in.tellg();

  in.seekg(0, ios::beg);
  uint64_t buffer = 0;

	// CBC
  uint64_t c_prev = iv;
  for (int i = 0; i < len / 8; ++i)
	{
    in.read((char *) &buffer, 8);
    uint64_t p_curr = hton64(&buffer);
    c_prev = des(subkeys, p_curr ^ c_prev, enc);
    uint64_t x = hton64(&c_prev);
    out.write((char *) &x, 8);
  }

	// Padding final usado: PKCS5 (ver o cipher_padding.(h|cpp)
  uint64_t padlen = get_pad_length(len);
  if (padlen == 8)
	{
    uint64_t p_curr = 0x0808080808080808;
    c_prev = des(subkeys, p_curr ^ c_prev, enc);
    uint64_t x = hton64(&c_prev);
    out.write((char *) &x, 8);
  } else
	{
    buffer = 0;
    in.read((char *) &buffer, len % 8);
    uint64_t p_curr = hton64(&buffer);
    p_curr = pad_with_length(p_curr, padlen);
    c_prev = des(subkeys, p_curr ^ c_prev, enc);
    uint64_t x = hton64(&c_prev);
    out.write((char *) &x, 8);
  }
  in.close();
  out.close();
}

void DES_cbc_decrypt(string input, string output, uint64_t (&subkeys)[ITERATIONS], uint64_t &iv, int enc)
{
  ifstream in;
  ofstream out;

  in.open(input, ios::binary | ios::in | ios::ate);
  out.open(output, ios::binary | ios::out);
  if (!in)
	{
  	cout << "Error: missing file " << input << endl;
  	exit(1);
  }

  uint64_t length = in.tellg();
  in.seekg(0, ios::beg);
  uint64_t buffer = 0;

  uint64_t c_prev = iv;
  for (uint64_t i = 0; i < length / 8 - 1; ++i)
	{
    in.read((char *) &buffer, 8);
    uint64_t p_curr = hton64(&buffer);
    uint64_t res = des(subkeys, p_curr, enc) ^c_prev;
    uint64_t x = hton64(&res);
    out.write((char *) &x, 8);
    c_prev = p_curr;
  }

  // remove os pad
  buffer = 0;
  in.read((char *) &buffer, 8);
  uint64_t p_curr = hton64(&buffer);
  uint64_t res = des(subkeys, p_curr, enc) ^c_prev;

  int padlen = (res & 0xFF); 

  if (padlen < 8)
	{
  	res = remove_pad(res, padlen);
  	uint64_t x = hton64(&res);
  	out.write((char *) &x, 8);
	}

  in.close();
  out.close();
}

void show_usage(string name)
{
	cout << "usage: " << name << " [-ed] [-in file] [-iv IV] [-K key] [-out file]\n\n"
	     << "-e\t\tEncrypt the input data\n"
	     << "-d\t\tDecrypt the input data\n"
	     << "-in file\tInput file to read from\n"
	     << "-iv IV\t\tIV to use, specified as a hexidecimal string\n"
	     << "-K key\t\tkey to use, specified as a hexidecimal string\n"
	     << "-out file\tOutput file to write to"
	<< endl;
}

int main(int argc, const char *argv[])
{
	//  se não passar chave ou valor initial o programa gera!
	if (argc != 6 && argc != 8 && argc != 10) {
	  show_usage(argv[0]);
	  return 1;
	}

  int enc = DES_ENCRYPT; // modo de opt
  string input = "input";
  string output = "output";
  uint64_t iv = 0x0000000000000000;	// Hex valor inicial -> hex string
  uint64_t K = 0x0000000000000000; 	// Hex key -> hex string

	// ""CLI""
  bitset<8> set;
  for (int i = 1; i < argc; ++i)
	{
    string arg = argv[i];
    if (arg == "-e")
		{
			// Modo: encypt
    	set[0] = 1;
      enc = DES_ENCRYPT;
    } else if (arg == "-d")
		{
			// Modo: Decrypt
      set[0] = 1;
      enc = DES_DECRYPT;
    } else if (arg == "-in")
		{
			// Path do input
      set[1] = 1;
      input = argv[++i];
    } else if (arg == "-iv")
		{
			// Valor init
      set[2] = 1;
      string str(argv[++i]);
      if (!valid_hex_string(str, str.length()))
			{
        cerr << "Invalid hex iv" << endl;
        return 1;
      }
      iv = DES_key_iv_check(str.c_str(), 8);
    } else if (arg == "-K")
		{
			// Key
      set[3] = 1;
      string str(argv[++i]);
      if (!valid_hex_string(str, str.length()))
			{
        cerr << "Invalid hex key" << endl;
        return 1;
      }
      K = DES_key_iv_check(str.c_str(), 8);
    } else if (arg == "-out")
		{
			// nome arq de saída
      set[4] = 1;
      output = argv[++i];
    } else
		{
			// Arg invalido
      cerr << "Unknown argument: " << arg << endl;
      show_usage(argv[0]);
      return 1;
    }
  }

  if (set[0] == 0 || set[1] == 0 || set[4] == 0) {
    show_usage(argv[0]);
    return 1;
  }

  if (enc == DES_DECRYPT && (set[2] == 0 || set[3] == 0)) {
    cerr << "Key and IV are needed for decryption!" << endl;
    show_usage(argv[0]);
    return 1;
  }

	// Random gen se não enviado
  if (set[2] == 0) { // iv
    cout << "IV not provided, gen andom!" << endl;
    string s = DES_random_string(8);
    iv = DES_key_iv_check(s.c_str(), 8);
  }

	// Gera chave
  if (set[3] == 0) {
    cout << "Key not provided, gen random!" << endl;
    string s = DES_random_string(8);
    K = DES_key_iv_check(s.c_str(), 8);
  }

  print_hex_string("iv  =\t", iv);
  print_hex_string("key =\t", K);

	// 16 subchaves gen
  uint64_t subkeys[ITERATIONS] = {0};
  key_schedule(K, subkeys);

	// for (auto subkey: subkeys)
	// {
	// 	cout << subkey << endl;
	// }

  // Enc | Dec modos de opt
  if (enc == DES_ENCRYPT) {
    DES_cbc_encrypt(input, output, subkeys, iv, DES_ENCRYPT);
    cout << "Enc Out: " << output << endl;
  } 
	else
	{
    DES_cbc_decrypt(input, output, subkeys, iv, DES_DECRYPT);
    cout << "Dec Out: " << output << endl;
  }

  return 0;
}
