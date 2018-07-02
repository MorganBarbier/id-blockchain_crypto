#include "id_blockchain_crypto_tools.h"

void print_string_hex(const unsigned char *msg, size_t len)
{
  int i;
  for(i = 0; i < len; i++)
    {
      printf("%02x ", msg[i]);
    }
  printf("\n");
}

