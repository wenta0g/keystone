#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "keystone/keystone.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size < 1) {
    return 0;
  }

  ks_engine *ks;
  ks_err err;
  size_t count;
  unsigned char *encode;
  size_t size;

  ks_arch arch = KS_ARCH_SYSTEMZ;
  int mode = KS_MODE_BIG_ENDIAN;

  err = ks_open(arch, mode, &ks);
  if (err != KS_ERR_OK) {
    return 0;
  }

  char *assembly = (char *)malloc(Size + 1);
  if (!assembly) {
      return 0;
  }
  memcpy(assembly, Data, Size);
  assembly[Size] = 0;

  if (ks_asm(ks, assembly, 0, &encode, &size, &count) == KS_ERR_OK) {
    ks_free(encode);
  }
  free(assembly);

  ks_close(ks);

  return 0;
}
