#include <stdint.h>
#include <stddef.h>
#include <string.h>
static const uint8_t* g_p; static size_t g_pos;
void rb_set(const uint8_t* p){ g_p=p; g_pos=0; }
void randombytes(uint8_t* out, size_t n){ memcpy(out, g_p+g_pos, n); g_pos+=n; }
