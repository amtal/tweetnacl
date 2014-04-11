/* Can't tell if this is dumb or brilliant. */
#include "tweetnacl.h"
extern void f(const char* def_name, const int def_val);
#define m(a) f(#a,a)
void scrape() {
m(crypto_box_NONCEBYTES);
m(crypto_box_ZEROBYTES);
m(crypto_box_BOXZEROBYTES);
m(crypto_box_PUBLICKEYBYTES);
m(crypto_box_SECRETKEYBYTES);
m(crypto_box_BEFORENMBYTES);
m(crypto_sign_BYTES);
m(crypto_sign_SECRETKEYBYTES);
m(crypto_sign_PUBLICKEYBYTES);
m(crypto_secretbox_NONCEBYTES);
m(crypto_secretbox_KEYBYTES);
m(crypto_secretbox_ZEROBYTES);
m(crypto_secretbox_BOXZEROBYTES);
m(crypto_hash_BYTES);
}
