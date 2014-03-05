#include <string.h> 
#include <limits.h>
#include <openssl/rand.h>
#include "erl_nif.h"
#include "tweetnacl.h"

#define NIF(name) static ERL_NIF_TERM name(ErlNifEnv* env, \
                                                 int argc, \
                                                 const ERL_NIF_TERM argv[])
#define R_BIN(name, index) \
        ErlNifBinary name; \
        enif_inspect_binary(env, argv[index], &name);
#define W_BIN(buf_name, term_name, size) \
        ERL_NIF_TERM term_name; \
        unsigned char* buf_name; \
        buf_name = enif_make_new_binary(env, size, &term_name);
// NOTE: make_new_binary -should- turn read-only on any return (even if it's
// not returned directly) so no release should be necessary in error cases.

NIF(c_secretbox)
{
        R_BIN(m, 0); R_BIN(n, 1); R_BIN(k, 2);
        W_BIN(out, c, m.size);
        crypto_secretbox(out, m.data, m.size, n.data, k.data);
        return c;
}

NIF(c_secretbox_open)
{
        R_BIN(c, 0); R_BIN(n, 1); R_BIN(k, 2);
        W_BIN(out, m, c.size);
        if (crypto_secretbox_open(out, c.data, c.size, n.data, k.data) == 0) {
                return m;
        }
        return enif_make_atom(env, "failed");
}

NIF(c_verify_16)
{
        R_BIN(x, 0) R_BIN(y, 1)
        return enif_make_int(env, crypto_verify_16(x.data, y.data));
}

NIF(c_verify_32)
{
        R_BIN(x, 0) R_BIN(y, 1)
        return enif_make_int(env, crypto_verify_32(x.data, y.data));
}

NIF(c_hash)
{
        R_BIN(msg, 0)
        W_BIN(out, hash, crypto_hash_BYTES);
        crypto_hash(out, msg.data, msg.size);
        return hash;
}


#define BIND(name,arity) {#name,arity,name}
static ErlNifFunc nif_funcs[] = {
        /* Secret-key cryptography */
        BIND(c_secretbox, 3),
        BIND(c_secretbox_open, 3),
        /* Low level functions */
        BIND(c_hash, 1),
        BIND(c_verify_16, 2),
        BIND(c_verify_32, 2),
};


static int upgrade(ErlNifEnv* env, void** priv, void** old_priv,
                                         ERL_NIF_TERM load_info)
{
        return 0; /* Return success so VM allows hot code reloads.
                     C library currently keeps no state, so what could
                     go wrong. Need to look at this again if opaque keys
                     are added.
                     */
}


/* Adhering to the NaCl coding advice at http://nacl.cr.yp.to/internals.html
 * just so happens to produce pure functions that are reentrant. As such,
 * hot code reloads should "just work". We just need to inform the BEAM VM of
 * that.
 */
ERL_NIF_INIT(tweetnacl, nif_funcs,
        NULL,   /* load: no global state */
        NULL,   /* reload: one more deprecated experiment that turned
                           out to be a bad idea, added to the legacy support
                           pile :) */
        upgrade,/* upgrade: must return success, or reload canceled */
        NULL);  /* unload: no global state */




/* Problem: how to neatly handle low entropy?
 *
 * Blocking sucks, but there's no mechanism for asserting failures in tweetnacl's 
 * C code short of faulting the entire node. And that's an Erlang no-no.
 * Blocking sucks extra-hard due to NIF interaction with the scheduler. Producing
 * an exception is probably best... But is a nasty surprise when switching 
 * architectures and traffic patterns.
 *
 * Ideal would be a user configured slider: 
 *  - On one side, high key churn + short term keys + high entropy systems.
 *  - On the other side, rare key generation + long term keys + low entropy VMs.
 *
 *  Switch between /dev/urandom and /dev/random then. OpenSSL's RAND_pseudo_bytes 
 *  may be more cross-platform... Although who's really going to run this on
 *  Windows?
 *
 *  Pass it as a parameter to app startup? Then it's a node-global config setting?
 *  Really, /dev/urandom is good enough outside edge cases like VMs generating
 *  LTS/signing keys. Which... Probably describes your average VPS running the
 *  latest dogecoin service. Hrm.
 *
 *
 *  Slept on it. 
 *
 *  Tweetnacl should to be a pervasive encryption library. You use it on
 *  everything, because you can. It should encourage short term keys, backed by
 *  lots of medium term keys... RNG blocking is for the edge case of
 *  low-entropy device trying to generate a long term key right after startup.
 *
 *  This is a reasonable edge case, but given the awkwardness of shoehorning a
 *  blocking keygen option for longterm keys on low entropy devices into the
 *  existing API it's getting dropped. Non-blocking RNGs ftw.
 *
 *
 *  Of course, this is further complicated by OpenSSL's RAND_bytes being a bit of a clusterfuck. In practice, theoretical discussions of what an ideal CSPRNG looks like, there's this:
 *
 *  http://jbp.io/2014/01/16/openssl-rand-api/
 *
 *  I'm gonna need to sleep on it some more.
 */
void randombytes(unsigned char* data, unsigned long long len)
{
        do {
                /* http://www.openssl.org/docs/crypto/RAND_bytes.html */
                int chunk = (len > INT_MAX)?INT_MAX:len;
                if (RAND_bytes(data, chunk) != 1) {
                        /* This is very, very, very un-Erlang. */
                        abort();
                }
                len -= chunk;
                data += chunk;
        } while (len > INT_MAX);
}
