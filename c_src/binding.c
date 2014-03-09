#include <openssl/rand.h> /* current RNG source, ehhh this or urandom? */
#include <limits.h>     /* un-unit-testable integer bounding in RNG, ehhh :| */
#include "erl_nif.h"    /* bindings to Erlang */
#include "tweetnacl.h"  /* lib being wrapped */

/* Simple Erlang C bindings are verbose and repetitive. If all sanitization
 * and padding is done in Erlang, the C code should become trivial. Since
 * it's trivial, trivial macros can be used ASSUMING:
 *
 * - Arguments are names, numbers, or struct members. NO EXPRESSIONS.
 * - Resulting eyeball-seconds saving is significant, IE lots of boilerplate
 *   gone.
 */

/* All NIFs look like this. */
#define NIF(name) static ERL_NIF_TERM name(ErlNifEnv* env, \
                                                 int argc, \
                                                 const ERL_NIF_TERM argv[])
/* Generic binary input, PRE-SANITIZED and padded on Erlang side. */
#define R_BIN(name, index) \
        ErlNifBinary name; \
        enif_inspect_binary(env, argv[index], &name)
#define R_BIN2(n0, n1)         R_BIN(n0, 0); R_BIN(n1, 1);
#define R_BIN3(n0, n1, n2)     R_BIN(n0, 0); R_BIN(n1, 1); R_BIN(n2, 2);
#define R_BIN4(n0, n1, n2, n3) R_BIN(n0, 0); R_BIN(n1, 1); R_BIN(n2, 2); \
                                       R_BIN(n3, 3); 
/* Generic happy-case binary output. {ok, Result} tag added on Erlang side. */
#define W_BIN(buf_name, term_name, size) \
        ERL_NIF_TERM term_name; \
        unsigned char* buf_name; \
        buf_name = enif_make_new_binary(env, size, &term_name)
/* NOTE: make_new_binary -should- turn read-only on any return (even if it's */
/* not returned directly) so no release should be necessary in error cases. */


/* Common crypto one-letter conventions for message/ciphertext apply. */

/* Simple pubkey */

NIF(c_box_keypair) /* XXX thread safety on RNG */
{
        W_BIN(pk, pk_term, crypto_box_PUBLICKEYBYTES);
        W_BIN(sk, sk_term, crypto_box_SECRETKEYBYTES);
        crypto_box_keypair(pk, sk);
        return enif_make_tuple2(env, pk_term, sk_term);
}

NIF(c_box) 
{
        R_BIN4(m, n, pk, sk);
        W_BIN(c, c_term, m.size);
        crypto_box(c, m.data, m.size, n.data, pk.data, sk.data);
        return c_term;
}

NIF(c_box_open) 
{
        R_BIN4(c, n, pk, sk);
        W_BIN(m, m_term, c.size);
        if (crypto_box_open(m, c.data, c.size, n.data, pk.data, sk.data) == 0) {
                return m_term;
        }
        return enif_make_atom(env, "failed");
}

/* Pubkey with symmetric portion split out */

NIF(c_box_beforenm)
{
        R_BIN2(pk, sk);
        W_BIN(k, k_term, crypto_box_BEFORENMBYTES);
        crypto_box_beforenm(k, pk.data, sk.data);
        return k_term;
}

NIF(c_box_afternm) 
{
        R_BIN3(m, n, k);
        W_BIN(c, c_term, m.size);
        crypto_box_afternm(c, m.data, m.size, n.data, k.data);
        return c_term;
}

NIF(c_box_open_afternm) 
{
        R_BIN3(c, n, k);
        W_BIN(m, m_term, c.size);
        if (crypto_box_open_afternm(m, c.data, c.size, n.data, k.data) == 0) {
                return m_term;
        }
        return enif_make_atom(env, "failed");
}

/* Symmetric */

NIF(c_secretbox)
{
        R_BIN3(m, n, k);
        W_BIN(c, c_term, m.size);
        crypto_secretbox(c, m.data, m.size, n.data, k.data);
        return c_term;
}

NIF(c_secretbox_open) /* Erlang will add {ok, M} */
{
        R_BIN3(c, n, k);
        W_BIN(m, m_term, c.size);
        if (crypto_secretbox_open(m, c.data, c.size, n.data, k.data) == 0) {
                return m_term;
        }
        return enif_make_atom(env, "failed");
}

/* Hashing and comparisons */

NIF(c_verify_16) /* Erlang return code conventions differ greatly from C */
{
        R_BIN2(x, y);
        return enif_make_int(env, crypto_verify_16(x.data, y.data));
}

NIF(c_verify_32)
{
        R_BIN2(x, y);
        return enif_make_int(env, crypto_verify_32(x.data, y.data));
}

NIF(c_hash)
{
        R_BIN(msg, 0);
        W_BIN(h, h_term, crypto_hash_BYTES);
        crypto_hash(h, msg.data, msg.size);
        return h_term;
}

/* Erlang NIF export and code upgrades */

#define BIND(name,arity) {#name,arity,name}
static ErlNifFunc nif_funcs[] = {
        /* Public-key cryptography */
        BIND(c_box_keypair, 0), /* keygen */
        BIND(c_box, 4), BIND(c_box_open, 4), /* decr/encr */
        BIND(c_box_beforenm, 2),  /* precomputation */
        BIND(c_box_afternm, 3), BIND(c_box_open_afternm, 3), /* symmetric */
        /* Secret-key cryptography */
        BIND(c_secretbox, 3), BIND(c_secretbox_open, 3),
        /* Low level functions */
        BIND(c_hash, 1), BIND(c_verify_16, 2), BIND(c_verify_32, 2),
};


static int upgrade(ErlNifEnv* env, void** priv, void** old_priv,
                                         ERL_NIF_TERM load_info)
{
        return 0; /* Return success so VM allows hot code reloads.
                     C library currently keeps no state, so what could
                     go wrong. Need to look at this again if opaque keys
                     are added. (Also once I settle on an RNG.)
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
