/* Minimal glue layer for tweetnacl.c
 *
 * Simple Erlang C bindings are verbose and repetitive. If all sanitization
 * and padding is done in Erlang, the C code should become trivial. Since
 * it's trivial, trivial macros can be used ASSUMING:
 *
 * - Arguments are names, numbers, or struct members. NO EXPRESSIONS.
 * - Resulting eyeball-seconds saving is significant, IE lots of boilerplate
 *   gone.
 *
 * Standard crypto one-letter naming conventions apply as usual.
 */
#include <fcntl.h>      /* /dev/urandom */
#include <unistd.h>     /* /dev/urandom */
#include <string.h>     /* memset */
#include <limits.h>     /* un-unit-testable integer bounding in RNG :| */
#include <erl_nif.h>    /* bindings to Erlang */
#include "tweetnacl.h"  /* lib being wrapped */


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


NIF(c_box_keypair) 
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

NIF(c_box_open) /* Erlang will add {ok, M} */
{
        R_BIN4(c, n, pk, sk);
        W_BIN(m, m_term, c.size);
        if (crypto_box_open(m, c.data, c.size, n.data, pk.data, sk.data) == 0) {
                return m_term;
        }
        return enif_make_atom(env, "failed");
}

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

void randombytes(unsigned char* data, unsigned long long len);
NIF(c_secretbox_key) 
{
        W_BIN(k, k_term, crypto_secretbox_KEYBYTES);
        randombytes(k, crypto_secretbox_KEYBYTES);
        return k_term;
}

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

NIF(c_sign_keypair)
{
        W_BIN(pk, pk_term, crypto_sign_PUBLICKEYBYTES);
        W_BIN(sk, sk_term, crypto_sign_SECRETKEYBYTES);
        crypto_sign_keypair(pk, sk);
        return enif_make_tuple2(env, pk_term, sk_term);
}

NIF(c_sign)
{
        R_BIN2(m, sk);
        W_BIN(sm, sm_term, m.size + crypto_sign_BYTES); /* so much for no expressions! */
        unsigned long long sm_size;
        crypto_sign(sm, &sm_size, m.data, m.size, sk.data);
        if (sm_size != (m.size + crypto_sign_BYTES)) {
                return enif_make_badarg(env); /* unreachable */
        }
        return sm_term;
}

NIF(c_sign_open)
{
        R_BIN2(sm, pk);
        W_BIN(m, m_term, sm.size);
        // Signed messages have the signature as a prefix. The open
        // function uses the output as a scratch buffer up to the size
        // of the input, but outputs only the message with the prefix
        // stripped.
        //
        // I'm guessing this is an API design choice to encourage clear
        // distinction of signed vs unsigned data, and single-location 
        // checking? Or just a coincidence.
        //
        // Either way, C returns crypto_sign_BYTES worth of junk at the
        // end of the retval. Strip in Erlang.
        unsigned long long m_size;
        if (crypto_sign_open(m, &m_size, sm.data, sm.size, pk.data) == 0) {
                if (m_size != (sm.size - crypto_sign_BYTES)) {
                        return enif_make_badarg(env); /* unreachable */
                }
                return m_term;
        }
        return enif_make_atom(env, "failed");
}

NIF(c_hash)
{
        R_BIN(msg, 0);
        W_BIN(h, h_term, crypto_hash_BYTES);
        crypto_hash(h, msg.data, msg.size);
        return h_term;
}

/* Erlang NIF export and code upgrades */

/* Globals: */
static int f_rand = -1; /* see randombytes() */

/* There's been extensive discussion on blocking vs non-blocking, and userland
 * vs kernel RNGs. Weighing the options, I've settled on /dev/urandom. The
 * tradeoffs are as follows:
 *
 * + Avoids binding to OpenSSL's shady API. [1] It's there, it's convenient,
 *   it's unclean and shall not be used.
 * - Windows is out. I'd like this to build on Windows just to say it does, but
 *   there's absolutely no sane real-world use case. The people running Erlang
 *   on Windows servers have bigger problems than a lack of accessible crypto.
 * + Avoids the brain teaser of elegantly handling "low entropy" blocking in a
 *   NIF inside a soft realtime VM. Aside from the fact that block-forever is a
 *   rather nasty edge case failure, blocking that far down without killing the
 *   scheduler will not fit within the code brevity goal set for this library.
 * - Low-entropy embedded devices, copied virtual machines, and similar use
 *   cases run into the seeding problem. The seeding problem is solved by
 *   writing /dev/random to /dev/urandom on boot as per the man page. This is
 *   an important step that deserves a very visible mention in the docs.
 *
 * [1] http://jbp.io/2014/01/16/openssl-rand-api
 */
void randombytes(unsigned char* data, unsigned long long len)
{
        /* Code based on nacl's devurandom.c, modified to use INT_MAX and
         * initialize file descriptor in init()
         */
        int chunk, bytes_read;
        while (len > 0) {
                chunk = (len > INT_MAX)?INT_MAX:len; /* looks right! */
                bytes_read = read(f_rand, data, chunk);
                if (bytes_read < 1) abort();
                /* Two possible causes for failed reads:
                 *
                 * 1) fd uninitialized/invalid, permanent fault
                 * 2) byzantine transient fault of some sort
                 *
                 * 1 seems far more likely than 2, so we hard fault
                 *
                 * End of file on urandom (0) also treated as fault.
                 */
                if (bytes_read < chunk) chunk = bytes_read;
                data += chunk;
                len -= chunk;
        }
}

static int load(ErlNifEnv* env, void** priv_data, ERL_NIF_TERM load_info)
{
        unsigned char rng_test[64], rng_acc = 0;
        int i;
        f_rand = open("/dev/urandom", O_RDONLY);

        if (f_rand == -1) return -1; /* Running on Windows? */

        memset(rng_test, 0, 64*sizeof(char));
        randombytes(rng_test, 64);
        for (i=0; i<64; i++) rng_acc |= rng_test[i];
        if (rng_acc == 0) return -1; /* RNG is a NOP for whatever reason */

        return 0;
}

static void unload(ErlNifEnv* env, void* priv_data)
{
        close(f_rand); /* any errors ignored */
}

static int upgrade(ErlNifEnv* env, void** priv, void** old_priv,
                                         ERL_NIF_TERM load_info)
{
        return 0; /* Return success so VM allows hot code reloads.
                     C library currently keeps no state, aside from urandom
                     fd which can be re-used.
                     */
}

#define BIND(name,arity) {#name,arity,name}
static ErlNifFunc nif_funcs[] = {
        /* Public-key authenticated encryption */
        BIND(c_box_keypair, 0), /* keygen */
        BIND(c_box, 4), BIND(c_box_open, 4), /* decr/encr */
        BIND(c_box_beforenm, 2),  /* precomputation */
        BIND(c_box_afternm, 3), BIND(c_box_open_afternm, 3), /* symmetric */
        /* Secret-key authenticated encryption */
        BIND(c_secretbox_key, 0), 
        BIND(c_secretbox, 3), BIND(c_secretbox_open, 3),
        /* Signatures */
        BIND(c_sign_keypair, 0),
        BIND(c_sign, 2), BIND(c_sign_open, 2),
        /* Low level functions */
        BIND(c_hash, 1),
};

/* NIF lifecycle functions get used for initializing singletons. */
ERL_NIF_INIT(tweetnacl, nif_funcs, load, NULL, upgrade, unload);
