Tweetnacl is a research project to improve the state of Erlang crypto.

API and codebase in flux while in v0.0.X, wear helmet while using.


# Design Considerations

Straight NaCl (well, libsodium) bindings would be useful but let's explore the design space for a moment.

## Failures Modes Addressed

Fail crypto is everywhere. Classes of failures, in order of increasing difficulty to exploit and avoid, are:

1. No encryption. (Too hard/no libraries.)
2. Broken by eavesdropping. (Nonce reuse/hardcoded keys/bruteforceable keys.)
3. Broken versus interaction. (No authentication/oracles/replay.)
4. Broken versus MITM. (Auth followed by plaintext session/no certificate pinning.)
5. Broken versus machine compromise. (Key theft/backdoors.)

There's also some stuff that's hard to place.

6. Broken code no one ever looks at.
7. Maintaining security during organic scope and feature growth.

This library tries to do a couple of things to tackle the above problems:

1. Try to avoid 1 2 and 3 by being as high level as possible. No confusing cipher options or moving parts. Move the primitives up a few levels.
2. Try to avoid 4 and 6 by reducing the cost of implementing key management. Specifically, try to provide a simple API for verifying short term keys.
3. Try to at least maintain confidentiality of old data during 5 by encouraging the generation of short term keys at an API level.

7 is an open problem.

## Failure Modes Not Addressed

I can try to avoid swapping-to-disk and properly erasing keys from RAM by writing a bunch of C, but that will bloat size. I want a tiny library. Key remanence is important for dealing with 5, but let's tackle 1-3 first.

This means keys being passed as Erlang binaries. Which means they'll be getting logged in crash messages, sent to log servers, and saved in crash dumps. 

## Alternative NaCl/libsodium Bindings

Comparing this binding to other projects, the major difference is binding to
tweetnacl rather than libsodium/original NaCl. Other implementation
differences:

- https://github.com/tonyg/erlang-nacl
    - Doesn't have all interesting primitives. I want symmetric + private.
- https://github.com/freza/salt
    - This one has very clean-looking code. Matches my original approach of
      by-the-book C, but finishes the job and publishes it first :)
    - As with tweetnacl vs libsodium, difference is in weight. I'll see how
      close I come to 1.4K lines of C depending on features and many macros I
      can justify using.

Don't think anyone's using PropEr tests, but given the domain that hardly
matters :)

Oh yes. The original goal was also to look at applying Erlang API design to the
problem of developer meets crypto code. This implementation may get creative
with failure modes and naming schemes. (One man project, so no bike shedding.)
