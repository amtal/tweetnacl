%%% Foolproof wrapper around (tweet)NaCl.
%%%
%%% - Trivial to add, without making mistakes or compromising on security.
%%% - Tiny codebase, to ease verification despite API changes.
%%% - Aimed for mass use with minimal misuse.
%%%
%%% Module is currently a catch-all wrapper for crypto_* NaCl functions.
%%%
%%% Will probably get split up and specialized a bit once a nice API is figured
%%% out. The decision isn't being hurried because a sane, safe, hard to
%%% misuse, easy to understand, easy to learn, well documented, low-noise API
%%% is a major project goal.
-module(tweetnacl).
-export(
    % Public-key cryptography
    [ box_keypair/0, box/4, box_open/4
    , box_beforenm/2, box_afternm/3, box_open_afternm/3
    % Secret-key cryptography
    , secretbox/3, secretbox_open/3, secretbox_key/0
    % Low-level functions
    , verify_16/2, verify_32/2, hash/1
    ]).
-on_load(init/0).
-include("include/tweetnacl.hrl").

-define(SYM_KEY, tweetnacl_symmetric_key).
-define(NM_KEY, tweetnacl_nm_key).

%% I don't think there's a way to foolproof this for people that don't
%% understand public/private keys. They'll put the wrong ones in, then wonder
%% why all messages get rejected. Put in some diagrams, hope that's enough?
%% 
%% Alternatively, could try using Remote/Local language. Or Self/Peer. Or
%% Self/Them.
%%
%% Going directly to application code, the language of MyId/PeerId/MySecret
%% may be easier to grok.

%% Generate a public + private keypair.
%% XXX opaque keys?
box_keypair() ->
    {Pub, Priv} = c_box_keypair(),
    {ok, {public, Pub}, {secret, Priv}}.
% where
    c_box_keypair() -> nif().

%% Wrap message in a box for PubKey, signed by SecKey.
box(<<M/binary>>, <<N:?box_NONCEBYTES/binary>>, PubKey, SecKey) ->
    {ok, unpad_c(c_box(pad_m(M), N, pubkey(PubKey), seckey(SecKey)))};
box(M, N, PK, SK) -> box_help(M, N, PK, SK).

%% Unwrap a box with SecKey, checking that it's from PubKey.
box_open(<<C/binary>>, <<N:?box_NONCEBYTES/binary>>, PubKey, SecKey) ->
    case c_box_open(pad_c(C), N, pubkey(PubKey), seckey(SecKey)) of
        failed -> failed;
        M -> {ok, unpad_m(M)}
    end;
box_open(C, N, PK, SK) -> box_help(C, N, PK, SK).

%% 
box_beforenm(PubKey, SecKey) ->
    {?NM_KEY, c_box_beforenm(pubkey(PubKey), seckey(SecKey))}.

box_afternm(<<M/binary>>, <<N:?box_NONCEBYTES/binary>>,
                {?NM_KEY, <<K:?box_BEFORENMBYTES/binary>>}) ->
    {ok, unpad_c(c_box_afternm(pad_m(M), N, K))};
box_afternm(M, N, _) -> box_help(M, N, unk, unk).

box_open_afternm(<<C/binary>>, <<N:?box_NONCEBYTES/binary>>,
                 {?NM_KEY, <<K:?box_BEFORENMBYTES/binary>>}) ->
    case c_box_open_afternm(pad_c(C), N, K) of
        failed -> failed;
        M -> {ok, unpad_m(M)}
    end;
box_open_afternm(C, N, _) -> box_help(C, N, unk, unk).
% where
    %% usability errors
    box_help(_, <<N/binary>>, _, _) when size(N) /= ?box_NONCEBYTES -> 
        {error, {nonce_size_not, ?box_NONCEBYTES}};
    box_help(M, N, _, _) when not is_binary(M); is_binary(N) ->
        inputs_must_be_binary.
    %% padding helpers; long way to go to avoid hardcoding sizes
    pad_c(C) -> <<0:?box_BOXZEROBYTES/unit:8, C/binary>>.
    unpad_c(<<0:?box_BOXZEROBYTES/unit:8, C/binary>>) -> C.
    pad_m(M) -> <<0:?box_ZEROBYTES/unit:8, M/binary>>.
    unpad_m(<<0:?box_ZEROBYTES/unit:8, M/binary>>) -> M.
    %% NIFs
    c_box(_, _, _, _) -> nif().
    c_box_open(_, _, _, _) -> nif().
    c_box_beforenm(_, _) -> nif().
    c_box_afternm(_, _, _) -> nif().
    c_box_open_afternm(_, _, _) -> nif().
    %% XXX wrap keys in opaque ref that isn't visible in crash dumps
    pubkey({public, <<K:?box_PUBLICKEYBYTES/binary>>}) -> K;
    pubkey(Bad) -> error(invalid_key, [Bad]).
    seckey({secret, <<K:?box_SECRETKEYBYTES/binary>>}) -> K;
    seckey(Bad) -> error(invalid_key, [Bad]).


secretbox(<<M/binary>>, <<N:?secretbox_NONCEBYTES/binary>>, K) ->
    <<0:?secretbox_BOXZEROBYTES/unit:8, C/binary>> = 
        c_secretbox(<<0:?secretbox_ZEROBYTES/unit:8, M/binary>>, N, key(K)),
    {ok, C};
secretbox(M, N, K) -> secretbox_help(M, N, K).
secretbox_open(<<C/binary>>, <<N:?secretbox_NONCEBYTES/binary>>, K) ->
    case c_secretbox_open(<<0:?secretbox_BOXZEROBYTES/unit:8, C/binary>>, N,
                          key(K)) of
        failed -> failed;
        <<0:?secretbox_ZEROBYTES/unit:8, M/binary>> -> {ok, M}
    end;
secretbox_open(C, N, K) -> secretbox_help(C, N, K).
% where
    secretbox_help(_, <<N/binary>>, _) when size(N) /= ?secretbox_NONCEBYTES -> 
        {error, {nonce_size_not, ?secretbox_NONCEBYTES}};
    secretbox_help(M, N, _) when not is_binary(M); not is_binary(N) ->
        inputs_must_be_binary.
    c_secretbox(_, _, _) -> nif().
    c_secretbox_open(_, _, _) -> nif().
    %% XXX wrap keys in opaque ref that isn't visible in crash dumps
    key({?SYM_KEY, <<K:?secretbox_KEYBYTES/binary>>}) -> K;
    key(Bad) -> error(invalid_key, [Bad]).


%% XXX bind dev/urandom with note on seeding in VMs/embedded? Can I build on 
%% Windows with OpenSSL+rebar, is it worth keeping just for that?
secretbox_key() -> {?SYM_KEY, crypto:strong_rand_bytes(?secretbox_KEYBYTES)}.


verify_32(<<A:32/binary>>, <<B:32/binary>>) -> is_good(c_verify_32(A, B)).
verify_16(<<A:16/binary>>, <<B:16/binary>>) -> is_good(c_verify_16(A, B)).
% where
    is_good(0) -> true;
    is_good(-1) -> false.
    c_verify_32(_, _) -> nif().
    c_verify_16(_, _) -> nif().

hash(<<M/binary>>) -> c_hash(M).
% where
    c_hash(_) -> nif().

%%%
%%% NIF Setup
%%%

%% Fail if not overridden by a NIF. Allows a fallback to pure-Erlang
%% implementations, but since this is a C binding that won't happen.
nif() -> exit({nif_not_loaded, ?MODULE}).

-define(APPNAME, tweetnacl). % name of .app file
-define(LIBNAME, tweetnacl). % library, so_name in rebar.config

%% Module initialization.
%%
%% Called by -on_load attribute, should always load the NIF which will override
%% most of our exported functions with C implementations.
init() ->
    SoName = case code:priv_dir(?APPNAME) of
        {error, bad_name} ->
            case filelib:is_dir(filename:join(["..", priv])) of
                true ->
                    filename:join(["..", priv, ?LIBNAME]);
                _ ->
                    filename:join([priv, ?LIBNAME])
            end;
        Dir ->
            filename:join(Dir, ?LIBNAME)
    end,
    erlang:load_nif(SoName, 0).

