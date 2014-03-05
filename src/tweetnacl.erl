%%% Catch-all wrapper for crypto_* NaCl functions.
%%%
%%% Will probably get split up and specialized a bit once a nice API is figured
%%% out. The deicision isn't being hurried because a sane, safe, hard to
%%% misuse, easy to understand, easy to learn, well documented, low-noise API
%%% is a major project goal.
-module(tweetnacl).
-export(
    % Public-key cryptography
    [ box_keypair/0, box/4, box_open/4
    % Secret-key cryptography
    , secretbox/3, secretbox_open/3, secretbox_key/0
    % Low-level functions
    , verify_16/2, verify_32/2, hash/1
    ]).
-on_load(init/0).
-include("include/tweetnacl.hrl").

-define(SYM_KEY, tweetnacl_symmetric_key).


%% XXX opaque keys?
box_keypair() ->
    {Pub, Priv} = c_box_keypair(),
    {ok, {public, Pub}, {secret, Priv}}.
% where
    c_box_keypair() -> nif().

box(<<M/binary>>, <<N:?box_NONCEBYTES/binary>>, PubKey, SecKey) ->
    MPad = 8*?box_ZEROBYTES,
    CPad = 8*?box_BOXZEROBYTES,
    <<0:CPad, C/binary>> = c_box(<<0:MPad, M/binary>>, N, pubkey(PubKey),
                                                          seckey(SecKey)),
    {ok, C};
box(M, N, PK, SK) -> box_help(M, N, PK, SK).
box_open(<<M/binary>>, <<N:?box_NONCEBYTES/binary>>, PubKey, SecKey) ->
    MPad = 8*?box_ZEROBYTES,
    CPad = 8*?box_BOXZEROBYTES,
    <<0:MPad, C/binary>> = c_box_open(<<0:CPad, M/binary>>, N, pubkey(PubKey), 
                                                               seckey(SecKey)),
    {ok, C};
box_open(C, N, PK, SK) -> box_help(C, N, PK, SK).
% where
    box_help(_, <<N/binary>>, _, _) when size(N) /= ?box_NONCEBYTES -> 
        {error, {nonce_size_not, ?box_NONCEBYTES}};
    box_help(M, N, _, _) when not is_binary(M); is_binary(N) ->
        inputs_must_be_binary.
    c_box(_, _, _, _) -> nif().
    c_box_open(_, _, _, _) -> nif().
    %% XXX wrap keys in opaque ref that isn't visible in crash dumps
    pubkey({public, <<K:?box_PUBLICKEYBYTES/binary>>}) -> K;
    pubkey(Bad) -> error(invalid_key, [Bad]).
    seckey({secret, <<K:?box_SECRETKEYBYTES/binary>>}) -> K;
    seckey(Bad) -> error(invalid_key, [Bad]).


secretbox(<<M/binary>>, <<N:?secretbox_NONCEBYTES/binary>>, K) ->
    MPad = 8*?secretbox_ZEROBYTES,
    CPad = 8*?secretbox_BOXZEROBYTES,
    <<0:CPad, C/binary>> = c_secretbox(<<0:MPad, M/binary>>, N, key(K)),
    {ok, C};
secretbox(M, N, K) -> secretbox_help(M, N, K).
secretbox_open(<<C/binary>>, <<N:?secretbox_NONCEBYTES/binary>>, K) ->
    MPad = 8*?secretbox_ZEROBYTES,
    CPad = 8*?secretbox_BOXZEROBYTES,
    case c_secretbox_open(<<0:CPad, C/binary>>, N, key(K)) of
        failed -> auth_failed;
        <<0:MPad, M/binary>> -> {ok, M}
    end;
secretbox_open(C, N, K) -> secretbox_help(C, N, K).
% where
    secretbox_help(_, <<N/binary>>, _) when size(N) /= ?secretbox_NONCEBYTES -> 
        {error, {nonce_size_not, ?secretbox_NONCEBYTES}};
    secretbox_help(M, N, _) when not is_binary(M); is_binary(N) ->
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

