%%% Interface with Erlang types+conventions around tweetnacl C API.
%%%
%%% All inputs are binaries, flatten iolists beforehand.
%%%
%%% Typical one-letter naming conventions at play:
%%%
%%% - plaintext (M)essages
%%% - encrypted+authenticated (C)iphertexts
%%% - secret (K)eys
%%% - a (N)once is a "number used once" and only once for a given key
%%%
%%% Note that nonces MUST NOT repeat for a given key. This includes different
%%% directions (receive and transmit should have distinct nonces) or sessions
%%% that re-use the same key.
%%%
%%% Random numbers sourced from /dev/urandom - if your system has low entropy
%%% on boot (cloned VM, embedded) seed /dev/urandom from /dev/random during
%%% provisioning then propagate a seed through reboots. See /dev/urandom
%%% manpage for instructions.
-module(tweetnacl).
-export(
    % Public-key authenticated encryption
    [ box_keypair/0, box/4, box_open/4
    , box_beforenm/2, box_afternm/3, box_open_afternm/3
    % Public-key signatures
    , sign_keypair/0, sign/2, sign_open/2
    % Symmetric-key authenticated encryption
    , secretbox/3, secretbox_open/3, secretbox_key/0
    % Hash functions
    , hash/1
    ]).
-on_load(init_nif/0).
-include("include/tweetnacl.hrl").

%%%
%%% Simple asymmetric authenticated encryption.
%%%

box_keypair() ->
    {Public, Secret} = c_box_keypair(),
    {Public, {'$box_key', Secret}}.

box(M, N, PeerPub, OwnSec) ->
    unpad_c(c_box(pad_m(M), nonce(N), pubkey(PeerPub), seckey(OwnSec))).

box_open(C, N, PeerPub, OwnSec) ->
    case c_box_open(pad_c(C), nonce(N), pubkey(PeerPub), seckey(OwnSec)) of
        failed -> failed;
        M -> {ok, unpad_m(M)}
    end.

%%%
%%% Optimized asymmetric with message-agnostic precomputation split into
%%% *_beforenm/2, and message-specific processing into *_afternm/3.
%%%

box_beforenm(PeerPub, OwnSec) ->
    {'$nm_symmetric_key', c_box_beforenm(pubkey(PeerPub), seckey(OwnSec))}.

box_afternm(<<M/binary>>, N, SharedSec) ->
    unpad_c(c_box_afternm(pad_m(M), nonce(N), nm_sym_key(SharedSec))).

box_open_afternm(<<C/binary>>, N, SharedSec) ->
    case c_box_open_afternm(pad_c(C), nonce(N), nm_sym_key(SharedSec)) of
        failed -> failed;
        M -> {ok, unpad_m(M)}
    end.
% where
    %% sanitizers
    nonce(<<N:?box_NONCEBYTES/binary>>) -> N;
    nonce(<<N/binary>>) -> 
        % Usability convention: detailed warnings for wrong user-provided sizes,
        % but laconic Erlang warnings for square-peg-in-round-slot mixups. Detailed
        % errors are good, but not too detailed.
        error({nonce_size_not, ?box_NONCEBYTES}, N).
    pubkey(<<K:?box_PUBLICKEYBYTES/binary>>) -> K.
    seckey({'$box_key', <<K:?box_SECRETKEYBYTES/binary>>}) -> K.
    nm_sym_key({'$nm_symmetric_key', <<K:?box_BEFORENMBYTES/binary>>}) -> K.
    %% padding
    pad_c(<<C/binary>>) -> <<0:?box_BOXZEROBYTES/unit:8, C/binary>>.
    unpad_c(<<0:?box_BOXZEROBYTES/unit:8, C/binary>>) -> C.
    pad_m(<<M/binary>>) -> <<0:?box_ZEROBYTES/unit:8, M/binary>>.
    unpad_m(<<0:?box_ZEROBYTES/unit:8, M/binary>>) -> M.
    %% NIFs
    c_box_keypair() -> nif().
    c_box(_, _, _, _) -> nif().
    c_box_open(_, _, _, _) -> nif().
    c_box_beforenm(_, _) -> nif().
    c_box_afternm(_, _, _) -> nif().
    c_box_open_afternm(_, _, _) -> nif().

%%% 
%%% Public key signatures
%%%

sign_keypair() ->
    {Public, Secret} = c_sign_keypair(),
    {Public, {'$signing_key', Secret}}.

sign(<<M/binary>>, Secret) ->
    c_sign(M, sign_seckey(Secret)).

sign_open(<<SignedM/binary>>, Public) ->
    case c_sign_open(SignedM, sign_pubkey(Public)) of
        failed -> failed;
        <<M/binary>> -> {ok, M}
    end.
% where
    sign_seckey({'$signing_key', <<K:?sign_SECRETKEYBYTES/binary>>}) -> K.
    sign_pubkey(<<K:?sign_PUBLICKEYBYTES/binary>>) -> K.
    c_sign_keypair() -> nif().
    c_sign(_, _) -> nif().
    c_sign_open(_, _) -> nif().

%%% 
%%% Symmetric authenticated encryption
%%%

secretbox_key() -> {'$symmetric_key', c_secretbox_key()}. % /dev/urandom wrapper

secretbox(<<M/binary>>, N, K) -> 
    sym_unpad_c(c_secretbox(sym_pad_m(M), sym_nonce(N), key(K))).

secretbox_open(<<C/binary>>, N, K) ->
    case c_secretbox_open(sym_pad_c(C), sym_nonce(N), key(K)) of
        failed -> failed;
        <<0:?secretbox_ZEROBYTES/unit:8, M/binary>> -> {ok, M}
    end.
% where
    %% sanitizers
    sym_nonce(<<N:?secretbox_NONCEBYTES/binary>>) -> N;
    sym_nonce(<<N/binary>>) -> error({nonce_size_not, ?secretbox_NONCEBYTES}, N).
    key({'$symmetric_key', <<K:?secretbox_KEYBYTES/binary>>}) -> K;
    key(Bad) -> error(invalid_key, [Bad]).
    %% padding
    sym_pad_m(M) -> <<0:?secretbox_ZEROBYTES/unit:8, M/binary>>.
    sym_unpad_c(<<0:?secretbox_BOXZEROBYTES/unit:8, C/binary>>) -> C.
    sym_pad_c(C) -> <<0:?secretbox_BOXZEROBYTES/unit:8, C/binary>>.
    %% nifs
    c_secretbox_key() -> nif().
    c_secretbox(_, _, _) -> nif().
    c_secretbox_open(_, _, _) -> nif().

%% SHA-512, for key identifiers and whatnot.
hash(<<Bin/binary>>) -> c_hash(Bin).
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

%% Called by -on_load attribute, should always load the NIF which will override
%% most of our exported functions with C implementations.
init_nif() ->
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

