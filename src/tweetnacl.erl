%%% Catch-all wrapper for crypto_* NaCl functions.
%%%
%%% Will probably get split up and specialized a bit once a nice API is figured
%%% out. The deicision isn't being hurried because a sane, safe, hard to
%%% misuse, easy to understand, easy to learn, well documented, low-noise API
%%% is a major project goal.
-module(tweetnacl).
-export(
    % Secret-key cryptography
    [ secretbox/3, secretbox_open/3, secretbox_key/0
    % Low-level functions
    , verify_16/2, verify_32/2, hash/1
    ]).
-on_load(init/0).
-include("include/tweetnacl.hrl").

-define(SYM_KEY, tweetnacl_symmetric_key).

secretbox(_, N, _) when is_binary(N), size(N) /= ?secretbox_NONCEBYTES -> 
    {wrong_nonce_size, size(N), ?secretbox_NONCEBYTES};
secretbox(M, <<N:?secretbox_NONCEBYTES/binary>>, {?SYM_KEY, K}) when 
        is_binary(N), size(K) == ?secretbox_KEYBYTES ->
    PadM = 8*?secretbox_ZEROBYTES,
    PadC = 8*?secretbox_BOXZEROBYTES,
    <<0:PadC, C/binary>> = c_secretbox(<<0:PadM, M/binary>>, N, K),
    {ok, C}.
% where
    c_secretbox(_, _, _) -> nif().

secretbox_open(C, <<N:?secretbox_NONCEBYTES/binary>>, {?SYM_KEY, K}) when 
        is_binary(N), size(K) == ?secretbox_KEYBYTES -> 
    PadM = 8*?secretbox_ZEROBYTES,
    PadC = 8*?secretbox_BOXZEROBYTES,
    case c_secretbox_open(<<0:PadC, C/binary>>, N, K) of
        failed -> auth_failed;
        <<0:PadM, M/binary>> -> {ok, M}
    end.
% where
    c_secretbox_open(_, _, _) -> nif().

secretbox_key() -> {?SYM_KEY, crypto:strong_rand_bytes(?secretbox_KEYBYTES)}.

verify_32(<<A:32/binary>>, <<B:32/binary>>) -> 
    case c_verify_32(A, B) of
        0 -> true;
       -1 -> false
    end.
% where
    c_verify_32(_, _) -> nif().

verify_16(A, B) -> 
    case c_verify_16(A, B) of
        0 -> true;
       -1 -> false
    end.
% where
    c_verify_16(_, _) -> nif().

hash(Msg) when is_binary(Msg) -> c_hash(Msg).
% where
    c_hash(_) -> nif().

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

