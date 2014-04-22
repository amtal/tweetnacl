%%% Nonce generation schemes usable with NaCl.
%%%
%%% All abstract away the nonce into an opaque piece of state to thread through
%%% the connection, making different tradeoffs in the process.
-module(example_nonces).
-export([rand_new/2, rand_box/2, rand_box_open/2]).
-export([counter_new/3, counter_box/2, counter_box_open/2]).
-export([timeout_new/3, timeout_box/2, timeout_box_open/2]).
-include("tweetnacl.hrl").


%% Large random simplest, but must be transmitted alongside ciphertext.
%%
%% The fact that they're unpredictable may be a requirement for some
%% cryptographic primitives, but not those in NaCl.
rand_new(PubKey, SecKey) -> 
    {rand, tweetnacl:box_beforenm(PubKey, SecKey)}.

rand_box(M, {rand, SessKey}) ->
    N = crypto:rand_bytes(?box_NONCEBYTES),
    C = tweetnacl:box_afternm(M, N, SessKey),
    <<N, C>>.

rand_box_open(<<N:?box_NONCEBYTES, C>>, {rand, SessKey}) ->
    tweetnacl:box_open_afternm(C, N, SessKey).


%% Counters can be kept in synch by server and client without appending them to
%% ciphertexts, but have pitfalls.
%%
%% For a given key, the counter must NEVER repeat: 
%%
%% - This includes in different directions, such as client-to-server colliding
%%   with server-to-client. 
%% - This includes faults that cause the counter to be reset, but maintain the
%%   same encryption key. (Time adjustments by NTP or manually, process
%%   restarts, etc.)
%% - Also overflows - it may be tempting to use a small nonce as a preemptive
%%   optimization, then forget to check for overflows.
%%
%% There are multople ways to achieve the goal: all have pitfalls.
%%
%% For example, note how sending messages to your own public key (which is the
%% wrong thing to do for multiple reasons, but is a likely thing to happen in
%% adhoc code) would have resulted in nonce repetition in the following
%% (otherwise fine) scheme:
counter_new(PubKey, _, PubKey) -> error({wrong_primitive, use_secretbox});
counter_new(PubKey, SecKey, <<MyPubKey:?box_PUBLICKEYBYTES>>) -> 
    SessKey = tweetnacl:box_beforenm(PubKey, SecKey),
    Dir = PubKey =< MyPubKey, % binary comparison to blindly set pecking order
    {ctr, rx_tx_diff(Dir), rx_tx_diff(not Dir), SessKey}.
% where
    rx_tx_diff(true)  -> <<0:1/unit:1, 0:181/unit:1>>;
    rx_tx_diff(false) -> <<1:1/unit:1, 0:181/unit:1>>.

counter_box(M, {ctr, Rx, Tx, SessKey}) ->
    C = tweetnacl:box_afternm(M, Tx, SessKey),
    {C, {ctr, Rx, ctr_next(Tx), SessKey}}.
counter_box_open(C, {ctr, Rx, Tx, SessKey}) ->
    case tweetnacl:box_open_afternm(C, Tx, SessKey) of
        {ok, M} -> 
            St = {ctr, ctr_next(Rx), Tx, SessKey},
            {ok, M, St};
        failed -> failed % do not advance counter
    end.
% where
    ctr_next(<<_:1/unit:1, -1:181/unit:1>>) -> exit(nonce_overflow);
    ctr_next(<<Dir:1/unit:1, N:181/unit:1>>) -> 
        <<Dir:1/unit:1, (N + 1):181/unit:1>>.


%% Time can be incorporated into a nonce to bound replays. (Counters are
%% virtual clocks.)
%%
%% Not all protocols are concerned about replays. Idempotent commands usually
%% aren't.
timeout_new(PubKey, _, PubKey) -> error({wrong_primitive, use_secretbox});
timeout_new(PubKey, SecKey, <<MyPubKey:?box_PUBLICKEYBYTES>>) -> 
    SessKey = tweetnacl:box_beforenm(PubKey, SecKey),
    Dir = PubKey =< MyPubKey, % binary comparison to blindly set pecking order
    {timeout, timeout_dir(Dir), SessKey}.
% where
    timeout_dir(true)  -> <<0:1/unit:1, 0:127/unit:1>>;
    timeout_dir(false) -> <<1:1/unit:1, 0:127/unit:1>>.
    time_since_epoch() -> 
        Date = calendar:universal_time(),
        Seconds = calendar:datetime_to_gregorian_seconds(Date),
        Granularity = 5, % fudge factor for time sync with peer
        Seconds / Granularity.

timeout_box(M, {timeout, TxCtr, SessKey}) ->
    Now = time_since_epoch(),
    C = tweetnacl:box_afternm(M, <<TxCtr, Now:8>>),
    {<<TxCtr, C>>, {timeout, timeout_ctr_next(TxCtr), SessKey}}.
% where
    timeout_ctr_next(<<_:1/unit:1, -1:127/unit:1>>) -> exit(nonce_overflow);
    timeout_ctr_next(<<Dir:1/unit:1, N:127/unit:1>>) -> 
        <<Dir:1/unit:1, (N + 1):127/unit:1>>.

%% To deal with time rollbacks, the following method uses a peer-provided
%% counter in addition to loosely synchronized time for replay protection.
%%
%% To prevent replays within a time window, cache commands for the duration of
%% the window and ignoring anything already in the cache. This halfassed, ugly
%% implementation doesn't do that and needs to be cleaned up to be a worthwhile
%% reference example.
timeout_box_open(<<Counter:16/unit:8, C>>, {timeout, _, SessKey}) ->
    % Need to do trial decryptions in case we're out of synch close to a
    % rollover. As a result, will accept messages within a 15 second window.
    Now = time_since_epoch(),
    Trial = fun(Nonce) -> tweetnacl:box_open_afternm(C, Nonce, SessKey) end,
    case Trial(<<Counter:16, Now:8>>) of
        failed -> 
            case Trial(<<Counter:16, (Now-1):8>>) of
                failed -> 
                    case Trial(<<Counter:16, (Now+1):8>>) of
                        failed -> failed;
                        {ok,_}=R -> R
                    end;
                {ok,_}=R -> R
            end;
        {ok,_}=R -> R
    end.

