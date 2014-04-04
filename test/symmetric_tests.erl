-module(symmetric_tests).

-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").

prop_hash_comp() ->
    ?FORALL(B, binary(), tweetnacl:hash(B) == tweetnacl:hash(B)).

prop_enc_dec() ->
    ?FORALL(M, binary(),
        ?FORALL(N, binary(24),
        begin
                K = tweetnacl:secretbox_key(),
                C = tweetnacl:secretbox(M, N, K),
                {ok,M2} = tweetnacl:secretbox_open(C, N, K),
                io:format("Test: ~p =?= ~p, N=~p, K=~p~n", [M,M2,N,K]),
                M==M2
        end)).

prop_keygen() ->
    {_,_} = tweetnacl:secretbox_key(),
    true.

proper_many_small_test_() ->
    Opts = [
        {to_file, user},
        {max_size, 64},
        {numtests, 100}
    ],
    {timeout, 60, ?_assertEqual([], proper:module(?MODULE, Opts))}.

proper_few_large_test_() ->
    Opts = [
        {to_file, user},
        {max_size, 100000},
        {numtests, 64}
    ],
    {timeout, 60, ?_assertEqual([], proper:module(?MODULE, Opts))}.

