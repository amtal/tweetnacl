-module(public_tests).

-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").

prop_enc_dec() ->
    ?FORALL(M, binary(),
        ?FORALL(N, binary(24),
        begin
                {ok,PK,SK} = tweetnacl:box_keypair(),
                {ok,C} = tweetnacl:box(M, N, PK, SK),
                {ok,M2} = tweetnacl:box_open(C, N, PK, SK),
                io:format("Test: ~p =?= ~p, N=~p, K=~p~n", [M,M2,N,{PK,SK}]),
                M==M2
        end)).

prop_precomp_enc_dec() ->
    ?FORALL(M, binary(),
        ?FORALL(N, binary(24),
        begin
                {ok,PK,SK} = tweetnacl:box_keypair(),
                K = tweetnacl:box_beforenm(PK, SK),
                {ok,C} = tweetnacl:box_afternm(M, N, K),
                {ok,M2} = tweetnacl:box_open_afternm(C, N, K),
                io:format("Test: ~p =?= ~p, N=~p, K=~p~n", [M,M2,N,K]),
                M==M2
        end)).

prop_keygen() ->
    {ok,_,_} = tweetnacl:box_keypair(),
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

