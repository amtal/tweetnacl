-module(public_tests).

-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").

prop_enc_dec() ->
    ?FORALL(M, binary(),
        ?FORALL(N, binary(24),
        begin
                {ok,PKA,SKA} = tweetnacl:box_keypair(), % agent A
                {ok,PKB,SKB} = tweetnacl:box_keypair(), % agent B
                {ok,C} = tweetnacl:box(M, N, PKB, SKA), % A sends to B
                {ok,M2} = tweetnacl:box_open(C, N, PKA, SKB), % B receives from A
                M==M2
        end)).

prop_precomp_enc_dec() ->
    ?FORALL(M, binary(),
        ?FORALL(N, binary(24),
        begin
                {ok,PKA,SKA} = tweetnacl:box_keypair(), % agent A
                {ok,PKB,SKB} = tweetnacl:box_keypair(), % agent B
                KA = tweetnacl:box_beforenm(PKB, SKA),
                KB = tweetnacl:box_beforenm(PKA, SKB), % shared key derivation
                {ok,C} = tweetnacl:box_afternm(M, N, KA), % A sends to B
                {ok,M2} = tweetnacl:box_open_afternm(C, N, KB), % B receives from A
                (KA == KB) and (M==M2)
        end)).

prop_keygen() ->
    {ok,_,_} = tweetnacl:box_keypair(),
    true.

proper_many_small_test_() ->
    Opts = [
        {to_file, user}, % save stdout
        {max_size, 64},
        {numtests, 100}
    ],
    {timeout, 60, ?_assertEqual([], proper:module(?MODULE, Opts))}.

proper_few_large_test_() ->
    Opts = [
        {to_file, user}, % save stdout
        {max_size, 100000},
        {numtests, 64}
    ],
    {timeout, 60, ?_assertEqual([], proper:module(?MODULE, Opts))}.

