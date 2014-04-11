-module(sign_tests).

-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").

prop_sign() ->
    ?FORALL(M, binary(),
    begin
            {Pub,Sec} = tweetnacl:sign_keypair(), 
            SignedM = tweetnacl:sign(M, Sec),
            {ok, M2} = tweetnacl:sign_open(SignedM, Pub),  
            M==M2
    end).

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

