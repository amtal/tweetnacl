%%% Some simple uses of the hash primitive.
-module(example_hashes).
-export([ordering/2, is_proof_of_work/3]).
-include("tweetnacl.hrl").

%% Asynchronously arrange master-slave relationships between identical peers,
%% spread resourses evenly throughout a space, etc...
ordering(<<A>>, <<B>>) -> 
    <<NA:?hash_BYTES/unit:8>> = tweetnacl:hash(A),
    <<NB:?hash_BYTES/unit:8>> = tweetnacl:hash(B),
    if  NA > NB -> left;
        NA < NB -> right;
        true -> equal
    end.

%% Computational cost with tunable parameter.
%%
%% Regardless of primitive choice, optimized/dedicated hardware (FPGAs, video
%% cards, etc) will have a major computational advantage. Beats nothing for
%% preventing server-DoS, though.
is_proof_of_work(<<Message>>, <<Pow:?hash_BYTES>>, WorkFactor) 
  when is_integer(WorkFactor) ->
    Rest = ?hash_BYTES * 8 - WorkFactor,
    <<0:WorkFactor/unit:1, _:Rest/unit:1>> = Pow,
    tweetnacl:hash(Message) == Pow.

