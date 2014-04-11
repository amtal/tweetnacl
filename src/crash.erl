-module(crash).
-compile(export_all).

start() ->
    M = crypto:rand_bytes(100000),
    %io:format(standard_error, "checking ~p~n", [M]),
    {Pub,Sec} = tweetnacl:sign_keypair(), 
    io:format(standard_error, "[x] keygen~n", []),
    SignedM = tweetnacl:sign(M, Sec),
    io:format(standard_error, "[x] sig~n", []),
    {ok, M2} = tweetnacl:sign_open(SignedM, Pub),  
    io:format(standard_error, "[x] verify~n", []),
    M==M2.

