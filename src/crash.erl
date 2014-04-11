%%% erlang R16B03_1-1
%%% erlang 17.0-1
%%% Linux localhost 3.13.6-1-ARCH #1 SMP PREEMPT Fri Mar 7 22:30:23 CET 2014 i686 GNU/Linux
%%%
%%% I must be doing something dumb.
-module(crash).
-compile(export_all).

start() ->
    %M = crypto:rand_bytes(100),
    %{Pub,Sec} = tweetnacl:sign_keypair(), 
    %SignedM = tweetnacl:sign(M, Sec),
    {Pub,_Sec} = {<<139,215,173,72,25,252,60,86,145,65,201,202,187,70,119,16,190,155,78,153,
                 185,92,224,10,148,166,122,217,215,164,186,34>>,
                 {'$signing_key',<<198,184,159,158,55,146,108,11,18,0,25,70,1,140,218,62,
                     115,158,225,216,147,165,146,216,154,154,134,118,144,203,
                     240,53,139,215,173,72,25,252,60,86,145,65,201,202,187,
                     70,119,16,190,155,78,153,185,92,224,10,148,166,122,217,
                     215,164,186,34>>}},
    M = <<29,100,173,253,145,158,190,104,153,8,233,132,15,158,5,73,112,52,148,
          239,41,77,64,244,47,127,159,30,214,54,233,48,78,80,125,35,43,50,207,
          34,207,148,192,136,10,112,17,71,158,37,8,227,43,188,190,88,228,151,
          138,213,54,120,221,128,152,41,98,207,35,197,72,72,35,133,166,59,148,
          53,135,194,101,50,223,76,117,161,133,64,99,83,54,240,207,5,77,137,78,
          60,123,100>>,
    SignedM = <<150,195,174,240,157,146,22,97,182,63,214,45,183,80,236,56,124,45,209,
          98,190,32,46,150,11,174,230,41,155,132,21,239,135,70,157,74,171,223,
          80,218,139,103,219,253,217,214,57,117,24,79,205,30,25,22,68,243,130,
          2,115,248,21,140,164,8,29,100,173,253,145,158,190,104,153,8,233,132,
          15,158,5,73,112,52,148,239,41,77,64,244,47,127,159,30,214,54,233,48,
          78,80,125,35,43,50,207,34,207,148,192,136,10,112,17,71,158,37,8,227,
          43,188,190,88,228,151,138,213,54,120,221,128,152,41,98,207,35,197,72,
          72,35,133,166,59,148,53,135,194,101,50,223,76,117,161,133,64,99,83,
          54,240,207,5,77,137,78,60,123,100>>,
    {ok, M2} = tweetnacl:sign_open(SignedM, Pub),  
    io:format(standard_error, "[x] verify~n", []),
    M==M2.

