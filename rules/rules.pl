?- ['schema.pl'].

%
% Helpers
%

normalize_path(WinPath, UnixPath) :-
    atom_chars(WinPath, Chars),
    maplist(replace_backslash, Chars, FixedChars),
    atom_chars(UnixPath, FixedChars).

replace_backslash('\\', '/') :- !.
replace_backslash(C, C).

file_get_base_name(File, BaseName) :-
    normalize_path(File, F),
    file_base_name(F, BaseName).

atom_ends_with(Atom, Suffix) :-
    sub_atom(Atom, _, _, 0, Suffix).

atom_contains(Atom, Sub) :-
    sub_atom(Atom, _, _, _, Sub).

%
% Fundamental Rules
%

:- discontiguous tag/2.

file_is_executable(File) :-
    file_path(File, FP),
    atom_ends_with(FP, '.exe').

file_is_executable(File) :-
    edge(_, File, loads, _).

file_is_vbscript(File) :-
    file_path(File, FP),
    atom_ends_with(FP, '.vbs').

file_is_downloaded(File, T) :-
    http_download(_, _, _, _, File, T).

socket_is_http(Socket) :-
    socket_port(Socket, 80);
    socket_port(Socket, 443).

socket_is_http(Socket) :-
    socket(Socket),
    edge(Socket, H, _, _),
    http_transaction(H).


http_transaction(Process, ClientSocket, ServerSocket, HttpTransaction, T) :-
    edge(Process, ClientSocket, binds_to, _),
    edge(Process, ServerSocket, connects_to, _),
    edge(ClientSocket, HttpTransaction, requests, _),
    edge(ServerSocket, HttpTransaction, responds_to, T).

http_download(Process, ClientSocket, ServerSocket, HttpTransaction, File, T) :-
    http_transaction(Process, ClientSocket, ServerSocket, HttpTransaction, T),
    (
        edge(Process, File, creates, U);
        edge(Process, File, writes_to, U)    
    ),
    abs(T - U) < 1.



tag(Entity, Tag) :-
    (
        (
            file_is_executable(Entity)    
        ), 
        atomic_list_concat(['file_is_executable', '_', Entity], Tag)
    );
    (
        (
            file_is_vbscript(Entity)
        ),
        atomic_list_concat(['file_is_script', '_', Entity], Tag)
    );
    (
        (
            http_transaction(Entity, _, _, _, T);
            http_transaction(_, Entity, _, _, T);
            http_transaction(_, _, Entity, _, T);
            http_transaction(_, _, _, Entity, T);
            http_transaction(_, _, _, _, T)
        ),
        atomic_list_concat(['http_transaction', '_', T], Tag)
    );
    (
        (
            http_download(Entity, _, _, _, _, T);
            http_download(_, Entity, _, _, _, T);
            http_download(_, _, Entity, _, _, T);
            http_download(_, _, _, Entity, _, T);
            http_download(_, _, _, _, Entity, T);
            http_download(_, _, _, _, _, T)
        ),
        atomic_list_concat(['http_download', '_', T], Tag)
    ).

%
% Detection Rules
%

% From ProvCon APT17

malicious(File) :-
    file_is_downloaded(File, _),
    file_is_executable(File).

malicious(Process) :-
    file_is_downloaded(File, _),
    file_is_executable(File),
    edge(Process, File, loads, _).

% From Splunk T1059.005

malicious(File) :-
    file_is_vbscript(File).

% TODO generalise this to "process unexpectedly spawns a network connection"
malicious(Process) :-
    process_name(Process, 'explorer.exe'),
    edge(Process, Socket, _, _),
    socket(Socket).

% From ProvCon APT32-B

malicious(Process) :-
    process_name(Process, PN),
    atom_contains(PN, 'cobalt_strike').

malicious(File) :-
    file_path(File, FP),
    atom_contains(FP, 'apt32').

% From Splunk T1059.001 SharpHound

malicious(File) :-
    file_path(File, FP),
    atom_contains(FP, 'hound').

contaminated(Entity) :-
    malicious(M),
    tag(M, T),
    tag(Entity, T),
    M \= Entity.