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

file_is_cmdscript(File) :-
    file_path(File, FP),
    atom_ends_with(FP, '.cmd').

file_is_downloaded(File, T) :-
    http_download(_, _, _, _, File, T).

process_is_powershell(Process) :-
    process_name(Process, 'powershell.exe').

process_executes_powershell(Process, T) :-
    edge(Process, P, executes, T),
    process_is_powershell(P).

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
    edge(ServerSocket, HttpTransaction, responds_to, T),
    http_transaction(HttpTransaction).

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
            malicious(Entity)    
        ), 
        atomic_list_concat(['malicious', '_', Entity], Tag)
    );
    (
        (
            file_is_executable(Entity)    
        ), 
        atomic_list_concat(['file_is_executable', '_', Entity], Tag)
    );
    (
        (
            file_is_vbscript(Entity),
            file_is_cmdscript(Entity)
        ),
        atomic_list_concat(['file_is_script', '_', Entity], Tag)
    );
    (
        (
            http_transaction(Entity, _, _, _, T);
            http_transaction(_, Entity, _, _, T);
            http_transaction(_, _, Entity, _, T);
            http_transaction(_, _, _, Entity, T)
        ),
        atomic_list_concat(['http_transaction', '__', T], Tag)
    );
    (
        (
            http_download(Entity, _, _, _, _, T);
            http_download(_, Entity, _, _, _, T);
            http_download(_, _, Entity, _, _, T);
            http_download(_, _, _, Entity, _, T);
            http_download(_, _, _, _, Entity, T)
        ),
        atomic_list_concat(['http_download', '__', T], Tag)
    ).

%
% Detection Rules
%

malicious(Process) :-
    process(Process),
    edge(Process, F, Relation, _),
    Relation \== 'loads',
    file(F),
    malicious(F).

malicious(Process) :-
    edge(P, Process, executes, _),
    malicious(P).

malicious(Socket) :-
    socket(Socket),
    edge(Socket, _, requests, _),
    edge(_, Socket, binds_to, _).

malicious(Socket) :-
    socket(Socket),
    edge(Socket, _, responds_to, _),
    edge(_, Socket, connects_to, _).

% malicious(TX) :-
%     http_transaction(TX).

%
% From ProvCon APT33
%

malicious(File) :-
    edge(_, File, creates, _),
    file_is_executable(File).

malicious(Socket) :-
    socket_ip(Socket, '127.0.0.1').

malicious(Process) :-
    process_name(Process, 'mshta.exe').

malicious(File) :-
    % process_name(Process, 'mshta.exe'),
    % edge(Process, File, _, _),
    file_path(File, FP),
    atom_ends_with(FP, '.hta').

malicious(File) :-
    file_path(File, FP),
    atom_contains(FP, 'artifact').

malicious(File) :-
    file_path(File, FP),
    atom_contains(FP, 'benign').

malicious(File) :-
    file_path(File, FP),
    atom_contains(FP, 'apt33').

% malicious(Process) :-
%     process_name(Process, 'download.exe').

% From ProvCon APT17

% malicious(File) :-
%     file_is_downloaded(File, _),
%     file_is_executable(File).

% malicious(Process) :-
%     file_is_downloaded(File, _),
%     file_is_executable(File),
%     edge(Process, File, loads, _).

% malicious(Process) :-
%     process_name(Provhost, 'wsmprovhost.exe'),
%     edge(Provhost, Process, executes, _),
%     process_name(Process, 'powershell.exe').


% From Splunk T1059.005

malicious(File) :-
    file_is_vbscript(File).

% TODO generalise this to "process unexpectedly spawns a network connection"
% malicious(Process) :-
%     process_name(Process, 'explorer.exe'),
%     edge(Process, Socket, _, _),
%     socket(Socket).

% From ProvCon APT32-B

% malicious(Process) :-
%     process_name(Process, PN),
%     atom_contains(PN, 'cobalt_strike').

% malicious(File) :-
%     file_path(File, FP),
%     atom_contains(FP, 'apt32').

% From Splunk T1059.001 SharpHound

% malicious(File) :-
%     file_path(File, FP),
%     atom_contains(FP, 'hound').

reachable(X, Y) :- edge(X, Y, _, _).

reachable(X, Y) :-
    edge(X, Z, _, _),
    reachable(Z, Y).

contaminated(Entity) :-
    malicious(M),
    tag(M, T),
    tag(Entity, T),
    M \= Entity.

% contaminated(Process) :-
%     edge(Process, P, executes, _),
%     malicious(P).

contaminated(Process) :-
    process(Process),
    malicious(P),
    (
        reachable(Process, P);
        reachable(P, Process)
    ).

% contaminated(Process) :-
%     edge(P, Process, executes, _),
%     malicious(P).

contaminated(Socket) :-
    socket(Socket),
    (
        edge(P, Socket, binds_to, _);
        edge(P, Socket, connects_to, _)
    ),
    malicious(P).