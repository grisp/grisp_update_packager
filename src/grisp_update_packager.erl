-module(grisp_update_packager).


%--- Includes ------------------------------------------------------------------

-include_lib("kernel/include/file.hrl").
-include_lib("public_key/include/public_key.hrl").


%--- Exports -------------------------------------------------------------------

%% API functions
-export([package/2]).


%--- Types ---------------------------------------------------------------------

-type update_file() :: #{
    name := iodata(),
    target := iodata(),
    local := iodata(),
    url => iodata() | undefined
}.

-type mbr_partition() :: #{
    role := boot | system | data,
    type => dos | fat | fat32 | undefined, % dos is deprecated
    start => non_neg_integer(),
    size := non_neg_integer()
}.

-type mbr_partition_table() :: [mbr_partition()].

-type gpt_partition() :: #{
    role := boot | system | data,
    type => linux | swap | home | efi | raid | llvm | bdp | binary() | string(),
    id := iodata(),
    start => non_neg_integer(),
    size := non_neg_integer()
}.

-type gpt_partition_table() :: [gpt_partition()].

-type package_options() :: #{
    tarball => boolean(),
    name := iodata() | undefined,
    version := iodata() | undefined,
    description => iodata() | undefined,
    architecture => string() | binary() | undefined,
    block_size => pos_integer(),
    key_file => iodata() | undefined,
    key => public_key:pem_entry(),
    system => iodata() | undefined,
    bootloader => iodata() | undefined,
    files => [update_file()],
    mbr => mbr_partition_table(),
    gpt => gpt_partition_table()
}.


%--- Macros --------------------------------------------------------------------

-define(DEFAULT_ARCHITECTURE, <<"arm-grisp2-rtems">>).
-define(DEFAULT_BLOCK_SIZE, 4194304).
-define(MIN_ZIP_PERCENT, 3).


%--- API Functions -------------------------------------------------------------

%% @doc Creates a GRiSP software update package.
%% The output path is either a directory where all the package files will be
%% stored, or a tarball file name that will contain all the package files.
%% In both cases the directory or the file must not already exist.
%% <p>Options:
%% <ul>
%%   <li><b>tarball</b> (optional boolean):
%%      If the package files should be stored in a tarball. if `false' the
%%      update manifest and files will be stored in the specified directory.
%%      Default: `true'.
%%   </li>
%%   <li><b>name</b> (required binary):
%%      The product name that will be specified in the manifest.
%%   </li>
%%   <li><b>version</b> (required binary):
%%      The product version that will be specified in the manifest.
%%   </li>
%%   <li><b>description</b> (optional binary):
%%      The product description that will be specified in the manifest.
%%   </li>
%%   <li><b>architecture</b> (optional binary):
%%      The target architecture of the update package.
%%      Default: `arm-grisp2-rtems'.
%%   </li>
%%   <li><b>block_size</b> (optional positive integer):
%%      The size in bytes of the update chunks before compression.
%%      Default: `4194304'.
%%   </li>
%%   <li><b>key_file</b> (optional binary):
%%      The path to a PEM file containing the signing key to use to seal the
%%      manifest. Only one of `key_file' and `key' option can be specified at
%%      the same time.
%%   </li>
%%   <li><b>key</b> (optional private key record):
%%      A decoded private key to use to seal the manifest. Only one of
%%      `key_file' and `key' option can be specified at the same time.
%%   </li>
%%   <li><b>system</b> (optional binary):
%%      The uncompressed system firmware image to be written on the update
%%      system partition. It is optional, so it is possible to create a
%%      bootloader-only update package.
%%   </li>
%%   <li><b>bootloader</b> (optional binary):
%%      The uncompressed bootloader firmware image to be included in the
%%      software update package. If not specified, the package will not contain
%%      the bootloader.
%%   </li>
%%   <li><b>files</b> (optional list):
%%      A list of extra files to be installed during software update.
%%      The files will not be chuncked and will be included as a single
%%      compressed block. If a URL is specified, the file will not be included
%%      in the update package, instead it will be expected to be available at
%%      the given external URL, the file is still required locally though,
%%      as it is needed to compute the hashes.
%%      The format of the file specification is a map with the following fields:
%%      <ul>
%%        <li><b>name</b> (required binary):
%%          The name of the system file as it will appear in the manifest.
%%        </li>
%%        <li><b>local</b> (required binary):
%%          The path to the local file to be included.
%%        </li>
%%        <li><b>target</b> (required binary):
%%          The path in the target filesystem where the file will be installed.
%%        </li>
%%        <li><b>url</b> (optional binary):
%%          The URL the data should be retrieved from instead of including the
%%          file in the update package.
%%        </li>
%%      </ul>
%%   </li>
%%   <li><b>mbr</b> (optional list):
%%      Either the option `mbr' or `gpt' is required.
%%      Specify the MBR partition table of the target filesystem.
%%      It is a list of at most 4 MBR partition specifications as maps with
%%      the following fields:
%%      <ul>
%%        <li><b>role</b> (required atom):
%%          The role of the partition, could be `boot', `system' or `data'.
%%          The firmware can only be written to a `system' partition.
%%        </li>
%%        <li><b>type</b> (optional atom):
%%          The type of the partition, can be `fat', `fat32' or `dos',
%%          all equivalent, `fat' being the default and `dos' being deprecated.
%%        </li>
%%        <li><b>start</b> (optional positive integer):
%%          The start position of the partition in bytes. Must be a multiple
%%          of the sector size (512). If not specified, it will be the end of
%%          the previous partition or `0'.
%%        </li>
%%        <li><b>size</b> (required positive integer):
%%          The size of the partition in bytes. Must be a multiple of the
%%          sector size (512).
%%        </li>
%%      </ul>
%%   </li>
%%   <li><b>gpt</b> (optional list):
%%      Either the option `mbr' or `gpt' is required.
%%      Specify GPT partition table of the target file-system.
%%      It is a list of GPT partition specifications as maps with
%%      the following fields:
%%      <ul>
%%        <li><b>role</b> (required atom):
%%          The role of the partition, could be `boot', `system' or `data'.
%%          The firmware can only be written to a `system' partition.
%%        </li>
%%        <li><b>type</b> (optional atom or binary):
%%          The type of the partition, can be one of the atoms `linux', `swap',
%%          `home', `efi',`raid', `llvm' or `bdp' for standard GPT partition
%%          types or a binary UUID.
%%        </li>
%%        <li><b>id</b> (required binary):
%%          The binary UUID identifier of the partition.
%%        </li>
%%        <li><b>start</b> (optional positive integer):
%%          The start position of the partition in bytes. Must be a multiple
%%          of the sector size (512). If not specified, it will be the end of
%%          the previous partition or `0'.
%%        </li>
%%        <li><b>size</b> (required positive integer):
%%          The size of the partition in bytes. Must be a multiple of the
%%          sector size (512).
%%        </li>
%%      </ul>
%%   </li>
%% </ul></p>
-spec package(OutputPath :: iodata(), package_options()) ->
    ok | {error, Reason :: term()}.
package(OutputPath0, Opts0) ->
    try
        OutputPath = check_does_not_exist(OutputPath0),
        Opts = validate_options(Opts0),
        build_package(OutputPath, Opts)
    catch
        throw:Reason -> {error, Reason}
    end.


%--- Internal Functions --------------------------------------------------------

validate_options(Opts0) ->
    Opts = lists:foldl(fun({Tag, CheckFun, Default},  Map) ->
        case maps:find(Tag, Map) of
            {ok, Value} when Value =/= undefined ->
                Map#{Tag => CheckFun(Value)};
            _ ->
                Map#{Tag => Default}
        end
    end, Opts0, [
        {tarball, fun check_boolean/1, true},
        {name, fun check_string/1, undefined},
        {version, fun check_string/1, undefined},
        {description, fun check_string/1, undefined},
        {architecture, fun check_string/1, ?DEFAULT_ARCHITECTURE},
        {block_size, fun check_pos_integer/1, ?DEFAULT_BLOCK_SIZE},
        {key_file, fun check_file_exists/1, undefined},
        {key, fun check_private_key/1, undefined},
        {system, fun check_file_exists/1, undefined},
        {bootloader, fun check_file_exists/1, undefined},
        {mbr, fun check_mbr/1, undefined},
        {gpt, fun check_gpt/1, undefined},
        {files, fun check_update_files/1, []}
    ]),
    required(Opts, name),
    required(Opts, version),
    require_one(Opts, [mbr, gpt]),
    require_only_one(Opts, [key_file, key]),

    case Opts of
        #{key_file := KeyFile, key := undefined} when KeyFile =/= undefined ->
            Opts#{key => termseal:load_private_key(KeyFile)};
        _ ->
            Opts
    end.

required(Opts, Name) ->
    case maps:find(Name, Opts) of
        {ok, _} -> ok;
        error -> throw({missing_option, Name})
    end.

require_one(Opts, Names) ->
    case [V || V <- maps:values(maps:with(Names, Opts)), V =/= undefined] of
        [_] -> ok;
        [] -> throw({missing_option, Names});
        _ -> throw({conflicting_options, Names})
    end.

require_only_one(Opts, Names) ->
    case [V || V <- maps:values(maps:with(Names, Opts)), V =/= undefined] of
        [_] -> ok;
        [] -> ok;
        _ -> throw({conflicting_options, Names})
    end.

check_file_exists(Path0) ->
    Path = check_string(Path0),
    case file:read_file_info(Path) of
        {error, enoent} -> throw({missing_file, Path});
        {ok, #file_info{type = regular}} -> Path
    end.

check_does_not_exist(Path0) ->
    Path = check_string(Path0),
    case file:read_file_info(Path) of
        {error, enoent} -> Path;
        {ok, #file_info{}} -> throw({already_exists, Path})
    end.

check_boolean(Value) when is_boolean(Value) -> Value;
check_boolean(BadValue) -> throw({bad_boolean, BadValue}).

check_string(Value) when is_list(Value); is_binary(Value) ->
    iolist_to_binary(Value);
check_string(BadValue) -> throw({bad_iodata, BadValue}).

check_pos_integer(Value) when is_integer(Value), Value > 0 -> Value;
check_pos_integer(BadValue) -> throw({bad_pos_integer, BadValue}).

check_uuid(Value) ->
    try
        uuid:string_to_uuid(Value)
    catch
        error:badarg -> throw({bad_uuid, Value})
    end.

check_url(Value) ->
    case uri_string:parse(check_string(Value)) of
        #{scheme := Schem}
          when Schem =:= <<"http">>; Schem =:= <<"https">> ->
            Value;
        _ ->
            throw({bad_url, Value})
    end.

check_private_key(#'ECPrivateKey'{} = Key) -> Key;
check_private_key(#'RSAPrivateKey'{} = Key) -> Key;
check_private_key(_Key) -> throw(bad_signing_key).

check_mbr(Value) when is_list(Value), length(Value) =< 4 ->
    check_mbr_partitions(Value, 0, []);
check_mbr(BadValue) ->
    throw({too_much_mbr_partitions, BadValue}).

check_partition_offset(Value, ErrorTag) ->
    Result = check_pos_integer(Value),
    case Result rem 512 of
        0 -> Result;
        _ -> throw({ErrorTag, Value})
    end.

check_mbr_partitions([], _, Acc) -> lists:reverse(Acc);
check_mbr_partitions([#{role := Role0, start := Start0,
                        size := Size0} = Part | Rest], Min, Acc) ->
    Role = case Role0 of
        R when R =:= boot; R =:= system; R =:= data -> R;
        O -> throw({bad_partition_role, O})
    end,
    Type = case maps:get(type, Part, fat) of
        dos -> fat;
        fat -> fat;
        fat32 -> fat;
        _ -> throw(mbr_partition_type_not_supported)
    end,
    Start = check_partition_offset(Start0, bad_partition_start),
    Size = check_partition_offset(Size0, bad_partition_size),
    case Start < Min of
        true -> throw(partition_overlap);
        _ -> ok
    end,
    check_mbr_partitions(Rest, Start + Size,
                         [#{role => Role, type => Type,
                            start => Start, size => Size} | Acc]);
check_mbr_partitions([#{role := _, size := _} = Part | Rest], Min, Acc) ->
    check_mbr_partitions([Part#{start => Min} | Rest], Min, Acc);
check_mbr_partitions([Part | _Rest], _Min, _Acc) ->
    throw({bad_mbr_partition, Part}).


check_gpt(Value) when is_list(Value) ->
    check_gpt_partitions(Value, 0, []).

check_gpt_partitions([], _, Acc) -> lists:reverse(Acc);
check_gpt_partitions([#{role := Role0, type := Type0, id := Id0,
                        start := Start0, size := Size0} | Rest],
                     Min, Acc) ->
    Role = case Role0 of
        R when R =:= boot; R =:= system; R =:= data -> R;
        O -> throw({bad_partition_role, O})
    end,
    Type = check_uuid(gpt_type(Type0)),
    Id = check_uuid(Id0),
    Start = check_partition_offset(Start0, bad_partition_start),
    Size = check_partition_offset(Size0, bad_partition_size),
    case Start < Min of
        true -> throw(partition_overlap);
        _ -> ok
    end,
    check_gpt_partitions(Rest, Start + Size,
                         [#{role => Role, type => Type, id => Id,
                            start => Start, size => Size} | Acc]);
check_gpt_partitions([#{role := _, type := _, id := _, size := _} = Part | Rest],
                     Min, Acc) ->
    check_gpt_partitions([Part#{start => Min} | Rest], Min, Acc);
check_gpt_partitions([Part | _Rest], _Min, _Acc) ->
    throw({bad_gpt_partition, Part}).

gpt_type(linux) -> "0fc63daf-8483-4772-8e79-3d69d8477de4"; % Linux Filesytem
gpt_type(swap) -> "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f"; % Linux Swap
gpt_type(home) -> "933ac7e1-2eb4-4f13-b844-0e14e2aef915"; % Linux home
gpt_type(efi) -> "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"; % EFI system partition
gpt_type(raid) -> "a19d880f-05fc-4d3b-a006-743f0f84911e"; % Linux Raid
gpt_type(llvm) -> "e6d6d379-f507-44c2-a23c-238f2a3df928"; % Linux LLVM
gpt_type(bdp) -> "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7"; % Widndows Basic Data Partition
gpt_type(Other) -> Other.

check_update_files(FileSpecs) when is_list(FileSpecs) ->
    [check_update_file(S) || S <- FileSpecs].

check_update_file(#{name := Name0, target := Target0,
                  local := Local0} = Spec) ->
    Url = case maps:find(url, Spec) of
        {ok, Url0} when Url0 =/= undefined ->
            check_url(Url0);
        _ -> undefined
    end,
    Name = check_string(Name0),
    Target = check_string(Target0),
    Local = check_file_exists(Local0),
    #{name => Name, target => Target,
      local => Local, url => Url};
check_update_file(Spec) ->
    throw({bad_file_spec, Spec}).

build_package(OutputPath, Opts) ->
    Output = output_init(OutputPath, Opts),
    try
        Manifest = create_manifest(Output, Opts),
        save_plain_manifest(Output, Manifest, Opts),
        save_sealed_manifest(Output, Manifest, Opts)
    after
        output_terminate(Output)
    end.

output_init(OutputPath, Opts) when is_binary(OutputPath) ->
    case maps:get(tarball, Opts) of
        true ->
            ok = filelib:ensure_dir(OutputPath),
            case erl_tar:open(OutputPath, [write]) of
                {ok, TarDesc} -> {tar, TarDesc};
                {error, Reason} ->
                    throw({tarball_open_error, OutputPath, Reason})
            end;
        false ->
            ok = filelib:ensure_dir(filename_join([OutputPath, "."])),
            {dir, OutputPath}
    end.

filename_join([V]) -> V;
filename_join([_|_] = Parts) -> filename:join(Parts).

write_file({dir, BaseDir}, Filepath, Data) ->
    FullPath = filename_join([BaseDir | Filepath]),
    ok = filelib:ensure_dir(FullPath),
    case file:write_file(FullPath, Data) of
        {error, Reason} -> throw({write_error, Reason});
        ok -> ok
    end;
write_file({tar, TarDesc}, Filepath, Data) ->
    TarPath = filename_join(Filepath),
    case erl_tar:add(TarDesc, iolist_to_binary(Data),
                     binary_to_list(TarPath), []) of
        {error, Reason} -> throw({write_error, Reason});
        ok -> ok
    end.

output_terminate({dir, _}) -> ok;
output_terminate({tar, TarDesc}) -> erl_tar:close(TarDesc).

save_plain_manifest(Output, Manifest, _Opts) ->
    ManifestPath = [<<"MANIFEST">>],
    ManifestText = io_lib:format("%% coding: utf-8~n~tp.~n", [Manifest]),
    ManifestData = unicode:characters_to_binary(ManifestText),
    write_file(Output, ManifestPath, ManifestData).

save_sealed_manifest(Output, Manifest, #{key := Key}) ->
    Box = termseal:seal(Manifest, Key),
    SealedManifestPath = [<<"MANIFEST.sealed">>],
    write_file(Output, SealedManifestPath, Box).

create_manifest(Output, Opts) ->
    #{name := Name, architecture := Arch, version := VersionOpt} = Opts,
    Version = parse_version(VersionOpt),
    RevManifest = structure(Opts) ++ [
        {architecture, iolist_to_binary(Arch)},
        {description, unicode:characters_to_binary(maps:get(desc, Opts, ""))},
        {version, Version},
        {product, unicode:characters_to_binary(Name)},
        {format, {1, 0, 0}}
    ],
    Objs = bootloader_objects(Opts, Output, []),
    Objs2 = system_objects(Opts, Output, Objs),
    Objs3 = firmware_objects(Opts, Output, Objs2),
    RevManifest2 = [{objects, lists:reverse(Objs3)} | RevManifest],
    lists:reverse(RevManifest2).

structure(#{mbr := PartSpecs}) ->
    [{structure, {mbr, [
        {sector_size, 512},
        {partitions,  partitions_mbr(PartSpecs, 0, [])}
    ]}}];
structure(#{gpt := PartSpecs}) ->
    [{structure, {gpt, [
        {sector_size, 512},
        {partitions,  partitions_gpt(PartSpecs, 0, [])}
    ]}}].

partitions_mbr([], _Id, Acc) -> lists:reverse(Acc);
partitions_mbr([#{role := system, type := T0,
                  start := B, size := S} | Rest], Id, Acc) ->
    T = backcomp_mpr_type(T0),
    Item = {system, [{type, T}, {id, Id}, {start, B div 512},
                     {size, S div 512}]},
    partitions_mbr(Rest, Id + 1, [Item | Acc]);
partitions_mbr([#{role := R, type := T0,
                  start := B, size := S} | Rest], Id, Acc) ->
    T = backcomp_mpr_type(T0),
    Item = {R, [{type, T}, {start, B div 512}, {size, S div 512}]},
    partitions_mbr(Rest, Id, [Item | Acc]).

backcomp_mpr_type(fat) -> dos;
backcomp_mpr_type(Type) -> Type.

partitions_gpt([], _Id, Acc) -> lists:reverse(Acc);
partitions_gpt([#{role := system, type := T, id := U,
                  start := B, size := S} | Rest], Id, Acc) ->
    Item = {system, [{type, uuid2bin(T)}, {id, Id}, {uuid, uuid2bin(U)},
                     {start, B div 512}, {size, S div 512}]},
    partitions_gpt(Rest, Id + 1, [Item | Acc]);
partitions_gpt([#{role := R, type := T, id := U,
                  start := B, size := S} | Rest], Id, Acc) ->
    Item = {R, [{type, uuid2bin(T)}, {uuid, uuid2bin(U)},
                {start, B div 512}, {size, S div 512}]},
    partitions_gpt(Rest, Id, [Item | Acc]).

uuid2bin(UUID) -> iolist_to_binary(uuid:uuid_to_string(UUID)).

bootloader_objects(#{bootloader := Filepath}, Output, Objs)
  when Filepath =/= undefined ->
    {ok, Data} = file:read_file(Filepath),
    Block = zlib:gzip(Data),
    BlockPath = [<<"bootloader.gz">>],
    write_file(Output, BlockPath, Block),
    [{bootloader, [
        {actions, [setup, bootloader]},
        {product, <<"barebox">>},
        {description, <<"Barebox Bootloader">>},
        {target, {raw, [{context, global}, {offset, 0}]}},
        {content, [
            {block, [
                {data_offset, 0},
                {data_size, byte_size(Data)},
                {data_hashes, [
                    {sha256, base64:encode(crypto:hash(sha256, Data))},
                    {crc32, erlang:crc32(Data)}
                ]},
                {block_format, gzip},
                {block_size, byte_size(Block)},
                {block_hashes, [
                    {sha256, base64:encode(crypto:hash(sha256, Block))},
                    {crc32, erlang:crc32(Block)}
                ]},
                {block_path, <<"bootloader.gz">>}
            ]}
        ]}
    ]} | Objs];
bootloader_objects(_Opts, _Output, Objs) ->
    Objs.

system_objects(#{files := SysFileSpecs} = Opts, _Output, Objs) ->
    system_objects(Opts, _Output, SysFileSpecs, Objs).

system_objects(_Opts, _Output, [], Objs) ->
    Objs;
system_objects(Opts, Output, [#{url := Url} = Spec | Rest], Objs) ->
    #{name := Name, local := Local, target := Target} = Spec,
    Blocks = generate_refblocks(Opts, Local, Url),
    Objs2 = [{binary_to_atom(Name), [
        {actions, [setup, update]},
        {target, {file, [{context, system}, {path, Target}]}},
        {content, Blocks}
    ]} | Objs],
    system_objects(Opts, Output, Rest, Objs2);
system_objects(Opts, Output, [Spec | Rest], Objs) ->
    #{name := Name, local := Local, target := Target} = Spec,
    Blocks = generate_blocks(Opts, Output, Local, Name),
    Objs2 = [{binary_to_atom(Name), [
        {actions, [setup, update]},
        {target, {file, [{context, system}, {path, Target}]}},
        {content, Blocks}
    ]} | Objs],
    system_objects(Opts, Output, Rest, Objs2).

firmware_objects(#{system := Filepath} = Opts, Output, Objs)
  when Filepath =/= undefined ->
    Blocks = generate_blocks(Opts, Output, Filepath, <<"rootfs">>),
    [{rootfs, [
        {actions, [setup, update]},
        {target, {raw, [{context, system}, {offset, 0}]}},
        {content, Blocks}
    ]} | Objs].

file_info(Filename) ->
    case file:open(Filename, [raw, read, binary]) of
        {error, Reason} ->
            throw({open_error, Filename, Reason});
        {ok, File} ->
            try
                {Size, Crc32, HashCtx} = file_info(Filename, File, 0,
                            erlang:crc32(<<>>), crypto:hash_init(sha256)),
                {Size, Crc32, crypto:hash_final(HashCtx)}
            after
                file:close(File)
            end
    end.

file_info(Filename, File, Size, Crc32, HashCtx) ->
    case file:read(File, 256 * 1024) of
        eof -> {Size, Crc32, HashCtx};
        {ok, Data} ->
            file_info(Filename, File, Size + byte_size(Data),
                      erlang:crc32(Crc32, Data),
                      crypto:hash_update(HashCtx, Data));
        {error, Reason} ->
            throw({read_error, Filename, Reason})
    end.

generate_refblocks(_Opts, InputFilename, Url) ->
    {DataSize, DataCrc, DataHashBin} = file_info(InputFilename),
    [{block, [
        {data_offset, 0},
        {data_size, DataSize},
        {data_hashes, [
            {sha256, base64:encode(DataHashBin)},
            {crc32, DataCrc}
        ]},
        {block_format, raw},
        {block_path, Url}
    ]}].

generate_blocks(#{block_size := Size}, Output, InputFilename, SubDir) ->
    case file:open(InputFilename, [read, raw, binary]) of
        {ok, File} ->
            generate_blocks_loop(Output, Size, File, SubDir, 0, 0, #{}, []);
        {error, Reason} ->
            throw({open_error, InputFilename, Reason})
    end. 

generate_blocks_loop(Output, ReadSize, File, SubDir, Index, Offset, Cache, Blocks) ->
    case file:read(File, ReadSize) of
        eof -> lists:reverse(Blocks);
        {ok, Data} ->
            DataSize = byte_size(Data),
            DataBinHash = crypto:hash(sha256, Data),
            BlockSpec1 = [
                {data_size, DataSize},
                {data_hashes, [
                    {sha256, base64:encode(DataBinHash)},
                    {crc32, erlang:crc32(Data)}
                ]}
            ],
            {Cache2, Index2, BlockSpec} =
                case maps:find(DataBinHash, Cache) of
                    {ok, Spec} -> {Cache, Index, Spec};
                    error ->
                        ZipBlock = zlib:gzip(Data),
                        ZipSize = byte_size(ZipBlock),
                        MaxSize = DataSize - (DataSize * ?MIN_ZIP_PERCENT div 100),
                        {Path, Block, Spec} = case ZipSize =< MaxSize of
                            true ->
                                Filename = iolist_to_binary(io_lib:format("~3..0b.gz", [Index])),
                                RelPath = [SubDir, Filename],
                                BinHash = crypto:hash(sha256, ZipBlock),
                                ZipHash = base64:encode(BinHash),
                                ZipCrc = erlang:crc32(ZipBlock),
                                BlockSpec2 = BlockSpec1 ++ [
                                    {block_format, gzip},
                                    {block_size, ZipSize},
                                    {block_hashes, [
                                        {sha256, ZipHash},
                                        {crc32, ZipCrc}
                                    ]},
                                    {block_path, filename_join(RelPath)}
                                ],
                                {RelPath, ZipBlock, BlockSpec2};
                            false ->
                                Filename = iolist_to_binary(io_lib:format("~3..0b", [Index])),
                                RelPath = [SubDir, Filename],
                                BlockSpec2 = BlockSpec1 ++ [
                                    {block_format, raw},
                                    {block_path, filename_join(RelPath)}
                                ],
                                {RelPath, Data, BlockSpec2}
                        end,
                        write_file(Output, Path, Block),
                        {Cache#{DataBinHash => Spec}, Index + 1, Spec}
                end,
            generate_blocks_loop(Output, ReadSize, File, SubDir, Index2,
                                 Offset + DataSize, Cache2, [
                {block, [{data_offset, Offset} | BlockSpec]} | Blocks])
    end.

parse_version({A, B, C})
  when is_integer(A), A >= 0, is_integer(B), B >= 0, is_integer(C), C >= 0 ->
    {A, B, C};
parse_version(N) when is_integer(N) ->
    {N, 0, 0};
parse_version(Str) when is_list(Str) ->
    parse_version(unicode:characters_to_binary(Str));
parse_version(Bin) when is_binary(Bin) ->
    case re:run(Bin, "^([0-9]*)\.([0-9]*)\.([0-9]*)$",
                [{capture, all, binary}]) of
        {match, [_, A, B, C]} ->
            {binary_to_integer(A), binary_to_integer(B), binary_to_integer(C)};
        _ ->
            Bin
    end.
