set -x LD_LIBRARY_PATH lib $LD_LIBRARY_PATH

set -q LATENCY || set -x LATENCY 50

set GDB_FLAGS\
	-ex run\
	-iex "set debuginfod enabled off"\
	-ex quit


set CLIENT_DEV_FLAGS\
	-debug\
	-default-to-nil-allocator\
	-define:LOCAL=true\
	-define:LATENCY=$LATENCY\
	-define:HOT_RELOAD=true\
	-define:RAYLIB_SHARED=true\
	-define:SQLITE_SHARED=true\
	-define:TRACK_ALLOCATIONS=true

alias client-dev 'odin build client $CLIENT_DEV_FLAGS &&\
	gdb client.bin $GDB_FLAGS'


set SERVER_DEV_FLAGS\
	-debug\
	-default-to-nil-allocator\
	-define:LATENCY=$LATENCY\
	-define:HOT_RELOAD=true\
	-define:RAYLIB_SHARED=true\
	-define:SQLITE_SHARED=true\
	-define:TRACK_ALLOCATIONS=true

alias server-dev 'odin build server $SERVER_DEV_FLAGS &&\
	gdb server.bin $GDB_FLAGS'

alias server-dev-mem 'odin run server $SERVER_DEV_FLAGS'


set SANDBOX_DEV_FLAGS\
	-debug\
	-define:HOT_RELOAD=true\
	-define:RAYLIB_SHARED=true\

alias sandbox-dev 'odin build sandbox $SANDBOX_DEV_FLAGS &&
	gdb sandbox.bin $GDB_FLAGS'
