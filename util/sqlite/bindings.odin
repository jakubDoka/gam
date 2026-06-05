package sqlite

import "core:c"

Connection :: distinct rawptr
Backup :: distinct rawptr
Statement :: distinct rawptr
Blob :: distinct rawptr

Type :: enum (c.int) {
	INTEGER = 1,
	FLOAT   = 2,
	TEXT    = 3,
	BLOB    = 4,
	NULL    = 5,
}

Open_Flag :: enum (c.int) {
	READONLY,
	READWRITE,
	CREATE,
	DELETEONCLOSE,
	EXCLUSIVE,
	AUTOPROXY,
	URI,
	MEMORY,
	MAIN_DB,
	TEMP_DB,
	TRANSIENT_DB,
	MAIN_JOURNAL,
	TEMP_JOURNAL,
	SUBJOURNAL,
	SUPER_JOURNAL,
	NOMUTEX,
	FULLMUTEX,
	SHAREDCACHE,
	PRIVATECACHE,
	WAL,
	NOFOLLOW = 25,
	EXRESCODE = 26,
}

Open_Flags :: bit_set[Open_Flag;c.int]

Config_Option :: enum (c.int) {
	SINGLE_THREAD       = 1,
	MULTI_THREAD        = 2,
	SERIALIZED          = 3,
	MALLOC              = 4,
	GET_MALLOC          = 5,
	SCRATCH             = 6,
	PAGE_CACHE          = 7,
	HEAP                = 8,
	MEM_STATUS          = 9,
	MUTEX               = 10,
	GET_MUTEX           = 11,
	LOOKASIDE           = 13,
	PCACHE              = 14,
	GET_PCACHE          = 15,
	LOG                 = 16,
	URI                 = 17,
	PCACHE2             = 18,
	GET_PCACHE2         = 19,
	COVERING_INDEX_SCAN = 20,
	SQLLOG              = 21,
	MMAP_SIZE           = 22,
	WIN32_HEAPSIZE      = 23,
	PCACHE_HDRSZ        = 24,
	PMASZ               = 25,
	STMTJRNL_SPILL      = 26,
	SMALL_MALLOC        = 27,
	SORTERREF_SIZE      = 28,
	MEMDB_MAXSIZE       = 29,
	ROWID_IN_VIEW       = 30,
}

Destructor_Behavior :: enum (int) {
	STATIC    = 0,
	TRANSIENT = -1,
}

Destructor :: struct #raw_union {
	callback:  proc(it: rawptr),
	behaviour: Destructor_Behavior,
}

Result_Code :: enum (c.int) {
	OK                      = 0,
	ERROR                   = 1,
	INTERNAL                = 2,
	PERM                    = 3,
	ABORT                   = 4,
	BUSY                    = 5,
	LOCKED                  = 6,
	NOMEM                   = 7,
	READONLY                = 8,
	INTERRUPT               = 9,
	IOERR                   = 10,
	CORRUPT                 = 11,
	NOTFOUND                = 12,
	FULL                    = 13,
	CANTOPEN                = 14,
	PROTOCOL                = 15,
	EMPTY                   = 16,
	SCHEMA                  = 17,
	TOOBIG                  = 18,
	CONSTRAINT              = 19,
	MISMATCH                = 20,
	MISUSE                  = 21,
	NOLFS                   = 22,
	AUTH                    = 23,
	FORMAT                  = 24,
	RANGE                   = 25,
	NOTA_DB                 = 26,
	NOTICE                  = 27,
	WARNING                 = 28,
	ROW                     = 100,
	DONE                    = 101,
	OK_LOAD_PERMANENTLY     = 256,
	ERROR_MISSING_COLLSEQ   = 257,
	BUSY_RECOVERY           = 261,
	LOCKED_SHAREDCACHE      = 262,
	READONLY_RECOVERY       = 264,
	IOERR_READ              = 266,
	CORRUPT_VTAB            = 267,
	CANTOPEN_NOTEMPDIR      = 270,
	CONSTRAINT_CHECK        = 275,
	AUTH_USER               = 279,
	NOTICE_RECOVER_WAL      = 283,
	WARNING_AUTOINDEX       = 284,
	ERROR_RETRY             = 513,
	ABORT_ROLLBACK          = 516,
	BUSY_SNAPSHOT           = 517,
	LOCKED_VTAB             = 518,
	READONLY_CANTLOCK       = 520,
	IOERR_SHORT_READ        = 522,
	CORRUPT_SEQUENCE        = 523,
	CANTOPEN_ISDIR          = 526,
	CONSTRAINT_COMMITHOOK   = 531,
	NOTICE_RECOVER_ROLLBACK = 539,
	ERROR_SNAPSHOT          = 769,
	BUSY_TIMEOUT            = 773,
	READONLY_ROLLBACK       = 776,
	IOERR_WRITE             = 778,
	CORRUPT_INDEX           = 779,
	CANTOPEN_FULLPATH       = 782,
	CONSTRAINT_FOREIGNKEY   = 787,
	READONLY_DBMOVED        = 1032,
	IOERR_FSYNC             = 1034,
	CANTOPEN_CONVPATH       = 1038,
	CONSTRAINT_FUNCTION     = 1043,
	READONLY_CANTINIT       = 1288,
	IOERR_DIR_FSYNC         = 1290,
	CANTOPEN_DIRTYWAL       = 1294,
	CONSTRAINT_NOTNULL      = 1299,
	READONLY_DIRECTORY      = 1544,
	IOERR_TRUNCATE          = 1546,
	CANTOPEN_SYMLINK        = 1550,
	CONSTRAINT_PRIMARYKEY   = 1555,
	IOERR_FSTAT             = 1802,
	CONSTRAINT_TRIGGER      = 1811,
	IOERR_UNLOCK            = 2058,
	CONSTRAINT_UNIQUE       = 2067,
	IOERR_RDLOCK            = 2314,
	CONSTRAINT_VTAB         = 2323,
	IOERR_DELETE            = 2570,
	CONSTRAINT_ROWID        = 2579,
	IOERR_BLOCKED           = 2826,
	CONSTRAINT_PINNED       = 2835,
	IOERR_NOMEM             = 3082,
	CONSTRAINT_DATATYPE     = 3091,
	IOERR_ACCESS            = 3338,
	IOERR_CHECKRESERVEDLOCK = 3594,
	IOERR_LOCK              = 3850,
	IOERR_CLOSE             = 4106,
	IOERR_DIR_CLOSE         = 4362,
	IOERR_SHMOPEN           = 4618,
	IOERR_SHMSIZE           = 4874,
	IOERR_SHMLOCK           = 5130,
	IOERR_SHMMAP            = 5386,
	IOERR_SEEK              = 5642,
	IOERR_DELETE_NOENT      = 5898,
	IOERR_MMAP              = 6154,
	IOERR_GETTEMPPATH       = 6410,
	IOERR_CONVPATH          = 6666,
	IOERR_VNODE             = 6922,
	IOERR_AUTH              = 7178,
	IOERR_BEGIN_ATOMIC      = 7434,
	IOERR_COMMIT_ATOMIC     = 7690,
	IOERR_ROLLBACK_ATOMIC   = 7946,
	IOERR_DATA              = 8202,
	IOERR_CORRUPTFS         = 8458,
}

SQLITE_SHARED :: #config(SQLITE_SHARED, false)

when SQLITE_SHARED {
	foreign import sqlite "../../lib/libsqlite.so"
} else {
	when ODIN_OS == .Linux {
		foreign import sqlite "../../lib/libsqlite.a"
	} else when ODIN_OS == .Windows {
		foreign import sqlite "../../lib/sqlite.lib"
	}
}

@(link_prefix = "sqlite3_")
foreign sqlite {
	step :: proc "c" (statement: Statement) -> Result_Code ---
	reset :: proc "c" (statement: Statement) -> Result_Code ---
	bind_parameter_count :: proc "c" (statement: Statement) -> c.int ---
	column_bytes :: proc "c" (statement: Statement, col_idx: c.int) -> c.int ---
	column_bytes16 :: proc "c" (statement: Statement, col_idx: c.int) -> c.int ---
	column_type :: proc "c" (statement: Statement, col_idx: c.int) -> Type ---
	column_count :: proc "c" (statement: Statement) -> c.int ---
	column_name :: proc "c" (statement: Statement, col_idx: c.int) -> cstring ---
	db_handle :: proc "c" (statement: Statement) -> Connection ---
	sql :: proc "c" (statement: Statement) -> cstring ---
	expanded_sql :: proc "c" (statement: Statement) -> cstring ---
	close :: proc "c" (db: Connection) -> Result_Code ---
	close_v2 :: proc "c" (db: Connection) -> Result_Code ---
	changes :: proc "c" (db: Connection) -> c.int ---
	changes64 :: proc "c" (db: Connection) -> c.int64_t ---
	errmsg :: proc "c" (db: Connection) -> cstring ---
}

@(link_prefix = "sqlite3")
foreign sqlite {
	_finalize :: proc "c" (statememt: Statement) -> Result_Code ---
	_free :: proc "c" (ptr: rawptr) ---
	_open :: proc "c" (filename: cstring, db: ^Connection) -> Result_Code ---
	_open16 :: proc "c" (filename: cstring, db: ^Connection) -> Result_Code ---
	_open_v2 :: proc "c" (filename: cstring, db: ^Connection, flags: Open_Flags, z_vfs: cstring = nil) -> Result_Code ---
	_prepare :: proc "c" (db: Connection, sql: cstring, n_bytes: c.int, statement: ^Statement, tail: ^^cstring) -> Result_Code ---
	_prepare_v2 :: proc "c" (db: Connection, sql: cstring, n_bytes: c.int, statement: ^Statement, tail: ^^cstring) -> Result_Code ---
	_exec :: proc "c" (db: Connection, sql: cstring, cb: proc "c" (ctx: rawptr, argc: c.int, argv: [^]cstring, col_names: [^]cstring) -> c.int, ctx: rawptr, err: ^cstring) -> Result_Code ---
	_extended_result_codes :: proc "c" (db: Connection, onoff: c.int) -> c.int ---
	_extended_errcode :: proc "c" (db: Connection) -> Result_Code ---
	_auto_extension :: proc "c" (x_entry_point: proc "c" ()) -> Result_Code ---
	_cancel_auto_extension :: proc "c" (x_entry_point: proc "c" ()) -> Result_Code ---
	_backup :: proc "c" (dest: Connection, dest_name: cstring, source: ^Connection, source_name: cstring) -> Backup ---
	_backup_step :: proc "c" (backup: Backup, n_page: c.int) -> c.int ---
	_backup_finish :: proc "c" (backup: Backup) -> Result_Code ---
	_backup_remaining :: proc "c" (backup: Backup) -> c.int ---
	_backup_pagecount :: proc "c" (backup: Backup) -> c.int ---
	_bind_blob :: proc "c" (statement: Statement, param_idx: c.int, param_value: [^]byte, param_len: c.int, free: Destructor) -> Result_Code ---
	_bind_blob64 :: proc "c" (statement: Statement, param_idx: c.int, param_value: [^]byte, param_len: c.int64_t, free: Destructor) -> Result_Code ---
	_bind_double :: proc "c" (statement: Statement, param_idx: c.int, param_value: c.double) -> Result_Code ---
	_bind_int :: proc "c" (statement: Statement, param_idx: c.int, param_value: c.int) -> Result_Code ---
	_bind_int64 :: proc "c" (statement: Statement, param_idx: c.int, param_value: c.int64_t) -> Result_Code ---
	_bind_null :: proc "c" (statement: Statement, param_idx: c.int) -> Result_Code ---
	_bind_text :: proc "c" (statement: Statement, param_idx: c.int, param_value: cstring, param_len: c.int, free: Destructor) -> Result_Code ---
	_bind_text16 :: proc "c" (statement: Statement, param_idx: c.int, param_value: cstring, param_len: c.int, free: Destructor) -> Result_Code ---
	_bind_text64 :: proc "c" (statement: Statement, param_idx: c.int, param_value: cstring, param_len: c.int64_t, free: Destructor, encoding: c.uchar) -> Result_Code ---
	_bind_zeroblob :: proc "c" (statement: Statement, param_idx: c.int, len: c.int) -> Result_Code ---
	_bind_zeroblob64 :: proc "c" (statement: Statement, param_idx: c.int, len: c.int64_t) -> Result_Code ---
	_bind_parameter_index :: proc "c" (statement: Statement, name: cstring) -> c.int ---
	_bind_parameter_name :: proc "c" (statement: Statement, param_idx: c.int) -> cstring ---
	_blob_bytes :: proc "c" (blob: Blob) -> c.int ---
	_blob_close :: proc "c" (blob: Blob) -> Result_Code ---
	_blob_open :: proc "c" (db: Connection, database_name: cstring, table: cstring, column: cstring, row_idx: c.int64_t, flags: c.int, blob: ^Blob) -> Result_Code ---
	_blob_read :: proc "c" (blob: Blob, dest: rawptr, n_bytes: c.int, n_bytes_offset: c.int) -> Result_Code ---
	_blob_write :: proc "c" (blob: Blob, source: rawptr, n_bytes: c.int, n_bytes_offset: c.int) -> Result_Code ---
	_blob_reopen :: proc "c" (blob: Blob, row_id: c.int64_t) -> Result_Code ---
	_busy_handler :: proc "c" (db: Connection, handler: proc "c" (ctx: rawptr, attempt: c.int) -> Result_Code, ctx: rawptr) -> Result_Code ---
	_busy_timeout :: proc "c" (db: Connection, ms: c.int) -> Result_Code ---
	@(require_results)
	_column_database_name :: proc "c" (statement: Statement, col_idx: c.int) -> cstring ---
	@(require_results)
	_column_database_name16 :: proc "c" (statement: Statement, col_idx: c.int) -> cstring ---
	@(require_results)
	_column_table_name :: proc "c" (statement: Statement, col_idx: c.int) -> cstring ---
	@(require_results)
	_column_table_name16 :: proc "c" (statement: Statement, col_idx: c.int) -> cstring ---
	@(require_results)
	_column_origin_name :: proc "c" (statement: Statement, col_idx: c.int) -> cstring ---
	@(require_results)
	_column_origin_name16 :: proc "c" (statement: Statement, col_idx: c.int) -> cstring ---
	@(require_results)
	_column_decltype :: proc "c" (statement: Statement, col_idx: c.int) -> cstring ---
	@(require_results)
	_column_decltype16 :: proc "c" (statement: Statement, col_idx: c.int) -> cstring ---
	@(require_results)
	_column_text :: proc "c" (statement: Statement, col_idx: c.int) -> [^]u8 ---
	_column_blob :: proc "c" (statement: Statement, col_idx: c.int) -> [^]u8 ---
	_column_double :: proc "c" (statement: Statement, col_idx: c.int) -> c.double ---
	_column_int :: proc "c" (statement: Statement, col_idx: c.int) -> c.int ---
	_column_int64 :: proc "c" (statement: Statement, col_idx: c.int) -> c.int64_t ---
	_commit_hook :: proc "c" (db: Connection, cb: proc "c" (ctx: rawptr) -> Result_Code, ctx: rawptr) -> rawptr ---
	_rollback_hook :: proc "c" (db: Connection, cb: proc "c" (ctx: rawptr) -> Result_Code, ctx: rawptr) -> rawptr ---
	_compileoption_used :: proc "c" (opt_name: cstring) -> c.int ---
	@(require_results)
	_compileoption_get :: proc "c" (n: c.int) -> cstring ---
	_complete :: proc "c" (sql: cstring) -> c.int ---
	_complete16 :: proc "c" (sql: cstring) -> c.int ---
	_config :: proc "c" (option: Config_Option) -> Result_Code ---
	_threadsafe :: proc "c" () -> c.int ---
}
