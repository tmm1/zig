const Wasm = @This();
const build_options = @import("build_options");

const builtin = @import("builtin");
const native_endian = builtin.cpu.arch.endian();

const std = @import("std");
const Allocator = std.mem.Allocator;
const Cache = std.Build.Cache;
const Path = Cache.Path;
const assert = std.debug.assert;
const fs = std.fs;
const gc_log = std.log.scoped(.gc);
const leb = std.leb;
const log = std.log.scoped(.link);
const mem = std.mem;

const Air = @import("../Air.zig");
const Archive = @import("Wasm/Archive.zig");
const CodeGen = @import("../arch/wasm/CodeGen.zig");
const Compilation = @import("../Compilation.zig");
const Dwarf = @import("Dwarf.zig");
const InternPool = @import("../InternPool.zig");
const Liveness = @import("../Liveness.zig");
const LlvmObject = @import("../codegen/llvm.zig").Object;
const Object = @import("Wasm/Object.zig");
const Symbol = @import("Wasm/Symbol.zig");
const Zcu = @import("../Zcu.zig");
const ZigObject = @import("Wasm/ZigObject.zig");
const codegen = @import("../codegen.zig");
const dev = @import("../dev.zig");
const link = @import("../link.zig");
const lldMain = @import("../main.zig").lldMain;
const trace = @import("../tracy.zig").trace;
const wasi_libc = @import("../wasi_libc.zig");

base: link.File,
/// Null-terminated strings, indexes have type String and string_table provides
/// lookup.
///
/// There are a couple of sites that add things here without adding
/// corresponding string_table entries. For such cases, when implementing
/// serialization/deserialization, they should be adjusted to prefix that data
/// with a null byte so that deserialization does not attempt to create
/// string_table entries for them. Alternately those sites could be moved to
/// use a different byte array for this purpose.
string_bytes: std.ArrayListUnmanaged(u8),
/// Omitted when serializing linker state.
string_table: String.Table,
/// Symbol name of the entry function to export
entry_name: OptionalString,
/// When true, will allow undefined symbols
import_symbols: bool,
/// Set of *global* symbol names to export to the host environment.
export_symbol_names: []const []const u8,
/// When defined, sets the start of the data section.
global_base: ?u64,
/// When defined, sets the initial memory size of the memory.
initial_memory: ?u64,
/// When defined, sets the maximum memory size of the memory.
max_memory: ?u64,
/// When true, will import the function table from the host environment.
import_table: bool,
/// When true, will export the function table to the host environment.
export_table: bool,
/// Output name of the file
name: []const u8,
/// If this is not null, an object file is created by LLVM and linked with LLD afterwards.
llvm_object: ?LlvmObject.Ptr = null,
zig_object: ?*ZigObject,
/// List of relocatable files to be linked into the final binary.
objects: std.ArrayListUnmanaged(Object) = .{},

/// Non-synthetic section that can essentially be mem-cpy'd into place after performing relocations.
object_relocatable_datas: std.ArrayListUnmanaged(RelocatableData) = .empty,
/// Non-synthetic section that can essentially be mem-cpy'd into place after performing relocations.
object_relocatable_codes: std.ArrayListUnmanaged(RelocatableCode) = .empty,
/// Non-synthetic section that can essentially be mem-cpy'd into place after performing relocations.
object_relocatable_customs: std.AutoArrayHashMapUnmanaged(SectionIndex, RelocatableCustom) = .empty,
/// All function imports for all objects.
object_function_imports: std.ArrayListUnmanaged(FunctionImport) = .empty,
/// All table imports for all objects.
object_table_imports: std.ArrayListUnmanaged(Table) = .empty,
/// All memory imports for all objects.
object_memory_imports: std.ArrayListUnmanaged(MemoryImport) = .empty,
/// All global imports for all objects.
object_global_imports: std.ArrayListUnmanaged(GlobalImport) = .empty,
/// All function types for all objects.
object_functions: std.ArrayListUnmanaged(FunctionType.Index) = .empty,
/// All parsed table sections for all objects.
object_tables: std.ArrayListUnmanaged(Table) = .empty,
/// All parsed memory sections for all objects.
object_memories: std.ArrayListUnmanaged(std.wasm.Memory) = .empty,
/// All parsed global sections for all objects.
object_globals: std.ArrayListUnmanaged(Global) = .empty,
/// All parsed export sections for all objects.
object_exports: std.ArrayListUnmanaged(Export) = .empty,
/// All symbols for all objects.
object_symbols: std.ArrayListUnmanaged(Symbol) = .empty,
/// For all objects, extra metadata about the linking section, such as
/// alignment of segments and their name.
object_named_segments: std.ArrayListUnmanaged(NamedSegment) = .empty,
/// A sequence of function initializers that must be called on startup for all
/// objects.
object_init_funcs: std.ArrayListUnmanaged(InitFunc) = .empty,
/// All comdat information for all objects.
object_comdats: std.ArrayListUnmanaged(Comdat) = .empty,
/// All relocations from all objects concatenated.
object_relocations: std.ArrayListUnmanaged(Relocation) = .empty,
/// A table that maps the relocations to be performed where the key represents
/// the section (across all objects) that the slice of relocations applies to.
object_relocations_table: std.AutoArrayHashMapUnmanaged(SectionIndex, Relocation.Slice) = .empty,
/// Incremented across all objects in order to enable calculation of `SectionIndex` values.
object_total_sections: u32 = 0,
/// All comdat symbols from all objects concatenated.
object_comdat_symbols: std.MultiArrayList(Comdat.Symbol) = .empty,

/// When importing objects from the host environment, a name must be supplied.
/// LLVM uses "env" by default when none is given. This would be a good default for Zig
/// to support existing code.
/// TODO: Allow setting this through a flag?
host_name: String,
/// List of symbols generated by the linker.
synthetic_symbols: std.ArrayListUnmanaged(Symbol) = .empty,

atoms: std.ArrayListUnmanaged(Atom) = .empty,
/// This can be used to find meta data of a symbol, such as its size, or its
/// offset to perform a relocation. Undefined (and synthetic) symbols do not
/// have an Atom and therefore cannot be mapped.
symbol_atom: std.AutoArrayHashMapUnmanaged(SymbolLoc, Atom.Index) = .empty,
segment_atom: std.AutoArrayHashMapUnmanaged(Segment.Index, Atom.Index) = .empty,
/// All relocs from all atoms concatenated.
atom_relocs: std.ArrayListUnmanaged(Relocation) = .empty,
/// All locals from all atoms concatenated.
atom_locals: std.ArrayListUnmanaged(Atom.Index) = .empty,

function_imports: std.ArrayListUnmanaged(FunctionImport) = .empty,
table_imports: std.ArrayListUnmanaged(Table) = .empty,
memory_imports: std.ArrayListUnmanaged(MemoryImport) = .empty,
global_imports: std.ArrayListUnmanaged(GlobalImport) = .empty,

/// Represents non-synthetic section entries.
/// Used for code, data and custom sections.
segments: std.ArrayListUnmanaged(Segment) = .empty,
/// Maps a data segment key (such as .rodata) to the index into `segments`.
data_segments: std.StringArrayHashMapUnmanaged(Segment.Index) = .empty,
/// A table of `NamedSegment` which provide meta data
/// about a data symbol such as its name where the key is
/// the segment index, which can be found from `data_segments`
segment_info: std.AutoArrayHashMapUnmanaged(Segment.Index, NamedSegment) = .empty,

/// Output type section
func_types: std.AutoArrayHashMapUnmanaged(FunctionType, void) = .empty,

/// Output function section where the key is the original
/// function index and the value is function.
/// This allows us to map multiple symbols to the same function.
functions: std.AutoArrayHashMapUnmanaged(
    struct {
        /// `none` in the case of synthetic sections.
        file: OptionalObjectId,
        /// Meaning depends on the value of `file`.
        index: u32,
    },
    OutputFunction,
) = .{},
output_globals: std.ArrayListUnmanaged(Global) = .empty,
/// Memory section
memories: std.wasm.Memory = .{ .limits = .{
    .min = 0,
    .max = undefined,
    .flags = .{ .has_max = false, .is_shared = false },
} },
/// Output table section
tables: std.ArrayListUnmanaged(Table) = .empty,
/// Output export section
exports: std.ArrayListUnmanaged(Export) = .empty,
/// List of initialization functions. These must be called in order of priority
/// by the (synthetic) __wasm_call_ctors function.
init_funcs: std.ArrayListUnmanaged(InitFuncLoc) = .empty,
/// Index to a function defining the entry of the wasm file
entry: ?u32 = null,

/// Indirect function table, used to call function pointers
/// When this is non-zero, we must emit a table entry,
/// as well as an 'elements' section.
///
/// Note: Key is symbol location, value represents the index into the table
function_table: std.AutoHashMapUnmanaged(SymbolLoc, u32) = .empty,

/// All archive files that are lazy loaded.
/// e.g. when an undefined symbol references a symbol from the archive.
/// None of this data is serialized to disk because it is trivially reloaded
/// from unchanged archive files on the next start of the compiler process,
/// or if those files have changed, the prelink phase needs to be restarted.
lazy_archives: std.ArrayListUnmanaged(LazyArchive) = .empty,

/// A map of global names to their symbol location
globals: std.AutoArrayHashMapUnmanaged(String, SymbolLoc) = .empty,
/// The list of GOT symbols and their location
got_symbols: std.ArrayListUnmanaged(SymbolLoc) = .empty,
/// Maps discarded symbols and their positions to the location of the symbol
/// it was resolved to
discarded: std.AutoHashMapUnmanaged(SymbolLoc, SymbolLoc) = .empty,
/// List of all symbol locations which have been resolved by the linker and will be emit
/// into the final binary.
resolved_symbols: std.AutoArrayHashMapUnmanaged(SymbolLoc, void) = .empty,
/// Symbols that remain undefined after symbol resolution.
undefs: std.AutoArrayHashMapUnmanaged(String, SymbolLoc) = .empty,

/// `--verbose-link` output.
/// Initialized on creation, appended to as inputs are added, printed during `flush`.
/// String data is allocated into Compilation arena.
dump_argv_list: std.ArrayListUnmanaged([]const u8),

/// Represents the index into `segments` where the 'code' section lives.
code_section_index: Segment.OptionalIndex = .none,
custom_sections: CustomSections,
preloaded_strings: PreloadedStrings,

const OutputFunction = extern struct {
    type_index: FunctionType.Index,
    symbol_index: Symbol.Index,
};

/// Uniquely identifies a section across all objects. Each Object has a section_start field.
/// By subtracting that value from this one, the Object section index is obtained.
pub const SectionIndex = enum(u32) {
    _,
};

/// Index into `object_named_segments`.
pub const ObjectSegmentIndex = enum(u32) {
    _,
};

/// Index into `object_function_imports`.
pub const ObjectFunctionImportIndex = enum(u32) {
    _,

    pub fn ptr(index: ObjectFunctionImportIndex, wasm: *const Wasm) *FunctionImport {
        return &wasm.object_function_imports.items[@intFromEnum(index)];
    }
};

/// Index into `object_global_imports`.
pub const ObjectGlobalImportIndex = enum(u32) {
    _,
};

/// Index into `object_table_imports`.
pub const ObjectTableImportIndex = enum(u32) {
    _,
};

/// Index into `object_tables`.
pub const ObjectTableIndex = enum(u32) {
    _,

    pub fn ptr(index: ObjectTableIndex, wasm: *const Wasm) *Table {
        return &wasm.object_tables.items[@intFromEnum(index)];
    }
};

/// Index into `function_imports`.
pub const FunctionImportIndex = enum(u32) {
    _,
};

/// Index into `global_imports`.
pub const GlobalImportIndex = enum(u32) {
    _,
};

/// Index into `table_imports`.
pub const TableImportIndex = enum(u32) {
    _,
};

/// Index into `memory_imports`.
pub const MemoryImportIndex = enum(u32) {
    _,
};

/// Index into `output_globals`.
pub const GlobalIndex = enum(u32) {
    _,

    fn ptr(index: GlobalIndex, wasm: *const Wasm) *Global {
        return &wasm.output_globals.items[@intFromEnum(index)];
    }
};

/// Index into `object_globals`.
pub const ObjectGlobalIndex = enum(u32) {
    _,
};

/// Index into `functions`.
pub const FunctionIndex = enum(u32) {
    _,

    fn ptr(index: FunctionIndex, wasm: *const Wasm) *OutputFunction {
        return &wasm.functions.values()[@intFromEnum(index)];
    }
};

/// Index into `tables`.
pub const TableIndex = enum(u32) {
    _,
};

/// Index into `object_functions`.
pub const ObjectFunctionIndex = enum(u32) {
    _,

    pub fn toOptional(i: ObjectFunctionIndex) OptionalObjectFunctionIndex {
        const result: OptionalObjectFunctionIndex = @enumFromInt(@intFromEnum(i));
        assert(result != .none);
        return result;
    }
};

/// Index into `object_functions`, or null.
pub const OptionalObjectFunctionIndex = enum(u32) {
    none = std.math.maxInt(u32),
    _,

    pub fn unwrap(i: OptionalObjectFunctionIndex) ?ObjectFunctionIndex {
        if (i == .none) return null;
        return @enumFromInt(@intFromEnum(i));
    }
};

pub const RelocatableData = extern struct {
    /// The data of the segment.
    payload: Payload,
    /// The offset within the section where the data starts
    offset: u32,
    /// Represents the index of the section it belongs to
    section_index: SectionIndex,

    pub const Payload = extern struct {
        /// Points into string_bytes. No corresponding string_table entry.
        off: u32,
        /// The size in bytes of the data representing the segment within the section.
        len: u32,

        fn slice(p: RelocatableData.Payload, wasm: *const Wasm) []const u8 {
            return wasm.string_bytes.items[p.off..][0..p.len];
        }
    };
};

pub const RelocatableCode = extern struct {
    /// The data of the segment.
    payload: Payload,
    /// First imported function of the owning object is 0; regular functions follow.
    function_index: u32,
    /// The offset within the section where the data starts.
    offset: u32,
    section_index: SectionIndex,

    pub const Payload = RelocatableData.Payload;
};

pub const RelocatableCustom = extern struct {
    /// Points into string_bytes. No corresponding string_table entry.
    data_off: u32,
    flags: packed struct(u32) {
        data_len: u31,
        /// Whether the relocatable section is represented by a symbol.
        represented: bool = false,
    },
    section_name: String,
};

pub const Global = extern struct {
    valtype: std.wasm.Valtype,
    mutable: bool,
    unused: [2]u8 = .{ 0, 0 },
    expr: Expr,

    pub const Type = struct {
        valtype: std.wasm.Valtype,
        mutable: bool,
    };

    pub fn @"type"(g: Global) Type {
        return .{
            .valtype = g.valtype,
            .mutable = g.mutable,
        };
    }
};

/// An index into string_bytes where a wasm expression is found.
pub const Expr = enum(u32) {
    _,
};

pub const FunctionType = extern struct {
    params: ValtypeList,
    returns: ValtypeList,

    /// Index into func_types
    pub const Index = enum(u32) {
        _,

        pub fn ptr(i: FunctionType.Index, wasm: *const Wasm) *FunctionType {
            return &wasm.func_types.keys()[@intFromEnum(i)];
        }
    };

    pub const format = @compileError("can't format without *Wasm reference");

    pub fn eql(a: FunctionType, b: FunctionType) bool {
        return a.params == b.params and a.returns == b.returns;
    }
};

/// Represents a function entry, holding the index to its type
pub const Func = extern struct {
    type_index: FunctionType.Index,
};

/// Type reflection is used on the field names to autopopulate each field
/// during initialization.
const PreloadedStrings = struct {
    __heap_base: String,
    __heap_end: String,
    __indirect_function_table: String,
    __linear_memory: String,
    __stack_pointer: String,
    __tls_align: String,
    __tls_base: String,
    __tls_size: String,
    __wasm_apply_global_tls_relocs: String,
    __wasm_call_ctors: String,
    __wasm_init_memory: String,
    __wasm_init_memory_flag: String,
    __wasm_init_tls: String,
    __zig_err_name_table: String,
    __zig_err_names: String,
    __zig_errors_len: String,
    _initialize: String,
    _start: String,
    memory: String,
};

/// Type reflection is used on the field names to autopopulate each inner `name` field.
const CustomSections = struct {
    @".debug_info": CustomSection,
    @".debug_pubtypes": CustomSection,
    @".debug_abbrev": CustomSection,
    @".debug_line": CustomSection,
    @".debug_str": CustomSection,
    @".debug_pubnames": CustomSection,
    @".debug_loc": CustomSection,
    @".debug_ranges": CustomSection,
};

const CustomSection = struct {
    name: String,
    index: Segment.OptionalIndex,
};

/// Index into string_bytes
pub const String = enum(u32) {
    _,

    const Table = std.HashMapUnmanaged(String, void, TableContext, std.hash_map.default_max_load_percentage);

    const TableContext = struct {
        bytes: []const u8,

        pub fn eql(_: @This(), a: String, b: String) bool {
            return a == b;
        }

        pub fn hash(ctx: @This(), key: String) u64 {
            return std.hash_map.hashString(mem.sliceTo(ctx.bytes[@intFromEnum(key)..], 0));
        }
    };

    const TableIndexAdapter = struct {
        bytes: []const u8,

        pub fn eql(ctx: @This(), a: []const u8, b: String) bool {
            return mem.eql(u8, a, mem.sliceTo(ctx.bytes[@intFromEnum(b)..], 0));
        }

        pub fn hash(_: @This(), adapted_key: []const u8) u64 {
            assert(mem.indexOfScalar(u8, adapted_key, 0) == null);
            return std.hash_map.hashString(adapted_key);
        }
    };

    pub fn toOptional(i: String) OptionalString {
        const result: OptionalString = @enumFromInt(@intFromEnum(i));
        assert(result != .none);
        return result;
    }
};

pub const OptionalString = enum(u32) {
    none = std.math.maxInt(u32),
    _,

    pub fn unwrap(i: OptionalString) ?String {
        if (i == .none) return null;
        return @enumFromInt(@intFromEnum(i));
    }
};

/// Stored identically to `String`. The bytes are reinterpreted as
/// `std.wasm.Valtype` elements.
pub const ValtypeList = enum(u32) {
    _,

    pub fn fromString(s: String) ValtypeList {
        return @enumFromInt(@intFromEnum(s));
    }

    pub fn slice(index: ValtypeList, wasm: *const Wasm) []const std.wasm.Valtype {
        return @bitCast(stringSlice(wasm, @enumFromInt(@intFromEnum(index))));
    }
};

/// Index into objects array or the zig object.
pub const ObjectId = enum(u16) {
    zig_object = std.math.maxInt(u16) - 1,
    _,

    pub fn toOptional(i: ObjectId) OptionalObjectId {
        const result: OptionalObjectId = @enumFromInt(@intFromEnum(i));
        assert(result != .none);
        return result;
    }
};

/// Optional index into objects array or the zig object.
pub const OptionalObjectId = enum(u16) {
    zig_object = std.math.maxInt(u16) - 1,
    none = std.math.maxInt(u16),
    _,

    pub fn unwrap(i: OptionalObjectId) ?ObjectId {
        if (i == .none) return null;
        return @enumFromInt(@intFromEnum(i));
    }
};

/// None of this data is serialized since it can be re-loaded from disk, or if
/// it has been changed, the data must be discarded.
const LazyArchive = struct {
    path: Path,
    file_contents: []const u8,
    archive: Archive,

    fn deinit(la: *LazyArchive, gpa: Allocator) void {
        la.archive.deinit(gpa);
        gpa.free(la.path.sub_path);
        gpa.free(la.file_contents);
        la.* = undefined;
    }
};

pub const Segment = extern struct {
    size: u32,
    offset: u32,
    flags: Flags,

    /// Index into Wasm `segments`.
    pub const Index = enum(u32) {
        _,

        pub fn toOptional(i: Index) OptionalIndex {
            const result: OptionalIndex = @enumFromInt(@intFromEnum(i));
            assert(result != .none);
            return result;
        }

        pub fn ptr(index: Segment.Index, wasm: *const Wasm) *Segment {
            return &wasm.segments.items[@intFromEnum(index)];
        }
    };

    /// Index into Wasm `segments`, or null.
    const OptionalIndex = enum(u32) {
        none = std.math.maxInt(u32),
        _,

        pub fn unwrap(i: OptionalIndex) ?Index {
            if (i == .none) return null;
            return @enumFromInt(@intFromEnum(i));
        }
    };

    pub const Flags = packed struct(u32) {
        is_passive: bool,
        has_memindex: bool,
        alignment: Alignment,
        _: u24 = 0,
    };

    fn needsPassiveInitialization(segment: *const Segment, import_mem: bool, is_bss: bool) bool {
        if (import_mem and !is_bss) return true;
        return segment.flags.is_passive;
    }
};

pub const SymbolLoc = struct {
    /// The index of the symbol within the specified file
    index: Symbol.Index,
    /// The index of the object file where the symbol resides.
    file: OptionalObjectId,
};

fn finalSymbolByLoc(wasm: *const Wasm, start_loc: SymbolLoc) *Symbol {
    return symbolByLoc(wasm, symbolLocFinalLoc(wasm, start_loc));
}

fn symbolByLoc(wasm: *const Wasm, loc: SymbolLoc) *Symbol {
    return switch (loc.file) {
        .none => &wasm.synthetic_symbols.items[@intFromEnum(loc.index)],
        .zig_object => wasm.zig_object.?.symbol(loc.index),
        _ => {
            const obj = objectById(wasm, loc.file.unwrap().?).?;
            return &wasm.object_symbols.items[obj.symbols.off..][0..obj.symbols.len][@intFromEnum(loc.index)];
        },
    };
}

/// From a given location, returns the name of the symbol.
pub fn symbolLocName(wasm: *const Wasm, loc: SymbolLoc) [:0]const u8 {
    return wasm.stringSlice(wasm.finalSymbolByLoc(loc).name);
}

/// From a given symbol location, returns the final location.
/// e.g. when a symbol was resolved and replaced by the symbol
/// in a different file, this will return said location.
/// If the symbol wasn't replaced by another, this will return
/// the given location itwasm.
pub fn symbolLocFinalLoc(wasm: *const Wasm, start_loc: SymbolLoc) SymbolLoc {
    var loc = start_loc;
    while (wasm.discarded.get(loc)) |new_loc| loc = new_loc;
    return loc;
}

// Contains the location of the function symbol, as well as
/// the priority itself of the initialization function.
pub const InitFuncLoc = struct {
    /// object file index in the list of objects.
    /// Unlike `SymbolLoc` this cannot be `null` as we never define
    /// our own ctors.
    file: ObjectId,
    /// Symbol index within the corresponding object file.
    index: Symbol.Index,
    /// The priority in which the constructor must be called.
    priority: u32,

    /// From a given `InitFuncLoc` returns the corresponding function symbol
    fn getSymbol(loc: InitFuncLoc, wasm: *const Wasm) *Symbol {
        return wasm.finalSymbolByLoc(getSymbolLoc(loc));
    }

    /// Turns the given `InitFuncLoc` into a `SymbolLoc`
    fn getSymbolLoc(loc: InitFuncLoc) SymbolLoc {
        return .{
            .file = loc.file.toOptional(),
            .index = loc.index,
        };
    }

    /// Returns true when `lhs` has a higher priority (e.i. value closer to 0) than `rhs`.
    fn lessThan(ctx: void, lhs: InitFuncLoc, rhs: InitFuncLoc) bool {
        _ = ctx;
        return lhs.priority < rhs.priority;
    }
};

pub fn open(
    arena: Allocator,
    comp: *Compilation,
    emit: Path,
    options: link.File.OpenOptions,
) !*Wasm {
    // TODO: restore saved linker state, don't truncate the file, and
    // participate in incremental compilation.
    return createEmpty(arena, comp, emit, options);
}

pub fn createEmpty(
    arena: Allocator,
    comp: *Compilation,
    emit: Path,
    options: link.File.OpenOptions,
) !*Wasm {
    const gpa = comp.gpa;
    const target = comp.root_mod.resolved_target.result;
    assert(target.ofmt == .wasm);

    const use_lld = build_options.have_llvm and comp.config.use_lld;
    const use_llvm = comp.config.use_llvm;
    const output_mode = comp.config.output_mode;
    const shared_memory = comp.config.shared_memory;
    const wasi_exec_model = comp.config.wasi_exec_model;

    // If using LLD to link, this code should produce an object file so that it
    // can be passed to LLD.
    // If using LLVM to generate the object file for the zig compilation unit,
    // we need a place to put the object file so that it can be subsequently
    // handled.
    const zcu_object_sub_path = if (!use_lld and !use_llvm)
        null
    else
        try std.fmt.allocPrint(arena, "{s}.o", .{emit.sub_path});

    const wasm = try arena.create(Wasm);
    wasm.* = .{
        .base = .{
            .tag = .wasm,
            .comp = comp,
            .emit = emit,
            .zcu_object_sub_path = zcu_object_sub_path,
            .gc_sections = options.gc_sections orelse (output_mode != .Obj),
            .print_gc_sections = options.print_gc_sections,
            .stack_size = options.stack_size orelse switch (target.os.tag) {
                .freestanding => 1 * 1024 * 1024, // 1 MiB
                else => 16 * 1024 * 1024, // 16 MiB
            },
            .allow_shlib_undefined = options.allow_shlib_undefined orelse false,
            .file = null,
            .disable_lld_caching = options.disable_lld_caching,
            .build_id = options.build_id,
        },
        .name = undefined,
        .string_table = .empty,
        .string_bytes = .empty,
        .import_table = options.import_table,
        .export_table = options.export_table,
        .import_symbols = options.import_symbols,
        .export_symbol_names = options.export_symbol_names,
        .global_base = options.global_base,
        .initial_memory = options.initial_memory,
        .max_memory = options.max_memory,

        .entry_name = undefined,
        .zig_object = null,
        .dump_argv_list = .empty,
        .host_name = undefined,
        .custom_sections = undefined,
        .preloaded_strings = undefined,
    };
    if (use_llvm and comp.config.have_zcu) {
        wasm.llvm_object = try LlvmObject.create(arena, comp);
    }
    errdefer wasm.base.destroy();

    wasm.host_name = try wasm.internString("env");

    inline for (@typeInfo(CustomSections).@"struct".fields) |field| {
        @field(wasm.custom_sections, field.name) = .{
            .index = .none,
            .name = try wasm.internString(field.name),
        };
    }

    inline for (@typeInfo(PreloadedStrings).@"struct".fields) |field| {
        @field(wasm.preloaded_strings, field.name) = try wasm.internString(field.name);
    }

    wasm.entry_name = switch (options.entry) {
        .disabled => .none,
        .default => if (output_mode != .Exe) .none else defaultEntrySymbolName(&wasm.preloaded_strings, wasi_exec_model).toOptional(),
        .enabled => defaultEntrySymbolName(&wasm.preloaded_strings, wasi_exec_model).toOptional(),
        .named => |name| (try wasm.internString(name)).toOptional(),
    };

    if (use_lld and (use_llvm or !comp.config.have_zcu)) {
        // LLVM emits the object file (if any); LLD links it into the final product.
        return wasm;
    }

    // What path should this Wasm linker code output to?
    // If using LLD to link, this code should produce an object file so that it
    // can be passed to LLD.
    const sub_path = if (use_lld) zcu_object_sub_path.? else emit.sub_path;

    wasm.base.file = try emit.root_dir.handle.createFile(sub_path, .{
        .truncate = true,
        .read = true,
        .mode = if (fs.has_executable_bit)
            if (target.os.tag == .wasi and output_mode == .Exe)
                fs.File.default_mode | 0b001_000_000
            else
                fs.File.default_mode
        else
            0,
    });
    wasm.name = sub_path;

    // create stack pointer symbol
    {
        const sym_index = try wasm.createSyntheticSymbol(wasm.preloaded_strings.__stack_pointer, .{
            .tag = .global,
        });
        const symbol = syntheticSymbolPtr(wasm, sym_index);
        // For object files we will import the stack pointer symbol
        if (output_mode == .Obj) {
            symbol.flags.undefined = true;
            symbol.pointee = .{ .global_import = @enumFromInt(wasm.global_imports.items.len) };
            try wasm.global_imports.append(gpa, .{
                .module_name = wasm.host_name,
                .name = symbol.name,
                .valtype = .i32,
                .mutable = true,
            });
        } else {
            symbol.flags.visibility_hidden = true;
            symbol.pointee = .{ .global = try addGlobal(wasm, .{
                .valtype = .i32,
                .mutable = true,
                .expr = try addInitExpr(wasm, .{ .i32_const = 0 }),
            }) };
        }
    }

    // create indirect function pointer symbol
    {
        const sym_index = try wasm.createSyntheticSymbol(wasm.preloaded_strings.__indirect_function_table, .{
            .tag = .table,
        });
        const symbol = syntheticSymbolPtr(wasm, sym_index);
        const table_ptr = if (output_mode == .Obj or options.import_table) t: {
            symbol.flags.undefined = true;
            symbol.pointee = .{ .table_import = @enumFromInt(wasm.table_imports.items.len) };
            break :t try wasm.table_imports.addOne(gpa);
        } else t: {
            if (wasm.export_table) {
                symbol.flags.exported = true;
            } else {
                symbol.flags.visibility_hidden = true;
            }
            symbol.pointee = .{ .table = @enumFromInt(wasm.tables.items.len) };
            break :t try wasm.tables.addOne(gpa);
        };
        // will be overwritten during `mapFunctionTable`
        table_ptr.* = .{
            .module_name = wasm.host_name,
            .name = symbol.name,
            .limits_min = 0,
            .limits_max = undefined,
            .limits_has_max = false,
            .limits_is_shared = false,
            .reftype = .funcref,
        };
    }

    // create __wasm_call_ctors
    {
        _ = try wasm.createSyntheticSymbol(wasm.preloaded_strings.__wasm_call_ctors, .{
            .tag = .function,
            .visibility_hidden = true,
        });
        // We do not know the function index until after we merged all sections.
        // Therefore we set `symbol.pointee` and create its corresponding
        // references at the end of `initializeCallCtorsFunction`.
    }

    // shared-memory symbols for TLS support
    if (shared_memory) {
        {
            const sym_index = try wasm.createSyntheticSymbol(wasm.preloaded_strings.__tls_base, .{
                .tag = .global,
                .visibility_hidden = true,
                .alive = true,
            });
            const symbol = syntheticSymbolPtr(wasm, sym_index);
            symbol.pointee = .{ .global = try addGlobal(wasm, .{
                .valtype = .i32,
                .mutable = true,
                .expr = undefined,
            }) };
        }
        {
            const sym_index = try wasm.createSyntheticSymbol(wasm.preloaded_strings.__tls_size, .{
                .tag = .global,
                .visibility_hidden = true,
                .alive = true,
            });
            const symbol = syntheticSymbolPtr(wasm, sym_index);
            symbol.pointee = .{ .global = try addGlobal(wasm, .{
                .valtype = .i32,
                .mutable = false,
                .expr = undefined,
            }) };
        }
        {
            const sym_index = try wasm.createSyntheticSymbol(wasm.preloaded_strings.__tls_align, .{
                .tag = .global,
                .visibility_hidden = true,
                .alive = true,
            });
            const symbol = syntheticSymbolPtr(wasm, sym_index);
            symbol.pointee = .{ .global = try addGlobal(wasm, .{
                .valtype = .i32,
                .mutable = false,
                .expr = undefined,
            }) };
        }
        {
            _ = try wasm.createSyntheticSymbol(wasm.preloaded_strings.__wasm_init_tls, .{
                .tag = .function,
                .visibility_hidden = true,
            });
        }
    }

    if (comp.zcu) |zcu| {
        if (!use_llvm) {
            const zig_object = try arena.create(ZigObject);
            wasm.zig_object = zig_object;
            zig_object.* = .{
                .path = .{
                    .root_dir = std.Build.Cache.Directory.cwd(),
                    .sub_path = try std.fmt.allocPrint(gpa, "{s}.o", .{fs.path.stem(zcu.main_mod.root_src_path)}),
                },
                .stack_pointer_sym = undefined,
            };
            try zig_object.init(wasm);
        }
    }

    return wasm;
}

/// Either creates a new import, or updates one if existing.
/// When `type_index` is non-null, we assume an external function.
/// In all other cases, a data-symbol will be created instead.
pub fn addOrUpdateImport(
    wasm: *Wasm,
    /// Name of the import
    name: []const u8,
    /// Symbol index that is external
    symbol_index: Symbol.Index,
    /// Optional library name (i.e. `extern "c" fn foo() void`
    lib_name: ?[:0]const u8,
    /// The index of the type that represents the function signature
    /// when the extern is a function. When this is null, a data-symbol
    /// is asserted instead.
    type_index: ?FunctionType.Index,
) !void {
    return wasm.zig_object.?.addOrUpdateImport(wasm, name, symbol_index, lib_name, type_index);
}

/// For a given name, creates a new global synthetic symbol.
/// Leaves index undefined and the default flags (0).
fn createSyntheticSymbol(wasm: *Wasm, name: String, flags: Symbol.Flags) error{OutOfMemory}!Symbol.Index {
    const sym_index: Symbol.Index = @enumFromInt(wasm.synthetic_symbols.items.len);
    const loc: SymbolLoc = .{ .index = sym_index, .file = .none };
    const gpa = wasm.base.comp.gpa;
    try wasm.synthetic_symbols.append(gpa, .{
        .name = name,
        .flags = flags,
        .pointee = undefined,
        .virtual_address = undefined,
    });
    try wasm.resolved_symbols.putNoClobber(gpa, loc, {});
    try wasm.globals.put(gpa, name, loc);
    return sym_index;
}

fn openParseObjectReportingFailure(wasm: *Wasm, path: Path) void {
    const diags = &wasm.base.comp.link_diags;
    const obj = link.openObject(path, false, false) catch |err| {
        switch (diags.failParse(path, "failed to open object: {s}", .{@errorName(err)})) {
            error.LinkFailure => return,
        }
    };
    wasm.parseObject(obj) catch |err| {
        switch (diags.failParse(path, "failed to parse object: {s}", .{@errorName(err)})) {
            error.LinkFailure => return,
        }
    };
}

fn parseObject(wasm: *Wasm, obj: link.Input.Object) !void {
    defer obj.file.close();
    const gpa = wasm.base.comp.gpa;
    try wasm.objects.ensureUnusedCapacity(gpa, 1);
    const stat = try obj.file.stat();
    const size = std.math.cast(usize, stat.size) orelse return error.FileTooBig;

    const file_contents = try gpa.alloc(u8, size);
    defer gpa.free(file_contents);

    const n = try obj.file.preadAll(file_contents, 0);
    if (n != file_contents.len) return error.UnexpectedEndOfFile;

    var func_types: std.ArrayListUnmanaged(FunctionType.Index) = .empty;
    defer func_types.deinit(gpa);

    wasm.objects.appendAssumeCapacity(try Object.parse(wasm, file_contents, obj.path, null, &func_types));
}

pub fn createAtom(wasm: *Wasm, sym_index: Symbol.Index, object_index: OptionalObjectId) !Atom.Index {
    const gpa = wasm.base.comp.gpa;
    const index: Atom.Index = @enumFromInt(wasm.atoms.items.len);
    const atom = try wasm.atoms.addOne(gpa);
    atom.* = .{
        .file = object_index,
        .sym_index = sym_index,
        .relocs = .{ .off = 0, .len = 0 },
        .code = .{ .off = 0, .len = 0 },
        .alignment = .@"1",
        .offset = 0,
        .original_offset = 0,
        .prev = .none,
        .locals = .{ .off = 0, .len = 0 },
    };
    try wasm.symbol_atom.putNoClobber(gpa, atom.symbolLoc(), index);

    return index;
}

pub fn atomPtr(wasm: *const Wasm, index: Atom.Index) *Atom {
    return &wasm.atoms.items[@intFromEnum(index)];
}

fn parseArchive(wasm: *Wasm, obj: link.Input.Object) !void {
    const gpa = wasm.base.comp.gpa;

    defer obj.file.close();

    const stat = try obj.file.stat();
    const size = std.math.cast(usize, stat.size) orelse return error.FileTooBig;

    const file_contents = try gpa.alloc(u8, size);
    var keep_file_contents = false;
    defer if (!keep_file_contents) gpa.free(file_contents);

    const n = try obj.file.preadAll(file_contents, 0);
    if (n != file_contents.len) return error.UnexpectedEndOfFile;

    var archive = try Archive.parse(gpa, file_contents);

    if (!obj.must_link) {
        errdefer archive.deinit(gpa);
        try wasm.lazy_archives.append(gpa, .{
            .path = .{
                .root_dir = obj.path.root_dir,
                .sub_path = try gpa.dupe(u8, obj.path.sub_path),
            },
            .file_contents = file_contents,
            .archive = archive,
        });
        keep_file_contents = true;
        return;
    }

    defer archive.deinit(gpa);

    // In this case we must force link all embedded object files within the archive
    // We loop over all symbols, and then group them by offset as the offset
    // notates where the object file starts.
    var offsets = std.AutoArrayHashMap(u32, void).init(gpa);
    defer offsets.deinit();
    for (archive.toc.values()) |symbol_offsets| {
        for (symbol_offsets.items) |sym_offset| {
            try offsets.put(sym_offset, {});
        }
    }

    for (offsets.keys()) |file_offset| {
        const object = try archive.parseObject(wasm, file_contents[file_offset..], obj.path);
        try wasm.objects.append(gpa, object);
    }
}

fn requiresTlsReloc(wasm: *const Wasm) bool {
    for (wasm.got_symbols.items) |loc| {
        if (wasm.finalSymbolByLoc(loc).isTLS()) {
            return true;
        }
    }
    return false;
}

fn objectSymbol(wasm: *const Wasm, object_id: ObjectId, index: Symbol.Index) *Symbol {
    const obj = wasm.objectById(object_id) orelse return wasm.zig_object.?.symbol(index);
    const symbols = wasm.object_symbols.items[obj.symbols.off..][0..obj.symbols.len];
    return &symbols[@intFromEnum(index)];
}

fn objectPath(wasm: *const Wasm, object_id: ObjectId) Path {
    const obj = wasm.objectById(object_id) orelse return wasm.zig_object.?.path;
    return obj.path;
}

fn objectSymbols(wasm: *const Wasm, object_id: ObjectId) []const Symbol {
    const obj = wasm.objectById(object_id) orelse return wasm.zig_object.?.symbols.items;
    return objectSymbolsByPtr(obj);
}

fn objectSymbolsByPtr(wasm: *const Wasm, object: *Object) []const Symbol {
    return wasm.object_symbols[object.symbols.off..][0..object.symbols.len];
}

fn objectFunction(wasm: *const Wasm, object_id: ObjectId, sym_index: Symbol.Index) FunctionType.Index {
    const obj = wasm.objectById(object_id) orelse {
        const zo = wasm.zig_object.?;
        const sym = zo.symbols.items[@intFromEnum(sym_index)];
        return zo.functions.items[sym.pointee.function_zo];
    };
    const sym = objectSymbolsByPtr(wasm, obj)[@intFromEnum(sym_index)];
    return wasm.object_functions.items[@intFromEnum(sym.pointee.function_obj)];
}

fn objectGlobal(wasm: *const Wasm, object_id: ObjectId, sym_index: Symbol.Index) *Global {
    const obj = wasm.objectById(object_id) orelse {
        const zo = wasm.zig_object.?;
        const sym = zo.symbols.items[@intFromEnum(sym_index)];
        return &zo.globals.items[sym.pointee.global_zo];
    };
    const sym = objectSymbolsByPtr(wasm, obj)[@intFromEnum(sym_index)];
    return objectGlobalPtr(wasm, sym.pointee.global_obj);
}

fn objectGlobals(wasm: *const Wasm, object_id: ObjectId) []const std.wasm.Global {
    const obj = wasm.objectById(object_id) orelse return wasm.zig_object.?.globals.items;
    return obj.globals;
}

fn objectSegmentInfo(wasm: *const Wasm, object_id: ObjectId) []const NamedSegment {
    const obj = wasm.objectById(object_id) orelse return wasm.zig_object.?.segment_info.items;
    return obj.segment_info;
}

/// Returns the object element pointer, or null if it is the ZigObject.
fn objectById(wasm: *const Wasm, object_id: ObjectId) ?*Object {
    if (object_id == .zig_object) return null;
    return &wasm.objects.items[@intFromEnum(object_id)];
}

fn resolveSymbolsInObject(wasm: *Wasm, object_id: ObjectId) !void {
    const gpa = wasm.base.comp.gpa;
    const diags = &wasm.base.comp.link_diags;
    const obj_path = objectPath(wasm, object_id);
    log.debug("Resolving symbols in object: '{'}'", .{obj_path});
    const symbols = objectSymbols(wasm, object_id);

    for (symbols, 0..) |symbol, i| {
        const sym_index: Symbol.Index = @enumFromInt(i);
        const location: SymbolLoc = .{
            .file = object_id.toOptional(),
            .index = sym_index,
        };
        if (symbol.name == wasm.preloaded_strings.__indirect_function_table) continue;

        if (symbol.isLocal()) {
            if (symbol.flags.undefined) {
                diags.addParseError(obj_path, "local symbol '{s}' references import", .{
                    wasm.stringSlice(symbol.name),
                });
            }
            try wasm.resolved_symbols.putNoClobber(gpa, location, {});
            continue;
        }

        const maybe_existing = try wasm.globals.getOrPut(gpa, symbol.name);
        if (!maybe_existing.found_existing) {
            maybe_existing.value_ptr.* = location;
            try wasm.resolved_symbols.putNoClobber(gpa, location, {});

            if (symbol.flags.undefined) {
                try wasm.undefs.putNoClobber(gpa, symbol.name, location);
            }
            continue;
        }

        const existing_loc = maybe_existing.value_ptr.*;
        const existing_sym = wasm.finalSymbolByLoc(existing_loc);
        const existing_file_path: Path = if (existing_loc.file.unwrap()) |id| objectPath(wasm, id) else .{
            .root_dir = std.Build.Cache.Directory.cwd(),
            .sub_path = wasm.name,
        };

        if (!existing_sym.flags.undefined) outer: {
            if (!symbol.flags.undefined) inner: {
                if (symbol.isWeak()) {
                    break :inner; // ignore the new symbol (discard it)
                }
                if (existing_sym.isWeak()) {
                    break :outer; // existing is weak, while new one isn't. Replace it.
                }
                // both are defined and weak, we have a symbol collision.
                var err = try diags.addErrorWithNotes(2);
                try err.addMsg("symbol '{s}' defined multiple times", .{wasm.stringSlice(symbol.name)});
                try err.addNote("first definition in '{'}'", .{existing_file_path});
                try err.addNote("next definition in '{'}'", .{obj_path});
            }

            try wasm.discarded.put(gpa, location, existing_loc);
            continue; // Do not overwrite defined symbols with undefined symbols
        }

        if (symbol.tag != existing_sym.tag) {
            var err = try diags.addErrorWithNotes(2);
            try err.addMsg("symbol '{s}' mismatching types '{s}' and '{s}'", .{
                wasm.stringSlice(symbol.name), @tagName(symbol.tag), @tagName(existing_sym.tag),
            });
            try err.addNote("first definition in '{'}'", .{existing_file_path});
            try err.addNote("next definition in '{'}'", .{obj_path});
        }

        if (existing_sym.flags.undefined and symbol.flags.undefined) {
            // only verify module/import name for function symbols
            if (symbol.tag == .function) {
                const existing_name = functionImportBySymbolLoc(wasm, existing_loc).module_name;
                const module_name = functionImportBySymbolIndex(wasm, object_id, sym_index).module_name;
                if (existing_name != module_name) {
                    var err = try diags.addErrorWithNotes(2);
                    try err.addMsg("symbol '{s}' module name mismatch. Expected '{s}', but found '{s}'", .{
                        wasm.stringSlice(symbol.name),
                        wasm.stringSlice(existing_name),
                        wasm.stringSlice(module_name),
                    });
                    try err.addNote("first definition in '{'}'", .{existing_file_path});
                    try err.addNote("next definition in '{'}'", .{obj_path});
                }
            }

            // both undefined so skip overwriting existing symbol and discard the new symbol
            try wasm.discarded.put(gpa, location, existing_loc);
            continue;
        }

        if (existing_sym.tag == .global) {
            const existing_ty = globalTypeBySymbolLoc(wasm, existing_loc);
            const new_ty = globalTypeBySymbolLoc(wasm, location);
            if (existing_ty.mutable != new_ty.mutable or existing_ty.valtype != new_ty.valtype) {
                var err = try diags.addErrorWithNotes(2);
                try err.addMsg("symbol '{s}' mismatching global types", .{wasm.stringSlice(symbol.name)});
                try err.addNote("first definition in '{'}'", .{existing_file_path});
                try err.addNote("next definition in '{'}'", .{obj_path});
            }
        }

        if (existing_sym.tag == .function) {
            const existing_ty = functionTypeBySymbolLoc(wasm, existing_loc);
            const new_ty = functionTypeBySymbolLoc(wasm, location);
            if (existing_ty != new_ty) {
                var err = try diags.addErrorWithNotes(3);
                try err.addMsg("symbol '{s}' mismatching function signatures.", .{wasm.stringSlice(symbol.name)});
                try err.addNote("expected signature {}, but found signature {}", .{ existing_ty, new_ty });
                try err.addNote("first definition in '{'}'", .{existing_file_path});
                try err.addNote("next definition in '{'}'", .{obj_path});
            }
        }

        // when both symbols are weak, we skip overwriting unless the existing
        // symbol is weak and the new one isn't, in which case we *do* overwrite it.
        if (existing_sym.isWeak() and symbol.isWeak()) blk: {
            if (existing_sym.flags.undefined and !symbol.flags.undefined) break :blk;
            try wasm.discarded.put(gpa, location, existing_loc);
            continue;
        }

        // simply overwrite with the new symbol
        log.debug("Overwriting symbol '{s}'", .{wasm.stringSlice(symbol.name)});
        log.debug("  old definition in '{'}'", .{existing_file_path});
        log.debug("  new definition in '{'}'", .{obj_path});
        try wasm.discarded.putNoClobber(gpa, existing_loc, location);
        maybe_existing.value_ptr.* = location;
        try wasm.globals.put(gpa, symbol.name, location);
        try wasm.resolved_symbols.put(gpa, location, {});
        assert(wasm.resolved_symbols.swapRemove(existing_loc));
        if (existing_sym.flags.undefined) {
            _ = wasm.undefs.swapRemove(symbol.name);
        }
    }
}

fn resolveSymbolsInArchives(wasm: *Wasm) !void {
    if (wasm.lazy_archives.items.len == 0) return;
    const gpa = wasm.base.comp.gpa;
    const diags = &wasm.base.comp.link_diags;

    log.debug("Resolving symbols in lazy_archives", .{});
    var index: u32 = 0;
    undef_loop: while (index < wasm.undefs.count()) {
        const sym_name_index = wasm.undefs.keys()[index];

        for (wasm.lazy_archives.items) |lazy_archive| {
            const sym_name = wasm.stringSlice(sym_name_index);
            log.debug("Detected symbol '{s}' in archive '{'}', parsing objects..", .{
                sym_name, lazy_archive.path,
            });
            const offset = lazy_archive.archive.toc.get(sym_name) orelse continue; // symbol does not exist in this archive

            // Symbol is found in unparsed object file within current archive.
            // Parse object and and resolve symbols again before we check remaining
            // undefined symbols.
            const file_contents = lazy_archive.file_contents[offset.items[0]..];
            const object = lazy_archive.archive.parseObject(wasm, file_contents, lazy_archive.path) catch |err| {
                // TODO this fails to include information to identify which object failed
                return diags.failParse(lazy_archive.path, "failed to parse object in archive: {s}", .{@errorName(err)});
            };
            try wasm.objects.append(gpa, object);
            try wasm.resolveSymbolsInObject(@enumFromInt(wasm.objects.items.len - 1));

            // continue loop for any remaining undefined symbols that still exist
            // after resolving last object file
            continue :undef_loop;
        }
        index += 1;
    }
}

/// Writes an unsigned 32-bit integer as a LEB128-encoded 'i32.const' value.
fn writeI32Const(writer: anytype, val: u32) !void {
    try writer.writeByte(@intFromEnum(std.wasm.Opcode.i32_const));
    try leb.writeIleb128(writer, @as(i32, @bitCast(val)));
}

fn setupInitMemoryFunction(wasm: *Wasm) !void {
    const comp = wasm.base.comp;
    const gpa = comp.gpa;
    const shared_memory = comp.config.shared_memory;
    const import_memory = comp.config.import_memory;

    _ = try wasm.createSyntheticSymbol(wasm.preloaded_strings.__wasm_init_memory, .{
        .tag = .function,
        .alive = true,
    });

    const flag_address: u32 = if (shared_memory) address: {
        // when we have passive initialization segments and shared memory
        // `setupMemory` will create this symbol and set its virtual address.
        const loc = wasm.globals.get(wasm.preloaded_strings.__wasm_init_memory_flag).?;
        break :address wasm.finalSymbolByLoc(loc).virtual_address;
    } else 0;

    var function_body: std.ArrayListUnmanaged(u8) = .empty;
    defer function_body.deinit(gpa);
    const writer = function_body.writer(gpa);

    // we have 0 locals
    try leb.writeUleb128(writer, @as(u32, 0));

    if (shared_memory) {
        // destination blocks
        // based on values we jump to corresponding label
        try writer.writeByte(@intFromEnum(std.wasm.Opcode.block)); // $drop
        try writer.writeByte(std.wasm.block_empty); // block type

        try writer.writeByte(@intFromEnum(std.wasm.Opcode.block)); // $wait
        try writer.writeByte(std.wasm.block_empty); // block type

        try writer.writeByte(@intFromEnum(std.wasm.Opcode.block)); // $init
        try writer.writeByte(std.wasm.block_empty); // block type

        // atomically check
        try writeI32Const(writer, flag_address);
        try writeI32Const(writer, 0);
        try writeI32Const(writer, 1);
        try writer.writeByte(@intFromEnum(std.wasm.Opcode.atomics_prefix));
        try leb.writeUleb128(writer, std.wasm.atomicsOpcode(.i32_atomic_rmw_cmpxchg));
        try leb.writeUleb128(writer, @as(u32, 2)); // alignment
        try leb.writeUleb128(writer, @as(u32, 0)); // offset

        // based on the value from the atomic check, jump to the label.
        try writer.writeByte(@intFromEnum(std.wasm.Opcode.br_table));
        try leb.writeUleb128(writer, @as(u32, 2)); // length of the table (we have 3 blocks but because of the mandatory default the length is 2).
        try leb.writeUleb128(writer, @as(u32, 0)); // $init
        try leb.writeUleb128(writer, @as(u32, 1)); // $wait
        try leb.writeUleb128(writer, @as(u32, 2)); // $drop
        try writer.writeByte(@intFromEnum(std.wasm.Opcode.end));
    }

    for (wasm.data_segments.keys(), wasm.data_segments.values(), 0..) |key, value, segment_index_usize| {
        const segment_index: u32 = @intCast(segment_index_usize);
        const segment = value.ptr(wasm);
        const is_bss = mem.eql(u8, key, ".bss");
        if (segment.needsPassiveInitialization(import_memory, is_bss)) {
            // For passive BSS segments we can simple issue a memory.fill(0).
            // For non-BSS segments we do a memory.init.  Both these
            // instructions take as their first argument the destination
            // address.
            try writeI32Const(writer, segment.offset);

            if (shared_memory and mem.eql(u8, key, ".tdata")) {
                // When we initialize the TLS segment we also set the `__tls_base`
                // global.  This allows the runtime to use this static copy of the
                // TLS data for the first/main thread.
                try writeI32Const(writer, segment.offset);
                try writer.writeByte(@intFromEnum(std.wasm.Opcode.global_set));
                const loc = wasm.globals.get(wasm.preloaded_strings.__tls_base).?;
                try leb.writeUleb128(writer, wasm.finalSymbolByLoc(loc).index);
            }

            try writeI32Const(writer, 0);
            try writeI32Const(writer, segment.size);
            try writer.writeByte(@intFromEnum(std.wasm.Opcode.misc_prefix));
            if (mem.eql(u8, key, ".bss")) {
                // fill bss segment with zeroes
                try leb.writeUleb128(writer, std.wasm.miscOpcode(.memory_fill));
            } else {
                // initialize the segment
                try leb.writeUleb128(writer, std.wasm.miscOpcode(.memory_init));
                try leb.writeUleb128(writer, segment_index);
            }
            try writer.writeByte(0); // memory index immediate
        }
    }

    if (shared_memory) {
        // we set the init memory flag to value '2'
        try writeI32Const(writer, flag_address);
        try writeI32Const(writer, 2);
        try writer.writeByte(@intFromEnum(std.wasm.Opcode.atomics_prefix));
        try leb.writeUleb128(writer, std.wasm.atomicsOpcode(.i32_atomic_store));
        try leb.writeUleb128(writer, @as(u32, 2)); // alignment
        try leb.writeUleb128(writer, @as(u32, 0)); // offset

        // notify any waiters for segment initialization completion
        try writeI32Const(writer, flag_address);
        try writer.writeByte(@intFromEnum(std.wasm.Opcode.i32_const));
        try leb.writeIleb128(writer, @as(i32, -1)); // number of waiters
        try writer.writeByte(@intFromEnum(std.wasm.Opcode.atomics_prefix));
        try leb.writeUleb128(writer, std.wasm.atomicsOpcode(.memory_atomic_notify));
        try leb.writeUleb128(writer, @as(u32, 2)); // alignment
        try leb.writeUleb128(writer, @as(u32, 0)); // offset
        try writer.writeByte(@intFromEnum(std.wasm.Opcode.drop));

        // branch and drop segments
        try writer.writeByte(@intFromEnum(std.wasm.Opcode.br));
        try leb.writeUleb128(writer, @as(u32, 1));

        // wait for thread to initialize memory segments
        try writer.writeByte(@intFromEnum(std.wasm.Opcode.end)); // end $wait
        try writeI32Const(writer, flag_address);
        try writeI32Const(writer, 1); // expected flag value
        try writer.writeByte(@intFromEnum(std.wasm.Opcode.i64_const));
        try leb.writeIleb128(writer, @as(i64, -1)); // timeout
        try writer.writeByte(@intFromEnum(std.wasm.Opcode.atomics_prefix));
        try leb.writeUleb128(writer, std.wasm.atomicsOpcode(.memory_atomic_wait32));
        try leb.writeUleb128(writer, @as(u32, 2)); // alignment
        try leb.writeUleb128(writer, @as(u32, 0)); // offset
        try writer.writeByte(@intFromEnum(std.wasm.Opcode.drop));

        try writer.writeByte(@intFromEnum(std.wasm.Opcode.end)); // end $drop
    }

    for (wasm.data_segments.keys(), wasm.data_segments.values(), 0..) |name, value, segment_index_usize| {
        const segment_index: u32 = @intCast(segment_index_usize);
        const segment = value.ptr(wasm);
        const is_bss = mem.eql(u8, name, ".bss");
        if (!is_bss and segment.needsPassiveInitialization(import_memory, is_bss)) {
            // The TLS region should not be dropped since its is needed
            // during the initialization of each thread (__wasm_init_tls).
            if (shared_memory and mem.eql(u8, name, ".tdata")) continue;

            try writer.writeByte(@intFromEnum(std.wasm.Opcode.misc_prefix));
            try leb.writeUleb128(writer, std.wasm.miscOpcode(.data_drop));
            try leb.writeUleb128(writer, segment_index);
        }
    }

    // End of the function body
    try writer.writeByte(@intFromEnum(std.wasm.Opcode.end));

    const empty_valtype_list = try internValtypeList(wasm, &.{});
    const empty_function_sig = try addFuncType(wasm, .{
        .params = empty_valtype_list,
        .returns = empty_valtype_list,
    });
    try wasm.createSyntheticFunction(
        wasm.preloaded_strings.__wasm_init_memory,
        empty_function_sig,
        function_body.items,
    );
}

/// Constructs a synthetic function that performs runtime relocations for
/// TLS symbols. This function is called by `__wasm_init_tls`.
fn setupTLSRelocationsFunction(wasm: *Wasm) !void {
    const comp = wasm.base.comp;
    const gpa = comp.gpa;

    _ = try wasm.createSyntheticSymbol(wasm.preloaded_strings.__wasm_apply_global_tls_relocs, .{
        .tag = .function,
        .alive = true,
    });
    var function_body: std.ArrayListUnmanaged(u8) = .empty;
    defer function_body.deinit(gpa);
    const writer = function_body.writer(gpa);

    // locals (we have none)
    try writer.writeByte(0);
    for (wasm.got_symbols.items, 0..) |got_loc, got_index| {
        const sym: *Symbol = wasm.finalSymbolByLoc(got_loc);
        if (!sym.isTLS()) continue; // only relocate TLS symbols
        if (sym.tag == .data and sym.isDefined()) {
            // get __tls_base
            try writer.writeByte(@intFromEnum(std.wasm.Opcode.global_get));
            try leb.writeUleb128(writer, wasm.finalSymbolByLoc(wasm.globals.get(wasm.preloaded_strings.__tls_base).?).index);

            // add the virtual address of the symbol
            try writer.writeByte(@intFromEnum(std.wasm.Opcode.i32_const));
            try leb.writeUleb128(writer, sym.virtual_address);
        } else if (sym.tag == .function) {
            @panic("TODO: relocate GOT entry of function");
        } else continue;

        try writer.writeByte(@intFromEnum(std.wasm.Opcode.i32_add));
        try writer.writeByte(@intFromEnum(std.wasm.Opcode.global_set));
        try leb.writeUleb128(writer, wasm.imported_globals_count + @as(u32, @intCast(wasm.output_globals.items.len + got_index)));
    }
    try writer.writeByte(@intFromEnum(std.wasm.Opcode.end));

    const empty_valtype_list = try internValtypeList(wasm, &.{});
    const empty_function_sig = try addFuncType(wasm, .{
        .params = empty_valtype_list,
        .returns = empty_valtype_list,
    });
    try wasm.createSyntheticFunction(
        wasm.preloaded_strings.__wasm_apply_global_tls_relocs,
        empty_function_sig,
        function_body.items,
    );
}

fn validateFeatures(
    wasm: *const Wasm,
    to_emit: *[@typeInfo(Feature.Tag).@"enum".fields.len]bool,
    emit_features_count: *u32,
) !void {
    const comp = wasm.base.comp;
    const diags = &wasm.base.comp.link_diags;
    const target = comp.root_mod.resolved_target.result;
    const shared_memory = comp.config.shared_memory;
    const cpu_features = target.cpu.features;
    const infer = cpu_features.isEmpty(); // when the user did not define any features, we infer them from linked objects.
    const known_features_count = @typeInfo(Feature.Tag).@"enum".fields.len;

    var allowed = [_]bool{false} ** known_features_count;
    var used = [_]u17{0} ** known_features_count;
    var disallowed = [_]u17{0} ** known_features_count;
    var required = [_]u17{0} ** known_features_count;

    // when false, we fail linking. We only verify this after a loop to catch all invalid features.
    var valid_feature_set = true;
    // will be set to true when there's any TLS segment found in any of the object files
    var has_tls = false;

    // When the user has given an explicit list of features to enable,
    // we extract them and insert each into the 'allowed' list.
    if (!infer) {
        inline for (@typeInfo(std.Target.wasm.Feature).@"enum".fields) |feature_field| {
            if (cpu_features.isEnabled(feature_field.value)) {
                allowed[feature_field.value] = true;
                emit_features_count.* += 1;
            }
        }
    }

    // extract all the used, disallowed and required features from each
    // linked object file so we can test them.
    for (wasm.objects.items, 0..) |*object, file_index| {
        for (object.features) |feature| {
            const value = (@as(u16, @intCast(file_index)) << 1) | 1;
            switch (feature.prefix) {
                .used => {
                    used[@intFromEnum(feature.tag)] = value;
                },
                .disallowed => {
                    disallowed[@intFromEnum(feature.tag)] = value;
                },
                .required => {
                    required[@intFromEnum(feature.tag)] = value;
                    used[@intFromEnum(feature.tag)] = value;
                },
            }
        }

        for (object.segment_info) |segment| {
            if (segment.isTLS()) {
                has_tls = true;
            }
        }
    }

    // when we infer the features, we allow each feature found in the 'used' set
    // and insert it into the 'allowed' set. When features are not inferred,
    // we validate that a used feature is allowed.
    for (used, 0..) |used_set, used_index| {
        const is_enabled = @as(u1, @truncate(used_set)) != 0;
        if (infer) {
            allowed[used_index] = is_enabled;
            emit_features_count.* += @intFromBool(is_enabled);
        } else if (is_enabled and !allowed[used_index]) {
            diags.addParseError(
                wasm.objects.items[used_set >> 1].path,
                "feature '{}' not allowed, but used by linked object",
                .{@as(Feature.Tag, @enumFromInt(used_index))},
            );
            valid_feature_set = false;
        }
    }

    if (!valid_feature_set) {
        return error.LinkFailure;
    }

    if (shared_memory) {
        const disallowed_feature = disallowed[@intFromEnum(Feature.Tag.shared_mem)];
        if (@as(u1, @truncate(disallowed_feature)) != 0) {
            diags.addParseError(
                wasm.objects.items[disallowed_feature >> 1].path,
                "shared-memory is disallowed because it wasn't compiled with 'atomics' and 'bulk-memory' features enabled",
                .{},
            );
            valid_feature_set = false;
        }

        for ([_]Feature.Tag{ .atomics, .bulk_memory }) |feature| {
            if (!allowed[@intFromEnum(feature)]) {
                var err = try diags.addErrorWithNotes(0);
                try err.addMsg("feature '{}' is not used but is required for shared-memory", .{feature});
            }
        }
    }

    if (has_tls) {
        for ([_]Feature.Tag{ .atomics, .bulk_memory }) |feature| {
            if (!allowed[@intFromEnum(feature)]) {
                var err = try diags.addErrorWithNotes(0);
                try err.addMsg("feature '{}' is not used but is required for thread-local storage", .{feature});
            }
        }
    }
    // For each linked object, validate the required and disallowed features
    for (wasm.objects.items) |*object| {
        var object_used_features = [_]bool{false} ** known_features_count;
        for (object.features) |feature| {
            if (feature.prefix == .disallowed) continue; // already defined in 'disallowed' set.
            // from here a feature is always used
            const disallowed_feature = disallowed[@intFromEnum(feature.tag)];
            if (@as(u1, @truncate(disallowed_feature)) != 0) {
                var err = try diags.addErrorWithNotes(2);
                try err.addMsg("feature '{}' is disallowed, but used by linked object", .{feature.tag});
                try err.addNote("disallowed by '{'}'", .{wasm.objects.items[disallowed_feature >> 1].path});
                try err.addNote("used in '{'}'", .{object.path});
                valid_feature_set = false;
            }

            object_used_features[@intFromEnum(feature.tag)] = true;
        }

        // validate the linked object file has each required feature
        for (required, 0..) |required_feature, feature_index| {
            const is_required = @as(u1, @truncate(required_feature)) != 0;
            if (is_required and !object_used_features[feature_index]) {
                var err = try diags.addErrorWithNotes(2);
                try err.addMsg("feature '{}' is required but not used in linked object", .{@as(Feature.Tag, @enumFromInt(feature_index))});
                try err.addNote("required by '{'}'", .{wasm.objects.items[required_feature >> 1].path});
                try err.addNote("missing in '{'}'", .{object.path});
                valid_feature_set = false;
            }
        }
    }

    if (!valid_feature_set) {
        return error.LinkFailure;
    }

    to_emit.* = allowed;
}

/// Creates synthetic linker-symbols, but only if they are being referenced from
/// any object file. For instance, the `__heap_base` symbol will only be created,
/// if one or multiple undefined references exist. When none exist, the symbol will
/// not be created, ensuring we don't unnecessarily emit unreferenced symbols.
fn resolveLazySymbols(wasm: *Wasm) !void {
    const comp = wasm.base.comp;
    const gpa = comp.gpa;
    const shared_memory = comp.config.shared_memory;

    if (wasm.getExistingString("__heap_base")) |name_offset| {
        if (wasm.undefs.fetchSwapRemove(name_offset)) |kv| {
            const loc = try wasm.createSyntheticSymbolOffset(name_offset, .data);
            try wasm.discarded.putNoClobber(gpa, kv.value, loc);
            _ = wasm.resolved_symbols.swapRemove(loc); // we don't want to emit this symbol, only use it for relocations.
        }
    }

    if (wasm.getExistingString("__heap_end")) |name_offset| {
        if (wasm.undefs.fetchSwapRemove(name_offset)) |kv| {
            const loc = try wasm.createSyntheticSymbolOffset(name_offset, .data);
            try wasm.discarded.putNoClobber(gpa, kv.value, loc);
            _ = wasm.resolved_symbols.swapRemove(loc);
        }
    }

    if (!shared_memory) {
        if (wasm.undefs.fetchSwapRemove(wasm.preloaded_strings.__tls_base)) |kv| {
            const sym_index = try wasm.createSyntheticSymbolOffset(wasm.preloaded_strings.__tls_base, .global);
            const symbol = syntheticSymbolPtr(wasm, sym_index);
            try wasm.discarded.putNoClobber(gpa, kv.value, .{ .file = .none, .index = sym_index });
            _ = wasm.resolved_symbols.swapRemove(kv.value);
            symbol.flags.visibility_hidden = true;
            symbol.pointee = .{ .global = try addGlobal(wasm, .{
                .valtype = .i32,
                .mutable = true,
                .expr = undefined,
            }) };
        }
    }
}

pub fn findGlobalSymbol(wasm: *const Wasm, name: []const u8) ?SymbolLoc {
    const name_index = wasm.getExistingString(name) orelse return null;
    return wasm.globals.get(name_index);
}

fn checkUndefinedSymbols(wasm: *const Wasm) !void {
    const diags = &wasm.base.comp.link_diags;

    var found_undefined_symbols = false;
    for (wasm.undefs.values()) |undef| {
        const symbol = wasm.finalSymbolByLoc(undef);
        if (symbol.tag == .data) {
            found_undefined_symbols = true;
            const symbol_name = wasm.symbolLocName(undef);
            switch (undef.file) {
                .zig_object => {
                    // TODO: instead of saying the zig compilation unit, attach an actual source location
                    // to this diagnostic
                    diags.addError("unresolved symbol in Zig compilation unit: {s}", .{symbol_name});
                },
                .none => {
                    diags.addError("internal linker bug: unresolved synthetic symbol: {s}", .{symbol_name});
                },
                _ => {
                    const path = wasm.objects.items[@intFromEnum(undef.file)].path;
                    diags.addParseError(path, "unresolved symbol: {s}", .{symbol_name});
                },
            }
        }
    }
    if (found_undefined_symbols) {
        return error.LinkFailure;
    }
}

pub fn deinit(wasm: *Wasm) void {
    const gpa = wasm.base.comp.gpa;
    if (wasm.llvm_object) |llvm_object| llvm_object.deinit();
    if (wasm.zig_object) |zig_obj| zig_obj.deinit(wasm);

    wasm.objects.deinit(gpa);
    wasm.object_relocatable_datas.deinit(gpa);
    wasm.object_relocatable_codes.deinit(gpa);
    wasm.object_relocatable_customs.deinit(gpa);
    wasm.object_function_imports.deinit(gpa);
    wasm.object_table_imports.deinit(gpa);
    wasm.object_memory_imports.deinit(gpa);
    wasm.object_global_imports.deinit(gpa);
    wasm.object_functions.deinit(gpa);
    wasm.object_tables.deinit(gpa);
    wasm.object_memories.deinit(gpa);
    wasm.object_globals.deinit(gpa);
    wasm.object_exports.deinit(gpa);
    wasm.object_symbols.deinit(gpa);
    wasm.object_named_segments.deinit(gpa);
    wasm.object_init_funcs.deinit(gpa);
    wasm.object_comdats.deinit(gpa);
    wasm.object_relocations.deinit(gpa);
    wasm.object_relocations_table.deinit(gpa);
    wasm.object_comdat_symbols.deinit(gpa);

    wasm.atoms.deinit(gpa);
    wasm.symbol_atom.deinit(gpa);
    wasm.segment_atom.deinit(gpa);
    wasm.atom_relocs.deinit(gpa);
    wasm.atom_locals.deinit(gpa);

    for (wasm.lazy_archives.items) |*lazy_archive| lazy_archive.deinit(gpa);
    wasm.lazy_archives.deinit(gpa);

    wasm.synthetic_symbols.deinit(gpa);
    wasm.globals.deinit(gpa);
    wasm.resolved_symbols.deinit(gpa);
    wasm.undefs.deinit(gpa);
    wasm.discarded.deinit(gpa);
    wasm.segments.deinit(gpa);
    wasm.data_segments.deinit(gpa);
    wasm.segment_info.deinit(gpa);

    wasm.function_imports.deinit(gpa);
    wasm.global_imports.deinit(gpa);
    wasm.table_imports.deinit(gpa);
    wasm.memory_imports.deinit(gpa);
    wasm.func_types.deinit(gpa);
    wasm.functions.deinit(gpa);
    wasm.output_globals.deinit(gpa);
    wasm.function_table.deinit(gpa);
    wasm.tables.deinit(gpa);
    wasm.init_funcs.deinit(gpa);
    wasm.exports.deinit(gpa);

    wasm.string_bytes.deinit(gpa);
    wasm.string_table.deinit(gpa);
    wasm.dump_argv_list.deinit(gpa);
}

pub fn updateFunc(wasm: *Wasm, pt: Zcu.PerThread, func_index: InternPool.Index, air: Air, liveness: Liveness) !void {
    if (build_options.skip_non_native and builtin.object_format != .wasm) {
        @panic("Attempted to compile for object format that was disabled by build configuration");
    }
    if (wasm.llvm_object) |llvm_object| return llvm_object.updateFunc(pt, func_index, air, liveness);
    try wasm.zig_object.?.updateFunc(wasm, pt, func_index, air, liveness);
}

// Generate code for the "Nav", storing it in memory to be later written to
// the file on flush().
pub fn updateNav(wasm: *Wasm, pt: Zcu.PerThread, nav: InternPool.Nav.Index) !void {
    if (build_options.skip_non_native and builtin.object_format != .wasm) {
        @panic("Attempted to compile for object format that was disabled by build configuration");
    }
    if (wasm.llvm_object) |llvm_object| return llvm_object.updateNav(pt, nav);
    try wasm.zig_object.?.updateNav(wasm, pt, nav);
}

pub fn updateNavLineNumber(wasm: *Wasm, pt: Zcu.PerThread, nav: InternPool.Nav.Index) !void {
    if (wasm.llvm_object) |_| return;
    try wasm.zig_object.?.updateNavLineNumber(pt, nav);
}

/// Asserts the Symbol represents a global.
fn globalTypeBySymbolLoc(wasm: *const Wasm, loc: SymbolLoc) Global.Type {
    const symbol = wasm.finalSymbolByLoc(loc);
    assert(symbol.tag == .global);
    const is_undefined = symbol.flags.undefined;
    return switch (loc.file) {
        .zig_object => if (is_undefined)
            symbol.pointee.global_import_zo.ptr(wasm.zig_object.?).type()
        else
            symbol.pointee.global_zo.ptr(wasm.zig_object.?).type(),
        .none => if (is_undefined)
            wasm.global_imports.items[@intFromEnum(symbol.pointee.global_import)].type()
        else
            wasm.output_globals.items[@intFromEnum(symbol.pointee.global)].type(),
        _ => if (is_undefined)
            objectGlobalImportPtr(wasm, symbol.pointee.global_import_obj).type()
        else
            objectGlobalPtr(wasm, symbol.pointee.global_obj).type(),
    };
}

/// Asserts the Symbol represents a function.
fn functionTypeBySymbolLoc(wasm: *const Wasm, loc: SymbolLoc) FunctionType.Index {
    const symbol = wasm.finalSymbolByLoc(loc);
    assert(symbol.tag == .function);
    const is_undefined = symbol.flags.undefined;
    switch (loc.file) {
        .zig_object => {
            const zo = wasm.zig_object.?;
            return if (is_undefined) symbol.pointee.function_import_zo.ptr(zo).type else symbol.pointee.function_zo.type(zo);
        },
        .none => {
            if (is_undefined) return functionImportPtr(wasm, symbol.pointee.function_import).type;
            return symbol.pointee.function.ptr(wasm).type;
        },
        _ => {
            if (is_undefined) return symbol.pointee.function_import_obj.ptr(wasm).type;
            return objectFunctionType(wasm, symbol.pointee.function_obj);
        },
    }
}

/// Returns the symbol index from a symbol of which its flag is set global,
/// such as an exported or imported symbol.
/// If the symbol does not yet exist, creates a new one symbol instead
/// and then returns the index to it.
pub fn getGlobalSymbol(wasm: *Wasm, name: []const u8, lib_name: ?[]const u8) !Symbol.Index {
    _ = lib_name;
    const name_index = try wasm.internString(name);
    return wasm.zig_object.?.getGlobalSymbol(wasm.base.comp.gpa, name_index);
}

/// For a given `Nav`, find the given symbol index's atom, and create a relocation for the type.
/// Returns the given pointer address
pub fn getNavVAddr(
    wasm: *Wasm,
    pt: Zcu.PerThread,
    nav: InternPool.Nav.Index,
    reloc_info: link.File.RelocInfo,
) !u64 {
    return wasm.zig_object.?.getNavVAddr(wasm, pt, nav, reloc_info);
}

pub fn lowerUav(
    wasm: *Wasm,
    pt: Zcu.PerThread,
    uav: InternPool.Index,
    explicit_alignment: Alignment,
    src_loc: Zcu.LazySrcLoc,
) !codegen.GenResult {
    return wasm.zig_object.?.lowerUav(wasm, pt, uav, explicit_alignment, src_loc);
}

pub fn getUavVAddr(wasm: *Wasm, uav: InternPool.Index, reloc_info: link.File.RelocInfo) !u64 {
    return wasm.zig_object.?.getUavVAddr(wasm, uav, reloc_info);
}

pub fn deleteExport(
    wasm: *Wasm,
    exported: Zcu.Exported,
    name: InternPool.NullTerminatedString,
) void {
    if (wasm.llvm_object) |_| return;
    return wasm.zig_object.?.deleteExport(wasm, exported, name);
}

pub fn updateExports(
    wasm: *Wasm,
    pt: Zcu.PerThread,
    exported: Zcu.Exported,
    export_indices: []const u32,
) !void {
    if (build_options.skip_non_native and builtin.object_format != .wasm) {
        @panic("Attempted to compile for object format that was disabled by build configuration");
    }
    if (wasm.llvm_object) |llvm_object| return llvm_object.updateExports(pt, exported, export_indices);
    return wasm.zig_object.?.updateExports(wasm, pt, exported, export_indices);
}

pub fn freeDecl(wasm: *Wasm, decl_index: InternPool.DeclIndex) void {
    if (wasm.llvm_object) |llvm_object| return llvm_object.freeDecl(decl_index);
    return wasm.zig_object.?.freeDecl(wasm, decl_index);
}

/// Assigns indexes to all indirect functions.
/// Starts at offset 1, where the value `0` represents an unresolved function pointer
/// or null-pointer
fn mapFunctionTable(wasm: *Wasm) void {
    var it = wasm.function_table.iterator();
    var index: u32 = 1;
    while (it.next()) |entry| {
        const symbol = wasm.finalSymbolByLoc(entry.key_ptr.*);
        if (symbol.flags.alive) {
            entry.value_ptr.* = index;
            index += 1;
        } else {
            wasm.function_table.removeByPtr(entry.key_ptr);
        }
    }

    if (wasm.import_table or wasm.base.comp.config.output_mode == .Obj) {
        const sym_loc = wasm.globals.get(wasm.preloaded_strings.__indirect_function_table).?;
        const import = wasm.imports.getPtr(sym_loc).?;
        import.kind.table.limits.min = index - 1; // we start at index 1.
    } else if (index > 1) {
        log.debug("appending indirect function table", .{});
        const sym_loc = wasm.globals.get(wasm.preloaded_strings.__indirect_function_table).?;
        const symbol = wasm.finalSymbolByLoc(sym_loc);
        const table = symbol.pointee.table.ptr(wasm);
        table.* = .{
            .module_name = table.module_name,
            .name = table.name,
            .limits_min = index,
            .limits_max = index,
            .limits_has_max = true,
            .limits_is_shared = false,
            .reftype = table.reftype,
        };
    }
}

/// From a given index, append the given `Atom` at the back of the linked list.
/// Inserts it into the map of atoms when it doesn't exist yet.
pub fn appendAtomAtIndex(wasm: *Wasm, index: Segment.Index, atom_index: Atom.Index) error{OutOfMemory}!void {
    const gpa = wasm.base.comp.gpa;
    try wasm.atoms.ensureUnusedCapacity(gpa, 1);
    const gop = try wasm.segment_atom.getOrPut(gpa, index);
    if (gop.found_existing) atomPtr(wasm, atom_index).prev = gop.value_ptr.*;
    gop.value_ptr.* = atom_index;
}

fn allocateAtoms(wasm: *Wasm) !void {
    for (wasm.segment_atom.keys(), wasm.segment_atom.values()) |segment_index, *start_atom_index| {
        const segment = segment_index.ptr(wasm);
        var atom_index = start_atom_index.*;
        if (segment_index.toOptional() == wasm.code_section_index) {
            // Code section is allocated upon writing as they are required to be ordered
            // to synchronise with the function section.
            continue;
        }
        var offset: u32 = 0;
        while (true) {
            const atom = wasm.atomPtr(atom_index);
            const symbol_loc = atom.symbolLoc();
            // Ensure we get the original symbol, so we verify the correct symbol on whether
            // it is dead or not and ensure an atom is removed when dead.
            // This is required as we may have parsed aliases into atoms.
            const sym = symbolByLoc(wasm, symbol_loc);

            // Dead symbols must be unlinked from the linked-list to prevent them
            // from being emit into the binary.
            if (!sym.flags.alive) {
                if (start_atom_index.* == atom_index and atom.prev != .none) {
                    // When the atom is dead and is also the first atom retrieved from wasm.atoms(index) we update
                    // the entry to point it to the previous atom to ensure we do not start with a dead symbol that
                    // was removed and therefore do not emit any code at all.
                    start_atom_index.* = atom.prev;
                }
                if (atom.prev == .none) break;
                atom_index = atom.prev;
                atom.prev = .none;
                continue;
            }
            offset = @intCast(atom.alignment.forward(offset));
            atom.offset = offset;
            log.debug("atom '{s}' allocated from 0x{x:0>8} to 0x{x:0>8} size={d}", .{
                wasm.symbolLocName(symbol_loc),
                offset,
                offset + atom.code.len,
                atom.code.len,
            });
            offset += atom.code.len;
            if (atom.prev == .none) break;
            atom_index = atom.prev;
        }
        segment.size = @intCast(segment.alignment.forward(offset));
    }
}

/// For each data symbol, sets the virtual address.
fn allocateVirtualAddresses(wasm: *Wasm) void {
    for (wasm.resolved_symbols.keys()) |loc| {
        const symbol = wasm.finalSymbolByLoc(loc);
        if (symbol.tag != .data or !symbol.flags.alive) {
            // Only data symbols have virtual addresses.
            // Dead symbols do not get allocated, so we don't need to set their virtual address either.
            continue;
        }
        const atom_index = wasm.symbol_atom.get(loc) orelse {
            // synthetic symbol that does not contain an atom
            continue;
        };

        const atom = wasm.getAtom(atom_index);
        const merge_segment = wasm.base.comp.config.output_mode != .Obj;
        const named_segment = switch (atom.file) {
            .zig_object => symbol.pointee.data_zo.ptr(&wasm.zig_object.?),
            .none => symbol.pointee.data_out.ptr(wasm),
            _ => symbol.pointee.data_obj.ptr(wasm),
        };
        const segment_name = named_segment.outputName(wasm, merge_segment);
        const segment_index = wasm.data_segments.get(segment_name).?;
        const segment = segment_index.ptr(wasm);

        // TLS symbols have their virtual address set relative to their own TLS segment,
        // rather than the entire Data section.
        symbol.virtual_address = if (symbol.flags.tls) atom.offset else atom.offset + segment.offset;
    }
}

fn sortDataSegments(wasm: *Wasm) !void {
    const gpa = wasm.base.comp.gpa;
    var new_mapping: std.StringArrayHashMapUnmanaged(Segment.Index) = .empty;
    try new_mapping.ensureUnusedCapacity(gpa, wasm.data_segments.count());
    errdefer new_mapping.deinit(gpa);

    const keys = try gpa.dupe([]const u8, wasm.data_segments.keys());
    defer gpa.free(keys);

    const SortContext = struct {
        fn sort(_: void, lhs: []const u8, rhs: []const u8) bool {
            return order(lhs) < order(rhs);
        }

        fn order(name: []const u8) u8 {
            if (mem.startsWith(u8, name, ".rodata")) return 0;
            if (mem.startsWith(u8, name, ".data")) return 1;
            if (mem.startsWith(u8, name, ".text")) return 2;
            return 3;
        }
    };

    mem.sort([]const u8, keys, {}, SortContext.sort);
    for (keys) |key| {
        const segment_index = wasm.data_segments.get(key).?;
        new_mapping.putAssumeCapacity(key, segment_index);
    }
    wasm.data_segments.deinit(gpa);
    wasm.data_segments = new_mapping;
}

/// Obtains all initfuncs from each object file, verifies its function signature,
/// and then appends it to our final `init_funcs` list.
/// After all functions have been inserted, the functions will be ordered based
/// on their priority.
/// NOTE: This function must be called before we merged any other section.
/// This is because all init funcs in the object files contain references to the
/// original functions and their types. We need to know the type to verify it doesn't
/// contain any parameters.
fn setupInitFunctions(wasm: *Wasm) !void {
    const gpa = wasm.base.comp.gpa;
    const diags = &wasm.base.comp.link_diags;
    // There's no constructors for Zig so we can simply search through linked object files only.
    for (wasm.objects.items, 0..) |*object, object_index| {
        const object_symbols = objectSymbolsByPtr(wasm, object);
        try wasm.init_funcs.ensureUnusedCapacity(gpa, object.init_funcs.len);
        for (object.init_funcs) |init_func| {
            const symbol = object_symbols[init_func.symbol_index];
            const ty_index: FunctionType.Index = if (symbol.flags.undefined)
                symbol.pointee.function_import_obj.ptr(wasm).index
            else
                symbol.pointee.function.ptr(wasm).type;
            const params = ty_index.ptr(wasm).params.slice(wasm);
            if (params.len != 0) diags.addError("constructor function '{s}' has non-empty parameter list", .{
                wasm.stringSlice(symbol.name),
            });
            log.debug("appended init func '{s}'", .{wasm.stringSlice(symbol.name)});
            wasm.init_funcs.appendAssumeCapacity(.{
                .index = @enumFromInt(init_func.symbol_index),
                .file = @enumFromInt(object_index),
                .priority = init_func.priority,
            });
            try wasm.mark(.{
                .index = @enumFromInt(init_func.symbol_index),
                .file = @enumFromInt(object_index),
            });
        }
    }

    // sort the initfunctions based on their priority
    mem.sort(InitFuncLoc, wasm.init_funcs.items, {}, InitFuncLoc.lessThan);

    if (wasm.init_funcs.items.len > 0) {
        const loc = wasm.globals.get(wasm.preloaded_strings.__wasm_call_ctors).?;
        try wasm.mark(loc);
    }
}

/// Creates a function body for the `__wasm_call_ctors` symbol.
/// Loops over all constructors found in `init_funcs` and calls them
/// respectively based on their priority which was sorted by `setupInitFunctions`.
/// NOTE: This function must be called after we merged all sections to ensure the
/// references to the function stored in the symbol have been finalized so we end
/// up calling the resolved function.
fn initializeCallCtorsFunction(wasm: *Wasm) !void {
    const gpa = wasm.base.comp.gpa;

    var function_body: std.ArrayListUnmanaged(u8) = .empty;
    defer function_body.deinit(gpa);
    const writer = function_body.writer(gpa);

    // Create the function body
    {
        // Write locals count (we have none)
        try leb.writeUleb128(writer, @as(u32, 0));

        // call constructors
        for (wasm.init_funcs.items) |init_func_loc| {
            const symbol = init_func_loc.getSymbol(wasm);
            const func_index = symbol.pointee.function;
            const func = func_index.ptr(wasm);
            const ty = wasm.func_types.items[func.type_index];

            // Call function by its function index
            try writer.writeByte(@intFromEnum(std.wasm.Opcode.call));
            try leb.writeUleb128(writer, @intFromEnum(func_index));

            // drop all returned values from the stack as __wasm_call_ctors has no return value
            for (ty.returns) |_| {
                try writer.writeByte(@intFromEnum(std.wasm.Opcode.drop));
            }
        }

        // End function body
        try writer.writeByte(@intFromEnum(std.wasm.Opcode.end));
    }

    const empty_valtype_list = try internValtypeList(wasm, &.{});
    const empty_function_sig = try addFuncType(wasm, .{
        .params = empty_valtype_list,
        .returns = empty_valtype_list,
    });
    try wasm.createSyntheticFunction(
        wasm.preloaded_strings.__wasm_call_ctors,
        empty_function_sig,
        function_body.items,
    );
}

fn createSyntheticFunction(
    wasm: *Wasm,
    symbol_name: String,
    function_type_index: FunctionType.Index,
    function_body: []const u8,
) !void {
    const gpa = wasm.base.comp.gpa;
    const loc = wasm.globals.get(symbol_name).?;
    assert(loc.file == .none);
    const symbol = syntheticSymbolPtr(wasm, loc.index);
    if (!symbol.flags.alive) return;
    const function_index: FunctionIndex = @enumFromInt(wasm.functions.count());
    try wasm.functions.putNoClobber(
        gpa,
        .{ .file = .none, .index = @intFromEnum(function_index) },
        .{ .type_index = function_type_index, .symbol_index = loc.index },
    );
    symbol.pointee = .{ .function = function_index };

    // Create the Atom to output into the final binary.
    const atom_index = try wasm.createAtom(loc.index, .none);
    const atom = wasm.atomPtr(atom_index);
    atom.code = try addRelocatableDataPayload(wasm, function_body);
    try wasm.appendAtomAtIndex(wasm.code_section_index.unwrap().?, atom_index);
}

/// Unlike `createSyntheticFunction` this function is to be called by
/// the codegeneration backend. This will not allocate the created Atom yet.
/// Returns the index of the symbol.
pub fn createFunction(
    wasm: *Wasm,
    symbol_name: []const u8,
    function_type: FunctionType.Index,
    function_body: *std.ArrayList(u8),
    relocations: *std.ArrayList(Relocation),
) !Symbol.Index {
    return wasm.zig_object.?.createFunction(wasm, symbol_name, function_type, function_body, relocations);
}

fn initializeTLSFunction(wasm: *Wasm) !void {
    const comp = wasm.base.comp;
    const gpa = comp.gpa;

    // ensure function is marked as we must emit it
    wasm.finalSymbolByLoc(wasm.globals.get(wasm.preloaded_strings.__wasm_init_tls).?).mark();

    var function_body: std.ArrayListUnmanaged(u8) = .empty;
    defer function_body.deinit(gpa);
    const writer = function_body.writer(gpa);

    // locals
    try writer.writeByte(0);

    // If there's a TLS segment, initialize it during runtime using the bulk-memory feature
    if (wasm.data_segments.getIndex(".tdata")) |data_index| {
        const segment_index = wasm.data_segments.entries.items(.value)[data_index];
        const segment = segment_index.ptr(wasm);

        const param_local: u32 = 0;

        try writer.writeByte(@intFromEnum(std.wasm.Opcode.local_get));
        try leb.writeUleb128(writer, param_local);

        const tls_base_loc = wasm.globals.get(wasm.preloaded_strings.__tls_base).?;
        try writer.writeByte(@intFromEnum(std.wasm.Opcode.global_set));
        try leb.writeUleb128(writer, wasm.finalSymbolByLoc(tls_base_loc).index);

        // load stack values for the bulk-memory operation
        {
            try writer.writeByte(@intFromEnum(std.wasm.Opcode.local_get));
            try leb.writeUleb128(writer, param_local);

            try writer.writeByte(@intFromEnum(std.wasm.Opcode.i32_const));
            try leb.writeUleb128(writer, @as(u32, 0)); //segment offset

            try writer.writeByte(@intFromEnum(std.wasm.Opcode.i32_const));
            try leb.writeUleb128(writer, @as(u32, segment.size)); //segment offset
        }

        // perform the bulk-memory operation to initialize the data segment
        try writer.writeByte(@intFromEnum(std.wasm.Opcode.misc_prefix));
        try leb.writeUleb128(writer, std.wasm.miscOpcode(.memory_init));
        // segment immediate
        try leb.writeUleb128(writer, @as(u32, @intCast(data_index)));
        // memory index immediate (always 0)
        try leb.writeUleb128(writer, @as(u32, 0));
    }

    // If we have to perform any TLS relocations, call the corresponding function
    // which performs all runtime TLS relocations. This is a synthetic function,
    // generated by the linker.
    if (wasm.globals.get(wasm.preloaded_strings.__wasm_apply_global_tls_relocs)) |loc| {
        try writer.writeByte(@intFromEnum(std.wasm.Opcode.call));
        try leb.writeUleb128(writer, wasm.finalSymbolByLoc(loc).index);
        wasm.finalSymbolByLoc(loc).mark();
    }

    try writer.writeByte(@intFromEnum(std.wasm.Opcode.end));

    try wasm.createSyntheticFunction(
        wasm.preloaded_strings.__wasm_init_tls,
        try addFuncType(wasm, .{
            .params = try internValtypeList(wasm, &.{.i32}),
            .returns = try internValtypeList(wasm, &.{}),
        }),
        function_body.items,
    );
}

fn mergeImports(wasm: *Wasm) error{OutOfMemory}!void {
    const gpa = wasm.base.comp.gpa;
    log.debug("merging imports", .{});
    for (wasm.resolved_symbols.keys()) |symbol_loc| {
        const object_id = symbol_loc.file.unwrap() orelse {
            // Synthetic symbols will already exist in the `import` section
            continue;
        };

        const symbol = wasm.finalSymbolByLoc(symbol_loc);
        if (!symbol.flags.alive) continue;
        if (!symbol.requiresImport()) continue;
        if (symbol.name == wasm.preloaded_strings.__indirect_function_table) continue;

        // TODO: De-duplicate imports when they contain the same names and type
        log.debug("importing symbol '{s}' from the host", .{wasm.stringSlice(symbol.name)});
        switch (symbol.flags.tag) {
            .function => {
                const function_import = functionImportBySymbolIndex(wasm, object_id, symbol_loc.index);
                try wasm.function_imports.append(gpa, function_import.*);
                symbol.pointee = .{ .function_import = @enumFromInt(wasm.function_imports.items.len - 1) };
            },
            .global => {
                const global_import = globalImportBySymbolIndex(wasm, object_id, symbol_loc.index);
                try wasm.global_imports.append(gpa, global_import.*);
                symbol.pointee = .{ .global_import = @enumFromInt(wasm.global_imports.items.len - 1) };
            },
            .table => {
                const table_import = tableImportBySymbolIndex(wasm, object_id, symbol_loc.index);
                try wasm.table_imports.append(gpa, table_import.*);
                symbol.pointee = .{ .table_import = @enumFromInt(wasm.table_imports.items.len - 1) };
            },

            .data => unreachable,
            .section => unreachable,
            .event => unreachable,

            .dead => unreachable,
            .uninitialized => unreachable,
        }
    }

    log.debug("merged {d} functions, {d} globals, {d} tables", .{
        wasm.function_imports.items.len, wasm.global_imports.items.len, wasm.table_imports.items.len,
    });
}

/// Takes the global, function and table section from each linked object file
/// and merges it into a single section for each.
/// Mutates symbol data.
fn mergeSections(wasm: *Wasm) !void {
    const gpa = wasm.base.comp.gpa;

    var removed_duplicates = std.ArrayList(SymbolLoc).init(gpa);
    defer removed_duplicates.deinit();

    for (wasm.resolved_symbols.keys()) |sym_loc| {
        const object_id = sym_loc.file.unwrap() orelse {
            // Synthetic symbols already live in the corresponding sections.
            continue;
        };

        const symbol = objectSymbol(wasm, object_id, sym_loc.index);
        // Skip undefined symbols as they go in the `import` section.
        if (!symbol.flags.alive or symbol.flags.undefined) continue;

        switch (symbol.tag) {
            .function => {
                const gop = try wasm.functions.getOrPut(gpa, .{
                    .file = sym_loc.file,
                    .index = if (object_id == .zig_object)
                        @intFromEnum(symbol.pointee.function_zo)
                    else
                        @intFromEnum(symbol.pointee.function_obj),
                });
                if (gop.found_existing) {
                    // We found an alias to the same function. Discard this
                    // symbol in favor of the original symbol and point the
                    // discard function to it. This ensures we only emit a
                    // single function, instead of duplicates. We favor keeping
                    // the global over a local.
                    const original_loc: SymbolLoc = .{ .file = gop.key_ptr.file, .index = gop.value_ptr.sym_index };
                    const original_sym = wasm.finalSymbolByLoc(original_loc);
                    if (original_sym.flags.binding == .local and symbol.flags.binding != .local) {
                        original_sym.unmark();
                        try wasm.discarded.put(gpa, original_loc, sym_loc);
                        try removed_duplicates.append(original_loc);
                    } else {
                        symbol.unmark();
                        try wasm.discarded.putNoClobber(gpa, sym_loc, original_loc);
                        try removed_duplicates.append(sym_loc);
                        continue;
                    }
                }
                gop.value_ptr.* = .{
                    .function_type = objectFunction(wasm, object_id, sym_loc.index),
                    .symbol_index = sym_loc.index,
                };
                symbol.pointee = .{ .function = @enumFromInt(gop.index) };
            },
            .global => {
                const original_global = objectGlobal(wasm, object_id, sym_loc.index);
                symbol.pointee = .{ .global = try addGlobal(wasm, original_global.*) };
            },
            .table => {
                assert(object_id != .zig_object);
                const original_table = symbol.pointee.table_obj.ptr(wasm);
                symbol.pointee = .{ .table = try addTable(wasm, original_table.*) };
            },
            .dead, .undefined => unreachable,
            else => {},
        }
    }

    // For any removed duplicates, remove them from the resolved symbols list
    for (removed_duplicates.items) |sym_loc| {
        assert(wasm.resolved_symbols.swapRemove(sym_loc));
        gc_log.debug("Removed duplicate for function '{s}'", .{wasm.symbolLocName(sym_loc)});
    }

    log.debug("Merged ({d}) functions", .{wasm.functions.count()});
    log.debug("Merged ({d}) globals", .{wasm.output_globals.items.len});
    log.debug("Merged ({d}) tables", .{wasm.tables.items.len});
}

fn checkExportNames(wasm: *Wasm) !void {
    const force_exp_names = wasm.export_symbol_names;
    const diags = &wasm.base.comp.link_diags;
    if (force_exp_names.len > 0) {
        var failed_exports = false;

        for (force_exp_names) |exp_name| {
            const exp_name_interned = try wasm.internString(exp_name);
            const loc = wasm.globals.get(exp_name_interned) orelse {
                var err = try diags.addErrorWithNotes(0);
                try err.addMsg("could not export '{s}', symbol not found", .{exp_name});
                failed_exports = true;
                continue;
            };

            const symbol = wasm.finalSymbolByLoc(loc);
            symbol.flags.exported = true;
        }

        if (failed_exports) {
            return error.LinkFailure;
        }
    }
}

fn setupExports(wasm: *Wasm) !void {
    const comp = wasm.base.comp;
    const gpa = comp.gpa;
    log.debug("building exports from symbols", .{});

    for (wasm.resolved_symbols.keys()) |sym_loc| {
        const symbol = wasm.finalSymbolByLoc(sym_loc);
        if (!symbol.isExported(comp.config.rdynamic)) continue;

        (try wasm.exports.addOne(gpa)).* = switch (symbol.tag) {
            .data => exp: {
                const global_index = try addGlobal(wasm, .{
                    .valtype = .i32,
                    .mutable = false,
                    .expr = try addInitExpr(wasm, .{ .i32_const = @intCast(symbol.virtual_address) }),
                });
                break :exp .{
                    .name = symbol.name,
                    .kind = .global,
                    .index = global_index,
                };
            },
            .function => .{
                .name = symbol.name,
                .kind = .function,
                .index = symbol.pointee.function,
            },
            .global => .{
                .name = symbol.name,
                .kind = .global,
                .index = symbol.pointee.global,
            },
            .table => .{
                .name = symbol.name,
                .kind = .table,
                .index = symbol.pointee.table,
            },

            .section => unreachable,
            .event => unreachable,
            .dead => unreachable,
            .uninitialized => unreachable,
        };
        const exp = &wasm.exports.items[wasm.exports.items.len - 1];
        log.debug("exporting symbol '{s}' as '{s}' at index {d}", .{
            wasm.stringSlice(symbol.name), wasm.stringSlice(exp.name), exp.index,
        });
    }

    log.debug("finished setting up {d} exports", .{wasm.exports.items.len});
}

fn setupStart(wasm: *Wasm) !void {
    const comp = wasm.base.comp;
    const diags = &wasm.base.comp.link_diags;
    // do not export entry point if user set none or no default was set.
    const entry_name = wasm.entry_name.unwrap() orelse return;

    const symbol_loc = wasm.globals.get(entry_name) orelse {
        var err = try diags.addErrorWithNotes(1);
        try err.addMsg("entry symbol '{s}' missing", .{wasm.stringSlice(entry_name)});
        try err.addNote("'-fno-entry' suppresses this error", .{});
        return error.LinkFailure;
    };

    const symbol = wasm.finalSymbolByLoc(symbol_loc);
    if (symbol.tag != .function)
        return diags.fail("entry symbol '{s}' is not a function", .{wasm.stringSlice(entry_name)});

    // Ensure the symbol is exported so host environment can access it
    if (comp.config.output_mode != .Obj) {
        symbol.flags.exported = true;
    }
}

/// Sets up the memory section of the wasm module, as well as the stack.
fn setupMemory(wasm: *Wasm) !void {
    const comp = wasm.base.comp;
    const diags = &wasm.base.comp.link_diags;
    const shared_memory = comp.config.shared_memory;
    log.debug("setting up memory layout", .{});
    const page_size = std.wasm.page_size; // 64kb
    const stack_alignment: Alignment = .@"16"; // wasm's stack alignment as specified by tool-convention
    const heap_alignment: Alignment = .@"16"; // wasm's heap alignment as specified by tool-convention

    // Always place the stack at the start by default unless the user specified the global-base flag.
    const place_stack_first, var memory_ptr: u64 = if (wasm.global_base) |base| .{ false, base } else .{ true, 0 };

    const is_obj = comp.config.output_mode == .Obj;

    const stack_ptr: GlobalIndex = if (wasm.globals.get(wasm.preloaded_strings.__stack_pointer)) |loc| index: {
        const sym = wasm.finalSymbolByLoc(loc);
        break :index sym.index - wasm.imported_globals_count;
    } else null;

    if (place_stack_first and !is_obj) {
        memory_ptr = stack_alignment.forward(memory_ptr);
        memory_ptr += wasm.base.stack_size;
        // We always put the stack pointer global at index 0
        if (stack_ptr) |index| {
            index.ptr(wasm).init = try addInitExpr(wasm, .{
                .i32_const = @bitCast(@as(u32, @intCast(memory_ptr))),
            });
        }
    }

    var offset: u32 = @intCast(memory_ptr);
    var data_seg_it = wasm.data_segments.iterator();
    while (data_seg_it.next()) |entry| {
        const segment = entry.value_ptr.ptr(wasm);
        memory_ptr = segment.alignment.forward(memory_ptr);

        // set TLS-related symbols
        if (mem.eql(u8, entry.key_ptr.*, ".tdata")) {
            if (wasm.globals.get(wasm.preloaded_strings.__tls_size)) |loc| {
                const sym = wasm.finalSymbolByLoc(loc);
                sym.pointee.global.ptr(wasm).init = try wasm.addInitExpr(.{ .i32_const = @intCast(segment.size) });
            }
            if (wasm.globals.get(wasm.preloaded_strings.__tls_align)) |loc| {
                const sym = wasm.finalSymbolByLoc(loc);
                sym.pointee.global.ptr(wasm).init = try wasm.addInitExpr(.{ .i32_const = @intCast(segment.alignment.toByteUnits().?) });
            }
            if (wasm.globals.get(wasm.preloaded_strings.__tls_base)) |loc| {
                const sym = wasm.finalSymbolByLoc(loc);
                sym.pointee.global.ptr(wasm).init = try wasm.addInitExpr(.{ .i32_const = if (shared_memory) 0 else @intCast(memory_ptr) });
            }
        }

        memory_ptr += segment.size;
        segment.offset = offset;
        offset += segment.size;
    }

    // create the memory init flag which is used by the init memory function
    if (shared_memory and wasm.hasPassiveInitializationSegments()) {
        memory_ptr = mem.alignForward(u64, memory_ptr, 4); // Align to pointer size.
        const sym_index = try wasm.createSyntheticSymbol(wasm.preloaded_strings.__wasm_init_memory_flag, .{
            .tag = .data,
            .alive = true,
        });
        const sym = syntheticSymbolPtr(wasm, sym_index);
        sym.virtual_address = @intCast(memory_ptr);
        memory_ptr += 4;
    }

    if (!place_stack_first and !is_obj) {
        memory_ptr = stack_alignment.forward(memory_ptr);
        memory_ptr += wasm.base.stack_size;
        if (stack_ptr) |index| {
            wasm.output_globals.items[index].init = try addInitExpr(wasm, .{
                .i32_const = @bitCast(@as(u32, @intCast(memory_ptr))),
            });
        }
    }

    // One of the linked object files has a reference to the __heap_base symbol.
    // We must set its virtual address so it can be used in relocations.
    if (wasm.globals.get(wasm.preloaded_strings.__heap_base)) |loc| {
        const symbol = wasm.finalSymbolByLoc(loc);
        symbol.virtual_address = @intCast(heap_alignment.forward(memory_ptr));
    }

    // Setup the max amount of pages
    // For now we only support wasm32 by setting the maximum allowed memory size 2^32-1
    const max_memory_allowed: u64 = (1 << 32) - 1;

    if (wasm.initial_memory) |initial_memory| {
        if (!mem.isAlignedGeneric(u64, initial_memory, page_size)) {
            diags.addError("initial memory must be {d}-byte aligned", .{page_size});
        }
        if (memory_ptr > initial_memory) {
            diags.addError("initial memory too small, must be at least {d} bytes", .{memory_ptr});
        }
        if (initial_memory > max_memory_allowed) {
            diags.addError("initial memory exceeds maximum memory {d}", .{max_memory_allowed});
        }
        memory_ptr = initial_memory;
    }
    memory_ptr = mem.alignForward(u64, memory_ptr, std.wasm.page_size);
    // In case we do not import memory, but define it ourselves,
    // set the minimum amount of pages on the memory section.
    wasm.memories.limits.min = @intCast(memory_ptr / page_size);
    log.debug("total memory pages: {d}", .{wasm.memories.limits.min});

    if (wasm.globals.get(wasm.preloaded_strings.__heap_end)) |loc| {
        const symbol = wasm.finalSymbolByLoc(loc);
        symbol.virtual_address = @intCast(memory_ptr);
    }

    if (wasm.max_memory) |max_memory| {
        if (!mem.isAlignedGeneric(u64, max_memory, page_size)) {
            diags.addError("maximum memory must be {d}-byte aligned", .{page_size});
        }
        if (memory_ptr > max_memory) {
            diags.addError("maximum memory too small, must be at least {d} bytes", .{memory_ptr});
        }
        if (max_memory > max_memory_allowed) {
            diags.addError("maximum memory exceeds maximum amount {d}", .{max_memory_allowed});
        }
        wasm.memories.limits.max = @intCast(max_memory / page_size);
        wasm.memories.limits.flags.has_max = true;
        if (shared_memory)
            wasm.memories.limits.flags.is_shared = true;
        log.debug("maximum memory pages: {?d}", .{wasm.memories.limits.max});
    }
}

/// From a given object's index and the index of the segment, returns the corresponding
/// index of the segment within the final data section. When the segment does not yet
/// exist, a new one will be initialized and appended. The new index will be returned in that case.
pub fn getMatchingSegment(wasm: *Wasm, object_id: ObjectId, symbol_index: Symbol.Index) !Segment.Index {
    const comp = wasm.base.comp;
    const gpa = comp.gpa;
    const diags = &wasm.base.comp.link_diags;
    const symbol = objectSymbols(wasm, object_id)[@intFromEnum(symbol_index)];
    const index: Segment.Index = @enumFromInt(wasm.segments.items.len);
    const shared_memory = comp.config.shared_memory;

    switch (symbol.tag) {
        .data => {
            const segment_info = objectSegmentInfo(wasm, object_id)[symbol.index];
            const merge_segment = comp.config.output_mode != .Obj;
            const result = try wasm.data_segments.getOrPut(gpa, segment_info.outputName(wasm, merge_segment));
            if (!result.found_existing) {
                result.value_ptr.* = index;
                try wasm.segments.append(gpa, .{
                    .size = 0,
                    .offset = 0,
                    .flags = .{
                        .is_passive = shared_memory,
                        .has_memindex = false,
                        .alignment = .@"1",
                    },
                });
                try wasm.segment_info.putNoClobber(gpa, index, .{
                    .name = try gpa.dupe(u8, segment_info.name),
                    .alignment = segment_info.alignment,
                    .flags = segment_info.flags,
                });
                return index;
            } else return result.value_ptr.*;
        },
        .function => return wasm.code_section_index.unwrap() orelse blk: {
            wasm.code_section_index = index.toOptional();
            try wasm.appendDummySegment();
            break :blk index;
        },
        .section => {
            const section_name = wasm.objectSymbol(object_id, symbol_index).name;

            inline for (@typeInfo(CustomSections).@"struct".fields) |field| {
                if (@field(wasm.custom_sections, field.name).name == section_name) {
                    const field_ptr = &@field(wasm.custom_sections, field.name).index;
                    return field_ptr.unwrap() orelse {
                        field_ptr.* = index.toOptional();
                        try wasm.appendDummySegment();
                        return index;
                    };
                }
            } else {
                return diags.failParse(objectPath(wasm, object_id), "unknown section: {s}", .{
                    wasm.stringSlice(section_name),
                });
            }
        },
        .global => unreachable,
        .event => unreachable,
        .table => unreachable,
        .dead => unreachable,
        .uninitialized => unreachable,
    }
}

/// Appends a new segment with default field values
fn appendDummySegment(wasm: *Wasm) !void {
    const gpa = wasm.base.comp.gpa;
    try wasm.segments.append(gpa, .{
        .alignment = .@"1",
        .size = 0,
        .offset = 0,
        .flags = 0,
    });
}

pub fn loadInput(wasm: *Wasm, input: link.Input) !void {
    const comp = wasm.base.comp;
    const gpa = comp.gpa;

    if (comp.verbose_link) {
        comp.mutex.lock(); // protect comp.arena
        defer comp.mutex.unlock();

        const argv = &wasm.dump_argv_list;
        switch (input) {
            .res => unreachable,
            .dso_exact => unreachable,
            .dso => unreachable,
            .object, .archive => |obj| try argv.append(gpa, try obj.path.toString(comp.arena)),
        }
    }

    switch (input) {
        .res => unreachable,
        .dso_exact => unreachable,
        .dso => unreachable,
        .object => |obj| try parseObject(wasm, obj),
        .archive => |obj| try parseArchive(wasm, obj),
    }
}

pub fn flush(wasm: *Wasm, arena: Allocator, tid: Zcu.PerThread.Id, prog_node: std.Progress.Node) link.File.FlushError!void {
    const comp = wasm.base.comp;
    const use_lld = build_options.have_llvm and comp.config.use_lld;

    if (use_lld) {
        return wasm.linkWithLLD(arena, tid, prog_node);
    }
    return wasm.flushModule(arena, tid, prog_node);
}

pub fn flushModule(wasm: *Wasm, arena: Allocator, tid: Zcu.PerThread.Id, prog_node: std.Progress.Node) link.File.FlushError!void {
    const tracy = trace(@src());
    defer tracy.end();

    const comp = wasm.base.comp;
    const shared_memory = comp.config.shared_memory;
    const diags = &comp.link_diags;
    if (wasm.llvm_object) |llvm_object| {
        try wasm.base.emitLlvmObject(arena, llvm_object, prog_node);
        const use_lld = build_options.have_llvm and comp.config.use_lld;
        if (use_lld) return;
    }

    if (comp.verbose_link) Compilation.dump_argv(wasm.dump_argv_list.items);

    const sub_prog_node = prog_node.start("Wasm Flush", 0);
    defer sub_prog_node.end();

    const module_obj_path: ?Path = if (wasm.base.zcu_object_sub_path) |path| .{
        .root_dir = wasm.base.emit.root_dir,
        .sub_path = if (fs.path.dirname(wasm.base.emit.sub_path)) |dirname|
            try fs.path.join(arena, &.{ dirname, path })
        else
            path,
    } else null;

    if (wasm.zig_object) |zig_object| try zig_object.flushModule(wasm, tid);

    if (module_obj_path) |path| openParseObjectReportingFailure(wasm, path);

    if (wasm.zig_object != null) {
        try wasm.resolveSymbolsInObject(.zig_object);
    }
    if (diags.hasErrors()) return error.LinkFailure;

    for (0..wasm.objects.items.len) |object_index| {
        try wasm.resolveSymbolsInObject(@enumFromInt(object_index));
    }
    if (diags.hasErrors()) return error.LinkFailure;

    var emit_features_count: u32 = 0;
    var enabled_features: [@typeInfo(Feature.Tag).@"enum".fields.len]bool = undefined;
    try wasm.validateFeatures(&enabled_features, &emit_features_count);
    try wasm.resolveSymbolsInArchives();
    if (diags.hasErrors()) return error.LinkFailure;

    try wasm.resolveLazySymbols();

    if (comp.config.output_mode != .Obj and wasm.import_symbols)
        try wasm.checkUndefinedSymbols();

    try wasm.checkExportNames();

    try wasm.setupInitFunctions();
    if (diags.hasErrors()) return error.LinkFailure;
    try wasm.setupStart();

    try wasm.markReferences();
    try wasm.mergeImports();
    try wasm.mergeSections();
    try sortDataSegments(wasm);
    try wasm.allocateAtoms();
    try wasm.setupMemory();
    if (diags.hasErrors()) return error.LinkFailure;

    wasm.allocateVirtualAddresses();
    wasm.mapFunctionTable();

    // No code to emit, so also no ctors to call
    if (wasm.code_section_index == .none) {
        // Make sure to remove it from the resolved symbols so we do not emit
        // it within any section. TODO: Remove this once we implement garbage collection.
        const loc = wasm.globals.get(wasm.preloaded_strings.__wasm_call_ctors).?;
        assert(wasm.resolved_symbols.swapRemove(loc));
    } else {
        try wasm.initializeCallCtorsFunction();
    }

    // Passive segments are used to avoid memory being reinitialized on each
    // thread's instantiation. These passive segments are initialized and
    // dropped in __wasm_init_memory, which is registered as the start function
    // We also initialize bss segments (using memory.fill) as part of this
    // function.
    if (wasm.hasPassiveInitializationSegments())
        try wasm.setupInitMemoryFunction();

    // When we have TLS GOT entries and shared memory is enabled,
    // we must perform runtime relocations or else we don't create the function.
    if (shared_memory) {
        if (wasm.requiresTlsReloc())
            try wasm.setupTLSRelocationsFunction();

        try wasm.initializeTLSFunction();
    }

    // If required, sets the function index in the `start` section.
    if (wasm.globals.get(wasm.preloaded_strings.__wasm_init_memory)) |loc| {
        wasm.entry = wasm.finalSymbolByLoc(loc).index;
    }

    if (comp.config.output_mode != .Obj)
        try wasm.setupExports();

    if (diags.hasErrors()) return error.LinkFailure;

    try wasm.writeToFile(enabled_features, emit_features_count, arena);
}

/// Writes the WebAssembly in-memory module to the file
fn writeToFile(
    wasm: *Wasm,
    enabled_features: [@typeInfo(Feature.Tag).@"enum".fields.len]bool,
    feature_count: u32,
    arena: Allocator,
) !void {
    const comp = wasm.base.comp;
    const diags = &comp.link_diags;
    const gpa = comp.gpa;
    const use_llvm = comp.config.use_llvm;
    const use_lld = build_options.have_llvm and comp.config.use_lld;
    const shared_memory = comp.config.shared_memory;
    const import_memory = comp.config.import_memory;
    const export_memory = comp.config.export_memory;

    // Size of each section header
    const header_size = 5 + 1;
    // The amount of sections that will be written
    var section_count: u32 = 0;
    // Index of the code section. Used to tell relocation table where the section lives.
    var code_section_index: ?u32 = null;
    // Index of the data section. Used to tell relocation table where the section lives.
    var data_section_index: ?u32 = null;
    const is_obj = comp.config.output_mode == .Obj or (!use_llvm and use_lld);

    var binary_bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer binary_bytes.deinit(gpa);
    const binary_writer = binary_bytes.writer(gpa);

    // We write the magic bytes at the end so they will only be written
    // if everything succeeded as expected. So populate with 0's for now.
    try binary_writer.writeAll(&[_]u8{0} ** 8);

    // Type section
    if (wasm.func_types.items.len != 0) {
        const header_offset = try reserveVecSectionHeader(gpa, &binary_bytes);
        log.debug("Writing type section. Count: ({d})", .{wasm.func_types.items.len});
        for (wasm.func_types.items) |func_type| {
            try leb.writeUleb128(binary_writer, std.wasm.function_type);
            try leb.writeUleb128(binary_writer, @as(u32, @intCast(func_type.params.len)));
            for (func_type.params) |param_ty| {
                try leb.writeUleb128(binary_writer, std.wasm.valtype(param_ty));
            }
            try leb.writeUleb128(binary_writer, @as(u32, @intCast(func_type.returns.len)));
            for (func_type.returns) |ret_ty| {
                try leb.writeUleb128(binary_writer, std.wasm.valtype(ret_ty));
            }
        }

        try writeVecSectionHeader(
            binary_bytes.items,
            header_offset,
            .type,
            @intCast(binary_bytes.items.len - header_offset - header_size),
            @intCast(wasm.func_types.items.len),
        );
        section_count += 1;
    }

    // Import section
    const total_imports_len = wasm.function_imports.items.len + wasm.global_imports.items.len +
        wasm.table_imports.items.len + wasm.memory_imports.items.len + @intFromBool(import_memory);

    if (total_imports_len > 0) {
        const header_offset = try reserveVecSectionHeader(gpa, &binary_bytes);

        for (wasm.function_imports.items) |*function_import| {
            const module_name = wasm.stringSlice(function_import.module_name);
            try leb.writeUleb128(binary_writer, @as(u32, @intCast(module_name.len)));
            try binary_writer.writeAll(module_name);

            const name = wasm.stringSlice(function_import.name);
            try leb.writeUleb128(binary_writer, @as(u32, @intCast(name.len)));
            try binary_writer.writeAll(name);

            try binary_writer.writeByte(@intFromEnum(std.wasm.ExternalKind.function));
            try leb.writeUleb128(binary_writer, function_import.index);
        }

        for (wasm.table_imports.items) |*table_import| {
            const module_name = wasm.stringSlice(table_import.module_name);
            try leb.writeUleb128(binary_writer, @as(u32, @intCast(module_name.len)));
            try binary_writer.writeAll(module_name);

            const name = wasm.stringSlice(table_import.name);
            try leb.writeUleb128(binary_writer, @as(u32, @intCast(name.len)));
            try binary_writer.writeAll(name);

            try binary_writer.writeByte(@intFromEnum(std.wasm.ExternalKind.table));
            try leb.writeUleb128(binary_writer, std.wasm.reftype(table_import.reftype));
            try emitLimits(binary_writer, table_import.limits);
        }

        for (wasm.memory_imports.items) |*memory_import| {
            try emitMemoryImport(wasm, binary_writer, memory_import);
        } else if (import_memory) {
            try emitMemoryImport(wasm, binary_writer, &.{
                .module_name = wasm.host_name,
                .name = if (is_obj) wasm.preloaded_strings.__linear_memory else wasm.preloaded_strings.memory,
                .limits_min = wasm.memories.limits.min,
                .limits_max = wasm.memories.limits.max,
                .limits_has_max = wasm.memories.limits.flags.has_max,
                .limits_is_shared = wasm.memories.limits.flags.is_shared,
            });
        }

        for (wasm.global_imports.items) |*global_import| {
            const module_name = wasm.stringSlice(global_import.module_name);
            try leb.writeUleb128(binary_writer, @as(u32, @intCast(module_name.len)));
            try binary_writer.writeAll(module_name);

            const name = wasm.stringSlice(global_import.name);
            try leb.writeUleb128(binary_writer, @as(u32, @intCast(name.len)));
            try binary_writer.writeAll(name);

            try binary_writer.writeByte(@intFromEnum(std.wasm.ExternalKind.global));
            try leb.writeUleb128(binary_writer, @intFromEnum(global_import.valtype));
            try binary_writer.writeByte(@intFromBool(global_import.mutable));
        }

        try writeVecSectionHeader(
            binary_bytes.items,
            header_offset,
            .import,
            @intCast(binary_bytes.items.len - header_offset - header_size),
            @intCast(total_imports_len),
        );
        section_count += 1;
    }

    // Function section
    if (wasm.functions.count() != 0) {
        const header_offset = try reserveVecSectionHeader(gpa, &binary_bytes);
        for (wasm.functions.values()) |function| {
            try leb.writeUleb128(binary_writer, function.func.type_index);
        }

        try writeVecSectionHeader(
            binary_bytes.items,
            header_offset,
            .function,
            @intCast(binary_bytes.items.len - header_offset - header_size),
            @intCast(wasm.functions.count()),
        );
        section_count += 1;
    }

    // Table section
    if (wasm.tables.items.len > 0) {
        const header_offset = try reserveVecSectionHeader(gpa, &binary_bytes);

        for (wasm.tables.items) |table| {
            try leb.writeUleb128(binary_writer, std.wasm.reftype(table.reftype));
            try emitLimits(binary_writer, table.limits);
        }

        try writeVecSectionHeader(
            binary_bytes.items,
            header_offset,
            .table,
            @intCast(binary_bytes.items.len - header_offset - header_size),
            @intCast(wasm.tables.items.len),
        );
        section_count += 1;
    }

    // Memory section
    if (!import_memory) {
        const header_offset = try reserveVecSectionHeader(gpa, &binary_bytes);

        try emitLimits(binary_writer, wasm.memories.limits);
        try writeVecSectionHeader(
            binary_bytes.items,
            header_offset,
            .memory,
            @intCast(binary_bytes.items.len - header_offset - header_size),
            1, // wasm currently only supports 1 linear memory segment
        );
        section_count += 1;
    }

    // Global section (used to emit stack pointer)
    if (wasm.output_globals.items.len > 0) {
        const header_offset = try reserveVecSectionHeader(gpa, &binary_bytes);

        for (wasm.output_globals.items) |global| {
            try binary_writer.writeByte(std.wasm.valtype(global.global_type.valtype));
            try binary_writer.writeByte(@intFromBool(global.global_type.mutable));
            try emitInit(binary_writer, global.init);
        }

        try writeVecSectionHeader(
            binary_bytes.items,
            header_offset,
            .global,
            @intCast(binary_bytes.items.len - header_offset - header_size),
            @intCast(wasm.output_globals.items.len),
        );
        section_count += 1;
    }

    // Export section
    if (wasm.exports.items.len != 0 or export_memory) {
        const header_offset = try reserveVecSectionHeader(gpa, &binary_bytes);

        for (wasm.exports.items) |exp| {
            const name = wasm.stringSlice(exp.name);
            try leb.writeUleb128(binary_writer, @as(u32, @intCast(name.len)));
            try binary_writer.writeAll(name);
            try leb.writeUleb128(binary_writer, @intFromEnum(exp.kind));
            try leb.writeUleb128(binary_writer, exp.index);
        }

        if (export_memory) {
            try leb.writeUleb128(binary_writer, @as(u32, @intCast("memory".len)));
            try binary_writer.writeAll("memory");
            try binary_writer.writeByte(std.wasm.externalKind(.memory));
            try leb.writeUleb128(binary_writer, @as(u32, 0));
        }

        try writeVecSectionHeader(
            binary_bytes.items,
            header_offset,
            .@"export",
            @intCast(binary_bytes.items.len - header_offset - header_size),
            @intCast(wasm.exports.items.len + @intFromBool(export_memory)),
        );
        section_count += 1;
    }

    if (wasm.entry) |entry_index| {
        const header_offset = try reserveVecSectionHeader(gpa, &binary_bytes);
        try writeVecSectionHeader(
            binary_bytes.items,
            header_offset,
            .start,
            @intCast(binary_bytes.items.len - header_offset - header_size),
            entry_index,
        );
    }

    // element section (function table)
    if (wasm.function_table.count() > 0) {
        const header_offset = try reserveVecSectionHeader(gpa, &binary_bytes);

        const table_loc = wasm.globals.get(wasm.preloaded_strings.__indirect_function_table).?;
        const table_sym = wasm.finalSymbolByLoc(table_loc);

        const flags: u32 = if (table_sym.index == 0) 0x0 else 0x02; // passive with implicit 0-index table or set table index manually
        try leb.writeUleb128(binary_writer, flags);
        if (flags == 0x02) {
            try leb.writeUleb128(binary_writer, table_sym.index);
        }
        try emitInit(binary_writer, .{ .i32_const = 1 }); // We start at index 1, so unresolved function pointers are invalid
        if (flags == 0x02) {
            try leb.writeUleb128(binary_writer, @as(u8, 0)); // represents funcref
        }
        try leb.writeUleb128(binary_writer, @as(u32, @intCast(wasm.function_table.count())));
        var symbol_it = wasm.function_table.keyIterator();
        while (symbol_it.next()) |symbol_loc_ptr| {
            const sym = wasm.finalSymbolByLoc(symbol_loc_ptr.*);
            assert(sym.flags.alive);
            assert(sym.index < wasm.functions.count() + wasm.imported_functions_count);
            try leb.writeUleb128(binary_writer, sym.index);
        }

        try writeVecSectionHeader(
            binary_bytes.items,
            header_offset,
            .element,
            @intCast(binary_bytes.items.len - header_offset - header_size),
            1,
        );
        section_count += 1;
    }

    // When the shared-memory option is enabled, we *must* emit the 'data count' section.
    const data_segments_count = wasm.data_segments.count() - @intFromBool(wasm.data_segments.contains(".bss") and !import_memory);
    if (data_segments_count != 0 and shared_memory) {
        const header_offset = try reserveVecSectionHeader(gpa, &binary_bytes);
        try writeVecSectionHeader(
            binary_bytes.items,
            header_offset,
            .data_count,
            @intCast(binary_bytes.items.len - header_offset - header_size),
            @intCast(data_segments_count),
        );
    }

    // Code section
    if (wasm.code_section_index != .none) {
        const header_offset = try reserveVecSectionHeader(gpa, &binary_bytes);
        const start_offset = binary_bytes.items.len - 5; // minus 5 so start offset is 5 to include entry count

        var func_it = wasm.functions.iterator();
        while (func_it.next()) |entry| {
            const sym_loc: SymbolLoc = .{ .index = entry.value_ptr.sym_index, .file = entry.key_ptr.file };
            const atom_index = wasm.symbol_atom.get(sym_loc).?;
            const atom = wasm.atomPtr(atom_index);

            if (!is_obj) {
                resolveAtomRelocs(wasm, atom);
            }
            atom.offset = @intCast(binary_bytes.items.len - start_offset);
            try leb.writeUleb128(binary_writer, atom.code.len);
            try binary_bytes.appendSlice(gpa, atom.code.slice(wasm));
        }

        try writeVecSectionHeader(
            binary_bytes.items,
            header_offset,
            .code,
            @intCast(binary_bytes.items.len - header_offset - header_size),
            @intCast(wasm.functions.count()),
        );
        code_section_index = section_count;
        section_count += 1;
    }

    // Data section
    if (data_segments_count != 0) {
        const header_offset = try reserveVecSectionHeader(gpa, &binary_bytes);

        var it = wasm.data_segments.iterator();
        var segment_count: u32 = 0;
        while (it.next()) |entry| {
            // do not output 'bss' section unless we import memory and therefore
            // want to guarantee the data is zero initialized
            if (!import_memory and mem.eql(u8, entry.key_ptr.*, ".bss")) continue;
            const segment_index = entry.value_ptr.*;
            const segment = segment_index.ptr(wasm);
            if (segment.size == 0) continue; // do not emit empty segments
            segment_count += 1;
            var atom_index = wasm.atoms.get(segment_index).?;

            try leb.writeUleb128(binary_writer, segment.flags);
            if (segment.flags & @intFromEnum(Segment.Flag.WASM_DATA_SEGMENT_HAS_MEMINDEX) != 0) {
                try leb.writeUleb128(binary_writer, @as(u32, 0)); // memory is always index 0 as we only have 1 memory entry
            }
            // when a segment is passive, it's initialized during runtime.
            if (!segment.isPassive()) {
                try emitInit(binary_writer, .{ .i32_const = @as(i32, @bitCast(segment.offset)) });
            }
            // offset into data section
            try leb.writeUleb128(binary_writer, segment.size);

            // fill in the offset table and the data segments
            var current_offset: u32 = 0;
            while (true) {
                const atom = wasm.atomPtr(atom_index);
                if (!is_obj) {
                    resolveAtomRelocs(wasm, atom);
                }

                // Pad with zeroes to ensure all segments are aligned
                if (current_offset != atom.offset) {
                    const diff = atom.offset - current_offset;
                    try binary_writer.writeByteNTimes(0, diff);
                    current_offset += diff;
                }
                assert(current_offset == atom.offset);
                try binary_bytes.appendSlice(gpa, atom.code.slice(wasm));

                current_offset += atom.code.len;
                if (atom.prev != .none) {
                    atom_index = atom.prev;
                } else {
                    // also pad with zeroes when last atom to ensure
                    // segments are aligned.
                    if (current_offset != segment.size) {
                        try binary_writer.writeByteNTimes(0, segment.size - current_offset);
                        current_offset += segment.size - current_offset;
                    }
                    break;
                }
            }
            assert(current_offset == segment.size);
        }

        try writeVecSectionHeader(
            binary_bytes.items,
            header_offset,
            .data,
            @intCast(binary_bytes.items.len - header_offset - header_size),
            @intCast(segment_count),
        );
        data_section_index = section_count;
        section_count += 1;
    }

    if (is_obj) {
        // relocations need to point to the index of a symbol in the final symbol table. To save memory,
        // we never store all symbols in a single table, but store a location reference instead.
        // This means that for a relocatable object file, we need to generate one and provide it to the relocation sections.
        var symbol_table = std.AutoArrayHashMap(SymbolLoc, u32).init(arena);
        try wasm.emitLinkSection(&binary_bytes, &symbol_table);
        if (code_section_index) |code_index| {
            try wasm.emitCodeRelocations(&binary_bytes, code_index, symbol_table);
        }
        if (data_section_index) |data_index| {
            if (wasm.data_segments.count() > 0)
                try wasm.emitDataRelocations(&binary_bytes, data_index, symbol_table);
        }
    } else if (comp.config.debug_format != .strip) {
        try wasm.emitNameSection(&binary_bytes, arena);
    }

    if (comp.config.debug_format != .strip) {
        // The build id must be computed on the main sections only,
        // so we have to do it now, before the debug sections.
        switch (wasm.base.build_id) {
            .none => {},
            .fast => {
                var id: [16]u8 = undefined;
                std.crypto.hash.sha3.TurboShake128(null).hash(binary_bytes.items, &id, .{});
                var uuid: [36]u8 = undefined;
                _ = try std.fmt.bufPrint(&uuid, "{s}-{s}-{s}-{s}-{s}", .{
                    std.fmt.fmtSliceHexLower(id[0..4]),
                    std.fmt.fmtSliceHexLower(id[4..6]),
                    std.fmt.fmtSliceHexLower(id[6..8]),
                    std.fmt.fmtSliceHexLower(id[8..10]),
                    std.fmt.fmtSliceHexLower(id[10..]),
                });
                try emitBuildIdSection(&binary_bytes, &uuid);
            },
            .hexstring => |hs| {
                var buffer: [32 * 2]u8 = undefined;
                const str = std.fmt.bufPrint(&buffer, "{s}", .{
                    std.fmt.fmtSliceHexLower(hs.toSlice()),
                }) catch unreachable;
                try emitBuildIdSection(&binary_bytes, str);
            },
            else => |mode| {
                var err = try diags.addErrorWithNotes(0);
                try err.addMsg("build-id '{s}' is not supported for WebAssembly", .{@tagName(mode)});
            },
        }

        var debug_bytes = std.ArrayList(u8).init(gpa);
        defer debug_bytes.deinit();

        inline for (@typeInfo(CustomSections).@"struct".fields) |field| {
            if (@field(wasm.custom_sections, field.name).index.unwrap()) |index| {
                var atom = wasm.atomPtr(wasm.atoms.get(index).?);
                while (true) {
                    resolveAtomRelocs(wasm, atom);
                    try debug_bytes.appendSlice(atom.code.slice(wasm));
                    if (atom.prev == .none) break;
                    atom = wasm.atomPtr(atom.prev);
                }
                if (debug_bytes.items.len > 0)
                    try emitDebugSection(gpa, &binary_bytes, debug_bytes.items, field.name);
                debug_bytes.clearRetainingCapacity();
            }
        }

        try emitProducerSection(&binary_bytes);
        if (feature_count > 0) {
            try emitFeaturesSection(&binary_bytes, &enabled_features, feature_count);
        }
    }

    // Only when writing all sections executed properly we write the magic
    // bytes. This allows us to easily detect what went wrong while generating
    // the final binary.
    {
        const src = std.wasm.magic ++ std.wasm.version;
        binary_bytes.items[0..src.len].* = src;
    }

    // Finally, write the entire binary into the file.
    const file = wasm.base.file.?;
    try file.pwriteAll(binary_bytes.items, 0);
    try file.setEndPos(binary_bytes.items.len);
}

fn emitDebugSection(
    gpa: Allocator,
    binary_bytes: *std.ArrayListUnmanaged(u8),
    data: []const u8,
    name: []const u8,
) !void {
    assert(data.len > 0);
    const header_offset = try reserveCustomSectionHeader(gpa, binary_bytes);
    const writer = binary_bytes.writer();
    try leb.writeUleb128(writer, @as(u32, @intCast(name.len)));
    try writer.writeAll(name);

    const start = binary_bytes.items.len - header_offset;
    log.debug("Emit debug section: '{s}' start=0x{x:0>8} end=0x{x:0>8}", .{ name, start, start + data.len });
    try writer.writeAll(data);

    try writeCustomSectionHeader(
        binary_bytes.items,
        header_offset,
        @as(u32, @intCast(binary_bytes.items.len - header_offset - 6)),
    );
}

fn emitProducerSection(gpa: Allocator, binary_bytes: *std.ArrayListUnmanaged(u8)) !void {
    const header_offset = try reserveCustomSectionHeader(gpa, binary_bytes);

    const writer = binary_bytes.writer();
    const producers = "producers";
    try leb.writeUleb128(writer, @as(u32, @intCast(producers.len)));
    try writer.writeAll(producers);

    try leb.writeUleb128(writer, @as(u32, 2)); // 2 fields: Language + processed-by

    // used for the Zig version
    var version_buf: [100]u8 = undefined;
    const version = try std.fmt.bufPrint(&version_buf, "{}", .{build_options.semver});

    // language field
    {
        const language = "language";
        try leb.writeUleb128(writer, @as(u32, @intCast(language.len)));
        try writer.writeAll(language);

        // field_value_count (TODO: Parse object files for producer sections to detect their language)
        try leb.writeUleb128(writer, @as(u32, 1));

        // versioned name
        {
            try leb.writeUleb128(writer, @as(u32, 3)); // len of "Zig"
            try writer.writeAll("Zig");

            try leb.writeUleb128(writer, @as(u32, @intCast(version.len)));
            try writer.writeAll(version);
        }
    }

    // processed-by field
    {
        const processed_by = "processed-by";
        try leb.writeUleb128(writer, @as(u32, @intCast(processed_by.len)));
        try writer.writeAll(processed_by);

        // field_value_count (TODO: Parse object files for producer sections to detect other used tools)
        try leb.writeUleb128(writer, @as(u32, 1));

        // versioned name
        {
            try leb.writeUleb128(writer, @as(u32, 3)); // len of "Zig"
            try writer.writeAll("Zig");

            try leb.writeUleb128(writer, @as(u32, @intCast(version.len)));
            try writer.writeAll(version);
        }
    }

    try writeCustomSectionHeader(
        binary_bytes.items,
        header_offset,
        @as(u32, @intCast(binary_bytes.items.len - header_offset - 6)),
    );
}

fn emitBuildIdSection(gpa: Allocator, binary_bytes: *std.ArrayListUnmanaged(u8), build_id: []const u8) !void {
    const header_offset = try reserveCustomSectionHeader(gpa, binary_bytes);

    const writer = binary_bytes.writer();
    const hdr_build_id = "build_id";
    try leb.writeUleb128(writer, @as(u32, @intCast(hdr_build_id.len)));
    try writer.writeAll(hdr_build_id);

    try leb.writeUleb128(writer, @as(u32, 1));
    try leb.writeUleb128(writer, @as(u32, @intCast(build_id.len)));
    try writer.writeAll(build_id);

    try writeCustomSectionHeader(
        binary_bytes.items,
        header_offset,
        @as(u32, @intCast(binary_bytes.items.len - header_offset - 6)),
    );
}

fn emitFeaturesSection(
    gpa: Allocator,
    binary_bytes: *std.ArrayListUnmanaged(u8),
    enabled_features: []const bool,
    features_count: u32,
) !void {
    const header_offset = try reserveCustomSectionHeader(gpa, binary_bytes);

    const writer = binary_bytes.writer();
    const target_features = "target_features";
    try leb.writeUleb128(writer, @as(u32, @intCast(target_features.len)));
    try writer.writeAll(target_features);

    try leb.writeUleb128(writer, features_count);
    for (enabled_features, 0..) |enabled, feature_index| {
        if (enabled) {
            const feature: Feature = .{ .prefix = .used, .tag = @as(Feature.Tag, @enumFromInt(feature_index)) };
            try leb.writeUleb128(writer, @intFromEnum(feature.prefix));
            var buf: [100]u8 = undefined;
            const string = try std.fmt.bufPrint(&buf, "{}", .{feature.tag});
            try leb.writeUleb128(writer, @as(u32, @intCast(string.len)));
            try writer.writeAll(string);
        }
    }

    try writeCustomSectionHeader(
        binary_bytes.items,
        header_offset,
        @as(u32, @intCast(binary_bytes.items.len - header_offset - 6)),
    );
}

fn emitNameSection(wasm: *Wasm, binary_bytes: *std.ArrayListUnmanaged(u8), arena: Allocator) !void {
    const comp = wasm.base.comp;
    const gpa = comp.gpa;
    const import_memory = comp.config.import_memory;
    const Name = struct {
        index: u32,
        name: []const u8,

        fn lessThan(context: void, lhs: @This(), rhs: @This()) bool {
            _ = context;
            return lhs.index < rhs.index;
        }
    };

    // we must de-duplicate symbols that point to the same function
    var funcs = std.AutoArrayHashMap(u32, Name).init(arena);
    try funcs.ensureUnusedCapacity(wasm.functions.count() + wasm.imported_functions_count);
    var globals = try std.ArrayList(Name).initCapacity(arena, wasm.output_globals.items.len + wasm.imported_globals_count);
    var segments = try std.ArrayList(Name).initCapacity(arena, wasm.data_segments.count());

    for (wasm.resolved_symbols.keys()) |sym_loc| {
        const symbol = wasm.finalSymbolByLoc(sym_loc).*;
        if (!symbol.flags.alive) continue;
        const name = wasm.symbolLocName(sym_loc);
        switch (symbol.tag) {
            .function => {
                const gop = funcs.getOrPutAssumeCapacity(symbol.index);
                if (!gop.found_existing) {
                    gop.value_ptr.* = .{ .index = symbol.index, .name = name };
                }
            },
            .global => globals.appendAssumeCapacity(.{ .index = symbol.index, .name = name }),
            else => {},
        }
    }
    // data segments are already 'ordered'
    var data_segment_index: u32 = 0;
    for (wasm.data_segments.keys()) |key| {
        // bss section is not emitted when this condition holds true, so we also
        // do not output a name for it.
        if (!import_memory and mem.eql(u8, key, ".bss")) continue;
        segments.appendAssumeCapacity(.{ .index = data_segment_index, .name = key });
        data_segment_index += 1;
    }

    mem.sort(Name, funcs.values(), {}, Name.lessThan);
    mem.sort(Name, globals.items, {}, Name.lessThan);

    const header_offset = try reserveCustomSectionHeader(gpa, binary_bytes);
    const writer = binary_bytes.writer();
    try leb.writeUleb128(writer, @as(u32, @intCast("name".len)));
    try writer.writeAll("name");

    try wasm.emitNameSubsection(.function, funcs.values(), writer);
    try wasm.emitNameSubsection(.global, globals.items, writer);
    try wasm.emitNameSubsection(.data_segment, segments.items, writer);

    try writeCustomSectionHeader(
        binary_bytes.items,
        header_offset,
        @as(u32, @intCast(binary_bytes.items.len - header_offset - 6)),
    );
}

fn emitNameSubsection(wasm: *Wasm, section_id: std.wasm.NameSubsection, names: anytype, writer: anytype) !void {
    const gpa = wasm.base.comp.gpa;

    // We must emit subsection size, so first write to a temporary list
    var section_list = std.ArrayList(u8).init(gpa);
    defer section_list.deinit();
    const sub_writer = section_list.writer();

    try leb.writeUleb128(sub_writer, @as(u32, @intCast(names.len)));
    for (names) |name| {
        log.debug("Emit symbol '{s}' type({s})", .{ name.name, @tagName(section_id) });
        try leb.writeUleb128(sub_writer, name.index);
        try leb.writeUleb128(sub_writer, @as(u32, @intCast(name.name.len)));
        try sub_writer.writeAll(name.name);
    }

    // From now, write to the actual writer
    try leb.writeUleb128(writer, @intFromEnum(section_id));
    try leb.writeUleb128(writer, @as(u32, @intCast(section_list.items.len)));
    try writer.writeAll(section_list.items);
}

fn emitLimits(writer: anytype, limits: std.wasm.Limits) !void {
    try writer.writeByte(limits.flags);
    try leb.writeUleb128(writer, limits.min);
    if (limits.flags.has_max) try leb.writeUleb128(writer, limits.max);
}

fn emitInit(writer: anytype, init_expr: std.wasm.InitExpression) !void {
    switch (init_expr) {
        .i32_const => |val| {
            try writer.writeByte(@intFromEnum(std.wasm.Opcode.i32_const));
            try leb.writeIleb128(writer, val);
        },
        .i64_const => |val| {
            try writer.writeByte(@intFromEnum(std.wasm.Opcode.i64_const));
            try leb.writeIleb128(writer, val);
        },
        .f32_const => |val| {
            try writer.writeByte(@intFromEnum(std.wasm.Opcode.f32_const));
            try writer.writeInt(u32, @bitCast(val), .little);
        },
        .f64_const => |val| {
            try writer.writeByte(@intFromEnum(std.wasm.Opcode.f64_const));
            try writer.writeInt(u64, @bitCast(val), .little);
        },
        .global_get => |val| {
            try writer.writeByte(@intFromEnum(std.wasm.Opcode.global_get));
            try leb.writeUleb128(writer, val);
        },
    }
    try writer.writeByte(@intFromEnum(std.wasm.Opcode.end));
}

fn emitMemoryImport(wasm: *Wasm, writer: anytype, memory_import: *const MemoryImport) error{OutOfMemory}!void {
    const module_name = wasm.stringSlice(memory_import.module_name);
    try leb.writeUleb128(writer, @as(u32, @intCast(module_name.len)));
    try writer.writeAll(module_name);

    const name = wasm.stringSlice(memory_import.name);
    try leb.writeUleb128(writer, @as(u32, @intCast(name.len)));
    try writer.writeAll(name);

    try writer.writeByte(@intFromEnum(std.wasm.ExternalKind.memory));
    try emitLimits(writer, memory_import.limits());
}

fn linkWithLLD(wasm: *Wasm, arena: Allocator, tid: Zcu.PerThread.Id, prog_node: std.Progress.Node) !void {
    dev.check(.lld_linker);

    const tracy = trace(@src());
    defer tracy.end();

    const comp = wasm.base.comp;
    const shared_memory = comp.config.shared_memory;
    const export_memory = comp.config.export_memory;
    const import_memory = comp.config.import_memory;
    const target = comp.root_mod.resolved_target.result;

    const gpa = comp.gpa;

    const directory = wasm.base.emit.root_dir; // Just an alias to make it shorter to type.
    const full_out_path = try directory.join(arena, &[_][]const u8{wasm.base.emit.sub_path});

    // If there is no Zig code to compile, then we should skip flushing the output file because it
    // will not be part of the linker line anyway.
    const module_obj_path: ?[]const u8 = if (comp.zcu != null) blk: {
        try wasm.flushModule(arena, tid, prog_node);

        if (fs.path.dirname(full_out_path)) |dirname| {
            break :blk try fs.path.join(arena, &.{ dirname, wasm.base.zcu_object_sub_path.? });
        } else {
            break :blk wasm.base.zcu_object_sub_path.?;
        }
    } else null;

    const sub_prog_node = prog_node.start("LLD Link", 0);
    defer sub_prog_node.end();

    const is_obj = comp.config.output_mode == .Obj;
    const compiler_rt_path: ?Path = blk: {
        if (comp.compiler_rt_lib) |lib| break :blk lib.full_object_path;
        if (comp.compiler_rt_obj) |obj| break :blk obj.full_object_path;
        break :blk null;
    };

    const id_symlink_basename = "lld.id";

    var man: Cache.Manifest = undefined;
    defer if (!wasm.base.disable_lld_caching) man.deinit();

    var digest: [Cache.hex_digest_len]u8 = undefined;

    if (!wasm.base.disable_lld_caching) {
        man = comp.cache_parent.obtain();

        // We are about to obtain this lock, so here we give other processes a chance first.
        wasm.base.releaseLock();

        comptime assert(Compilation.link_hash_implementation_version == 14);

        try link.hashInputs(&man, comp.link_inputs);
        for (comp.c_object_table.keys()) |key| {
            _ = try man.addFilePath(key.status.success.object_path, null);
        }
        try man.addOptionalFile(module_obj_path);
        try man.addOptionalFilePath(compiler_rt_path);
        man.hash.addOptionalBytes(wasm.optionalStringSlice(wasm.entry_name));
        man.hash.add(wasm.base.stack_size);
        man.hash.add(wasm.base.build_id);
        man.hash.add(import_memory);
        man.hash.add(export_memory);
        man.hash.add(wasm.import_table);
        man.hash.add(wasm.export_table);
        man.hash.addOptional(wasm.initial_memory);
        man.hash.addOptional(wasm.max_memory);
        man.hash.add(shared_memory);
        man.hash.addOptional(wasm.global_base);
        man.hash.addListOfBytes(wasm.export_symbol_names);
        // strip does not need to go into the linker hash because it is part of the hash namespace

        // We don't actually care whether it's a cache hit or miss; we just need the digest and the lock.
        _ = try man.hit();
        digest = man.final();

        var prev_digest_buf: [digest.len]u8 = undefined;
        const prev_digest: []u8 = Cache.readSmallFile(
            directory.handle,
            id_symlink_basename,
            &prev_digest_buf,
        ) catch |err| blk: {
            log.debug("WASM LLD new_digest={s} error: {s}", .{ std.fmt.fmtSliceHexLower(&digest), @errorName(err) });
            // Handle this as a cache miss.
            break :blk prev_digest_buf[0..0];
        };
        if (mem.eql(u8, prev_digest, &digest)) {
            log.debug("WASM LLD digest={s} match - skipping invocation", .{std.fmt.fmtSliceHexLower(&digest)});
            // Hot diggity dog! The output binary is already there.
            wasm.base.lock = man.toOwnedLock();
            return;
        }
        log.debug("WASM LLD prev_digest={s} new_digest={s}", .{ std.fmt.fmtSliceHexLower(prev_digest), std.fmt.fmtSliceHexLower(&digest) });

        // We are about to change the output file to be different, so we invalidate the build hash now.
        directory.handle.deleteFile(id_symlink_basename) catch |err| switch (err) {
            error.FileNotFound => {},
            else => |e| return e,
        };
    }

    if (is_obj) {
        // LLD's WASM driver does not support the equivalent of `-r` so we do a simple file copy
        // here. TODO: think carefully about how we can avoid this redundant operation when doing
        // build-obj. See also the corresponding TODO in linkAsArchive.
        const the_object_path = blk: {
            if (link.firstObjectInput(comp.link_inputs)) |obj| break :blk obj.path;

            if (comp.c_object_table.count() != 0)
                break :blk comp.c_object_table.keys()[0].status.success.object_path;

            if (module_obj_path) |p|
                break :blk Path.initCwd(p);

            // TODO I think this is unreachable. Audit this situation when solving the above TODO
            // regarding eliding redundant object -> object transformations.
            return error.NoObjectsToLink;
        };
        try fs.Dir.copyFile(
            the_object_path.root_dir.handle,
            the_object_path.sub_path,
            directory.handle,
            wasm.base.emit.sub_path,
            .{},
        );
    } else {
        // Create an LLD command line and invoke it.
        var argv = std.ArrayList([]const u8).init(gpa);
        defer argv.deinit();
        // We will invoke ourselves as a child process to gain access to LLD.
        // This is necessary because LLD does not behave properly as a library -
        // it calls exit() and does not reset all global data between invocations.
        const linker_command = "wasm-ld";
        try argv.appendSlice(&[_][]const u8{ comp.self_exe_path.?, linker_command });
        try argv.append("--error-limit=0");

        if (comp.config.lto) {
            switch (comp.root_mod.optimize_mode) {
                .Debug => {},
                .ReleaseSmall => try argv.append("-O2"),
                .ReleaseFast, .ReleaseSafe => try argv.append("-O3"),
            }
        }

        if (import_memory) {
            try argv.append("--import-memory");
        }

        if (export_memory) {
            try argv.append("--export-memory");
        }

        if (wasm.import_table) {
            assert(!wasm.export_table);
            try argv.append("--import-table");
        }

        if (wasm.export_table) {
            assert(!wasm.import_table);
            try argv.append("--export-table");
        }

        // For wasm-ld we only need to specify '--no-gc-sections' when the user explicitly
        // specified it as garbage collection is enabled by default.
        if (!wasm.base.gc_sections) {
            try argv.append("--no-gc-sections");
        }

        if (comp.config.debug_format == .strip) {
            try argv.append("-s");
        }

        if (wasm.initial_memory) |initial_memory| {
            const arg = try std.fmt.allocPrint(arena, "--initial-memory={d}", .{initial_memory});
            try argv.append(arg);
        }

        if (wasm.max_memory) |max_memory| {
            const arg = try std.fmt.allocPrint(arena, "--max-memory={d}", .{max_memory});
            try argv.append(arg);
        }

        if (shared_memory) {
            try argv.append("--shared-memory");
        }

        if (wasm.global_base) |global_base| {
            const arg = try std.fmt.allocPrint(arena, "--global-base={d}", .{global_base});
            try argv.append(arg);
        } else {
            // We prepend it by default, so when a stack overflow happens the runtime will trap correctly,
            // rather than silently overwrite all global declarations. See https://github.com/ziglang/zig/issues/4496
            //
            // The user can overwrite this behavior by setting the global-base
            try argv.append("--stack-first");
        }

        // Users are allowed to specify which symbols they want to export to the wasm host.
        for (wasm.export_symbol_names) |symbol_name| {
            const arg = try std.fmt.allocPrint(arena, "--export={s}", .{symbol_name});
            try argv.append(arg);
        }

        if (comp.config.rdynamic) {
            try argv.append("--export-dynamic");
        }

        if (wasm.optionalStringSlice(wasm.entry_name)) |entry_name| {
            try argv.appendSlice(&.{ "--entry", entry_name });
        } else {
            try argv.append("--no-entry");
        }

        try argv.appendSlice(&.{
            "-z",
            try std.fmt.allocPrint(arena, "stack-size={d}", .{wasm.base.stack_size}),
        });

        if (wasm.import_symbols) {
            try argv.append("--allow-undefined");
        }

        if (comp.config.output_mode == .Lib and comp.config.link_mode == .dynamic) {
            try argv.append("--shared");
        }
        if (comp.config.pie) {
            try argv.append("--pie");
        }

        // XXX - TODO: add when wasm-ld supports --build-id.
        // if (wasm.base.build_id) {
        //     try argv.append("--build-id=tree");
        // }

        try argv.appendSlice(&.{ "-o", full_out_path });

        if (target.cpu.arch == .wasm64) {
            try argv.append("-mwasm64");
        }

        if (target.os.tag == .wasi) {
            const is_exe_or_dyn_lib = comp.config.output_mode == .Exe or
                (comp.config.output_mode == .Lib and comp.config.link_mode == .dynamic);
            if (is_exe_or_dyn_lib) {
                for (comp.wasi_emulated_libs) |crt_file| {
                    try argv.append(try comp.crtFileAsString(
                        arena,
                        wasi_libc.emulatedLibCRFileLibName(crt_file),
                    ));
                }

                if (comp.config.link_libc) {
                    try argv.append(try comp.crtFileAsString(
                        arena,
                        wasi_libc.execModelCrtFileFullName(comp.config.wasi_exec_model),
                    ));
                    try argv.append(try comp.crtFileAsString(arena, "libc.a"));
                }

                if (comp.config.link_libcpp) {
                    try argv.append(try comp.libcxx_static_lib.?.full_object_path.toString(arena));
                    try argv.append(try comp.libcxxabi_static_lib.?.full_object_path.toString(arena));
                }
            }
        }

        // Positional arguments to the linker such as object files.
        var whole_archive = false;
        for (comp.link_inputs) |link_input| switch (link_input) {
            .object, .archive => |obj| {
                if (obj.must_link and !whole_archive) {
                    try argv.append("-whole-archive");
                    whole_archive = true;
                } else if (!obj.must_link and whole_archive) {
                    try argv.append("-no-whole-archive");
                    whole_archive = false;
                }
                try argv.append(try obj.path.toString(arena));
            },
            .dso => |dso| {
                try argv.append(try dso.path.toString(arena));
            },
            .dso_exact => unreachable,
            .res => unreachable,
        };
        if (whole_archive) {
            try argv.append("-no-whole-archive");
            whole_archive = false;
        }

        for (comp.c_object_table.keys()) |key| {
            try argv.append(try key.status.success.object_path.toString(arena));
        }
        if (module_obj_path) |p| {
            try argv.append(p);
        }

        if (comp.libc_static_lib) |crt_file| {
            try argv.append(try crt_file.full_object_path.toString(arena));
        }

        if (compiler_rt_path) |p| {
            try argv.append(try p.toString(arena));
        }

        if (comp.verbose_link) {
            // Skip over our own name so that the LLD linker name is the first argv item.
            Compilation.dump_argv(argv.items[1..]);
        }

        if (std.process.can_spawn) {
            // If possible, we run LLD as a child process because it does not always
            // behave properly as a library, unfortunately.
            // https://github.com/ziglang/zig/issues/3825
            var child = std.process.Child.init(argv.items, arena);
            if (comp.clang_passthrough_mode) {
                child.stdin_behavior = .Inherit;
                child.stdout_behavior = .Inherit;
                child.stderr_behavior = .Inherit;

                const term = child.spawnAndWait() catch |err| {
                    log.err("unable to spawn {s}: {s}", .{ argv.items[0], @errorName(err) });
                    return error.UnableToSpawnWasm;
                };
                switch (term) {
                    .Exited => |code| {
                        if (code != 0) {
                            std.process.exit(code);
                        }
                    },
                    else => std.process.abort(),
                }
            } else {
                child.stdin_behavior = .Ignore;
                child.stdout_behavior = .Ignore;
                child.stderr_behavior = .Pipe;

                try child.spawn();

                const stderr = try child.stderr.?.reader().readAllAlloc(arena, std.math.maxInt(usize));

                const term = child.wait() catch |err| {
                    log.err("unable to spawn {s}: {s}", .{ argv.items[0], @errorName(err) });
                    return error.UnableToSpawnWasm;
                };

                switch (term) {
                    .Exited => |code| {
                        if (code != 0) {
                            const diags = &comp.link_diags;
                            diags.lockAndParseLldStderr(linker_command, stderr);
                            return error.LLDReportedFailure;
                        }
                    },
                    else => {
                        log.err("{s} terminated with stderr:\n{s}", .{ argv.items[0], stderr });
                        return error.LLDCrashed;
                    },
                }

                if (stderr.len != 0) {
                    log.warn("unexpected LLD stderr:\n{s}", .{stderr});
                }
            }
        } else {
            const exit_code = try lldMain(arena, argv.items, false);
            if (exit_code != 0) {
                if (comp.clang_passthrough_mode) {
                    std.process.exit(exit_code);
                } else {
                    return error.LLDReportedFailure;
                }
            }
        }

        // Give +x to the .wasm file if it is an executable and the OS is WASI.
        // Some systems may be configured to execute such binaries directly. Even if that
        // is not the case, it means we will get "exec format error" when trying to run
        // it, and then can react to that in the same way as trying to run an ELF file
        // from a foreign CPU architecture.
        if (fs.has_executable_bit and target.os.tag == .wasi and
            comp.config.output_mode == .Exe)
        {
            // TODO: what's our strategy for reporting linker errors from this function?
            // report a nice error here with the file path if it fails instead of
            // just returning the error code.
            // chmod does not interact with umask, so we use a conservative -rwxr--r-- here.
            std.posix.fchmodat(fs.cwd().fd, full_out_path, 0o744, 0) catch |err| switch (err) {
                error.OperationNotSupported => unreachable, // Not a symlink.
                else => |e| return e,
            };
        }
    }

    if (!wasm.base.disable_lld_caching) {
        // Update the file with the digest. If it fails we can continue; it only
        // means that the next invocation will have an unnecessary cache miss.
        Cache.writeSmallFile(directory.handle, id_symlink_basename, &digest) catch |err| {
            log.warn("failed to save linking hash digest symlink: {s}", .{@errorName(err)});
        };
        // Again failure here only means an unnecessary cache miss.
        man.writeManifest() catch |err| {
            log.warn("failed to write cache manifest when linking: {s}", .{@errorName(err)});
        };
        // We hang on to this lock so that the output file path can be used without
        // other processes clobbering it.
        wasm.base.lock = man.toOwnedLock();
    }
}

fn reserveVecSectionHeader(gpa: Allocator, bytes: *std.ArrayListUnmanaged(u8)) error{OutOfMemory}!u32 {
    // section id + fixed leb contents size + fixed leb vector length
    const header_size = 1 + 5 + 5;
    try bytes.appendNTimes(gpa, 0, header_size);
    return @intCast(bytes.items.len - header_size);
}

fn reserveCustomSectionHeader(gpa: Allocator, bytes: *std.ArrayListUnmanaged(u8)) error{OutOfMemory}!u32 {
    // unlike regular section, we don't emit the count
    const header_size = 1 + 5;
    try bytes.appendNTimes(gpa, 0, header_size);
    return @intCast(bytes.items.len - header_size);
}

fn writeVecSectionHeader(buffer: []u8, offset: u32, section: std.wasm.Section, size: u32, items: u32) !void {
    var buf: [1 + 5 + 5]u8 = undefined;
    buf[0] = @intFromEnum(section);
    leb.writeUnsignedFixed(5, buf[1..6], size);
    leb.writeUnsignedFixed(5, buf[6..], items);
    buffer[offset..][0..buf.len].* = buf;
}

fn writeCustomSectionHeader(buffer: []u8, offset: u32, size: u32) !void {
    var buf: [1 + 5]u8 = undefined;
    buf[0] = 0; // 0 = 'custom' section
    leb.writeUnsignedFixed(5, buf[1..6], size);
    buffer[offset..][0..buf.len].* = buf;
}

fn emitLinkSection(
    wasm: *Wasm,
    binary_bytes: *std.ArrayListUnmanaged(u8),
    symbol_table: *std.AutoArrayHashMapUnmanaged(SymbolLoc, u32),
) !void {
    const gpa = wasm.base.comp.gpa;
    const offset = try reserveCustomSectionHeader(gpa, binary_bytes);
    const writer = binary_bytes.writer();
    // emit "linking" custom section name
    const section_name = "linking";
    try leb.writeUleb128(writer, section_name.len);
    try writer.writeAll(section_name);

    // meta data version, which is currently '2'
    try leb.writeUleb128(writer, @as(u32, 2));

    // For each subsection type (found in Subsection) we can emit a section.
    // Currently, we only support emitting segment info and the symbol table.
    try wasm.emitSymbolTable(binary_bytes, symbol_table);
    try wasm.emitSegmentInfo(binary_bytes);

    const size: u32 = @intCast(binary_bytes.items.len - offset - 6);
    try writeCustomSectionHeader(binary_bytes.items, offset, size);
}

fn emitSymbolTable(
    wasm: *Wasm,
    binary_bytes: *std.ArrayList(u8),
    symbol_table: *std.AutoArrayHashMap(SymbolLoc, u32),
) !void {
    const writer = binary_bytes.writer();

    try leb.writeUleb128(writer, @intFromEnum(SubsectionType.WASM_SYMBOL_TABLE));
    const table_offset = binary_bytes.items.len;

    var symbol_count: u32 = 0;
    for (wasm.resolved_symbols.keys()) |sym_loc| {
        const symbol = wasm.finalSymbolByLoc(sym_loc).*;
        if (symbol.tag == .dead) continue; // Do not emit dead symbols
        try symbol_table.putNoClobber(sym_loc, symbol_count);
        symbol_count += 1;
        log.debug("Emit symbol: {}", .{symbol});
        try leb.writeUleb128(writer, @intFromEnum(symbol.tag));
        try leb.writeUleb128(writer, symbol.flags);

        const sym_name = wasm.symbolLocName(sym_loc);
        switch (symbol.tag) {
            .data => {
                try leb.writeUleb128(writer, @as(u32, @intCast(sym_name.len)));
                try writer.writeAll(sym_name);

                if (symbol.isDefined()) {
                    try leb.writeUleb128(writer, symbol.index);
                    const atom_index = wasm.symbol_atom.get(sym_loc).?;
                    const atom = wasm.getAtom(atom_index);
                    try leb.writeUleb128(writer, @as(u32, atom.offset));
                    try leb.writeUleb128(writer, @as(u32, atom.code.len));
                }
            },
            .section => {
                try leb.writeUleb128(writer, symbol.index);
            },
            else => {
                try leb.writeUleb128(writer, symbol.index);
                if (symbol.isDefined()) {
                    try leb.writeUleb128(writer, @as(u32, @intCast(sym_name.len)));
                    try writer.writeAll(sym_name);
                }
            },
        }
    }

    var buf: [10]u8 = undefined;
    leb.writeUnsignedFixed(5, buf[0..5], @intCast(binary_bytes.items.len - table_offset + 5));
    leb.writeUnsignedFixed(5, buf[5..], symbol_count);
    try binary_bytes.insertSlice(table_offset, &buf);
}

fn emitSegmentInfo(wasm: *Wasm, binary_bytes: *std.ArrayList(u8)) !void {
    const writer = binary_bytes.writer();
    try leb.writeUleb128(writer, @intFromEnum(SubsectionType.WASM_SEGMENT_INFO));
    const segment_offset = binary_bytes.items.len;

    try leb.writeUleb128(writer, @as(u32, @intCast(wasm.segment_info.count())));
    for (wasm.segment_info.values()) |segment_info| {
        log.debug("Emit segment: {s} align({d}) flags({b})", .{
            segment_info.name,
            segment_info.alignment,
            segment_info.flags,
        });
        try leb.writeUleb128(writer, @as(u32, @intCast(segment_info.name.len)));
        try writer.writeAll(segment_info.name);
        try leb.writeUleb128(writer, segment_info.alignment.toLog2Units());
        try leb.writeUleb128(writer, segment_info.flags);
    }

    var buf: [5]u8 = undefined;
    leb.writeUnsignedFixed(5, &buf, @as(u32, @intCast(binary_bytes.items.len - segment_offset)));
    try binary_bytes.insertSlice(segment_offset, &buf);
}

pub fn getUleb128Size(uint_value: anytype) u32 {
    const T = @TypeOf(uint_value);
    const U = if (@typeInfo(T).int.bits < 8) u8 else T;
    var value = @as(U, @intCast(uint_value));

    var size: u32 = 0;
    while (value != 0) : (size += 1) {
        value >>= 7;
    }
    return size;
}

/// For each relocatable section, emits a custom "relocation.<section_name>" section
fn emitCodeRelocations(
    wasm: *Wasm,
    binary_bytes: *std.ArrayListUnmanaged(u8),
    section_index: u32,
    symbol_table: std.AutoArrayHashMapUnmanaged(SymbolLoc, u32),
) !void {
    const comp = wasm.base.comp;
    const gpa = comp.gpa;
    const code_index = wasm.code_section_index.unwrap() orelse return;
    const writer = binary_bytes.writer();
    const header_offset = try reserveCustomSectionHeader(gpa, binary_bytes);

    // write custom section information
    const name = "reloc.CODE";
    try leb.writeUleb128(writer, @as(u32, @intCast(name.len)));
    try writer.writeAll(name);
    try leb.writeUleb128(writer, section_index);
    const reloc_start = binary_bytes.items.len;

    var count: u32 = 0;
    var atom: *Atom = wasm.atomPtr(wasm.atoms.get(code_index).?);
    // for each atom, we calculate the uleb size and append that
    var size_offset: u32 = 5; // account for code section size leb128
    while (true) {
        size_offset += getUleb128Size(atom.code.len);
        for (atom.relocs.items) |relocation| {
            count += 1;
            const sym_loc: SymbolLoc = .{ .file = atom.file, .index = @enumFromInt(relocation.index) };
            const symbol_index = symbol_table.get(sym_loc).?;
            try leb.writeUleb128(writer, @intFromEnum(relocation.tag));
            const offset = atom.offset + relocation.offset + size_offset;
            try leb.writeUleb128(writer, offset);
            try leb.writeUleb128(writer, symbol_index);
            if (relocation.tag.addendIsPresent()) {
                try leb.writeIleb128(writer, relocation.addend);
            }
            log.debug("Emit relocation: {}", .{relocation});
        }
        if (atom.prev == .none) break;
        atom = wasm.atomPtr(atom.prev);
    }
    if (count == 0) return;
    var buf: [5]u8 = undefined;
    leb.writeUnsignedFixed(5, &buf, count);
    try binary_bytes.insertSlice(reloc_start, &buf);
    const size: u32 = @intCast(binary_bytes.items.len - header_offset - 6);
    try writeCustomSectionHeader(binary_bytes.items, header_offset, size);
}

fn emitDataRelocations(
    wasm: *Wasm,
    binary_bytes: *std.ArrayList(u8),
    section_index: u32,
    symbol_table: std.AutoArrayHashMap(SymbolLoc, u32),
) !void {
    const comp = wasm.base.comp;
    const gpa = comp.gpa;
    const writer = binary_bytes.writer();
    const header_offset = try reserveCustomSectionHeader(gpa, binary_bytes);

    // write custom section information
    const name = "reloc.DATA";
    try leb.writeUleb128(writer, @as(u32, @intCast(name.len)));
    try writer.writeAll(name);
    try leb.writeUleb128(writer, section_index);
    const reloc_start = binary_bytes.items.len;

    var count: u32 = 0;
    // for each atom, we calculate the uleb size and append that
    var size_offset: u32 = 5; // account for code section size leb128
    for (wasm.data_segments.values()) |segment_index| {
        var atom: *Atom = wasm.atomPtr(wasm.atoms.get(segment_index).?);
        while (true) {
            size_offset += getUleb128Size(atom.code.len);
            for (atom.relocs.items) |relocation| {
                count += 1;
                const sym_loc: SymbolLoc = .{ .file = atom.file, .index = @enumFromInt(relocation.index) };
                const symbol_index = symbol_table.get(sym_loc).?;
                try leb.writeUleb128(writer, @intFromEnum(relocation.tag));
                const offset = atom.offset + relocation.offset + size_offset;
                try leb.writeUleb128(writer, offset);
                try leb.writeUleb128(writer, symbol_index);
                if (relocation.tag.addendIsPresent()) {
                    try leb.writeIleb128(writer, relocation.addend);
                }
                log.debug("Emit relocation: {}", .{relocation});
            }
            if (atom.prev == .none) break;
            atom = wasm.atomPtr(atom.prev);
        }
    }
    if (count == 0) return;

    var buf: [5]u8 = undefined;
    leb.writeUnsignedFixed(5, &buf, count);
    try binary_bytes.insertSlice(reloc_start, &buf);
    const size = @as(u32, @intCast(binary_bytes.items.len - header_offset - 6));
    try writeCustomSectionHeader(binary_bytes.items, header_offset, size);
}

fn hasPassiveInitializationSegments(wasm: *const Wasm) bool {
    const comp = wasm.base.comp;
    const import_memory = comp.config.import_memory;

    var it = wasm.data_segments.iterator();
    while (it.next()) |entry| {
        const segment = entry.value_ptr.ptr(wasm);
        const is_bss = mem.eql(u8, entry.key_ptr.*, ".bss");
        if (segment.needsPassiveInitialization(import_memory, is_bss)) {
            return true;
        }
    }
    return false;
}

/// For the given `nav`, stores the corresponding type representing the function signature.
/// Asserts declaration has an associated `Atom`.
/// Returns the index into the list of types.
pub fn storeNavType(wasm: *Wasm, nav: InternPool.Nav.Index, func_type: FunctionType.Index) error{OutOfMemory}!void {
    return wasm.zig_object.?.storeDeclType(wasm.base.comp.gpa, nav, func_type);
}

/// Returns the symbol index of the error name table.
///
/// When the symbol does not yet exist, it will create a new one instead.
pub fn getErrorTableSymbol(wasm: *Wasm, pt: Zcu.PerThread) !u32 {
    const sym_index = try wasm.zig_object.?.getErrorTableSymbol(wasm, pt);
    return @intFromEnum(sym_index);
}

/// For a given `InternPool.DeclIndex` returns its corresponding `Atom.Index`.
/// When the index was not found, a new `Atom` will be created, and its index will be returned.
/// The newly created Atom is empty with default fields as specified by `Atom.empty`.
pub fn getOrCreateAtomForNav(wasm: *Wasm, pt: Zcu.PerThread, nav: InternPool.Nav.Index) !Atom.Index {
    return wasm.zig_object.?.getOrCreateAtomForNav(wasm, pt, nav);
}

/// Verifies all resolved symbols and checks whether itself needs to be marked alive,
/// as well as any of its references.
fn markReferences(wasm: *Wasm) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const do_garbage_collect = wasm.base.gc_sections;
    const comp = wasm.base.comp;

    for (wasm.resolved_symbols.keys()) |sym_loc| {
        const sym = wasm.finalSymbolByLoc(sym_loc);
        if (sym.isExported(comp.config.rdynamic) or sym.isNoStrip() or !do_garbage_collect) {
            try wasm.mark(sym_loc);
            continue;
        }

        // Debug sections may require to be parsed and marked when it contains
        // relocations to alive symbols.
        if (sym.tag == .section and comp.config.debug_format != .strip) {
            const object_id = sym_loc.file.unwrap() orelse continue; // Incremental debug info is done independently
            _ = try wasm.parseSymbolIntoAtom(object_id, sym_loc.index);
            sym.mark();
        }
    }
}

/// Marks a symbol as 'alive' recursively so itself and any references it contains to
/// other symbols will not be omit from the binary.
fn mark(wasm: *Wasm, loc: SymbolLoc) !void {
    const symbol = wasm.finalSymbolByLoc(loc);
    if (symbol.flags.alive) {
        // Symbol is already marked alive, including its references.
        // This means we can skip it so we don't end up marking the same symbols
        // multiple times.
        return;
    }
    symbol.mark();
    gc_log.debug("Marked symbol '{s}'", .{wasm.symbolLocName(loc)});
    if (symbol.flags.undefined) {
        // undefined symbols do not have an associated `Atom` and therefore also
        // do not contain relocations.
        return;
    }

    const atom_index = if (loc.file.unwrap()) |object_id|
        try wasm.parseSymbolIntoAtom(object_id, loc.index)
    else
        wasm.symbol_atom.get(loc) orelse return;

    const atom = wasm.getAtom(atom_index);
    for (atom.relocs.items) |reloc| {
        const target_loc: SymbolLoc = .{ .index = @enumFromInt(reloc.index), .file = loc.file };
        try wasm.mark(wasm.symbolLocFinalLoc(target_loc));
    }
}

fn defaultEntrySymbolName(
    preloaded_strings: *const PreloadedStrings,
    wasi_exec_model: std.builtin.WasiExecModel,
) String {
    return switch (wasi_exec_model) {
        .reactor => preloaded_strings._initialize,
        .command => preloaded_strings._start,
    };
}

pub const Atom = struct {
    /// Represents the index of the file this atom was generated from.
    /// This is `none` when the atom was generated by a synthetic linker symbol.
    file: OptionalObjectId,
    /// symbol index of the symbol representing this atom
    sym_index: Symbol.Index,
    /// Points into Wasm atom_relocs
    relocs: RelativeSlice,
    /// The binary data of an atom, which can be non-relocated.
    code: RelocatableData.Payload,
    /// For code this is 1, for data this is set to the highest value of all segments
    alignment: Alignment,
    /// Offset into the section where the atom lives, this already accounts
    /// for alignment.
    offset: u32,
    /// The original offset within the object file. This value is subtracted from
    /// relocation offsets to determine where in the `data` to rewrite the value
    original_offset: u32,
    /// Previous atom in relation to this atom, or none when this atom is the
    /// first in its order.
    prev: Atom.OptionalIndex,
    /// Contains decls local to an atom.
    locals: RelativeSlice,

    pub const RelativeSlice = struct {
        off: u32,
        len: u32,
    };

    /// Index into Wasm `atoms`.
    pub const Index = enum(u32) {
        _,

        pub fn toOptional(i: Index) OptionalIndex {
            const result: OptionalIndex = @enumFromInt(@intFromEnum(i));
            assert(result != .none);
            return result;
        }
    };

    /// Index into Wasm `atoms`, or `none`.
    pub const OptionalIndex = enum(u32) {
        none = std.math.maxInt(u32),
        _,

        pub fn unwrap(i: OptionalIndex) ?Index {
            if (i == .none) return null;
            return @enumFromInt(@intFromEnum(i));
        }
    };

    pub fn format(atom: Atom, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        try writer.print("Atom{{ .sym_index = {d}, .alignment = {d}, .size = {d}, .offset = 0x{x:0>8} }}", .{
            @intFromEnum(atom.sym_index), atom.alignment, atom.code.len, atom.offset,
        });
    }

    /// Returns the location of the symbol that represents this `Atom`
    pub fn symbolLoc(atom: Atom) SymbolLoc {
        return .{
            .file = atom.file,
            .index = atom.sym_index,
        };
    }

    fn relocSlice(atom: *const Atom, wasm: *const Wasm) []const Relocation {
        return wasm.atom_relocs.items[atom.relocs.off..][0..atom.relocs.len];
    }
};

/// Resolves the relocations within the atom, writing the new value
/// at the calculated offset.
pub fn resolveAtomRelocs(wasm: *const Wasm, atom: *Atom) void {
    const symbol_name = wasm.symbolLocName(atom.symbolLoc());
    log.debug("resolving {d} relocs in atom '{s}'", .{ atom.relocs.items.len, symbol_name });

    for (atom.relocSlice(wasm)) |reloc| {
        const value = atomRelocationValue(wasm, atom, reloc);
        log.debug("relocating '{s}' referenced in '{s}' offset=0x{x:0>8} value={d}", .{
            wasm.symbolLocName(.{
                .file = atom.file,
                .index = @enumFromInt(reloc.index),
            }),
            symbol_name,
            reloc.offset,
            value,
        });

        switch (reloc.tag) {
            .TABLE_INDEX_I32,
            .FUNCTION_OFFSET_I32,
            .GLOBAL_INDEX_I32,
            .MEMORY_ADDR_I32,
            .SECTION_OFFSET_I32,
            => mem.writeInt(u32, atom.code.slice(wasm)[reloc.offset - atom.original_offset ..][0..4], @as(u32, @truncate(value)), .little),

            .TABLE_INDEX_I64,
            .MEMORY_ADDR_I64,
            => mem.writeInt(u64, atom.code.slice(wasm)[reloc.offset - atom.original_offset ..][0..8], value, .little),

            .GLOBAL_INDEX_LEB,
            .EVENT_INDEX_LEB,
            .FUNCTION_INDEX_LEB,
            .MEMORY_ADDR_LEB,
            .MEMORY_ADDR_SLEB,
            .TABLE_INDEX_SLEB,
            .TABLE_NUMBER_LEB,
            .TYPE_INDEX_LEB,
            .MEMORY_ADDR_TLS_SLEB,
            => leb.writeUnsignedFixed(5, atom.code.slice(wasm)[reloc.offset - atom.original_offset ..][0..5], @as(u32, @truncate(value))),

            .MEMORY_ADDR_LEB64,
            .MEMORY_ADDR_SLEB64,
            .TABLE_INDEX_SLEB64,
            .MEMORY_ADDR_TLS_SLEB64,
            => leb.writeUnsignedFixed(10, atom.code.slice(wasm)[reloc.offset - atom.original_offset ..][0..10], value),
        }
    }
}

/// From a given `relocation` will return the new value to be written.
/// All values will be represented as a `u64` as all values can fit within it.
/// The final value must be casted to the correct size.
fn atomRelocationValue(wasm: *const Wasm, atom: *const Atom, relocation: *const Relocation) u64 {
    if (relocation.tag == .TYPE_INDEX_LEB) {
        // Eagerly resolved when parsing the object file.
        if (true) @panic("TODO the eager resolve when parsing");
        return relocation.index;
    }
    const target_loc = wasm.symbolLocFinalLoc(.{
        .file = atom.file,
        .index = @enumFromInt(relocation.index),
    });
    const symbol = wasm.finalSymbolByLoc(target_loc);
    if (symbol.tag != .section and !symbol.flags.alive) {
        const val = atom.tombstone(wasm) orelse relocation.addend;
        return @bitCast(val);
    }
    switch (relocation.tag) {
        .FUNCTION_INDEX_LEB => return symbol.index,
        .TABLE_NUMBER_LEB => return symbol.index,
        .TABLE_INDEX_I32,
        .TABLE_INDEX_I64,
        .TABLE_INDEX_SLEB,
        .TABLE_INDEX_SLEB64,
        => return wasm.function_table.get(.{ .file = atom.file, .index = @enumFromInt(relocation.index) }) orelse 0,

        .TYPE_INDEX_LEB => unreachable, // handled above
        .GLOBAL_INDEX_I32, .GLOBAL_INDEX_LEB => return symbol.index,

        .MEMORY_ADDR_I32,
        .MEMORY_ADDR_I64,
        .MEMORY_ADDR_LEB,
        .MEMORY_ADDR_LEB64,
        .MEMORY_ADDR_SLEB,
        .MEMORY_ADDR_SLEB64,
        => {
            assert(symbol.tag == .data);
            if (symbol.flags.undefined) {
                return 0;
            }
            const va: i33 = @intCast(symbol.virtual_address);
            return @intCast(va + relocation.addend);
        },
        .EVENT_INDEX_LEB => return symbol.index,
        .SECTION_OFFSET_I32 => {
            const target_atom_index = wasm.symbol_atom.get(target_loc).?;
            const target_atom = wasm.getAtom(target_atom_index);
            const rel_value: i33 = @intCast(target_atom.offset);
            return @intCast(rel_value + relocation.addend);
        },
        .FUNCTION_OFFSET_I32 => {
            if (symbol.flags.undefined) {
                const val = atom.tombstone(wasm) orelse relocation.addend;
                return @bitCast(val);
            }
            const target_atom_index = wasm.symbol_atom.get(target_loc).?;
            const target_atom = wasm.getAtom(target_atom_index);
            const rel_value: i33 = @intCast(target_atom.offset);
            return @intCast(rel_value + relocation.addend);
        },
        .MEMORY_ADDR_TLS_SLEB,
        .MEMORY_ADDR_TLS_SLEB64,
        => {
            const va: i33 = @intCast(symbol.virtual_address);
            return @intCast(va + relocation.addend);
        },
    }
}

// For a given `Atom` returns whether it has a tombstone value or not.
/// This defines whether we want a specific value when a section is dead.
fn tombstone(atom: Atom, wasm: *const Wasm) ?i64 {
    const atom_name = wasm.finalSymbolByLoc(atom.symbolLoc()).name;
    if (atom_name == wasm.custom_sections.@".debug_ranges".name or
        atom_name == wasm.custom_sections.@".debug_loc".name)
    {
        return -2;
    } else if (mem.startsWith(u8, wasm.stringSlice(atom_name), ".debug_")) {
        return -1;
    } else {
        return null;
    }
}

pub const Relocation = struct {
    /// Represents the type of the `Relocation`
    tag: Tag,
    /// Offset of the value to rewrite relative to the relevant section's contents.
    /// When `offset` is zero, its position is immediately after the id and size of the section.
    offset: u32,
    /// The index of the symbol used.
    /// When the type is `TYPE_INDEX_LEB`, it represents the index of the type.
    index: u32,
    /// Addend to add to the address.
    /// This field is only non-zero for `MEMORY_ADDR_*`, `FUNCTION_OFFSET_I32` and `SECTION_OFFSET_I32`.
    addend: i32 = 0,

    /// All possible relocation types currently existing.
    /// This enum is exhaustive as the spec is WIP and new types
    /// can be added which means that a generated binary will be invalid,
    /// so instead we will show an error in such cases.
    pub const Tag = enum(u8) {
        FUNCTION_INDEX_LEB = 0,
        TABLE_INDEX_SLEB = 1,
        TABLE_INDEX_I32 = 2,
        MEMORY_ADDR_LEB = 3,
        MEMORY_ADDR_SLEB = 4,
        MEMORY_ADDR_I32 = 5,
        TYPE_INDEX_LEB = 6,
        GLOBAL_INDEX_LEB = 7,
        FUNCTION_OFFSET_I32 = 8,
        SECTION_OFFSET_I32 = 9,
        EVENT_INDEX_LEB = 10,
        GLOBAL_INDEX_I32 = 13,
        MEMORY_ADDR_LEB64 = 14,
        MEMORY_ADDR_SLEB64 = 15,
        MEMORY_ADDR_I64 = 16,
        TABLE_INDEX_SLEB64 = 18,
        TABLE_INDEX_I64 = 19,
        TABLE_NUMBER_LEB = 20,
        MEMORY_ADDR_TLS_SLEB = 21,
        MEMORY_ADDR_TLS_SLEB64 = 25,

        /// Returns true for relocation types where the `addend` field is present.
        pub fn addendIsPresent(self: Tag) bool {
            return switch (self) {
                .MEMORY_ADDR_LEB,
                .MEMORY_ADDR_SLEB,
                .MEMORY_ADDR_I32,
                .MEMORY_ADDR_LEB64,
                .MEMORY_ADDR_SLEB64,
                .MEMORY_ADDR_I64,
                .MEMORY_ADDR_TLS_SLEB,
                .MEMORY_ADDR_TLS_SLEB64,
                .FUNCTION_OFFSET_I32,
                .SECTION_OFFSET_I32,
                => true,
                else => false,
            };
        }
    };

    /// Verifies the relocation type of a given `Relocation` and returns
    /// true when the relocation references a function call or address to a function.
    pub fn isFunction(self: Relocation) bool {
        return switch (self.tag) {
            .FUNCTION_INDEX_LEB,
            .TABLE_INDEX_SLEB,
            => true,
            else => false,
        };
    }

    pub fn format(self: Relocation, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        try writer.print("{s} offset=0x{x:0>6} symbol={d}", .{
            @tagName(self.tag),
            self.offset,
            self.index,
        });
    }

    /// Points into object_relocations.
    pub const Slice = struct {
        off: u32,
        len: u32,
    };
};

pub const FunctionImport = extern struct {
    module_name: String,
    name: String,
    type: FunctionType.Index,
};

pub const Table = extern struct {
    module_name: String,
    name: String,
    limits_min: u32,
    limits_max: u32,
    limits_has_max: bool,
    limits_is_shared: bool,
    reftype: std.wasm.RefType,
    padding: [1]u8 = .{0},
};

pub const MemoryImport = extern struct {
    module_name: String,
    name: String,
    limits_min: u32,
    limits_max: u32,
    limits_has_max: bool,
    limits_is_shared: bool,
    padding: [2]u8 = .{ 0, 0 },
};

pub const GlobalImport = extern struct {
    module_name: String,
    name: String,
    mutable: bool,
    valtype: std.wasm.Valtype,
    padding: [2]u8 = .{ 0, 0 },

    pub fn @"type"(gi: GlobalImport) Global.Type {
        return .{
            .valtype = gi.valtype,
            .mutable = gi.mutable,
        };
    }
};

pub const Export = struct {
    name: String,
    index: u32,
    kind: std.wasm.ExternalKind,
};

/// Layout of the table that can be found at `table_index`.
pub const Element = struct {
    table_index: u32,
    offset: std.wasm.InitExpression,
    func_indexes: []const u32,
};

pub const SubsectionType = enum(u8) {
    segment_info = 5,
    init_funcs = 6,
    comdat_info = 7,
    symbol_table = 8,
};

pub const Alignment = @import("../InternPool.zig").Alignment;

pub const NamedSegment = extern struct {
    name: String,
    flags: Flags,

    pub const Flags = packed struct(u32) {
        strings: bool,
        tls: bool,
        _: u24 = 0,
        alignment: Alignment,
    };

    /// Returns the name as how it will be output into the final object
    /// file or binary. When `merge` is true, this will return the
    /// short name. i.e. ".rodata". When false, it returns the entire name instead.
    pub fn outputName(ns: NamedSegment, wasm: *const Wasm, merge: bool) [:0]const u8 {
        if (ns.flags.tls) return ".tdata";
        const name = wasm.stringSlice(ns.name);
        if (!merge) return name;
        if (mem.startsWith(u8, name, ".rodata.")) return ".rodata";
        if (mem.startsWith(u8, name, ".text.")) return ".text";
        if (mem.startsWith(u8, name, ".data.")) return ".data";
        if (mem.startsWith(u8, name, ".bss.")) return ".bss";
        return name;
    }
};

pub const InitFunc = struct {
    /// Priority of the init function
    priority: u32,
    symbol_index: Symbol.Index,
};

pub const Comdat = struct {
    name: String,
    /// Must be zero, no flags are currently defined by the tool-convention.
    flags: u32,
    symbols: Comdat.Symbol.Slice,

    pub const Symbol = struct {
        kind: Comdat.Symbol.Type,
        /// Index of the data segment/function/global/event/table within a WASM module.
        /// The object must not be an import.
        index: u32,

        pub const Slice = struct {
            /// Index into Wasm object_comdat_symbols
            off: u32,
            len: u32,
        };

        pub const Type = enum(u8) {
            data = 0,
            function = 1,
            global = 2,
            event = 3,
            table = 4,
            section = 5,
        };
    };
};

/// Stored as a u8 so it can reuse the string table mechanism.
pub const Feature = packed struct(u8) {
    prefix: Prefix,
    /// Type of the feature, must be unique in the sequence of features.
    tag: Tag,

    /// Stored identically to `String`. The bytes are reinterpreted as `Feature`
    /// elements. Elements must be sorted before string-interning.
    pub const Set = enum(u32) {
        _,

        pub fn fromString(s: String) Set {
            return @enumFromInt(@intFromEnum(s));
        }
    };

    /// Unlike `std.Target.wasm.Feature` this also contains linker-features such as shared-mem.
    /// Additionally the name uses convention matching the wasm binary format.
    pub const Tag = enum(u6) {
        atomics = 0,
        @"bulk-memory" = 1,
        @"exception-handling" = 2,
        @"extended-const" = 3,
        @"half-precision" = 4,
        multimemory = 5,
        multivalue = 6,
        @"mutable-globals" = 7,
        @"nontrapping-fptoint" = 8,
        @"reference-types" = 9,
        @"relaxed-simd" = 10,
        @"sign-ext" = 11,
        simd128 = 12,
        @"tail-call" = 13,
        @"shared-mem" = 14,

        pub fn fromCpuFeature(feature: std.Target.wasm.Feature) Tag {
            return @enumFromInt(@intFromEnum(feature));
        }

        pub const format = @compileError("use @tagName instead");
    };

    /// Provides information about the usage of the feature.
    pub const Prefix = enum(u2) {
        /// Reserved so that a 0-byte Feature is invalid and therefore can be a sentinel.
        invalid,
        /// '0x2b': Object uses this feature, and the link fails if feature is
        /// not in the allowed set.
        @"+",
        /// '0x2d': Object does not use this feature, and the link fails if
        /// this feature is in the allowed set.
        @"-",
        /// '0x3d': Object uses this feature, and the link fails if this
        /// feature is not in the allowed set, or if any object does not use
        /// this feature.
        @"=",
    };

    pub fn format(feature: Feature, comptime fmt: []const u8, opt: std.fmt.FormatOptions, writer: anytype) !void {
        _ = opt;
        _ = fmt;
        try writer.print("{s} {s}", .{ @tagName(feature.prefix), @tagName(feature.tag) });
    }

    pub fn lessThan(_: void, a: Feature, b: Feature) bool {
        assert(a != b);
        const a_int: u8 = @bitCast(a);
        const b_int: u8 = @bitCast(b);
        return a_int < b_int;
    }
};

/// Parses an object file into atoms, for code and data sections
fn parseSymbolIntoAtom(wasm: *Wasm, object_id: ObjectId, symbol_index: Symbol.Index) !Atom.Index {
    const object = wasm.objectById(object_id) orelse
        return wasm.zig_object.?.parseSymbolIntoAtom(wasm, symbol_index);
    const comp = wasm.base.comp;
    const gpa = comp.gpa;
    const symbol = objectSymbol(wasm, object_id, symbol_index);
    const relocatable_data: RelocatableData = switch (symbol.tag) {
        .function => object.relocatable_data.get(.code).?[symbol.index - object.imported_functions_count],
        .data => object.relocatable_data.get(.data).?[symbol.index],
        .section => blk: {
            const data = object.relocatable_data.get(.custom).?;
            _ = @import("../main.zig").@"bad O(N)";
            for (data) |dat| {
                if (dat.section_index == symbol.index) {
                    break :blk dat;
                }
            }
            unreachable;
        },
        else => unreachable,
    };
    const final_index = try wasm.getMatchingSegment(object_id, symbol_index);
    const atom_index = try wasm.createAtom(symbol_index, object_id.toOptional());
    try wasm.appendAtomAtIndex(final_index, atom_index);

    const atom = wasm.atomPtr(atom_index);
    atom.alignment = relocatable_data.getAlignment(object);
    atom.code = relocatable_data.payload;
    atom.original_offset = relocatable_data.offset;

    const segment = final_index.ptr(wasm);
    if (relocatable_data.type == .data) { //code section and custom sections are 1-byte aligned
        segment.alignment = segment.alignment.max(atom.alignment);
    }

    if (object.relocations.get(relocatable_data.section_index)) |relocations| {
        const start = searchRelocStart(relocations, relocatable_data.offset);
        const len = searchRelocEnd(relocations[start..], relocatable_data.offset + atom.code.len);
        atom.relocs = std.ArrayListUnmanaged(Relocation).fromOwnedSlice(relocations[start..][0..len]);
        for (atom.relocs.items) |reloc| {
            switch (reloc.tag) {
                .TABLE_INDEX_I32,
                .TABLE_INDEX_I64,
                .TABLE_INDEX_SLEB,
                .TABLE_INDEX_SLEB64,
                => {
                    try wasm.function_table.put(gpa, .{
                        .file = object_id.toOptional(),
                        .index = @enumFromInt(reloc.index),
                    }, 0);
                },
                .GLOBAL_INDEX_I32,
                .GLOBAL_INDEX_LEB,
                => {
                    const sym = objectSymbolsByPtr(wasm, object)[reloc.index];
                    if (sym.tag != .global) {
                        try wasm.got_symbols.append(gpa, .{
                            .file = object_id.toOptional(),
                            .index = @enumFromInt(reloc.index),
                        });
                    }
                },
                else => {},
            }
        }
    }

    return atom_index;
}

fn searchRelocStart(relocs: []const Relocation, address: u32) usize {
    var min: usize = 0;
    var max: usize = relocs.len;
    while (min < max) {
        const index = (min + max) / 2;
        const curr = relocs[index];
        if (curr.offset < address) {
            min = index + 1;
        } else {
            max = index;
        }
    }
    return min;
}

fn searchRelocEnd(relocs: []const Relocation, address: u32) usize {
    for (relocs, 0..relocs.len) |reloc, index| {
        if (reloc.offset > address) {
            return index;
        }
    }
    return relocs.len;
}

pub fn internString(wasm: *Wasm, bytes: []const u8) error{OutOfMemory}!String {
    assert(mem.indexOfScalar(u8, bytes, 0) == null);
    const gpa = wasm.base.comp.gpa;
    const gop = try wasm.string_table.getOrPutContextAdapted(
        gpa,
        @as([]const u8, bytes),
        @as(String.TableIndexAdapter, .{ .bytes = wasm.string_bytes.items }),
        @as(String.TableContext, .{ .bytes = wasm.string_bytes.items }),
    );
    if (gop.found_existing) return gop.key_ptr.*;

    try wasm.string_bytes.ensureUnusedCapacity(gpa, bytes.len + 1);
    const new_off: String = @enumFromInt(wasm.string_bytes.items.len);

    wasm.string_bytes.appendSliceAssumeCapacity(bytes);
    wasm.string_bytes.appendAssumeCapacity(0);

    gop.key_ptr.* = new_off;

    return new_off;
}

pub fn getExistingString(wasm: *const Wasm, bytes: []const u8) ?String {
    assert(mem.indexOfScalar(u8, bytes, 0) == null);
    return wasm.string_table.getKeyAdapted(bytes, @as(String.TableIndexAdapter, .{
        .bytes = wasm.string_bytes.items,
    }));
}

pub fn stringSlice(wasm: *const Wasm, index: String) [:0]const u8 {
    const slice = wasm.string_bytes.items[@intFromEnum(index)..];
    return slice[0..mem.indexOfScalar(u8, slice, 0).? :0];
}

pub fn internValtypeList(wasm: *Wasm, valtype_list: []const std.wasm.Valtype) error{OutOfMemory}!ValtypeList {
    return .fromString(try internString(wasm, @ptrCast(valtype_list)));
}

pub fn optionalStringSlice(wasm: *const Wasm, index: OptionalString) ?[:0]const u8 {
    return stringSlice(wasm, index.unwrap() orelse return null);
}

pub fn castToString(wasm: *const Wasm, index: u32) String {
    assert(index == 0 or wasm.string_bytes.items[index - 1] == 0);
    return @enumFromInt(index);
}

fn objectGlobalImportPtr(wasm: *const Wasm, index: ObjectGlobalImportIndex) *GlobalImport {
    return &wasm.object_global_imports.items[@intFromEnum(index)];
}

fn objectGlobalPtr(wasm: *const Wasm, index: ObjectGlobalIndex) *Global {
    return &wasm.object_globals.items[@intFromEnum(index)];
}

fn objectFunctionType(wasm: *const Wasm, index: ObjectFunctionIndex) FunctionType.Index {
    return &wasm.object_functions.items[@intFromEnum(index)];
}

fn objectTableImportPtr(wasm: *const Wasm, index: ObjectTableImportIndex) *Table {
    return &wasm.object_table_imports.items[@intFromEnum(index)];
}

pub fn addFuncType(wasm: *Wasm, ft: FunctionType) error{OutOfMemory}!FunctionType.Index {
    const gpa = wasm.base.comp.gpa;
    const gop = try wasm.func_types.getOrPut(gpa, ft);
    return @enumFromInt(gop.index);
}

fn addInitExpr(wasm: *Wasm, init_expr: std.wasm.InitExpression) error{OutOfMemory}!Expr {
    var buffer: [10]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buffer);
    emitInit(fbs.writer(), init_expr) catch unreachable;
    return addExpr(wasm, fbs.getWritten());
}

pub fn addExpr(wasm: *Wasm, bytes: []const u8) error{OutOfMemory}!Expr {
    const gpa = wasm.base.comp.gpa;
    // We can't use string table deduplication here since these expressions can
    // have null bytes in them however it may be interesting to explore since
    // it is likely for globals to share initialization values. Then again
    // there may not be very many globals in total.
    try wasm.string_bytes.appendSlice(gpa, bytes);
    return @enumFromInt(wasm.string_bytes.items.len - bytes.len);
}

pub fn addRelocatableDataPayload(wasm: *Wasm, bytes: []const u8) error{OutOfMemory}!RelocatableData.Payload {
    const gpa = wasm.base.comp.gpa;
    try wasm.string_bytes.appendSlice(gpa, bytes);
    return @enumFromInt(wasm.string_bytes.items.len - bytes.len);
}

fn syntheticSymbolPtr(wasm: *const Wasm, index: Symbol.Index) *Symbol {
    return &wasm.synthetic_symbols.items[@intFromEnum(index)];
}

fn functionImportPtr(wasm: *const Wasm, index: FunctionImportIndex) *FunctionImport {
    return &wasm.function_imports.items[@intFromEnum(index)];
}

fn globalImportPtr(wasm: *const Wasm, index: GlobalImportIndex) *GlobalImport {
    return &wasm.global_imports.items[@intFromEnum(index)];
}

fn tableImportPtr(wasm: *const Wasm, index: TableImportIndex) *Table {
    return &wasm.table_imports.items[@intFromEnum(index)];
}

fn functionImportBySymbolLoc(wasm: *const Wasm, loc: SymbolLoc) *FunctionImport {
    if (loc.file.unwrap()) |obj_id| return functionImportBySymbolIndex(wasm, obj_id, loc.index);
    const symbol = &wasm.synthetic_symbols.items[@intFromEnum(loc.index)];
    return functionImportPtr(wasm, symbol.pointee.function_import);
}

fn functionImportBySymbolIndex(wasm: *const Wasm, object_id: ObjectId, symbol_index: Symbol.Index) *FunctionImport {
    switch (object_id) {
        .zig_object => {
            const zo = wasm.zig_object.?;
            const sym = zo.symbol(symbol_index);
            return zo.functionImportPtr(sym.pointee.function_import_zo);
        },
        _ => {
            const obj = &wasm.objects.items[@intFromEnum(object_id)];
            const symbols = wasm.object_symbols.items[obj.symbols.off..][0..obj.symbols.len];
            const sym = &symbols[@intFromEnum(symbol_index)];
            return functionImportPtr(wasm, sym.pointee.function_import);
        },
    }
}

fn globalImportBySymbolIndex(wasm: *const Wasm, object_id: ObjectId, symbol_index: Symbol.Index) *GlobalImport {
    switch (object_id) {
        .zig_object => {
            const zo = wasm.zig_object.?;
            const sym = zo.symbol(symbol_index);
            return zo.globalImportPtr(sym.pointee.global_import_zo);
        },
        _ => {
            const obj = &wasm.objects.items[@intFromEnum(object_id)];
            const symbols = wasm.object_symbols.items[obj.symbols.off..][0..obj.symbols.len];
            const sym = &symbols[@intFromEnum(symbol_index)];
            return globalImportPtr(wasm, sym.pointee.global_import);
        },
    }
}

fn tableImportBySymbolIndex(wasm: *const Wasm, object_id: ObjectId, symbol_index: Symbol.Index) *Table {
    switch (object_id) {
        .zig_object => {
            const zo = wasm.zig_object.?;
            const sym = zo.symbol(symbol_index);
            return zo.tableImportPtr(sym.pointee.table_import_zo);
        },
        _ => {
            const obj = &wasm.objects.items[@intFromEnum(object_id)];
            const symbols = wasm.object_symbols.items[obj.symbols.off..][0..obj.symbols.len];
            const sym = &symbols[@intFromEnum(symbol_index)];
            return tableImportPtr(wasm, sym.pointee.table_import);
        },
    }
}

fn addGlobal(wasm: *Wasm, global: Global) error{OutOfMemory}!GlobalIndex {
    const gpa = wasm.base.comp.gpa;
    try wasm.output_globals.append(gpa, global);
    return @enumFromInt(wasm.output_globals.items.len - 1);
}

fn addTable(wasm: *Wasm, table: Table) error{OutOfMemory}!TableIndex {
    const gpa = wasm.base.comp.gpa;
    try wasm.tables.append(gpa, table);
    return @enumFromInt(wasm.tables.items.len - 1);
}
