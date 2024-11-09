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
const Zcu = @import("../Zcu.zig");
const ZigObject = @import("Wasm/ZigObject.zig");
const codegen = @import("../codegen.zig");
const dev = @import("../dev.zig");
const link = @import("../link.zig");
const lldMain = @import("../main.zig").lldMain;
const trace = @import("../tracy.zig").trace;
const wasi_libc = @import("../wasi_libc.zig");
const Value = @import("../Value.zig");

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
/// List of relocatable files to be linked into the final binary.
objects: std.ArrayListUnmanaged(Object) = .{},

func_types: std.AutoArrayHashMapUnmanaged(FunctionType, void) = .empty,
/// Provides a mapping of both imports and provided functions to symbol name.
/// Local functions may be unnamed.
object_function_imports: std.AutoArrayHashMapUnmanaged(String, FunctionImport) = .empty,
/// All functions for all objects.
object_functions: std.ArrayListUnmanaged(Function) = .empty,

/// Provides a mapping of both imports and provided globals to symbol name.
/// Local globals may be unnamed.
object_global_imports: std.AutoArrayHashMapUnmanaged(String, GlobalImport) = .empty,
/// All globals for all objects.
object_globals: std.ArrayListUnmanaged(Global) = .empty,

/// List of initialization functions. These must be called in order of priority
/// by the (synthetic) __wasm_call_ctors function.
object_init_funcs: std.ArrayListUnmanaged(InitFunc) = .empty,
/// All relocations from all objects concatenated. `relocs_start` marks the end
/// point of object relocations and start point of Zcu relocations.
relocations: std.MultiArrayList(Relocation) = .empty,

/// Non-synthetic section that can essentially be mem-cpy'd into place after performing relocations.
object_relocatable_datas: std.ArrayListUnmanaged(RelocatableData) = .empty,
/// Non-synthetic section that can essentially be mem-cpy'd into place after performing relocations.
object_relocatable_customs: std.AutoArrayHashMapUnmanaged(InputSectionIndex, RelocatableCustom) = .empty,
/// All table imports for all objects.
object_table_imports: std.ArrayListUnmanaged(Table) = .empty,
/// All memory imports for all objects.
object_memory_imports: std.ArrayListUnmanaged(MemoryImport) = .empty,
/// All parsed table sections for all objects.
object_tables: std.ArrayListUnmanaged(Table) = .empty,
/// All parsed memory sections for all objects.
object_memories: std.ArrayListUnmanaged(std.wasm.Memory) = .empty,
/// All parsed export sections for all objects.
object_exports: std.ArrayListUnmanaged(Export) = .empty,
/// All comdat information for all objects.
object_comdats: std.ArrayListUnmanaged(Comdat) = .empty,
/// A table that maps the relocations to be performed where the key represents
/// the section (across all objects) that the slice of relocations applies to.
object_relocations_table: std.AutoArrayHashMapUnmanaged(InputSectionIndex, Relocation.Slice) = .empty,
/// Incremented across all objects in order to enable calculation of `InputSectionIndex` values.
object_total_sections: u32 = 0,
/// All comdat symbols from all objects concatenated.
object_comdat_symbols: std.MultiArrayList(Comdat.Symbol) = .empty,

/// When importing objects from the host environment, a name must be supplied.
/// LLVM uses "env" by default when none is given. This would be a good default for Zig
/// to support existing code.
/// TODO: Allow setting this through a flag?
host_name: String,

table_imports: std.ArrayListUnmanaged(Table) = .empty,
memory_imports: std.ArrayListUnmanaged(MemoryImport) = .empty,

/// Represents non-synthetic section entries.
/// Used for code, data and custom sections.
segments: std.ArrayListUnmanaged(Segment) = .empty,
/// Maps a data segment key (such as .rodata) to the index into `segments`.
data_segments: std.StringArrayHashMapUnmanaged(Segment.Index) = .empty,


indirect_function_table: std.AutoArrayHashMapUnmanaged(OutputFunctionIndex, u32) = .empty,


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
/// Index to a function defining the entry of the wasm file
entry: ?u32 = null,

/// `--verbose-link` output.
/// Initialized on creation, appended to as inputs are added, printed during `flush`.
/// String data is allocated into Compilation arena.
dump_argv_list: std.ArrayListUnmanaged([]const u8),

/// Represents the index into `segments` where the 'code' section lives.
code_section_index: Segment.OptionalIndex = .none,
custom_sections: CustomSections,
preloaded_strings: PreloadedStrings,

navs: std.AutoArrayHashMapUnmanaged(InternPool.Nav.Index, Nav) = .empty,
nav_exports: std.AutoArrayHashMapUnmanaged(NavExport, Zcu.Export.Index) = .empty,
uav_exports: std.AutoArrayHashMapUnmanaged(UavExport, Zcu.Export.Index) = .empty,
imports: std.AutoArrayHashMapUnmanaged(InternPool.Nav.Index, void) = .empty,

/// During the pre-link phase, the `function_imports` field of Wasm contains
/// all the functions that remain undefined after processing all the linker
/// inputs. These could be resolved to functions defined by ZigObject, or if no
/// such function is present, they will be emitted into the import section.
///
/// This integer tracks the end position of that `function_imports` field after
/// the pre-link phase but before any ZigObject functions are generated. This
/// way, that same map can be used to store additional function imports needed
/// by the ZigObject, while retaining the ability to restore state back to end
/// of the pre-link phase.
function_import_start: u32,
/// Same as `function_import_start` but for global imports.
global_import_start: u32,
/// Same as `function_import_start` but for output globals.
global_start: u32,
/// Same as `function_import_start` but for relocations
relocs_start: u32,

dwarf: ?Dwarf = null,
debug_sections: DebugSections,

/// The first N indexes correspond to input objects (`objects`) array.
/// After that, the indexes correspond to the `source_locations` array,
/// representing a location in a Zig source file that can be pinpointed
/// precisely via AST node and token.
pub const SourceLocation = enum(u32) {
    zig_object_nofile = std.math.maxInt(u32) - 1,
    none = std.math.maxInt(u32),
    _,
};

/// The lower bits of this ABI-match the flags here:
/// https://github.com/WebAssembly/tool-conventions/blob/df8d737539eb8a8f446ba5eab9dc670c40dfb81e/Linking.md#symbol-table-subsection
/// The upper bits are used for nefarious purposes.
pub const SymbolFlags = packed struct(u32) {
    binding: Binding = .strong,
    /// Indicating that this is a hidden symbol. Hidden symbols are not to be
    /// exported when performing the final link, but may be linked to other
    /// modules.
    visibility_hidden: bool = false,
    padding0: u1 = 0,
    /// Indicating that this symbol is not defined. For non-data symbols, this
    /// must match whether the symbol is an import or is defined; for data
    /// symbols, determines whether a segment is specified.
    undefined: bool = false,
    /// The symbol is intended to be exported from the wasm module to the host
    /// environment. This differs from the visibility flags in that it effects
    /// the static linker.
    exported: bool = false,
    /// The symbol uses an explicit symbol name, rather than reusing the name
    /// from a wasm import. This allows it to remap imports from foreign
    /// WebAssembly modules into local symbols with different names.
    explicit_name: bool = false,
    /// The symbol is intended to be included in the linker output, regardless
    /// of whether it is used by the program. Same meaning as `retain`.
    no_strip: bool = false,
    /// The symbol resides in thread local storage.
    tls: bool = false,
    /// The symbol represents an absolute address. This means its offset is
    /// relative to the start of the wasm memory as opposed to being relative
    /// to a data segment.
    absolute: bool = false,

    // Above here matches the tooling conventions ABI.

    padding1: u8 = 0,
    /// Zig-specific. Dead things are allowed to be garbage collected.
    alive: bool = false,
    /// Zig-specific. Segments only. Signals that the segment contains only
    /// null terminated strings allowing the linker to perform merging.
    strings: bool = false,
    /// Zig-specific. This symbol comes from an object that must be included in
    /// the final link.
    must_link: bool = false,
    /// Zig-specific. Segments only.
    alignment: Alignment = .none,
    /// Zig-specific. Globals only.
    global_type: Global.Type = .zero,

    pub const Binding = enum(u2) {
        strong = 0,
        /// Indicating that this is a weak symbol. When linking multiple modules
        /// defining the same symbol, all weak definitions are discarded if any
        /// strong definitions exist; then if multiple weak definitions exist all
        /// but one (unspecified) are discarded; and finally it is an error if more
        /// than one definition remains.
        weak = 1,
        /// Indicating that this is a local symbol. Local symbols are not to be
        /// exported, or linked to other modules/sections. The names of all
        /// non-local symbols must be unique, but the names of local symbols
        /// are not considered for uniqueness. A local function or global
        /// symbol cannot reference an import.
        local = 2,
    };

    pub fn clearZigSpecific(flags: *SymbolFlags, must_link: bool) void {
        flags.alive = false;
        flags.strings = false;
        flags.must_link = must_link;
        flags.alignment = .none;
        flags.global_type = .zero;
    }

    pub fn isIncluded(flags: SymbolFlags, is_dynamic: bool) bool {
        return flags.exported or
            (is_dynamic and !flags.visibility_hidden) or
            (flags.no_strip and flags.must_link);
    }

    pub fn isExported(flags: SymbolFlags, is_dynamic: bool) bool {
        if (flags.undefined or flags.binding == .local) return false;
        if (is_dynamic and !flags.visibility_hidden) return true;
        return flags.exported;
    }

    pub fn requiresImport(flags: SymbolFlags, is_data: bool) bool {
        if (is_data) return false;
        if (!flags.undefined) return false;
        if (flags.binding == .weak) return false;
        return true;
    }

    /// Returns the name as how it will be output into the final object
    /// file or binary. When `merge` is true, this will return the
    /// short name. i.e. ".rodata". When false, it returns the entire name instead.
    pub fn outputName(flags: SymbolFlags, name: []const u8, merge: bool) []const u8 {
        if (flags.tls) return ".tdata";
        if (!merge) return name;
        if (mem.startsWith(u8, name, ".rodata.")) return ".rodata";
        if (mem.startsWith(u8, name, ".text.")) return ".text";
        if (mem.startsWith(u8, name, ".data.")) return ".data";
        if (mem.startsWith(u8, name, ".bss.")) return ".bss";
        return name;
    }
};

pub const Nav = extern struct {
    code: RelocatableData.Payload,
    relocs: Relocation.Slice,

    pub const Code = RelocatableData.Payload;

    /// Index into `navs`.
    /// Note that swapRemove is sometimes performed on `navs`.
    pub const Index = enum(u32) {
        _,

        pub fn key(i: @This(), zo: *const ZigObject) *InternPool.Nav.Index {
            return &zo.navs.keys()[@intFromEnum(i)];
        }

        pub fn value(i: @This(), zo: *const ZigObject) *Nav {
            return &zo.navs.values()[@intFromEnum(i)];
        }
    };
};

pub const NavExport = extern struct {
    name: String,
    nav_index: InternPool.Nav.Index,
};

pub const UavExport = extern struct {
    name: String,
    uav_index: InternPool.Index,
};

const DebugSections = struct {
    abbrev: DebugSection,
    info: DebugSection,
    line: DebugSection,
    loc: DebugSection,
    pubnames: DebugSection,
    pubtypes: DebugSection,
    ranges: DebugSection,
    str: DebugSection,
};

const DebugSection = struct {};

pub const FunctionImport = extern struct {
    flags: SymbolFlags,
    module_name: String,
    source_location: SourceLocation,
    resolution: Resolution,
    type: FunctionType.Index,

    /// Represents a synthetic function, or a function from an object.
    pub const Resolution = enum(u32) {
        unresolved,
        // put tags for synthetic functions here
        _,
    };
};

pub const Function = extern struct {
    flags: SymbolFlags,
    /// `none` if this function has no symbol describing it.
    name: OptionalString,
    type_index: FunctionType.Index,
    code: Code,
    /// The offset within the section where the data starts.
    offset: u32,
    section_index: InputSectionIndex,
    source_location: SourceLocation,

    pub const Code = RelocatableData.Payload;
};

pub const GlobalImport = extern struct {
    flags: SymbolFlags,
    module_name: String,
    source_location: SourceLocation,
    resolution: Resolution,

    /// Represents a synthetic global, or a global from an object.
    pub const Resolution = enum(u32) {
        unresolved,
        __heap_base,
        __heap_end,
        __tls_base,
        _,
    };

};

pub const Global = extern struct {
    /// `none` if this function has no symbol describing it.
    name: OptionalString,
    flags: SymbolFlags,
    expr: Expr,

    pub const Type = packed struct(u4) {
        valtype: Valtype,
        mutable: bool,

        pub const zero: Type = @bitCast(@as(u4, 0));
    };

    pub const Valtype = enum(u3) {
        i32,
        i64,
        f32,
        f64,
        v128,

        pub fn from(v: std.wasm.Valtype) Valtype {
            return switch (v) {
                .i32 => .i32,
                .i64 => .i64,
                .f32 => .f32,
                .f64 => .f64,
                .v128 => .v128,
            };
        }

        pub fn to(v: Valtype) std.wasm.Valtype {
            return switch (v) {
                .i32 => .i32,
                .i64 => .i64,
                .f32 => .f32,
                .f64 => .f64,
                .v128 => .v128,
            };
        }
    };

    /// Index into `output_globals`.
    pub const Index = enum(u32) {
        _,

        fn ptr(index: Index, wasm: *const Wasm) *Global {
            return &wasm.output_globals.items[@intFromEnum(index)];
        }
    };
};



/// Uniquely identifies a section across all objects. Each Object has a section_start field.
/// By subtracting that value from this one, the Object section index is obtained.
pub const InputSectionIndex = enum(u32) {
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

/// Index into `object_globals`.
pub const ObjectGlobalIndex = enum(u32) {
    _,
};

/// First index into the output import section.
/// Next index into the output functions (code section).
pub const OutputFunctionIndex = enum(u32) {
    _,
};

/// Index into `tables`.
pub const TableIndex = enum(u32) {
    _,
};

/// Index into `object_functions`.
pub const ObjectFunctionIndex = enum(u32) {
    _,

    pub fn ptr(index: ObjectFunctionIndex, wasm: *const Wasm) *Function {
        return &wasm.object_functions.items[@intFromEnum(index)];
    }

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
    /// `none` if no symbol describes it.
    name: OptionalString,
    flags: SymbolFlags,
    payload: Payload,
    segment_offset: u32,
    section_index: InputSectionIndex,

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

pub const RelocatableCustom = extern struct {
    payload: Payload,
    flags: SymbolFlags,
    section_name: String,

    pub const Payload = RelocatableData.Payload;
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

    pub fn slice(index: String, wasm: *const Wasm) [:0]const u8 {
        const start_slice = wasm.string_bytes.items[@intFromEnum(index)..];
        return start_slice[0..mem.indexOfScalar(u8, start_slice, 0).? :0];
    }


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
        return @bitCast(String.slice(@enumFromInt(@intFromEnum(index)), wasm));
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
    const is_wasm32 = target.cpu.arch == .wasm32;

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
                .valtype = if (is_wasm32) .i32 else .i64,
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
        }
    }

    return wasm;
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

    var ss: Object.ScratchSpace = .{};
    defer ss.deinit(gpa);

    const object = try Object.parse(wasm, file_contents, obj.path, null, wasm.host_name, &ss, obj.must_link);
    wasm.objects.appendAssumeCapacity(object);
}

fn parseArchive(wasm: *Wasm, obj: link.Input.Object) !void {
    const gpa = wasm.base.comp.gpa;

    defer obj.file.close();

    const stat = try obj.file.stat();
    const size = std.math.cast(usize, stat.size) orelse return error.FileTooBig;

    const file_contents = try gpa.alloc(u8, size);
    defer gpa.free(file_contents);

    const n = try obj.file.preadAll(file_contents, 0);
    if (n != file_contents.len) return error.UnexpectedEndOfFile;

    var archive = try Archive.parse(gpa, file_contents);
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

    var ss: Object.ScratchSpace = .{};
    defer ss.deinit(gpa);

    try wasm.objects.ensureUnusedCapacity(gpa, offsets.count());
    for (offsets.keys()) |file_offset| {
        const contents = file_contents[file_offset..];
        const object = try archive.parseObject(wasm, contents, obj.path, wasm.host_name, &ss, obj.must_link);
        wasm.objects.appendAssumeCapacity(object);
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
        if (sym.tag == .data and !sym.flags.undefined) {
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

pub fn deinit(wasm: *Wasm) void {
    const gpa = wasm.base.comp.gpa;
    if (wasm.llvm_object) |llvm_object| llvm_object.deinit();

    wasm.navs.deinit(gpa);
    wasm.nav_exports.deinit(gpa);
    wasm.uav_exports.deinit(gpa);
    wasm.imports.deinit(gpa);

    if (wasm.dwarf) |*dwarf| dwarf.deinit();

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

    wasm.synthetic_symbols.deinit(gpa);
    wasm.globals.deinit(gpa);
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

    const zcu = pt.zcu;
    const gpa = zcu.gpa;
    const func = pt.zcu.funcInfo(func_index);
    const nav_index = func.owner_nav;

    const code_start: u32 = @intCast(wasm.string_bytes.items.len);
    const relocs_start: u32 = @intCast(wasm.relocations.items.len);
    wasm.string_bytes_lock.lock();

    const wasm_codegen = @import("../../arch/wasm/CodeGen.zig");
    dev.check(.wasm_backend);
    const result = try wasm_codegen.generate(
        &wasm.base,
        pt,
        zcu.navSrcLoc(nav_index),
        func_index,
        air,
        liveness,
        &wasm.string_bytes,
        .none,
    );

    const code_len: u32 = @intCast(wasm.string_bytes.items.len - code_start);
    const relocs_len: u32 = @intCast(wasm.relocations.items.len - relocs_start);
    wasm.string_bytes_lock.unlock();

    const code: Nav.Code = switch (result) {
        .ok => .{
            .off = code_start,
            .len = code_len,
        },
        .fail => |em| {
            try pt.zcu.failed_codegen.put(gpa, nav_index, em);
            return;
        },
    };

    const gop = try wasm.navs.getOrPut(gpa, nav_index);
    if (gop.found_existing) {
        @panic("TODO reuse these resources");
    } else {
        _ = wasm.imports.swapRemove(nav_index);
    }
    gop.value_ptr.* = .{
        .code = code,
        .relocs = .{
            .off = relocs_start,
            .len = relocs_len,
        },
    };
}

// Generate code for the "Nav", storing it in memory to be later written to
// the file on flush().
pub fn updateNav(wasm: *Wasm, pt: Zcu.PerThread, nav_index: InternPool.Nav.Index) !void {
    if (build_options.skip_non_native and builtin.object_format != .wasm) {
        @panic("Attempted to compile for object format that was disabled by build configuration");
    }
    if (wasm.llvm_object) |llvm_object| return llvm_object.updateNav(pt, nav_index);
    const zcu = pt.zcu;
    const ip = &zcu.intern_pool;
    const nav = ip.getNav(nav_index);
    const gpa = wasm.base.comp.gpa;

    const nav_val = zcu.navValue(nav_index);
    const is_extern, const nav_init = switch (ip.indexToKey(nav_val.toIntern())) {
        .variable => |variable| .{ false, Value.fromInterned(variable.init) },
        .func => unreachable,
        .@"extern" => b: {
            assert(!ip.isFunctionType(nav.typeOf(ip)));
            break :b .{ true, nav_val };
        },
        else => .{ false, nav_val },
    };

    if (!nav_init.typeOf(zcu).hasRuntimeBits(zcu)) {
        _ = wasm.imports.swapRemove(nav_index);
        _ = wasm.navs.swapRemove(nav_index); // TODO reclaim resources
        return;
    }

    if (is_extern) {
        try wasm.imports.put(nav_index, {});
        _ = wasm.navs.swapRemove(nav_index); // TODO reclaim resources
        return;
    }

    const code_start: u32 = @intCast(wasm.string_bytes.items.len);
    const relocs_start: u32 = @intCast(wasm.relocations.items.len);
    wasm.string_bytes_lock.lock();

    const res = try codegen.generateSymbol(
        &wasm.base,
        pt,
        zcu.navSrcLoc(nav_index),
        nav_init,
        &wasm.string_bytes,
        .none,
    );

    const code_len: u32 = @intCast(wasm.string_bytes.items.len - code_start);
    const relocs_len: u32 = @intCast(wasm.relocations.items.len - relocs_start);
    wasm.string_bytes_lock.unlock();

    const code: Nav.Code = switch (res) {
        .ok => .{
            .off = code_start,
            .len = code_len,
        },
        .fail => |em| {
            try zcu.failed_codegen.put(gpa, nav_index, em);
            return;
        },
    };

    const gop = try wasm.navs.getOrPut(gpa, nav_index);
    if (gop.found_existing) {
        @panic("TODO reuse these resources");
    } else {
        _ = wasm.imports.swapRemove(nav_index);
    }
    gop.value_ptr.* = .{
        .code = code,
        .relocs = .{
            .off = relocs_start,
            .len = relocs_len,
        },
    };
}

pub fn updateNavLineNumber(wasm: *Wasm, pt: Zcu.PerThread, nav_index: InternPool.Nav.Index) !void {
    if (wasm.llvm_object != null) return;
    const ip = &pt.zcu.intern_pool;
    const nav = ip.getNav(nav_index);

    log.debug("updateNavLineNumber {}({d})", .{ nav.fqn.fmt(ip), nav_index });

    if (wasm.dwarf) |*dwarf| {
        try dwarf.updateNavLineNumber(pt.zcu, nav_index);
    }
}

pub fn deleteExport(
    wasm: *Wasm,
    exported: Zcu.Exported,
    name: InternPool.NullTerminatedString,
) void {
    if (wasm.llvm_object != null) return;

    const zcu = wasm.base.comp.zcu.?;
    const ip = &zcu.intern_pool;
    const export_name = try wasm.internString(name.toSlice(ip));
    switch (exported) {
        .nav => |nav_index| assert(wasm.nav_exports.swapRemove(.{ .nav_index = nav_index, .name = export_name })),
        .uav => |uav_index| assert(wasm.uav_exports.swapRemove(.{ .uav_index = uav_index, .name = export_name })),
    }
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

    const zcu = pt.zcu;
    const gpa = zcu.gpa;
    const ip = &zcu.intern_pool;
    for (export_indices) |export_idx| {
        const exp = export_idx.ptr(zcu);
        const name = try wasm.internString(exp.opts.name.toSlice(ip));
        switch (exported) {
            .nav => |nav_index| wasm.nav_exports.put(gpa, .{ .nav_index = nav_index, .name = name }, export_idx),
            .uav => |uav_index| wasm.uav_exports.put(gpa, .{ .uav_index = uav_index, .name = name }, export_idx),
        }
    }
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

/// Creates a function body for the `__wasm_call_ctors` symbol.
/// Loops over all constructors found in `object_init_funcs` and calls them
/// respectively based on their priority.
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
        for (wasm.object_init_funcs.items) |init_func_loc| {
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

    code = try addRelocatableDataPayload(wasm, function_body);
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
            symbol.name.slice(wasm), exp.name.slice(wasm), exp.index,
        });
    }

    log.debug("finished setting up {d} exports", .{wasm.exports.items.len});
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

    const stack_ptr: Global.Index = if (wasm.globals.get(wasm.preloaded_strings.__stack_pointer)) |loc| index: {
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

pub fn prelink(wasm: *Wasm, prog_node: std.Progress.Node) anyerror!void {
    const tracy = trace(@src());
    defer tracy.end();

    const sub_prog_node = prog_node.start("Wasm Prelink", 0);
    defer sub_prog_node.end();

    const comp = wasm.base.comp;
    const shared_memory = comp.config.shared_memory;
    const diags = &comp.link_diags;

    if (wasm.object_init_funcs.items.len > 0) {
        // Zig has no constructors so these are only for object file inputs.
        mem.sortUnstable(InitFunc, wasm.object_init_funcs.items, {}, InitFunc.lessThan);
        try wasm.initializeCallCtorsFunction();
    }

    if (wasm.zig_object) |zo| {
        zo.function_import_start = @intCast(wasm.function_imports.count());
        zo.global_import_start = @intCast(wasm.global_imports.count());
        zo.global_start = @intCast(wasm.output_globals.items.len);
        assert(wasm.output_globals.items.len == wasm.global_names.count());
    }
}

fn lazyMarkSyntheticGlobal(wasm: *Wasm, name: String, resolution: GlobalImport.Resolution, flags: SymbolFlags) void {
    const import = wasm.object_global_imports.getPtr(name) orelse return;
    if (import.resolution == .none) {
        import.resolution = resolution;
        import.flags = flags; // TODO emit compile error for bad flags
    }
}

pub fn flushModule(wasm: *Wasm, arena: Allocator, tid: Zcu.PerThread.Id, prog_node: std.Progress.Node) anyerror!void {
    const comp = wasm.base.comp;
    const shared_memory = comp.config.shared_memory;
    const diags = &comp.link_diags;
    const gpa = comp.gpa;
    const use_llvm = comp.config.use_llvm;
    const use_lld = build_options.have_llvm and comp.config.use_lld;
    const import_memory = comp.config.import_memory;
    const export_memory = comp.config.export_memory;
    const target = comp.root_mod.resolved_target.result;
    const rdynamic = comp.config.rdynamic;
    const gc_sections = wasm.base.gc_sections;

    if (wasm.llvm_object) |llvm_object| {
        try wasm.base.emitLlvmObject(arena, llvm_object, prog_node);
        if (use_lld) return;
    }

    if (comp.verbose_link) Compilation.dump_argv(wasm.dump_argv_list.items);

    if (wasm.base.zcu_object_sub_path) |path| {
        const module_obj_path = .{
            .root_dir = wasm.base.emit.root_dir,
            .sub_path = if (fs.path.dirname(wasm.base.emit.sub_path)) |dirname|
                try fs.path.join(arena, &.{ dirname, path })
            else
                path,
        };
        openParseObjectReportingFailure(wasm, module_obj_path);
        try prelink(wasm, prog_node);
    }

    const tracy = trace(@src());
    defer tracy.end();

    const sub_prog_node = prog_node.start("Wasm Flush", 0);
    defer sub_prog_node.end();

    if (wasm.zig_object) |zo| {
        try zo.populateErrorNameTable(wasm, tid);
        try zo.setupErrorsLen(wasm);
    }

    // Create synthetic symbols, but only if they are referenced from any object file.
    lazyMarkSyntheticGlobal(wasm, wasm.preloaded_strings.__heap_base, .__heap_base, .{
        .visibility_hidden = true,
        .global_type = .{ .valtype = .i32, .mutable = false },
    });
    lazyMarkSyntheticGlobal(wasm, wasm.preloaded_strings.__heap_end, .__heap_end, .{
        .visibility_hidden = true,
        .global_type = .{ .valtype = .i32, .mutable = false },
    });
    if (!shared_memory) lazyMarkSyntheticGlobal(wasm, wasm.preloaded_strings.__tls_base, .__tls_base, .{
        .visibility_hidden = true,
        .global_type = .{ .valtype = .i32, .mutable = false },
    });

    for (wasm.export_symbol_names) |exp_name| {
        const exp_name_interned = try wasm.internString(exp_name);
        if (wasm.object_function_imports.getPtr(exp_name_interned)) |*import| {
            if (import.resolution != .unresolved) {
                import.flags.exported = true;
                continue;
            }
        }
        if (wasm.object_global_imports.getPtr(exp_name_interned)) |*import| {
            if (import.resolution != .unresolved) {
                import.flags.exported = true;
                continue;
            }
        }
        diags.addError("manually specified export name '{s}' undefined", .{exp_name});
    }

    if (wasm.entry_name.unwrap()) |entry_name| {
        if (wasm.object_function_imports.getPtr(entry_name)) |*import| {
            if (import.resolution != .unresolved) {
                import.flags.exported = true;
                continue;
            }
        }
        var err = try diags.addErrorWithNotes(1);
        try err.addMsg("entry symbol '{s}' missing", .{entry_name.slice(wasm)});
        try err.addNote("'-fno-entry' suppresses this error", .{});
    }

    if (diags.hasErrors()) return error.LinkFailure;

    // This loop does both recursive marking of alive symbols well as checking for undefined symbols.
    // When garbage collection is disabled, skip the "mark" logic.
    const allow_undefined = comp.config.output_mode == .Obj or wasm.import_symbols;
    for (wasm.object_function_imports.keys(), wasm.object_function_imports.values()) |name, *import| {
        if (!allow_undefined and import.resolution == .unresolved) {
            diags.addSrcError(import.source_location, "undefined function: {s}", .{name.slice(wasm)});
            continue;
        }
        if (!gc_sections) continue;
        if (import.flags.isIncluded(rdynamic)) {
            try markFunction(wasm, import);
            continue;
        }
    }
    for (wasm.object_global_imports.keys(), wasm.object_global_imports.values()) |name, *import| {
        if (!allow_undefined and import.resolution == .unresolved) {
            diags.addSrcError(import.source_location, "undefined global: {s}", .{name.slice(wasm)});
            continue;
        }
        if (!gc_sections) continue;
        if (import.flags.isIncluded(rdynamic)) {
            try markGlobal(wasm, import);
            continue;
        }
    }

    if (diags.hasErrors()) return error.LinkFailure;

    try sortDataSegments(wasm);
    try wasm.setupMemory();
    if (diags.hasErrors()) return error.LinkFailure;

    wasm.allocateVirtualAddresses();
    wasm.mapFunctionTable();

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
            const module_name = function_import.module_name.slice(wasm);
            try leb.writeUleb128(binary_writer, @as(u32, @intCast(module_name.len)));
            try binary_writer.writeAll(module_name);

            const name = function_import.name.slice(wasm);
            try leb.writeUleb128(binary_writer, @as(u32, @intCast(name.len)));
            try binary_writer.writeAll(name);

            try binary_writer.writeByte(@intFromEnum(std.wasm.ExternalKind.function));
            try leb.writeUleb128(binary_writer, function_import.index);
        }

        for (wasm.table_imports.items) |*table_import| {
            const module_name = table_import.module_name.slice(wasm);
            try leb.writeUleb128(binary_writer, @as(u32, @intCast(module_name.len)));
            try binary_writer.writeAll(module_name);

            const name = table_import.name.slice(wasm);
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
            const module_name = global_import.module_name.slice(wasm);
            try leb.writeUleb128(binary_writer, @as(u32, @intCast(module_name.len)));
            try binary_writer.writeAll(module_name);

            const name = global_import.name.slice(wasm);
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
            const name = exp.name.slice(wasm);
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
            const atom = atom_index.ptr(wasm);

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
            if (segment.flags.has_memindex) {
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
                const atom = atom_index.ptr(wasm);
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
                var atom = wasm.atoms.get(index).?.ptr(wasm);
                while (true) {
                    resolveAtomRelocs(wasm, atom);
                    try debug_bytes.appendSlice(atom.code.slice(wasm));
                    if (atom.prev == .none) break;
                    atom = atom.prev.ptr(wasm);
                }
                if (debug_bytes.items.len > 0)
                    try emitDebugSection(gpa, &binary_bytes, debug_bytes.items, field.name);
                debug_bytes.clearRetainingCapacity();
            }
        }

        try emitProducerSection(&binary_bytes);
        if (!target.cpu.features.isEmpty())
            try emitFeaturesSection(&binary_bytes, target.cpu.features);
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
    features: []const Feature,
) !void {
    const header_offset = try reserveCustomSectionHeader(gpa, binary_bytes);

    const writer = binary_bytes.writer();
    const target_features = "target_features";
    try leb.writeUleb128(writer, @as(u32, @intCast(target_features.len)));
    try writer.writeAll(target_features);

    try leb.writeUleb128(writer, @as(u32, @intCast(features.len)));
    for (features) |feature| {
        assert(feature.prefix != .invalid);
        try leb.writeUleb128(writer, @tagName(feature.prefix)[0]);
        const name = @tagName(feature.tag);
        try leb.writeUleb128(writer, @as(u32, name.len));
        try writer.writeAll(name);
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

    // Deduplicate symbols that point to the same function.
    var funcs: std.AutoArrayHashMapUnmanaged(u32, String) = .empty;
    try funcs.ensureUnusedCapacityPrecise(arena, wasm.functions.count() + wasm.function_imports.items.len);

    const NamedIndex = struct {
        index: u32,
        name: String,
    };

    var globals: std.MultiArrayList(NamedIndex) = .empty;
    try globals.ensureTotalCapacityPrecise(arena, wasm.output_globals.items.len + wasm.global_imports.items.len);

    var segments: std.MultiArrayList(NamedIndex) = .empty;
    try segments.ensureTotalCapacityPrecise(arena, wasm.data_segments.count());

    for (wasm.resolved_symbols.keys()) |sym_loc| {
        const symbol = wasm.finalSymbolByLoc(sym_loc).*;
        if (!symbol.flags.alive) continue;
        const name = wasm.finalSymbolByLoc(sym_loc).name;
        switch (symbol.tag) {
            .function => {
                const index = if (symbol.flags.undefined)
                    @intFromEnum(symbol.pointee.function_import)
                else
                    wasm.function_imports.items.len + @intFromEnum(symbol.pointee.function);
                const gop = funcs.getOrPutAssumeCapacity(index);
                if (gop.found_existing) {
                    assert(gop.value_ptr.* == name);
                } else {
                    gop.value_ptr.* = name;
                }
            },
            .global => {
                globals.appendAssumeCapacity(.{
                    .index = if (symbol.flags.undefined)
                        @intFromEnum(symbol.pointee.global_import)
                    else
                        @intFromEnum(symbol.pointee.global),
                    .name = name,
                });
            },
            else => {},
        }
    }

    for (wasm.data_segments.keys(), 0..) |key, index| {
        // bss section is not emitted when this condition holds true, so we also
        // do not output a name for it.
        if (!import_memory and mem.eql(u8, key, ".bss")) continue;
        segments.appendAssumeCapacity(.{ .index = @intCast(index), .name = key });
    }

    const Sort = struct {
        indexes: []const u32,
        pub fn lessThan(ctx: @This(), lhs: usize, rhs: usize) bool {
            return ctx.indexes[lhs] < ctx.indexes[rhs];
        }
    };
    funcs.entries.sortUnstable(@as(Sort, .{ .indexes = funcs.keys() }));
    globals.sortUnstable(@as(Sort, .{ .indexes = globals.items(.index) }));
    // Data segments are already ordered.

    const header_offset = try reserveCustomSectionHeader(gpa, binary_bytes);
    const writer = binary_bytes.writer();
    try leb.writeUleb128(writer, @as(u32, @intCast("name".len)));
    try writer.writeAll("name");

    try emitNameSubsection(wasm, binary_bytes, .function, funcs.keys(), funcs.values());
    try emitNameSubsection(wasm, binary_bytes, .global, globals.items(.index), globals.items(.name));
    try emitNameSubsection(wasm, binary_bytes, .data_segment, segments.items(.index), segments.items(.name));

    try writeCustomSectionHeader(
        binary_bytes.items,
        header_offset,
        @as(u32, @intCast(binary_bytes.items.len - header_offset - 6)),
    );
}

fn emitNameSubsection(
    wasm: *const Wasm,
    binary_bytes: *std.ArrayListUnmanaged(u8),
    section_id: std.wasm.NameSubsection,
    indexes: []const u32,
    names: []const String,
) !void {
    assert(indexes.len == names.len);
    const gpa = wasm.base.comp.gpa;
    // We must emit subsection size, so first write to a temporary list
    var section_list: std.ArrayListUnmanaged(u8) = .empty;
    defer section_list.deinit(gpa);
    const sub_writer = section_list.writer(gpa);

    try leb.writeUleb128(sub_writer, @as(u32, @intCast(names.len)));
    for (indexes, names) |index, name_index| {
        const name = name_index.slice(wasm);
        log.debug("emit symbol '{s}' type({s})", .{ name, @tagName(section_id) });
        try leb.writeUleb128(sub_writer, index);
        try leb.writeUleb128(sub_writer, @as(u32, @intCast(name.len)));
        try sub_writer.writeAll(name);
    }

    // From now, write to the actual writer
    const writer = binary_bytes.writer(gpa);
    try leb.writeUleb128(writer, @intFromEnum(section_id));
    try leb.writeUleb128(writer, @as(u32, @intCast(section_list.items.len)));
    try binary_bytes.appendSlice(gpa, section_list.items);
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
    const module_name = memory_import.module_name.slice(wasm);
    try leb.writeUleb128(writer, @as(u32, @intCast(module_name.len)));
    try writer.writeAll(module_name);

    const name = memory_import.name.slice(wasm);
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
    binary_bytes: *std.ArrayListUnmanaged(u8),
    symbol_table: *std.AutoArrayHashMapUnmanaged(SymbolLoc, u32),
) !void {
    const gpa = wasm.base.comp.gpa;
    const writer = binary_bytes.writer(gpa);

    try leb.writeUleb128(writer, @intFromEnum(SubsectionType.symbol_table));
    const table_offset = binary_bytes.items.len;

    var symbol_count: u32 = 0;
    for (wasm.resolved_symbols.keys()) |sym_loc| {
        const symbol = wasm.finalSymbolByLoc(sym_loc).*;
        if (symbol.tag == .dead) continue;
        try symbol_table.putNoClobber(gpa, sym_loc, symbol_count);
        symbol_count += 1;
        log.debug("emit symbol: {}", .{symbol});
        try leb.writeUleb128(writer, @intFromEnum(symbol.tag));
        try leb.writeUleb128(writer, symbol.flags);

        const sym_name = wasm.symbolLocName(sym_loc);
        switch (symbol.tag) {
            .data => {
                try leb.writeUleb128(writer, @as(u32, @intCast(sym_name.len)));
                try writer.writeAll(sym_name);

                if (!symbol.flags.undefined) {
                    try leb.writeUleb128(writer, @intFromEnum(symbol.pointee.data_out));
                    const atom_index = wasm.symbol_atom.get(sym_loc).?;
                    const atom = wasm.getAtom(atom_index);
                    try leb.writeUleb128(writer, @as(u32, atom.offset));
                    try leb.writeUleb128(writer, @as(u32, atom.code.len));
                }
            },
            .section => {
                try leb.writeUleb128(writer, @intFromEnum(symbol.pointee.section));
            },
            .function => {
                if (symbol.flags.undefined) {
                    try leb.writeUleb128(writer, @intFromEnum(symbol.pointee.function_import));
                } else {
                    try leb.writeUleb128(writer, @intFromEnum(symbol.pointee.function));
                    try leb.writeUleb128(writer, @as(u32, @intCast(sym_name.len)));
                    try writer.writeAll(sym_name);
                }
            },
            .global => {
                if (symbol.flags.undefined) {
                    try leb.writeUleb128(writer, @intFromEnum(symbol.pointee.global_import));
                } else {
                    try leb.writeUleb128(writer, @intFromEnum(symbol.pointee.global));
                    try leb.writeUleb128(writer, @as(u32, @intCast(sym_name.len)));
                    try writer.writeAll(sym_name);
                }
            },
            .table => {
                if (symbol.flags.undefined) {
                    try leb.writeUleb128(writer, @intFromEnum(symbol.pointee.table_import));
                } else {
                    try leb.writeUleb128(writer, @intFromEnum(symbol.pointee.table));
                    try leb.writeUleb128(writer, @as(u32, @intCast(sym_name.len)));
                    try writer.writeAll(sym_name);
                }
            },
            .event => unreachable,
            .dead => unreachable,
            .uninitialized => unreachable,
        }
    }

    var buf: [10]u8 = undefined;
    leb.writeUnsignedFixed(5, buf[0..5], @intCast(binary_bytes.items.len - table_offset + 5));
    leb.writeUnsignedFixed(5, buf[5..], symbol_count);
    try binary_bytes.insertSlice(table_offset, &buf);
}

fn emitSegmentInfo(wasm: *Wasm, binary_bytes: *std.ArrayList(u8)) !void {
    const writer = binary_bytes.writer();
    try leb.writeUleb128(writer, @intFromEnum(SubsectionType.segment_info));
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
    var atom: *Atom = wasm.atoms.get(code_index).?.ptr(wasm);
    // for each atom, we calculate the uleb size and append that
    var size_offset: u32 = 5; // account for code section size leb128
    while (true) {
        size_offset += getUleb128Size(atom.code.len);
        for (atom.relocSlice(wasm)) |relocation| {
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
        atom = atom.prev.ptr(wasm);
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
        var atom: *Atom = wasm.atoms.get(segment_index).?.ptr(wasm);
        while (true) {
            size_offset += getUleb128Size(atom.code.len);
            for (atom.relocSlice(wasm)) |relocation| {
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
            atom = atom.prev.ptr(wasm);
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

/// Returns the symbol index of the error name table.
///
/// When the symbol does not yet exist, it will create a new one instead.
pub fn getErrorTableSymbol(wasm: *Wasm, pt: Zcu.PerThread) !u32 {
    const sym_index = try wasm.zig_object.?.getErrorTableSymbol(wasm, pt);
    return @intFromEnum(sym_index);
}

/// Recursively mark alive everything referenced by the function.
fn markFunction(wasm: *Wasm, import: *FunctionImport) !void {
    if (import.flags.alive) return;
    import.flags.alive = true;

    for (wasm.functionResolutionRelocSlice(import.resolution)) |reloc|
        try wasm.markReloc(reloc);
}

/// Recursively mark alive everything referenced by the global.
fn markGlobal(wasm: *Wasm, import: *GlobalImport) !void {
    if (import.flags.alive) return;
    import.flags.alive = true;

    for (wasm.globalResolutionRelocSlice(import.resolution)) |reloc|
        try wasm.markReloc(reloc);
}

fn globalResolutionRelocSlice(wasm: *Wasm, resolution: GlobalImport.Resolution) ![]const Relocation {
    assert(resolution != .none);
    @panic("TODO");
}

fn functionResolutionRelocSlice(wasm: *Wasm, resolution: GlobalImport.Resolution) ![]const Relocation {
    assert(resolution != .none);
    @panic("TODO");
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

/// Resolves the relocations within the atom, writing the new value
/// at the calculated offset.
fn resolveAtomRelocs(wasm: *const Wasm, atom: *Atom) void {
    const symbol_name = wasm.symbolLocName(atom.symbolLoc());
    log.debug("resolving {d} relocs in atom '{s}'", .{ atom.relocs.len, symbol_name });

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
    return switch (relocation.tag) {
        .FUNCTION_INDEX_LEB => if (symbol.flags.undefined)
            @intFromEnum(symbol.pointee.function_import)
        else
            @intFromEnum(symbol.pointee.function) + wasm.function_imports.items.len,
        .TABLE_NUMBER_LEB => if (symbol.flags.undefined)
            @intFromEnum(symbol.pointee.table_import)
        else
            @intFromEnum(symbol.pointee.table) + wasm.table_imports.items.len,
        .TABLE_INDEX_I32,
        .TABLE_INDEX_I64,
        .TABLE_INDEX_SLEB,
        .TABLE_INDEX_SLEB64,
        => wasm.function_table.get(.{ .file = atom.file, .index = @enumFromInt(relocation.index) }) orelse 0,

        .TYPE_INDEX_LEB => unreachable, // handled above
        .GLOBAL_INDEX_I32, .GLOBAL_INDEX_LEB => if (symbol.flags.undefined)
            @intFromEnum(symbol.pointee.global_import)
        else
            @intFromEnum(symbol.pointee.global) + wasm.global_imports.items.len,

        .MEMORY_ADDR_I32,
        .MEMORY_ADDR_I64,
        .MEMORY_ADDR_LEB,
        .MEMORY_ADDR_LEB64,
        .MEMORY_ADDR_SLEB,
        .MEMORY_ADDR_SLEB64,
        => {
            assert(symbol.tag == .data);
            if (symbol.flags.undefined) return 0;
            const va: i33 = symbol.virtual_address;
            return @intCast(va + relocation.addend);
        },
        .EVENT_INDEX_LEB => @panic("TODO: expose this as an error, events are unsupported"),
        .SECTION_OFFSET_I32 => {
            const target_atom_index = wasm.symbol_atom.get(target_loc).?;
            const target_atom = wasm.getAtom(target_atom_index);
            const rel_value: i33 = target_atom.offset;
            return @intCast(rel_value + relocation.addend);
        },
        .FUNCTION_OFFSET_I32 => {
            if (symbol.flags.undefined) {
                const val = atom.tombstone(wasm) orelse relocation.addend;
                return @bitCast(val);
            }
            const target_atom_index = wasm.symbol_atom.get(target_loc).?;
            const target_atom = wasm.getAtom(target_atom_index);
            const rel_value: i33 = target_atom.offset;
            return @intCast(rel_value + relocation.addend);
        },
        .MEMORY_ADDR_TLS_SLEB,
        .MEMORY_ADDR_TLS_SLEB64,
        => {
            const va: i33 = symbol.virtual_address;
            return @intCast(va + relocation.addend);
        },
    };
}

// For a given `Atom` returns whether it has a tombstone value or not.
/// This defines whether we want a specific value when a section is dead.
fn tombstone(atom: Atom, wasm: *const Wasm) ?i64 {
    const atom_name = wasm.finalSymbolByLoc(atom.symbolLoc()).name;
    if (atom_name == wasm.custom_sections.@".debug_ranges".name or
        atom_name == wasm.custom_sections.@".debug_loc".name)
    {
        return -2;
    } else if (mem.startsWith(u8, atom_name.slice(wasm), ".debug_")) {
        return -1;
    } else {
        return null;
    }
}

pub const Relocation = struct {
    tag: Tag,
    /// Offset of the value to rewrite relative to the relevant section's contents.
    /// When `offset` is zero, its position is immediately after the id and size of the section.
    offset: u32,
    pointee: Pointee,
    /// Populated only for `MEMORY_ADDR_*`, `FUNCTION_OFFSET_I32` and `SECTION_OFFSET_I32`.
    addend: i32,

    pub const Pointee = union {
        symbol_name: String,
        type_index: FunctionType.Index,
        section: InputSectionIndex,
    };

    pub const Slice = extern struct {
        /// Index into `relocations`.
        off: u32,
        len: u32,

        pub fn slice(s: Slice, wasm: *const Wasm) []Relocation {
            return wasm.relocations.items[s.off..][0..s.len];
        }
    };

    pub const Tag = enum(u8) {
        /// Uses `symbol_name`.
        FUNCTION_INDEX_LEB=      0,
        TABLE_INDEX_SLEB=        1,
        TABLE_INDEX_I32=         2,
        MEMORY_ADDR_LEB=         3,
        MEMORY_ADDR_SLEB=        4,
        MEMORY_ADDR_I32=         5,
        /// Uses `type_index`.
        TYPE_INDEX_LEB=          6,
        /// Uses `symbol_name`.
        GLOBAL_INDEX_LEB=        7,
        FUNCTION_OFFSET_I32=     8,
        SECTION_OFFSET_I32=      9,
        TAG_INDEX_LEB=          10,
        MEMORY_ADDR_REL_SLEB=   11,
        TABLE_INDEX_REL_SLEB=   12,
        /// Uses `symbol_name`.
        GLOBAL_INDEX_I32=       13,
        MEMORY_ADDR_LEB64=      14,
        MEMORY_ADDR_SLEB64=     15,
        MEMORY_ADDR_I64=        16,
        MEMORY_ADDR_REL_SLEB64= 17,
        TABLE_INDEX_SLEB64=     18,
        TABLE_INDEX_I64=        19,
        TABLE_NUMBER_LEB=       20,
        MEMORY_ADDR_TLS_SLEB=   21,
        FUNCTION_OFFSET_I64=    22,
        MEMORY_ADDR_LOCREL_I32= 23,
        TABLE_INDEX_REL_SLEB64= 24,
        MEMORY_ADDR_TLS_SLEB64= 25,
        /// Uses `symbol_name`.
        FUNCTION_INDEX_I32=     26,
    };

};

pub const Table = extern struct {
    module_name: String,
    name: String,
    flags: SymbolFlags,
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

pub const InitFunc = extern struct {
    priority: u32,
    function_index: ObjectFunctionIndex,

    fn lessThan(ctx: void, lhs: InitFunc, rhs: InitFunc) bool {
        _ = ctx;
        if (lhs.priority == rhs.priority) {
            return @intFromEnum(lhs.function_index) < @intFromEnum(rhs.function_index);
        } else {
            return lhs.priority < rhs.priority;
        }
    }
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
        atomics,
        @"bulk-memory",
        @"exception-handling",
        @"extended-const",
        @"half-precision",
        multimemory,
        multivalue,
        @"mutable-globals",
        @"nontrapping-fptoint",
        @"reference-types",
        @"relaxed-simd",
        @"sign-ext",
        simd128,
        @"tail-call",
        @"shared-mem",

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

fn addGlobal(wasm: *Wasm, global: Global) error{OutOfMemory}!Global.Index {
    const gpa = wasm.base.comp.gpa;
    try wasm.output_globals.append(gpa, global);
    return @enumFromInt(wasm.output_globals.items.len - 1);
}

fn addTable(wasm: *Wasm, table: Table) error{OutOfMemory}!TableIndex {
    const gpa = wasm.base.comp.gpa;
    try wasm.tables.append(gpa, table);
    return @enumFromInt(wasm.tables.items.len - 1);
}
