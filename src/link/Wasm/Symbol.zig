flags: Flags,
name: Wasm.String,
pointee: Pointee,
/// Contains the virtual address of the symbol, relative to the start of its section.
/// This differs from the offset of an `Atom` which is relative to the start of a segment.
virtual_address: u32,

/// Local index into an Object's symbol list.
pub const Index = enum(u32) {
    _,
};

pub const Pointee = union {
    function: Wasm.FunctionIndex,
    function_obj: Wasm.ObjectFunctionIndex,
    function_zo: ZigObject.FunctionIndex,
    function_import: Wasm.FunctionImportIndex,
    function_import_obj: Wasm.ObjectFunctionImportIndex,
    function_import_zo: ZigObject.FunctionImportIndex,
    data_out: Wasm.Segment.Index,
    data_obj: Wasm.ObjectSegmentIndex,
    data_zo: ZigObject.SegmentIndex,
    data_import: void,
    global: Wasm.GlobalIndex,
    global_obj: Wasm.ObjectGlobalIndex,
    global_zo: ZigObject.GlobalIndex,
    global_import: Wasm.GlobalImportIndex,
    global_import_obj: Wasm.ObjectGlobalImportIndex,
    global_import_zo: ZigObject.GlobalImportIndex,
    section: Wasm.SectionIndex,
    section_zo: void,
    event: void,
    table: Wasm.TableIndex,
    table_obj: Wasm.ObjectTableIndex,
    table_import: Wasm.TableImportIndex,
    table_import_obj: Wasm.ObjectTableImportIndex,
    dead: void,
};

pub const Tag = enum(u3) {
    function,
    data,
    global,
    section,
    event,
    table,

    /// synthetic kind used by the wasm linker during incremental compilation
    /// to notate a symbol has been freed, but still lives in the symbol list.
    dead,
    uninitialized,

    /// From a given symbol tag, returns the `ExternalType`
    /// Asserts the given tag can be represented as an external type.
    pub fn externalType(tag: Tag) std.wasm.ExternalKind {
        return switch (tag) {
            .function => .function,
            .global => .global,
            .data => unreachable, // Data symbols will generate a global
            .section => unreachable, // Not an external type
            .event => unreachable, // Not an external type
            .dead => unreachable, // Dead symbols should not be referenced
            .uninitialized => unreachable,
            .table => .table,
        };
    }
};

pub const Flags = packed struct(u32) {
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
    /// of whether it is used by the program.
    no_strip: bool = false,
    /// The symbol resides in thread local storage.
    tls: bool = false,
    /// The symbol represents an absolute address. This means its offset is
    /// relative to the start of the wasm memory as opposed to being relative
    /// to a data segment.
    absolute: bool = false,

    padding1: u18 = 0,
    /// Zig-specific. Tag stored here for memory efficiency.
    tag: Tag,
    /// Zig-specific. Dead symbols are allowed to be garbage collected.
    alive: bool = false,

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
};

/// Verifies if the given symbol should be imported from the
/// host environment or not
pub fn requiresImport(symbol: Symbol) bool {
    if (symbol.tag == .data) return false;
    if (!symbol.flags.undefined) return false;
    if (symbol.flags.binding == .weak) return false;
    return true;
}

/// Marks a symbol as 'alive', ensuring the garbage collector will not collect the trash.
pub fn mark(symbol: *Symbol) void {
    symbol.flags.alive = true;
}

pub fn unmark(symbol: *Symbol) void {
    symbol.flags.alive = false;
}

pub fn isExported(symbol: Symbol, is_dynamic: bool) bool {
    if (symbol.flags.undefined or symbol.binding == .local) return false;
    if (is_dynamic and !symbol.flags.visibility_hidden) return true;
    return symbol.flags.exported;
}

/// Formats the symbol into human-readable text
pub fn format(symbol: Symbol, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
    _ = fmt;
    _ = options;

    const kind_fmt: u8 = switch (symbol.tag) {
        .function => 'F',
        .data => 'D',
        .global => 'G',
        .section => 'S',
        .event => 'E',
        .table => 'T',
        .dead => '-',
        .uninitialized => unreachable,
    };
    const visible: []const u8 = if (symbol.isVisible()) "yes" else "no";
    const binding: []const u8 = if (symbol.isLocal()) "local" else "global";
    const undef: []const u8 = if (symbol.isUndefined()) "undefined" else "";

    try writer.print(
        "{c} binding={s} visible={s} name_offset={d} {s}",
        .{ kind_fmt, binding, visible, symbol.name, undef },
    );
}

const std = @import("std");
const Symbol = @This();
const Wasm = @import("../Wasm.zig");
const ZigObject = @import("ZigObject.zig");
