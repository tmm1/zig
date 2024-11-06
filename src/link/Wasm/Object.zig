const Object = @This();

const Wasm = @import("../Wasm.zig");
const Alignment = Wasm.Alignment;
const Symbol = @import("Symbol.zig");

const std = @import("std");
const Allocator = std.mem.Allocator;
const Path = std.Build.Cache.Path;
const log = std.log.scoped(.object);
const assert = std.debug.assert;

/// Wasm spec version used for this `Object`
version: u32,
/// For error reporting purposes only.
/// Name (read path) of the object or archive file.
path: Path,
/// For error reporting purposes only.
/// If this represents an object in an archive, it's the basename of the
/// object, and path refers to the archive.
archive_member_name: ?[]const u8,
/// Represents the function ID that must be called on startup.
/// This is `null` by default as runtimes may determine the startup
/// function themselves. This is essentially legacy.
start_function: Wasm.OptionalObjectFunctionIndex,
/// A slice of features that tell the linker what features are mandatory, used
/// (or therefore missing) and must generate an error when another object uses
/// features that are not supported by the other.
features: Wasm.Feature.Set,
/// Points into Wasm object_function_imports
function_imports: RelativeSlice,
/// Points into Wasm object_globals_imports
globals_imports: RelativeSlice,
/// Points into Wasm object_tables_imports
tables_imports: RelativeSlice,
/// Points into Wasm object_relocatable_datas
relocatable_data: RelativeSlice,
/// Points into Wasm object_relocatable_codes
relocatable_code: RelativeSlice,
/// Points into Wasm object_relocatable_customs
relocatable_custom: RelativeSlice,
/// For calculating local section index from `Wasm.SectionIndex`.
local_section_index_base: u32,
/// Points into Wasm object_named_segments
named_segments: RelativeSlice,
/// Points into Wasm object_init_funcs
init_funcs: RelativeSlice,
/// Points into Wasm object_comdats
comdats: RelativeSlice,
/// Points into Wasm object_symbols
symbols: RelativeSlice,

pub const RelativeSlice = struct {
    off: u32,
    len: u32,
};

fn parse(
    wasm: *Wasm,
    bytes: []const u8,
    path: Path,
    archive_member_name: ?[]const u8,
    /// Temporary scratch space used to look up function type indexes while
    /// parsing and remap them.
    func_types: *std.ArrayListUnmanaged(Wasm.FunctionType.Index),
) anyerror!Object {
    const gpa = wasm.base.comp.gpa;
    const diags = &wasm.base.comp.link_diags;

    var pos: usize = 0;

    if (!std.mem.eql(u8, bytes[0..std.wasm.magic.len], &std.wasm.magic)) return error.BadObjectMagic;
    pos += std.wasm.magic.len;

    const version = std.mem.readInt(u32, bytes[pos..][0..4], .little);
    pos += 4;

    const relocatable_data_start: u32 = @intCast(wasm.object_relocatable_datas.items.len);
    const relocatable_code_start: u32 = @intCast(wasm.object_relocatable_codes.items.len);
    const relocatable_custom_start: u32 = @intCast(wasm.object_relocatable_customs.items.len);
    const imports_start: u32 = @intCast(wasm.object_imports.items.len);
    const functions_start: u32 = @intCast(wasm.object_functions.items.len);
    const tables_start: u32 = @intCast(wasm.object_tables.items.len);
    const memories_start: u32 = @intCast(wasm.object_memories.items.len);
    const globals_start: u32 = @intCast(wasm.object_globals.items.len);
    const named_segments_start: u32 = @intCast(wasm.object_named_segments.items.len);
    const init_funcs_start: u32 = @intCast(wasm.object_init_funcs.items.len);
    const comdats_start: u32 = @intCast(wasm.object_comdats.items.len);
    const symbols_start: u32 = @intCast(wasm.object_symbols.items.len);
    const function_imports_start: u32 = @intCast(wasm.object_function_imports.items.len);
    const global_imports_start: u32 = @intCast(wasm.object_global_imports.items.len);
    const table_imports_start: u32 = @intCast(wasm.object_table_imports.items.len);
    const local_section_index_base = wasm.object_total_sections;

    func_types.clearRetainingCapacity();

    var start_function: Wasm.OptionalObjectFunctionIndex = .none;
    var features: ?Wasm.Feature.Set = null;
    var saw_linking_section = false;
    var saw_type_section = false;
    var local_section_index: u32 = 0;
    while (pos < bytes.len) : (local_section_index += 1) {
        const section_index: Wasm.SectionIndex = @enumFromInt(local_section_index_base + local_section_index);

        const section_tag: std.wasm.Section = @enumFromInt(bytes[pos]);
        pos += 1;

        const len, pos = readLeb(u32, bytes, pos);
        const section_end = pos + len;
        switch (section_tag) {
            .custom => {
                const section_name, pos = readBytes(bytes, pos);
                if (std.mem.eql(u8, section_name, "linking")) {
                    saw_linking_section = true;
                    const section_version, pos = readLeb(u32, bytes, pos);
                    log.debug("Link meta data version: {d}", .{section_version});
                    if (section_version != 2) return error.UnsupportedVersion;
                    while (pos < section_end) {
                        const sub_type, pos = readLeb(u8, bytes, pos);
                        log.debug("found subsection: {s}", .{@tagName(@as(Wasm.SubsectionType, @enumFromInt(sub_type)))});
                        const payload_len, pos = readLeb(u32, bytes, pos);
                        if (payload_len == 0) break;

                        const count, pos = readLeb(u32, bytes, pos);

                        switch (@as(Wasm.SubsectionType, @enumFromInt(sub_type))) {
                            .segment_info => {
                                for (try wasm.object_named_segments.addManyAsSlice(gpa, count)) |*segment| {
                                    const name, pos = readBytes(bytes, pos);
                                    const alignment, pos = readLeb(u32, bytes, pos);
                                    const flags, pos = readLeb(u32, bytes, pos);
                                    segment.* = .{
                                        .name = try wasm.internString(name),
                                        .flags = .{
                                            .strings = (flags & 1) != 0,
                                            .tls = ((flags & 2) != 0) or
                                                // Supports legacy object files that specified
                                                // being TLS by the name instead of the TLS flag.
                                                std.mem.startsWith(u8, name, ".tdata") or
                                                std.mem.startsWith(u8, name, ".tbss"),
                                            .alignment = @enumFromInt(alignment),
                                        },
                                    };
                                    log.debug("found segment: {s} align({d}) flags({b})", .{
                                        name, segment.alignment, segment.flags,
                                    });
                                }
                            },
                            .init_funcs => {
                                for (try wasm.object_init_funcs.addManyAsSlice(gpa, count)) |*func| {
                                    const priority, pos = readLeb(u32, bytes, pos);
                                    const symbol_index, pos = readLeb(u32, bytes, pos);
                                    func.* = .{
                                        .priority = priority,
                                        .symbol_index = symbol_index,
                                    };
                                    log.debug("found init_funcs - prio: {d}, index: {d}", .{ func.priority, func.symbol_index });
                                }
                            },
                            .comdat_info => {
                                for (try wasm.object_comdats.addManyAsSlice(gpa, count)) |*comdat| {
                                    const name, pos = readBytes(bytes, pos);
                                    const flags, pos = readLeb(u32, bytes, pos);
                                    if (flags != 0) return error.UnexpectedComdatFlags;
                                    const symbol_count, pos = readLeb(u32, bytes, pos);
                                    const start_off: u32 = @intCast(wasm.object_comdat_symbols.items.len);
                                    for (try wasm.object_comdat_symbols.addManyAsSlice(gpa, symbol_count)) |*symbol| {
                                        const kind, pos = readEnum(Wasm.Comdat.Symbol.Type, bytes, pos);
                                        const index, pos = readLeb(u32, bytes, pos);
                                        if (true) @panic("TODO rebase index depending on kind");
                                        symbol.* = .{
                                            .kind = kind,
                                            .index = index,
                                        };
                                    }
                                    comdat.* = .{
                                        .name = try wasm.internString(name),
                                        .flags = flags,
                                        .symbols = .{
                                            .off = start_off,
                                            .len = @intCast(wasm.object_comdat_symbols.items.len - start_off),
                                        },
                                    };
                                }
                            },
                            .symbol_table => {
                                var table_count: usize = 0;
                                for (try wasm.object_symbols.addManyAsSlice(gpa, count)) |*symbol| {
                                    const tag, pos = readEnum(Symbol.Tag, bytes, pos);
                                    const flags, pos = readLeb(u32, bytes, pos);
                                    symbol.* = .{
                                        .flags = @bitCast(flags),
                                        .name = undefined,
                                        .pointee = undefined,
                                        .virtual_address = undefined,
                                    };
                                    // Initialize zig-specific flags.
                                    symbol.flags.alive = false;
                                    symbol.tag = tag;

                                    switch (tag) {
                                        .data => {
                                            const name, pos = readBytes(bytes, pos);
                                            symbol.name = try wasm.internString(name);
                                            if (symbol.flags.undefined) {
                                                symbol.pointee = .data_import;
                                            } else {
                                                const segment_index, pos = readLeb(u32, bytes, pos);
                                                const segment_offset, pos = readLeb(u32, bytes, pos);
                                                const size, pos = readLeb(u32, bytes, pos);

                                                symbol.pointee = .{ .data_obj = @enumFromInt(named_segments_start + segment_index) };
                                                _ = segment_offset;
                                                _ = size;
                                            }
                                        },
                                        .section => {
                                            const local_section, pos = readLeb(u32, bytes, pos);
                                            const section: Wasm.SectionIndex = @enumFromInt(local_section_index_base + local_section);
                                            const rc = wasm.object_relocatable_customs.getPtr(section) orelse
                                                return error.SectionNotFound;
                                            symbol.name = rc.section_name;
                                            symbol.pointee = .{ .section = section };
                                            rc.flags.represented = true;
                                        },

                                        .function => {
                                            const local_index, pos = readLeb(u32, bytes, pos);
                                            if (symbol.flags.undefined) {
                                                const function_import: Wasm.ObjectFunctionImportIndex = @enumFromInt(function_imports_start + local_index);
                                                symbol.pointee = .{ .function_import_obj = function_import };
                                                if (flags.explicit_name) {
                                                    const name, pos = readBytes(bytes, pos);
                                                    symbol.name = try wasm.internString(name);
                                                } else {
                                                    symbol.name = wasm.objectFunctionImportPtr(function_import).name;
                                                }
                                            } else {
                                                symbol.pointee = .{ .function_obj = @enumFromInt(functions_start + local_index) };
                                                const name, pos = readBytes(bytes, pos);
                                                symbol.name = try wasm.internString(name);
                                            }
                                        },
                                        .global => {
                                            const local_index, pos = readLeb(u32, bytes, pos);
                                            if (symbol.flags.undefined) {
                                                const global_import: Wasm.ObjectGlobalImportIndex = @enumFromInt(global_imports_start + local_index);
                                                symbol.pointee = .{ .global_import_obj = global_import };
                                                if (flags.explicit_name) {
                                                    const name, pos = readBytes(bytes, pos);
                                                    symbol.name = try wasm.internString(name);
                                                } else {
                                                    symbol.name = wasm.objectGlobalImportPtr(global_import).name;
                                                }
                                            } else {
                                                symbol.pointee = .{ .global_obj = @enumFromInt(globals_start + local_index) };
                                                const name, pos = readBytes(bytes, pos);
                                                symbol.name = try wasm.internString(name);
                                            }
                                        },
                                        .table => {
                                            table_count += 1;
                                            const local_index, pos = readLeb(u32, bytes, pos);
                                            if (symbol.flags.undefined) {
                                                const table_import: Wasm.ObjectTableImportIndex = @enumFromInt(table_imports_start + local_index);
                                                symbol.pointee = .{ .table_import_obj = table_import };
                                                if (flags.explicit_name) {
                                                    const name, pos = readBytes(bytes, pos);
                                                    symbol.name = try wasm.internString(name);
                                                } else {
                                                    symbol.name = wasm.objectTableImportPtr(table_import).name;
                                                }
                                            } else {
                                                symbol.pointee = .{ .table_obj = @enumFromInt(tables_start + local_index) };
                                                const name, pos = readBytes(bytes, pos);
                                                symbol.name = try wasm.internString(name);
                                            }
                                        },
                                        else => {
                                            log.debug("unrecognized symbol type tag: {x}", .{tag});
                                            return error.UnrecognizedSymbolType;
                                        },
                                    }
                                    log.debug("found symbol: {}", .{symbol});
                                }

                                // Check for indirect function table in case of an MVP object file.
                                legacy_indirect_function_table: {
                                    const table_imports = wasm.object_table_imports.items[table_imports_start..];
                                    // If there is a symbol for each import table, this is not a legacy object file.
                                    if (table_imports.len == table_count) break :legacy_indirect_function_table;
                                    if (table_count != 0) {
                                        return diags.failParse(path, "expected a table entry symbol for each of the {d} table(s), but instead got {d} symbols.", .{
                                            table_imports.len, table_count,
                                        });
                                    }
                                    // MVP object files cannot have any table definitions, only
                                    // imports (for the indirect function table).
                                    const tables = wasm.object_tables.items[tables_start..];
                                    if (tables.len > 0) {
                                        return diags.failParse(path, "table definition without representing table symbols", .{});
                                    }
                                    if (table_imports.len != 1) {
                                        return diags.failParse(path, "found more than one table import, but no representing table symbols", .{});
                                    }
                                    const table_import_name = table_imports[0].name;
                                    if (table_import_name != wasm.preloaded_strings.__indirect_function_table) {
                                        return diags.failParse(path, "non-indirect function table import '{s}' is missing a corresponding symbol", .{
                                            wasm.stringSlice(table_import_name),
                                        });
                                    }
                                    try wasm.object_symbols.append(gpa, .{
                                        .flags = .{
                                            .undefined = true,
                                            .no_strip = true,
                                            .tag = .table,
                                        },
                                        .name = table_import_name,
                                        .pointee = .{ .table_import = @enumFromInt(table_imports_start) },
                                        .virtual_address = undefined,
                                    });
                                    log.debug("created symbol for legacy indirect function table", .{});
                                }

                                // Not all debug sections may be represented by a symbol, for those sections
                                // we manually create a symbol.
                                const rc_section_indexes = wasm.object_relocatable_customs.keys()[relocatable_custom_start..];
                                const rcs = wasm.object_relocatable_customs.values()[relocatable_custom_start..];
                                for (rc_section_indexes, rcs) |rc_section_index, *rc| {
                                    if (rc.represented) continue;
                                    rc.represented = true;
                                    try wasm.object_symbols.append(gpa, .{
                                        .name = rc.section_name,
                                        .flags = .{
                                            .binding = .local,
                                        },
                                        .tag = .section,
                                        .virtual_address = 0,
                                        .index = rc_section_index,
                                    });
                                    log.debug("created synthetic custom section symbol for '{s}'", .{wasm.stringSlice(section_name)});
                                }
                            },
                        }
                    }
                } else if (std.mem.startsWith(u8, section_name, "reloc")) {
                    const local_section, pos = readLeb(u32, bytes, pos);
                    const count, pos = readLeb(u32, bytes, pos);
                    const section: Wasm.SectionIndex = @enumFromInt(local_section_index_base + local_section);

                    log.debug("found {d} relocations for local_section={d}, total_section={d}", .{
                        count, local_section, section,
                    });

                    for (try wasm.object_relocations.addManyAsSlice(gpa, count)) |*relocation| {
                        const tag: Wasm.Relocation.Tag = @enumFromInt(bytes[pos]);
                        pos += 1;
                        const offset, pos = readLeb(u32, bytes, pos);
                        const index, pos = readLeb(u32, bytes, pos);
                        const addend: i32, pos = if (tag.addendIsPresent()) readLeb(i32, bytes, pos) else .{ 0, pos };
                        relocation.* = .{
                            .tag = tag,
                            .offset = offset,
                            .index = index,
                            .addend = addend,
                        };
                        log.debug("found relocation: {}", .{relocation});
                    }

                    try wasm.object_relocations_table.putNoClobber(gpa, section, .{
                        .off = @intCast(wasm.object_relocations.items.len - count),
                        .len = count,
                    });
                } else if (std.mem.eql(u8, section_name, "target_features")) {
                    features, pos = try parseFeatures(wasm, bytes, pos, path);
                } else if (std.mem.startsWith(u8, section_name, ".debug")) {
                    const debug_content = bytes[pos..section_end];
                    pos = section_end;

                    const data_off: u32 = @enumFromInt(wasm.string_bytes.items.len);
                    try wasm.string_bytes.appendSlice(gpa, debug_content);

                    try wasm.object_relocatable_customs.put(gpa, section_index, .{
                        .data_off = data_off,
                        .flags = .{
                            .data_len = @intCast(debug_content.len),
                            .represented = false, // set when scanning symbol table
                        },
                        .section_name = try wasm.internString(section_name),
                    });
                } else {
                    pos = section_end;
                }
            },
            .type => {
                if (saw_type_section) return error.DuplicateTypeSection;
                saw_type_section = true;
                const func_types_len, pos = readLeb(u32, bytes, pos);
                try func_types.resize(gpa, func_types_len);
                for (func_types.items) |*func_type| {
                    if (bytes[pos] != std.wasm.function_type) return error.ExpectedFuncType;
                    pos += 1;

                    const params, pos = readBytes(bytes, pos);
                    const returns, pos = readBytes(bytes, pos);
                    func_type.* = try wasm.addFuncType(.{
                        .params = .fromString(try wasm.internString(params)),
                        .returns = .fromString(try wasm.internString(returns)),
                    });
                }
            },
            .import => {
                if (!saw_type_section) return error.ImportSectionBeforeTypeSection;

                const imports_len, pos = readLeb(u32, bytes, pos);
                for (0..imports_len) |_| {
                    const module_name, pos = readBytes(bytes, pos);
                    const name, pos = readBytes(bytes, pos);
                    const kind, pos = readEnum(std.wasm.ExternalKind, bytes, pos);
                    const interned_module_name = try wasm.internString(module_name);
                    const interned_name = try wasm.internString(name);
                    switch (kind) {
                        .function => {
                            const function, pos = readLeb(u32, bytes, pos);
                            try wasm.object_function_imports.append(gpa, .{
                                .module_name = interned_module_name,
                                .name = interned_name,
                                .index = func_types.items[function],
                            });
                        },
                        .memory => {
                            const limits, pos = readLimits(bytes, pos);
                            try wasm.object_memory_imports.append(gpa, .{
                                .module_name = interned_module_name,
                                .name = interned_name,
                                .limits_min = limits.min,
                                .limits_max = limits.max,
                                .limits_has_max = limits.flags.has_max,
                                .limits_is_shared = limits.flags.is_shared,
                            });
                        },
                        .global => {
                            const valtype, pos = readEnum(std.wasm.Valtype, bytes, pos);
                            const mutable = bytes[pos] == 0x01;
                            pos += 1;
                            try wasm.object_global_imports.append(gpa, .{
                                .module_name = interned_module_name,
                                .name = interned_name,
                                .mutable = mutable,
                                .valtype = valtype,
                            });
                        },
                        .table => {
                            const reftype, pos = readEnum(std.wasm.RefType, bytes, pos);
                            const limits, pos = readLimits(bytes, pos);
                            try wasm.object_table_imports.append(gpa, .{
                                .module_name = interned_module_name,
                                .name = interned_name,
                                .limits_min = limits.min,
                                .limits_max = limits.max,
                                .limits_has_max = limits.flags.has_max,
                                .limits_is_shared = limits.flags.is_shared,
                                .reftype = reftype,
                            });
                        },
                    }
                }
            },
            .function => {
                if (!saw_type_section) return error.FunctionSectionBeforeTypeSection;

                const functions_len, pos = readLeb(u32, bytes, pos);
                for (try wasm.object_functions.addManyAsSlice(gpa, functions_len)) |*func| {
                    const func_type_index, pos = readLeb(u32, bytes, pos);
                    func.* = func_types.items[func_type_index];
                }
            },
            .table => {
                const tables_len, pos = readLeb(u32, bytes, pos);
                for (try wasm.object_tables.addManyAsSlice(gpa, tables_len)) |*table| {
                    const reftype, pos = readEnum(std.wasm.RefType, bytes, pos);
                    const limits, pos = readLimits(bytes, pos);
                    table.* = .{
                        .reftype = reftype,
                        .limits = limits,
                    };
                }
            },
            .memory => {
                const memories_len, pos = readLeb(u32, bytes, pos);
                for (try wasm.object_memories.addManyAsSlice(gpa, memories_len)) |*memory| {
                    const limits, pos = readLimits(bytes, pos);
                    memory.* = .{ .limits = limits };
                }
            },
            .global => {
                const globals_len, pos = readLeb(u32, bytes, pos);
                for (try wasm.object_globals.addManyAsSlice(gpa, globals_len)) |*global| {
                    const valtype, pos = readEnum(std.wasm.Valtype, bytes, pos);
                    const mutable = bytes[pos] == 0x01;
                    pos += 1;
                    const expr, pos = try readInit(wasm, bytes, pos);
                    global.* = .{
                        .valtype = valtype,
                        .mutable = mutable,
                        .expr = expr,
                    };
                }
            },
            .@"export" => {
                const exports_len, pos = readLeb(u32, bytes, pos);
                for (try wasm.object_exports.addManyAsSlice(gpa, exports_len)) |*exp| {
                    const name, pos = readBytes(bytes, pos);
                    const kind: std.wasm.ExternalKind = @enumFromInt(bytes[pos]);
                    pos += 1;
                    const index, pos = readLeb(u32, bytes, pos);
                    const rebased_index = index + switch (kind) {
                        .function => functions_start,
                        .table => tables_start,
                        .memory => memories_start,
                        .global => globals_start,
                    };
                    exp.* = .{
                        .name = try wasm.internString(name),
                        .kind = kind,
                        .index = rebased_index,
                    };
                }
            },
            .start => {
                const index, pos = readLeb(u32, bytes, pos);
                start_function = @enumFromInt(functions_start + index);
            },
            .element => {
                log.warn("unimplemented: element section in {}", .{path});
                pos = section_end;
            },
            .code => {
                const start = pos;
                const count, pos = readLeb(u32, bytes, pos);
                const function_imports_len = wasm.object_function_imports.items[function_imports_start..].len;
                for (
                    try wasm.object_relocatable_codes.addManyAsSlice(gpa, count),
                    function_imports_len..,
                ) |*elem, index| {
                    const code_len, pos = readLeb(u32, bytes, pos);
                    const offset: u32 = @intCast(pos - start);
                    const payload = try wasm.addRelocatableDataPayload(bytes[pos..][0..code_len]);
                    pos += code_len;
                    elem.* = .{
                        .payload = payload,
                        .index = @intCast(index),
                        .offset = offset,
                        .section_index = section_index,
                    };
                }
            },
            .data => {
                const start = pos;
                const count, pos = readLeb(u32, bytes, pos);
                for (try wasm.object_relocatable_datas.addManyAsSlice(gpa, count)) |*elem| {
                    const memidx, pos = readLeb(u32, bytes, pos);
                    _ = memidx;
                    pos = skipInit(bytes, pos);
                    const data_len, pos = readLeb(u32, bytes, pos);
                    const offset: u32 = @intCast(pos - start);
                    const payload = try wasm.addRelocatableDataPayload(bytes[pos..][0..data_len]);
                    pos += data_len;
                    elem.* = .{
                        .payload = payload,
                        .offset = offset,
                        .section_index = section_index,
                    };
                }
            },
            else => pos = section_end,
        }
        if (pos != section_end) return error.MalformedSection;
    }
    if (!saw_linking_section) return error.MissingLinkingSection;

    wasm.object_total_sections = local_section_index_base + local_section_index;

    return .{
        .version = version,
        .path = path,
        .archive_member_name = archive_member_name,
        .start_function = start_function,
        .features = features orelse return error.MissingFeatures,
        .imports = .{
            .off = imports_start,
            .len = @intCast(wasm.object_imports.items.len - imports_start),
        },
        .functions = .{
            .off = functions_start,
            .len = @intCast(wasm.object_functions.items.len - functions_start),
        },
        .tables = .{
            .off = tables_start,
            .len = @intCast(wasm.object_tables.items.len - tables_start),
        },
        .memories = .{
            .off = memories_start,
            .len = @intCast(wasm.object_memories.items.len - memories_start),
        },
        .globals = .{
            .off = globals_start,
            .len = @intCast(wasm.object_globals.items.len - globals_start),
        },
        .named_segments_start = .{
            .off = named_segments_start,
            .len = @intCast(wasm.object_named_segments.items.len - named_segments_start),
        },
        .init_funcs = .{
            .off = init_funcs_start,
            .len = @intCast(wasm.object_init_funcs.items.len - init_funcs_start),
        },
        .comdats = .{
            .off = comdats_start,
            .len = @intCast(wasm.object_comdats.items.len - comdats_start),
        },
        .symbols = .{
            .off = symbols_start,
            .len = @intCast(wasm.object_symbols.items.len - symbols_start),
        },
        .relocatable_data = .{
            .off = relocatable_data_start,
            .len = @intCast(wasm.object_relocatable_datas.items.len - relocatable_data_start),
        },
        .relocatable_code = .{
            .off = relocatable_code_start,
            .len = @intCast(wasm.object_relocatable_codes.items.len - relocatable_code_start),
        },
        .relocatable_custom = .{
            .off = relocatable_custom_start,
            .len = @intCast(wasm.object_relocatable_customs.items.len - relocatable_custom_start),
        },
        .local_section_index_base = local_section_index_base,
    };
}

/// Based on the "features" custom section, parses it into a list of
/// features that tell the linker what features were enabled and may be mandatory
/// to be able to link.
fn parseFeatures(
    wasm: *Wasm,
    bytes: []const u8,
    start_pos: usize,
    path: Path,
) error{ OutOfMemory, LinkFailure }!struct { Wasm.Feature.Set, usize } {
    const gpa = wasm.base.comp.gpa;
    const diags = &wasm.base.comp.link_diags;
    const features_len, var pos = readLeb(u32, bytes, start_pos);
    // This temporary allocation could be avoided by using the string_bytes buffer as a scratch space.
    const feature_buffer = try gpa.alloc(Wasm.Feature, features_len);
    defer gpa.free(feature_buffer);
    for (feature_buffer) |*feature| {
        const prefix: Wasm.Feature.Prefix = switch (bytes[pos]) {
            '-' => .@"-",
            '+' => .@"+",
            '=' => .@"=",
            else => return error.InvalidFeaturePrefix,
        };
        pos += 1;
        const name, pos = readBytes(bytes, pos);
        const tag = std.meta.stringToEnum(Wasm.Feature.Tag, name) orelse {
            return diags.failParse(path, "unrecognized wasm feature in object: {s}", .{name});
        };
        feature.* = .{
            .prefix = prefix,
            .tag = tag,
        };
    }
    std.mem.sortUnstable(Wasm.Feature, feature_buffer, {}, Wasm.Feature.lessThan);

    return .{
        .fromString(try wasm.internString(@bitCast(feature_buffer))),
        pos,
    };
}

fn readLeb(comptime T: type, bytes: []const u8, pos: usize) struct { T, usize } {
    var fbr = std.io.fixedBufferStream(bytes[pos..]);
    return .{
        switch (@typeInfo(T).int.signedness) {
            .signed => std.leb.readIleb128(T, fbr.reader()) catch unreachable,
            .unsigned => std.leb.readUleb128(T, fbr.reader()) catch unreachable,
        },
        pos + fbr.pos,
    };
}

fn readBytes(bytes: []const u8, start_pos: usize) struct { []const u8, usize } {
    const len, const pos = readLeb(u32, bytes, start_pos);
    return .{
        bytes[pos..][0..len],
        pos + len,
    };
}

fn readEnum(comptime T: type, bytes: []const u8, pos: usize) struct { T, usize } {
    const Tag = @typeInfo(T).@"enum".tag_type;
    const int, const new_pos = readLeb(Tag, bytes, pos);
    return .{ @enumFromInt(int), new_pos };
}

fn readLimits(bytes: []const u8, start_pos: usize) struct { std.wasm.Limits, usize } {
    const flags = bytes[start_pos];
    const min, const max_pos = readLeb(u32, bytes, start_pos + 1);
    const max, const end_pos = if (flags.has_max) readLeb(u32, bytes, max_pos) else .{ undefined, max_pos };
    return .{ .{
        .flags = flags,
        .min = min,
        .max = max,
    }, end_pos };
}

fn readInit(wasm: *Wasm, bytes: []const u8, pos: usize) !struct { Wasm.Expr, usize } {
    const end_pos = skipInit(bytes, pos); // one after the end opcode
    return .{ try wasm.addExpr(bytes[pos..end_pos]), end_pos };
}

fn skipInit(bytes: []const u8, pos: usize) !usize {
    const opcode = bytes[pos];
    const end_pos = switch (@as(std.wasm.Opcode, @enumFromInt(opcode))) {
        .i32_const => readLeb(i32, bytes, pos + 1)[1],
        .i64_const => readLeb(i64, bytes, pos + 1)[1],
        .f32_const => pos + 5,
        .f64_const => pos + 9,
        .global_get => readLeb(u32, bytes, pos + 1)[1],
        else => return error.InvalidInitOpcode,
    };
    if (readEnum(std.wasm.Opcode, bytes, end_pos) != .end) return error.InitExprMissingEnd;
    return end_pos + 1;
}
