#!/usr/bin/ruby

# this script uses the metasm framework to patch the Dwarf Fortress
# the patch initializes all newly-allocated C++ objects with 0x33
# this is useful to match uninitialized fields in known structures
# should work on other binaries too

require 'metasm'

bin = ARGV.shift || 'Dwarf Fortress.exe'

puts "loading #{bin}"
pe = Metasm::PE.decode_file(bin, :nodecode_relocs)

dasm = pe.disassembler
dasm.load_plugin 'patch_file'

# TODO reuse COFF::Header etc
# structs from slipfest/pe.h
dasm.parse_c <<EOS
#define u8  unsigned char
#define u16 unsigned short
#define u32 unsigned int
#define u64 unsigned long long

struct coff_file_header
{
  u16 machine;
  u16 number_of_sections;
  u32 timestamp;
  u32 pointer_to_symboltable;
  u32 number_of_symbols;
  u16 size_of_optional_header;
  u16 characteristics;
};

struct coff_directory
{
  u32 rva;
  u32 size;
};

struct coff_optional_header
{
  u16 magic;
  u8  major_linker_version;
  u8  minor_linker_version;
  u32 size_of_code;
  u32 size_of_initialized_data;
  u32 size_of_uninitialized_data;
  u32 entrypoint;
  u32 base_of_code;
  u32 base_of_data;

  u32 image_base;
  u32 section_alignment;
  u32 file_alignment;
  u16 major_os_version;
  u16 minor_os_version;
  u16 major_image_version;
  u16 minor_image_version;
  u16 major_subsystem_version;
  u16 minor_subsystem_version;
  u32 win32_version_value;
  u32 size_of_image;
  u32 size_of_headers;
  u32 checksum;
  u16 subsystem;
  u16 dll_characteristics;
  u32 size_of_stack_reserve;
  u32 size_of_stack_commit;
  u32 size_of_heap_reserve;
  u32 size_of_heap_commit;
  u32 loader_flags;
  u32 number_of_rva_and_sizes;
  struct coff_directory data_directory[0];
};

struct coff_full_header {
	struct coff_file_header header;
	struct coff_optional_header optheader;
};

struct coff_section_header
{
  char name[8];
  u32 virtual_size;
  u32 virtual_address;
  u32 size_of_raw_data;
  u32 pointer_to_raw_data;
  u32 pointer_to_relocations;
  u32 pointer_to_linenumbers;
  u16 number_of_relocations;
  u16 number_of_linenumbers;
  u32 characteristics;
};
EOS

puts 'patch DYNAMIC_BASE'
hdr = dasm.decode_c_struct('coff_full_header', pe.optheader.image_base + pe.coff_offset)
case hdr.dll_characteristics
when 0x8140
	hdr.dll_characteristics = 0x8100
when 0x8100
	puts 'already patched'
else
	raise 'invalid dll_characteristics!'
end


puts 'patch IAT rw'
# import name for C++ 'new'
mangled_new = 'iat___2_YAPAXI_Z'
# find an unused area to store the backup ptr
iat_new = iat_bak_addr = dasm.prog_binding[mangled_new]
raise 'cant find new?' if not iat_bak_addr
iat_bak_addr += 4 while dasm.prog_binding.index(iat_bak_addr)
raise 'no memset' if not iat_memset = dasm.prog_binding['iat_memset']

# find the section with the iat
secs_addr = pe.optheader.image_base + pe.coff_offset + hdr.header.sizeof + hdr.size_of_optional_header
secs = dasm.decode_c_ary('coff_section_header', secs_addr, hdr.number_of_sections).to_array
iat = secs.find { |sec| sec.virtual_address+pe.optheader.image_base <= iat_bak_addr and sec.virtual_address+sec.virtual_size+pe.optheader.image_base > iat_bak_addr }
raise 'cant find iat?' if not iat
sec_write = Metasm::COFF::SECTION_CHARACTERISTIC_BITS.index('MEM_WRITE')
if iat.characteristics & sec_write > 0
	puts 'already patched'
else
	iat.characteristics |= sec_write
end


puts 'scan for 0xCC holes'
text = pe.sections.find { |sec| sec.name == '.text' }
# patch instrs are max 6 bytes, + jmp = 10 (XXX use space at end of .text)
# XXX check previous bytes if last 0xCC might be the last byte of a jmp?
holes = dasm.pattern_scan(/\xCC{11,}/n, text.virtaddr, text.virtsize)

cur_addr = holes.shift
raise 'no hole' if not cur_addr
assemble = lambda { |src, may_jmp|
	# encode the source instructions
	sc = Metasm::Shellcode.new(dasm.cpu, cur_addr)
	sc.assemble(src)
	raw = sc.encode_string
	# if they fit in the code, + leave space for a jmp
	check_len = raw.length
	check_len += ((holes.first > cur_addr+129+raw.length) ? 5 : 2) if may_jmp
	ed = dasm.get_edata_at(cur_addr)
	if ed.data[ed.ptr, check_len].unpack('C*').uniq == [0xCC]
		# patch them in, advance cur_addr
		ed[ed.ptr, raw.length] = raw
		cur_addr += raw.length
	elsif may_jmp
		next_addr = holes.shift
		raise 'no hole left' if not next_addr
		assemble["jmp $+#{next_addr-cur_addr}", false]
		cur_addr = next_addr
		assemble[src, may_jmp]
	else
		raise 'hole too small?'
	end
}


hooked_new_addr = cur_addr
puts 'store hooked new() at %X' % hooked_new_addr
# whenever the program calls new(), it will call this code instead
hooked_new_asm = <<EOS
push [esp+4]	// arg = alloc size
call [#{iat_bak_addr}]	// call original new()
push [esp+8]	// arg = alloc size (new() is cdecl)
push 0x33	// pattern
push eax	// retval = alloced addr
call [#{iat_memset}]
add esp, 16	// fix stack (memset + new are cdecl)
ret		// memset returns the alloced addr
EOS

hooked_new_asm.each_line { |l| assemble[l, true] }


cur_addr = holes.shift
iat_hook_addr = cur_addr
puts 'setup IAT hook at %X' % iat_hook_addr

orig_entrypoint = pe.optheader.image_base + pe.optheader.entrypoint

# on program start, it will patch its IAT for new() to point to hooked_new
iat_hook_asm = <<EOS
push [#{iat_new}]
pop [#{iat_bak_addr}]	// save original new() at iat_hook
push #{hooked_new_addr}
pop [#{iat_new}]	// put hooked_new address instead
jmp #{orig_entrypoint}	// back to entrypoint
EOS

iat_hook_asm.each_line { |l| assemble[l, true] }

puts 'patch entrypoint'
hdr.entrypoint = iat_hook_addr - pe.optheader.image_base

puts "done, original file backed up in #{bin}.bak"
