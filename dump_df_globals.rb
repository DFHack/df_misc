require 'metasm'

# metasm script to dump the global table added by Toady for 0.44.1

# the table begins by dd 0x12345678 0x87654321 (32-bit) or dd 0x12345678 0x12345678 0x87654321 0x87654321 (64-bit)
# then a succession of [<ptr to string with global name> <ptr to global variable>]

ENV['METASM_NODECODE_RELOCS'] = '1'
binpath = ARGV.shift || 'Dwarf Fortress.exe'
dasm = Metasm::AutoExe.decode_file(binpath).disassembler
if dasm.cpu.size == 64
	bits = 64
else
	bits = 32
end

MAGIC1 = "\x78\x56\x34\x12"
MAGIC2 = "\x21\x43\x65\x87"
MAGIC1.force_encoding('BINARY') rescue nil
MAGIC2.force_encoding('BINARY') rescue nil
table_start = dasm.pattern_scan(MAGIC1).find { |off|
	dasm.read_raw_data(off, 8) == MAGIC1 + MAGIC2 or
	dasm.read_raw_data(off, 16) == MAGIC1 + MAGIC1 + MAGIC2 + MAGIC2
}

if not table_start
	abort "Cannot find magic bytes"
end

$stderr.puts "Global table starts at #{Metasm::Expression[table_start]}"

off = table_start + 2*bits/8
xml = []
while true
	ptr_str = dasm.decode_dword(off)
	off += bits/8
	ptr_var = dasm.decode_dword(off)
	off += bits/8
	break if ptr_str == 0
	name = dasm.decode_strz(ptr_str)
	xml << "<global-address name='#{name}' value='0x#{'%08x' % ptr_var}'/>"
end

puts xml
