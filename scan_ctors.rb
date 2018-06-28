require 'metasm'

binpath = ARGV.shift || 'libs/Dwarf_Fortress'
dasm = Metasm::AutoExe.decode_file(binpath).disassembler

ctor = dasm.section_info.assoc('.init_array')
ctor = dasm.section_info.assoc('.ctors') if not ctor
abort 'no .ctors' if not ctor

ctorlen = {}

$ptrsz = 4
$ptrsz = 8 if dasm.cpu.size == 64

addr = ctor[1]
(ctor[2]/$ptrsz).times {
	ct = dasm.decode_dword(addr)
	dasm.disassemble_fast_deep(ct)
	ctorlen[ct] = dasm.function_blocks(ct).length
	addr += $ptrsz
}

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

$stderr.puts "Global table starts at #{Metasm::Expression[table_start]}" if $VERBOSE
off = table_start + 2*$ptrsz

named_globals = {}

while true
	ptr_str = dasm.decode_dword(off)
	off += $ptrsz
	ptr_var = dasm.decode_dword(off)
	off += $ptrsz
	break if ptr_str == 0
	name = dasm.decode_strz(ptr_str)
	puts '%X => %s' % [ptr_var, name] if $VERBOSE
	named_globals[ptr_var] = [name, 0]
end

prev_key = 0
prev_value = [0,0]

named_globals.sort.map do |key, value|
	if prev_key > 0 then
		prev_value[1] = key - prev_key
	end
	prev_key = key
	prev_value = value
end

globals = []

big = ctorlen.sort_by { |k, v| v }.last[0]
puts "big ctor at %x" % big if $VERBOSE
dasm.each_function_block(big) { |a|
	call = dasm.block_at(a).list[-1]
	if call.opcode.name == 'call' and call.instruction.args[0].to_s =~ /cxa_atexit/
		funcarg1 = dasm.backtrace(Metasm::Indirection[:esp, 4], call.address) if $ptrsz == 4
		funcarg2 = dasm.backtrace(Metasm::Indirection[[:esp, :+, 4], 4], call.address) if $ptrsz == 4
		funcarg1 = dasm.backtrace([:rdi], call.address) if $ptrsz == 8
		funcarg2 = dasm.backtrace([:rsi], call.address) if $ptrsz == 8
		globals << [funcarg1[0].reduce, funcarg2[0].reduce]
	end
}

globals.each { |destr, obj|
	len = globals.map { |d, o| o }.sort.find { |o| o > obj }.to_i - obj
	name = named_globals.fetch(obj, [("obj_%X" % obj), len])
	name[1] = len if name[1] == 0
	if name[1] > 0
		puts '<global-object name="%s" offset="0x%x" size="%d">' % [name[0], obj, name[1]]
	else
		puts '<global-object name="%s" offset="0x%x">' % [name[0], obj]
	end
	puts '    <comment>dtor 0x%X</comment>' % destr
	puts '</global-object>'
}
