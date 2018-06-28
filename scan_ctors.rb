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
	if len > 0
		puts '<global-object name="obj_%X" offset="0x%x" size="%d">' % [obj, obj, len]
	else
		puts '<global-object name="obj_%X" offset="0x%x">' % [obj, obj]
	end
	puts '    <comment>dtor 0x%X</comment>' % destr
	puts '</global-object>'
}
