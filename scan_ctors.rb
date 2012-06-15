require 'metasm'

binpath = ARGV.shift || 'libs/Dwarf_Fortress'
dasm = Metasm::AutoExe.decode_file(binpath).disassembler

ctor = dasm.section_info.assoc('.ctors')
abort 'no .ctors' if not ctor

ctorlen = {}

addr = ctor[1]
(ctor[2]/4).times {
	ct = dasm.decode_dword(addr)
	dasm.disassemble_fast_deep(ct)
	ctorlen[ct] = dasm.function_blocks(ct).length
	addr += 4
}

globals = []

big = ctorlen.sort_by { |k, v| v }.last[0]
puts "big ctor at %x" % big if $VERBOSE
dasm.each_function_block(big) { |a|
	call = dasm.block_at(a).list[-1]
	if call.opcode.name == 'call' and call.instruction.args[0].to_s =~ /cxa_atexit/
		funcarg1 = dasm.backtrace(Metasm::Indirection[:esp, 4], call.address)
		funcarg2 = dasm.backtrace(Metasm::Indirection[[:esp, :+, 4], 4], call.address)
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
