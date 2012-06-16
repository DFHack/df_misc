require 'metasm'

binpath = ARGV.shift || 'dwarfort.exe'
dasm = Metasm::AutoExe.decode_file(binpath).disassembler

ctor = dasm.section_info.assoc('__mod_init_func')
abort 'no .ctors' if not ctor

ctorlen = {}

addr = ctor[1]
(ctor[2]/4).times {
	ct = dasm.decode_dword(addr)
	dasm.disassemble_fast(ct)
	ctorlen[ct] = dasm.function_blocks(ct).length
	addr += 4
}

globals = []

big = ctorlen.sort_by { |k, v| v }.last[0]
puts "big ctor at %x" % big if $VERBOSE

# pop_eip
dasm.disassemble dasm.block_at(big).to_normal.first

# we dont decode macho imports yet
# -> just do stats on the call site, and hope cxa_atexit is most frequent
called = Hash.new(0)
dasm.each_function_block(big) { |a|
	call = dasm.block_at(a).list[-1]
	if call.opcode.name == 'call'
		# disassemble the function now, so that backtrace works
		dasm.disassemble_fast call.instruction.args[0].to_s
		# disassemble changes the label name, dont cache it!
		called[call.instruction.args[0].to_s] += 1
	end
}
atexit = called.sort_by { |k, v| v }.last[0]

dasm.each_function_block(big) { |a|
	call = dasm.block_at(a).list[-1]
	if call.opcode.name == 'call' and call.instruction.args[0].to_s == atexit
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
