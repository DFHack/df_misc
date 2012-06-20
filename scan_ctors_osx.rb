require 'metasm'

binpath = ARGV.shift || 'dwarfort.exe'
dasm = Metasm::AutoExe.decode_file(binpath).disassembler

ctor = dasm.section_info.assoc('__mod_init_func')
abort 'no .ctors' if not ctor

dasm.backtrace_maxblocks_fast = 1

ctorlist = []

addr = ctor[1]
(ctor[2]/4).times {
	ct = dasm.decode_dword(addr)
	dasm.disassemble_fast_deep(ct)
	ctorlist << ct
	addr += 4
}

globals = []

big = ctorlist.sort_by { |c| dasm.function_blocks(c).length }.last
puts "big ctor at %x" % big if $VERBOSE

# binding for getpc_ebx
dasm.backtrace_update_function_binding dasm.block_at(big).to_normal.first

# macho gcc does weird stuff for __cxa_atexit, in a wrapper with dlsym etc
# here we do some stats on the biggest ctor, and assume the most frequent subfunc call is to this wrapper
called = Hash.new(0)
dasm.each_function_block(big) { |a|
	call = dasm.block_at(a).list[-1]
	if call.opcode.name == 'call'
		called[call.instruction.args[0].to_s] += 1
	end
}
atexit = called.sort_by { |k, v| v }.last[0]

ctorlist.each { |ct|
	ctorlen = dasm.function_blocks(ct).length
	next if ctorlen < 6	# skip 'small' ctor funcs
	dasm.each_function_block(ct) { |a|
		call = dasm.block_at(a).list[-1]
		if call.opcode.name == 'call' and call.instruction.args[0].to_s == atexit
			arg2 = dasm.backtrace(Metasm::Indirection[[:esp, :+, 4], 4], call.address)[0].reduce
			globals << [ct, arg2]
		end
	}
}

globals.each { |ct, obj|
	len = globals.map { |c, o| o }.sort.find { |o| o > obj }.to_i - obj
	puts '<global-object ctor="sub_%xh" name="obj_%X" offset="0x%x" size="%d"/>' % [ct, obj, obj, len]
}
