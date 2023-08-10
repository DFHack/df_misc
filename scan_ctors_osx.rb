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

puts ctorlist.map { |ct| "<ctor addr='0x%x' len='%d'/>" % [ct, dasm.function_blocks(ct).length] } if $VERBOSE

big = ctorlist.sort_by { |ct| dasm.function_blocks(ct).length }.last
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

globals = []

ctorlist.each { |ct|
    ctorlen = dasm.function_blocks(ct).length
    #next if ctorlen < 6    # skip 'small' ctor funcs
    dasm.each_function_block(ct) { |a|
        call = dasm.block_at(a).list[-1]
        if call.opcode.name == 'call' and call.instruction.args[0].to_s == atexit

            arg1 = dasm.backtrace(Metasm::Indirection[[:esp], 4], call.address)[0].reduce
            arg2 = dasm.backtrace(Metasm::Indirection[[:esp, :+, 4], 4], call.address)[0].reduce

            next if arg1.to_s =~ /^__Z/    # std destructors
            next if not arg2.kind_of?(::Integer)    # ???
            #next if arg2 == 0

            globals << [ct, arg2, call.address]
        end
    }
}

globals.each { |ct, obj, ca|
    len = globals.map { |c, o, a| o }.sort.find { |o| o > obj }.to_i - obj
    puts '<global-object ctorlist="sub_%xh" callsite="0x%x" name="obj_%X" offset="0x%x" size="%d"/>' % [ct, ca, obj, obj, len]
}
