require 'metasm'

# this scripts scans a binary for the number 7 used as starting dwarf count in fortress mode
# works for the windows/linux and macos versions

# the sizeof_structunit can be found using the get_sizeofunit.pl script

abort 'usage: scan <exe> <sizeof_unitstruct>' if ARGV.length != 2

ENV['METASM_NODECODE_RELOCS'] = '1'

exe = Metasm::AutoExe.decode_file(ARGV.shift)
$sizeofunit = Integer(ARGV.shift)

dasm = exe.disassembler

# the 7 is used as the initial value of a counter to allocate 7 unit structures
# in the code, we find the value 7 close to the sizeof(unit), and it is used
# to load the value used as a loop condition

# function containing this is called from viewscreen_choose_startsitest::feed(), right before viewscreen::addscreen()

# find all 0x00000007 in the binary
puts 'scan 7' if $VERBOSE
off_7 = dasm.pattern_scan([7].pack('L'))

# find all 0xsizeofunit in the binary
puts 'scan sizeof unit' if $VERBOSE
off_sz = dasm.pattern_scan([$sizeofunit].pack('L'))

# search close couples
puts 'proximity scan' if $VERBOSE
candidates_7 = off_7.find_all { |a7| off_sz.find { |au| au > a7 and au < a7 + 64 } }

p off_sz, candidates_7 if $DEBUG

def test_candidates(dasm, candidates_7)
found = 0
# look for the loop condition thing
candidates_7.each { |addr_7|
    # scan for the instruction containing '7' as 2nd argument
    di_addr = addr_7 - 1
    addr_7_instr = nil
    stores = []
    8.times { |i|
        # May have multiple overlapping candidates, eg in x64
        #   mov edi, 7  and  mov r15d, 7 (at previous offset, with x64 REX prefix)
        # We keep them all.
        di = dasm.disassemble_instruction(di_addr)
        if di and di_addr + di.bin_length >= addr_7 + 4 and di.instruction.args[1] == Metasm::Expression[7]
            addr_7_instr = di_addr
            puts di if $VERBOSE
            # find register/memory where the value 7 is stored
            # eg mov eax, 7  =>  eax
            stores << di.instruction.args[0].to_s
            8.times { |j|
                di = dasm.disassemble_instruction(di.next_addr)
                break if not di or di.instruction.opname != 'mov' or di.instruction.args.last.to_s != stores.last
                stores << di.instruction.args.first.to_s
            }
        end
        di_addr -= 1
    }

    next if stores.empty?

    # disassemble from this instruction
    dasm.disassemble_fast addr_7_instr

    # check loop condition: loop_body is the block following 'di',
    #  find the blocks jumping back to loop_body and different from the current block (loop_init)
    #  the end-of-loop test is the next-to-last instr of these blocks
    #  if the loop test depends on 'store', assume we found it
    loop_init = dasm.block_at(addr_7_instr)

    sizeofunit_str = Metasm::Expression[$sizeofunit].to_s
    # take all addresses jumping to the blocks following loop_init
    endaddrs = loop_init.to_normal.to_a.map { |loop_body_addr|
        next if not body = dasm.block_at(loop_body_addr)
        # ensure the loop body references sizeof_unit
        if not body.list.find { |bdi| bdi.instruction.args.last.to_s == sizeofunit_str }
            # indirect: may call new_unit() which has a ref to sizeofunit
            next if body.list.last.instruction.opname != 'call'
            first_subfunc = body.to_normal.last
            dasm.disassemble_fast first_subfunc
            next if not dasm.function_blocks(first_subfunc).keys.find { |fb| dasm.block_at(fb).list.find { |bdi| bdi.instruction.args.last.to_s == sizeofunit_str } }
        end
        body.from_normal rescue nil
    }.flatten.compact - [loop_init.list.last.address]

    # search if the next-to-last instr uses 'store', eg  cmp eax, 0  jnz loop_body
    ebl = nil
    if endaddrs.find { |ea|
        ebl = dasm.block_at(ea)
        stores.find { |store|
            ebl.list.length >= 2 and ebl.list[-2].instruction.args[0].to_s == store
        }
    }
        puts ebl.list[-2, 2] if $VERBOSE
        puts "fileoff='0x%x'" % dasm.addr_to_fileoff(addr_7) if $VERBOSE
        puts "<global-address name='start_dwarf_count' value='0x%x'/>" % addr_7
        found += 1
    end
}
found
end

if test_candidates(dasm, candidates_7) == 0
    puts 'proximity scan indirect' if $VERBOSE
    #
    # look for a code structure like
    #
    #  mov reg, 7
    # loop_begin:
    #  call allocate_unit
    #  dec reg
    #  jnz loop_begin
    #
    # allocate_unit: (elsewhere in the binary)
    #  push sizeof_unit
    #  call new()
    #  ret
    #
    candidates_7 = off_7.find_all { |a7|
        goodcall = false
        di_addr = a7+4
        while di_addr < a7+32 and !goodcall
            di = dasm.disassemble_instruction(di_addr)
            break if not di
            di_addr += di.bin_length
            if di.instruction.opname == 'call' or di.instruction.opname == 'jmp'
                call_tg = Metasm::Expression[di.instruction.args.first].reduce
                if call_tg.kind_of?(::Integer) and off_sz.find { |au|
                    au > call_tg and au < call_tg + 64
                }
                    goodcall = true
                end
            end
        end
        goodcall
    }
    p candidates_7 if $DEBUG

    test_candidates(dasm, candidates_7)
end
