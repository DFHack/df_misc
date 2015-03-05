require 'metasm'

# this scripts scans a binary for the number 7 used as starting dwarf count in fortress mode
# works for the windows/linux and macos versions

# the sizeof_structunit can be found using the get_sizeofunit.pl script

abort 'usage: scan <exe> <sizeof_unitstruct>' if ARGV.length != 2

ENV['METASM_NODECODE_RELOCS'] = '1'

exe = Metasm::AutoExe.decode_file(ARGV.shift)
sizeofunit = Integer(ARGV.shift)

dasm = exe.disassembler

# the 7 is used as the initial value of a counter to allocate 7 unit structures
# in the code, we find the value 7 close to the sizeof(unit), and it is used
# to load the value used as a loop condition

# find all 0x00000007 in the binary
puts 'scan 7' if $VERBOSE
off_7 = dasm.pattern_scan([7].pack('L'))

# find all 0xsizeofunit in the binary
puts 'scan sizeof unit' if $VERBOSE
off_sz = dasm.pattern_scan([sizeofunit].pack('L'))

# search close couples
puts 'proximity scan' if $VERBOSE
candidates_7 = off_7.find_all { |a7| off_sz.find { |au| au > a7 and au < a7 + 32 } }

p off_sz, candidates_7 if $DEBUG

# look for the loop condition thing
candidates_7.each { |addr_7|
	# scan for the instruction containing '7' as 2nd argument
	di_addr = addr_7 - 1
	di = nil
	8.times { |i|
		di = dasm.disassemble_instruction(di_addr)
		break if di and di.instruction.args[1] == Metasm::Expression[7] and di.bin_length > 4
		di_addr -= 1
		di = nil
	}

	next if not di
	puts di if $VERBOSE

	# disassemble from this instruction
	dasm.disassemble_fast di_addr

	# find register/memory 7 is stored
	# eg mov eax, 7  =>  eax
	store = di.instruction.args[0].to_s

	# check loop condition: loop_body is the block following 'di',
	#  find the blocks jumping back to loop_body and different from the current block (loop_init)
	#  the end-of-loop test is the next-to-last instr of these blocks
	#  if the loop test depends on 'store', assume we found it
	loop_init = dasm.block_at(di_addr)

	# take all addresses jumping to the blocks following loop_init
	endaddrs = loop_init.to_normal.map { |loop_body_addr|
		dasm.block_at(loop_body_addr).from_normal rescue []
	}.flatten - [loop_init.list.last.address]

	# search if the next-to-last instr uses 'store', eg  cmp eax, 0  jnz loop_body
	ebl = nil
	if endaddrs.find { |ea|
		ebl = dasm.block_at(ea)
		ebl.list[-2].instruction.args[0].to_s == store
	}
		puts ebl.list[-2, 2] if $VERBOSE
		puts "fileoff='0x%x" % dasm.addr_to_fileoff(addr_7) if $VERBOSE
		puts "<global-address name='start_dwarf_count' value='0x%x'/>" % addr_7
	end
}
