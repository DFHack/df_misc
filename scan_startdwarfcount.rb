require 'metasm'

# this scripts scans a binary for the number 7 used as starting dwarf count in fortress mode
abort 'usage: scan <exe> <sizeofunit>' if ARGV.length != 2
ENV['METASM_NODECODE_RELOCS'] = '1'

exe = Metasm::AutoExe.decode_file(ARGV.shift)
sizeofunit = Integer(ARGV.shift)

dasm = exe.disassembler

# the 7 is used as the initial value of a counter to allocate 7 unit structures
# in the code, we find the value 7 close to the sizeof(unit), and it is used
# to load the value used as a loop condition

# find all 0x00000007 in the binary
puts 'scan 7' if $VERBOSE
o7 = dasm.pattern_scan([7].pack('L'))

# find all 0xsizeofunit in the binary
puts 'scan sizeof unit' if $VERBOSE
ou = dasm.pattern_scan([sizeofunit].pack('L'))

# search close couples
puts 'proximity scan' if $VERBOSE
may = o7.find_all { |a7| ou.find { |au| au > a7 and au < a7 + 32 } }

p ou, may if $DEBUG

# look for the loop condition thing
may.each { |o|
	# find the instruction containing '7' as 2nd argument
	adi = o - 2
	di = nil
	8.times { |i|
		di = dasm.disassemble_instruction(adi)
		break if di and di.instruction.args[1] == Metasm::Expression[7]
		adi -= 1
		di = nil
	}

	next if not di
	puts di if $VERBOSE

	# disassemble from there
	dasm.disassemble_fast adi

	# find where 7 is loaded
	store = di.instruction.args[0].to_s

	# find loop condition
	block7 = dasm.block_at(adi)
	endaddrs = block7.to_normal.map { |to| dasm.block_at(to).from_normal }.flatten - [block7.list.last.address]
	if endaddrs.find { |ea| dasm.block_at(ea).list[-2].instruction.args[0].to_s == store }
		puts "<global-address name='start_dwarf_count' value='0x%x' fileoff='0x%x'/>" % [o, dasm.addr_to_fileoff(o)]
	end
}
