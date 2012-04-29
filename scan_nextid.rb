require 'metasm'

# metasm script to find all 'job_next_id' 'building_next_id' etc globals in dwarf fortress
# tested in 34.07, linux/windows

# code has pattern:
#tryagain:
#  cmp eax, [job_next_id]
#  jl foobar
#  ...
#  mov eax, a_load_game_invalid_job_id_number
#  ...
#  jz tryagain
#
#a_load_game_invalid_job_id_number db "Load Game: Invalid Job ID Number, ", 0

# disable decoding of relocs, takes a while for win binary ASLR aware
ENV['METASM_NODECODE_RELOCS'] = '1'

puts 'read file' if $VERBOSE
binpath = ARGV.shift || 'Dwarf Fortress.exe'	# works with linux too
dasm = Metasm::AutoExe.decode_file(binpath).disassembler

puts 'scan "invalid id" strings' if $VERBOSE
strings = {}
dasm.pattern_scan(/Load Game: Invalid (\w|\s)* ID Number/) { |addr|
	strings[addr] = dasm.decode_strz(addr)
}

xml = []
puts 'dasm xrefs' if $VERBOSE
strings.each { |addr, str|
	xo = nil
	dasm.pattern_scan([addr].pack('L')) { |xaddr| xo = xaddr }
	if !xo
		puts "no xref for #{str.inspect}"
		next
	end

	# found the xref: disassemble next instruction, will loop back where we need
	dasm.disassemble_fast(xo+4)

	# find the previous 'jl'
	a = xo
	id_addr = nil
	10.times {
		di = dasm.di_including(a)
		if di.opcode.name == 'jl'
			# find previous 'cmp'
			10.times {
				di = dasm.di_including(a)
				if di.opcode.name == 'cmp' and mrm = di.instruction.args.grep(Metasm::Ia32::ModRM)[0]
					id_addr = dasm.normalize mrm.imm
					break
				end
				a = di.address-1
			}
			break
		end
		a = di.address-1
	}

	if !id_addr
		puts "no pattern for #{str.inspect}"
		next
	end

	name = str[/Invalid (.*) ID Number/, 1].downcase.gsub(' ', '_') + '_next_id'

	xml << "<global-address name='#{name}' value='0x#{'%08x' % id_addr}'/>"
}

puts xml.sort
