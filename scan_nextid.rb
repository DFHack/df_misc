require 'metasm'

$: << File.dirname(__FILE__)
require 'osx_scanxrefs'

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

$stderr.puts 'read file' if $VERBOSE
binpath = ARGV.shift || 'Dwarf Fortress.exe'	# works with linux too
dasm = Metasm::AutoExe.decode_file(binpath).disassembler

$stderr.puts 'scan "invalid id" strings' if $VERBOSE
strings = {}
dasm.pattern_scan(/Load Game: Invalid (\w|\s)* ID Number/) { |addr|
	strings[addr] = dasm.decode_strz(addr)
}

xml = []
$stderr.puts 'dasm xrefs' if $VERBOSE
strings.each { |addr, str|
	xo = scan_code_xrefs(dasm, addr)
	if xo.empty?
		$stderr.puts "no xref for #{str.inspect}"
		next
	end

	$stderr.puts "xrefs: #{xo.inspect} to #{str}" if $VERBOSE

	id_addr = nil
xo.each { |xoa|
	# found the xref: disassemble next instruction, will loop back where we need
	dasm.disassemble_fast(xoa+4)

	# find the previous 'jl'
	a = xoa
	16.times {
		di = dasm.di_including(a)
		if not di
			a = a-1
			next
		end
		if di.opcode.name == 'jl'
			# find previous 'cmp'
			10.times {
				di = dasm.di_including(a)
				if not di
					a = a-1
					next
				end
				if di.opcode.name == 'cmp' and mrm = di.instruction.args.find { |arg| arg.class.name.split('::').last == 'ModRM' }
					id_addr = dasm.normalize mrm.imm
					if dasm.cpu.size == 64
						if id_addr.to_i < 0x1000
							id_addr = nil

							# win x64: code is actually
							# mov eax, [rip-$_+xref_nextid]
							#  cmp [esi+128], eax
							#  jl label_whatever

							if di = dasm.di_including(di.address-1)
								mrm = di.instruction.args.find { |arg| arg.class.name.split('::').last == 'ModRM' }
							end
						end
						if mrm and (mrm.b.to_s == 'rip' or mrm.i.to_s == 'rip')
							id_addr = dasm.normalize(mrm.imm) + di.next_addr
						end
					end
					break
				end
				a = di.address-1
			}
			break
		end
		a = di.address-1
	}
	break if id_addr
}

	if !id_addr
		$stderr.puts "no pattern for #{str.inspect}"
		next
	end

	name = str[/Invalid (.*) ID Number/, 1].downcase.gsub(' ', '_') + '_next_id'

	xml << "<global-address name='#{name}' value='0x#{'%08x' % id_addr}'/>"
}

puts xml.sort
