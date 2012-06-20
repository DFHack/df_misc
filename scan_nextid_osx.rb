require 'metasm'

# metasm script to find all 'job_next_id' 'building_next_id' etc globals in dwarf fortress
# tested in 34.10, osx
# run with ruby -v for debug msgs

# code has pattern:
#  push ebp
#  push edi
#  call get_pc_thunk_ebx
#  lea ebp, [ebx+ptr_job_next_id-gotip]
#  lea eax, [ebx+a_load_game-gotip]
#  mov ecx, [ebp]
#  cmp eax, [ecx]
#  jl foobar
#
#ptr_job_next_id dd job_next_id
#job_next_id dd 0
#a_load_game_invalid_job_id_number db "Load Game: Invalid Job ID Number, ", 0

puts 'read file' if $VERBOSE
binpath = ARGV.shift || 'dwarfort.exe'
dasm = Metasm::AutoExe.decode_file(binpath).disassembler

puts 'scan "invalid id" strings' if $VERBOSE
strings = {}
dasm.pattern_scan(/Load Game: Invalid (\w|\s)* ID Number/) { |addr|
	strings[addr] = dasm.decode_strz(addr)
}

puts 'scan geteip' if $VERBOSE
getip = dasm.pattern_scan(/\x8b\x1c\x24\xc3/)[0]
dasm.disassemble(getip)

puts 'scan 1st data xref' if $VERBOSE

#
# due to how osx binaries are, we cant easily check for xrefs
#
# so we'll use the fact that this function starts with a
#  call put_my_retaddr_in_ebx
# and quickly does
#  lea reg, [ebx + a_job_nextid - lastretaddr]
#
# so we scan for this constant ^, by reading every dword in the
# binary (val), adding its own address (which is an approximation
# of lastretaddr), and checking if the result is close to a_job_nextid
# 
# the 0x40 constant assumes that the 'lea' is no more than 0x40 bytes
# after the call getip
#
# also, do the scan in C for speed (dont scan 25Mo in a ruby loop)
#
dldr = Metasm::DynLdr
dldr.new_func_c <<EOC
// delta = &a_nextid - &.text
unsigned scanaround(unsigned delta, char*str, unsigned strlen) {
	unsigned i;
	unsigned val;
	for (i=strlen-4 ; i ; --i) {
		val = i+4+*(unsigned*)(str+i);
		if (val > delta && val < delta+0x40)
			return i;
	}
	return 0;
}
EOC
puts 'jitted' if $VERBOSE

# assume all code is in the same segment as getip
text = dasm.get_section_at(getip)
sec_raw = text[0].data.to_str
puts 'raw section read' if $VERBOSE

# expects JobID to be the first string
off = sec_raw.length
a_jobid = strings.index('Load Game: Invalid Job ID Number, ')
delta = a_jobid - text[1]
funcstart = nil
until funcstart
	# find something that may be a getip+str xref
	off = dldr.scanaround(delta, sec_raw, off)
	puts 'scanaround %x %x' % [off, text[1]+off] if $VERBOSE
	raise 'scanaround failed' if off == 0
	addr = text[1] + off
	0x100.times { |i|
		# on linux/windows, the code loops around the xref, so we can simply
		# disassemble from the xref. Here on osx, this is not the case, so scan for
		# function prologue (4 push reg or more)
		if dasm.decode_byte(addr-i) & 0xf0 == 0x50 and
		   dasm.decode_byte(addr-i+1) & 0xf0 == 0x50 and
		   dasm.decode_byte(addr-i+2) & 0xf0 == 0x50 and
		   dasm.decode_byte(addr-i+3) & 0xf0 == 0x50 and
		   dasm.decode_byte(addr-i-1) & 0xf0 != 0x50	# ensure this is the 1st push
			puts 'funcstart %x' % (addr-i) if $VERBOSE
			dasm.disassemble_fast(addr-i)
			# check we actually get an xref to 'Invalid Job ID'
			if getstr = dasm.di_including(addr) and getstr.opcode.name == 'lea'
				# find the value of lea's reg arg
				a0 = getstr.instruction.args[0].symbolic
				bt = dasm.backtrace(a0, getstr.address, :include_start => true)
				if bt.length == 1 and bt[0].reduce == a_jobid
					# lea loads the address of the Job ID string !
					funcstart = addr-i
					break
				end
			end
		end
	}
end

puts 'found initIDs function: %x' % funcstart if $VERBOSE

# now we can parse the function, and check for the code pattern
xml = []
dasm.each_function_block(funcstart) { |baddr|
	# for every basic bloc ending in a 'jl'
	blk = dasm.block_at(baddr)
	next if blk.list.last.opcode.name != 'jl'
	cmp = blk.list[-2]
	raise 'no cmp/jl?' if cmp.opcode.name != 'cmp'
	# find the memory pointer used for comparison, this is the nextid value
	ptr = cmp.instruction.args[1].symbolic.target
	id_addr = dasm.normalize(dasm.backtrace(ptr, cmp.address).first)

	# now we assume we have only 2 blocks:
	# one with the 2 lea, and it jumps to the block with the jl
        # lea nextid_ptr ; lea str ; jmp foo
	# foo: cmp reg, [nextid]; jl xx
	# now, find the predecessor of the 'jl' block having only 1 successor
	strblk = blk.from_normal.find { |fb| dasm.block_at(fb).to_normal.length == 1 }
	dasm.block_at(strblk).list.each { |di|
		# find all lea reg, [ebx+XX]
		next unless di.opcode.name == 'lea' and di.instruction.args[1].b.symbolic == :ebx
		# compute the loaded register value
		bt = dasm.backtrace(di.instruction.args[0].symbolic, di.address, :include_start => true)
		# if it maps to one of the scanned nextID strings, we won
		if bt.length == 1 and str = strings[bt[0].reduce]
			name = str[/Invalid (.*) ID Number/, 1].downcase.gsub(' ', '_') + '_next_id'
			xml << "<global-address name='#{name}' value='0x#{'%08x' % id_addr}'/>"
			puts xml.last if $VERBOSE
		end
	}
}
puts if $VERBOSE

puts xml.sort
