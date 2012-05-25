require 'metasm'

# metasm script to find all 'job_next_id' 'building_next_id' etc globals in dwarf fortress
# tested in 34.10, osx

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

text = dasm.get_section_at(getip)
sec_raw = text[0].data.to_str
puts 'raw section read' if $VERBOSE

off = sec_raw.length
a_jobid = strings.index('Load Game: Invalid Job ID Number, ')
delta = a_jobid - text[1]
funcstart = nil
until funcstart
	off = dldr.scanaround(delta, sec_raw, off)
	puts 'scanaround %x %x' % [off, text[1]+off] if $VERBOSE
	raise 'scanaround failed' if off == 0
	addr = text[1] + off
	0x100.times { |i|
		# 4x 'push reg' is function prolog
		if dasm.decode_byte(addr-i) & 0xf0 == 0x50 and
		   dasm.decode_byte(addr-i-1) & 0xf0 != 0x50 and
		   dasm.decode_byte(addr-i+1) & 0xf0 == 0x50 and
		   dasm.decode_byte(addr-i+2) & 0xf0 == 0x50 and
		   dasm.decode_byte(addr-i+3) & 0xf0 == 0x50
			puts 'funcstart %x' % (addr-i) if $VERBOSE
			dasm.disassemble_fast(addr-i)
			# check we actually get an xref to 'Invalid Job ID'
			if getstr = dasm.di_including(addr) and getstr.opcode.name == 'lea'
				a0 = getstr.instruction.args[0].symbolic
				bt = dasm.backtrace(a0, getstr.address, :include_start => true)
				if bt.length == 1 and bt[0].reduce == a_jobid
					funcstart = addr-i
					break
				end
			end
		end
	}
end

puts 'found initIDs function: %x' % funcstart

xml = []
dasm.each_function_block(funcstart) { |baddr|
	blk = dasm.block_at(baddr)
	next if blk.list.last.opcode.name != 'jl'
	cmp = blk.list[-2]
	raise 'no cmp/jl?' if cmp.opcode.name != 'cmp'
	ptr = cmp.instruction.args[1].symbolic.target
	id_addr = dasm.backtrace(ptr, cmp.address).map { |bt| bt.reduce }.grep(Integer).first
	# XXX assume we have only 2 blk: lea nextid_ptr ; lea str ; jmp foo  ;  foo: cmp ; jl
	strblk = blk.from_normal.find { |fb| dasm.block_at(fb).to_normal.length == 1 }
	dasm.block_at(strblk).list.each { |di|
		next unless di.opcode.name == 'lea' and di.instruction.args[1].b.symbolic == :ebx
		bt = dasm.backtrace(di.instruction.args[0].symbolic, di.address, :include_start => true)
		if bt.length == 1 and str = strings[bt[0].reduce]
			name = str[/Invalid (.*) ID Number/, 1].downcase.gsub(' ', '_') + '_next_id'
			xml << "<global-address name='#{name}' value='0x#{'%08x' % id_addr}'/>"
			puts xml.last if $VERBOSE
		end
	}
}

puts xml.sort
