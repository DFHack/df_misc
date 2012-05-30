require 'metasm'

dumpfuncs = ARGV.delete '--dumpfuncs'
dumpfuncinfo = ARGV.delete '--dumpfuncinfo'
dumpfuncs = true if dumpfuncinfo

puts 'read file' if $VERBOSE
binpath = ARGV.shift || 'libs/Dwarf_Fortress'
dasm = Metasm::AutoExe.decode_file(binpath).disassembler

puts 'scan *st' if $VERBOSE
strings = {}
dasm.pattern_scan(/\d+\w+st\0/) { |addr|
	strings[addr] = dasm.decode_strz(addr)
}

def demangle_str(s)
	len = s[/^\d+/]
	s[len.length, len.to_i]
end


Metasm::DynLdr.new_func_c <<EOC
#line #{__LINE__}
// return the index in str where it contains one of ptrs
// starts from the end, iterate by restarting at last offset found
int scanptrs(char *str, int strlen, unsigned *ptrs, int ptrslen) {
	int i;
	unsigned p;
	for (i=strlen-4 ; i ; --i) {
		p = *(unsigned*)(str+i);
		if (p < ptrs[0] || p > ptrs[ptrslen-1])
			continue;
		for (int j=0 ; j<ptrslen ; ++j)
			if (p == ptrs[j])
				return i;
	}
	return -1;
}
EOC

def scanptrs(raw, hash)
	off = raw.length
	ptrs = hash.keys.sort.pack('L*')
	ret = []
	loop do
		off = Metasm::DynLdr.scanptrs(raw, off, ptrs, hash.length)
		break if off < 0
		ret << [off, hash[raw[off, 4].unpack('L')[0]]]
	end
	ret
end




# linux vtable:

# vtable-4  typeinfoptr
# vtable    vfunc0
# vtable+4  vfunc1
# ...
#
# typeinfoptr   parent?
# typeinfoptr+4 mangled_classname_ptr


# find all pointers to what looks like mangled structure name ("06unitst")
file_raw = File.read(binpath)

sptr = {}
scanptrs(file_raw, strings).each { |off, str|
	vaddr = dasm.fileoff_to_addr(off) - 4
	sptr[vaddr] = str
}

# find [address, length] of the .text section
text = dasm.section_info.find { |n, a, l, i| n == '.text' }.values_at(1, 2)

# vtable 
vtable = {}
scanptrs(file_raw, sptr).each { |off, str|
	vaddr = dasm.fileoff_to_addr(off) + 4

	# check that we have an actual function pointer here (eg into .text)
	vf = dasm.decode_dword(vaddr)
	next if vf < text[0] or vf > text[0]+text[1]

	s = demangle_str(str)
	if vtable[s]
		vtable[s] += ' or 0x%x' % vaddr
	else
		vtable[s] = '0x%x' % vaddr
	end
}

vtable.sort.each { |str, vaddr|
	if vaddr =~ / or /
		puts "<!-- CONFLICT vtable-address name='#{str}' value='#{vaddr}'/ -->"
	elsif dumpfuncs
		puts "<vtable-address name='#{str}' value='#{vaddr}'>"
		a = vaddr.to_i(16)
		loop do
			vf = dasm.decode_dword(a)
			break if vf < text[0] or vf > text[0]+text[1]
			ninsns = 0
			if dumpfuncinfo
				dasm.disassemble_fast(vf)
				dasm.each_function_block(vf) { |baddr, bto|
					ninsns += dasm.block_at(baddr).list.length
				}
			end
			puts "    <vtable-function addr='0x%x' ninsns='%d'/>" % [vf, ninsns]
			a += 4
		end
		puts "</vtable-address>"
	else
		puts "<vtable-address name='#{str}' value='#{vaddr}'/>"
	end
}
