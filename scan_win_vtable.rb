require 'metasm'

dumpfuncs = ARGV.delete '--dumpfuncs'

binpath = ARGV.shift || 'Dwarf Fortress.exe'
ENV['METASM_NODECODE_RELOCS'] = '1'
dasm = Metasm::AutoExe.decode_file(binpath).disassembler

strings = {}
dasm.pattern_scan(/\.\?AV\w+st@@/) { |addr|
	strings[addr-8] = dasm.decode_strz(addr)
}

def demangle_str(s)
	s[4, s.length-6]
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




# windows vtable:

# vtable-4  typeinfoptr
# vtable    vfunc0
# vtable+4  vfunc1
# ...
#
# typeinfoptr   0
# typeinfoptr+4 0
# typeinfoptr+8 0
# typeinfoptr+C mangled_classname_ptr
#
# mangled_classname_ptr   dd ?
# mangled_classname_ptr+4 dd 0
# mangled_classname_ptr+8 db ".?AVbuilding_bedst@@"


# find all pointers to what looks like mangled structure name ("06unitst")
file_raw = File.read(binpath)

sptr = {}
scanptrs(file_raw, strings).each { |off, str|
	vaddr = dasm.fileoff_to_addr(off) - 0xc
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
	vtable[s] ||= []
	vtable[s] << vaddr
}

vtable.sort.each { |str, vaddrs|
	if vaddrs.length != 1
		puts "<!-- CONFLICT vtable-address name='#{str}' value='#{vaddrs.map { |va| '0x%x' % va }.join(' or ')}'/ -->"
	elsif dumpfuncs
		puts "<vtable-address name='#{str}' value='#{'0x%x' % vaddrs[0]}'>"
		a = vaddrs[0]
		i = 0
		loop do
			vf = dasm.decode_dword(a)
			break if vf < text[0] or vf > text[0]+text[1]
			if dumpfuncinfo
				ninsns = 0
				dasm.disassemble_fast(vf)
				dasm.each_function_block(vf) { |baddr, bto|
					ninsns += dasm.block_at(baddr).list.length
				}
				puts "    <vtable-function index='%d' addr='0x%x' ninsns='%d'/>" % [i, vf, ninsns]
			else
				puts "    <vtable-function index='%d' addr='0x%x'/>" % [i, vf]
			end
			a += 4
			i += 1
		end
		puts "</vtable-address>"
	else
		puts "<vtable-address name='#{str}' value='#{'0x%x' % vaddrs[0]}'/>"
	end
}
