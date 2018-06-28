require 'metasm'

dumpfuncs = ARGV.delete '--dumpfuncs'
dumpmap = ARGV.delete '--map'
$scanargs = ARGV.delete '--args'

binpath = ARGV.shift
abort "usage: scan_vtable.rb /path/to/df_exe [--map] [--dumpfuncs] [--args]" if not binpath

ENV['METASM_NODECODE_RELOCS'] = '1'
dasm = Metasm::AutoExe.decode_file(binpath).disassembler

$ptrsz = 4
$ptrsz = 8 if dasm.cpu.size == 64

Metasm::DynLdr.new_func_c <<EOC
#line #{__LINE__}
// return the index in str where it contains one of ptrs
// starts from the end, iterate by restarting at last offset found
int scanptrs32(char *str, int strlen, unsigned __int32 *ptrs, int ptrslen) {
	int i;
	unsigned __int32 p;
	if (ptrslen > 0)
		for (i=strlen-4 ; i ; --i) {
			p = *(unsigned __int32 *)(str+i);
			if ((p < ptrs[0]) || (p > ptrs[ptrslen-1]))
				continue;
			for (unsigned min=0, max=ptrslen-1; (max - min) < ptrslen ;) {
				unsigned j = min + (max - min >> 2);
				if (p == ptrs[j])
					return i;
				if (p > ptrs[j])
					min = j+1;
				else
					max = j-1;
			}
		}
	return -1;
}

int scanptrs64(char *str, int strlen, unsigned __int64 *ptrs, int ptrslen) {
	int i;
	unsigned __int64 p;
	if (ptrslen > 0)
		for (i=strlen-8; i ; --i) {
			p = *(unsigned __int64 *)(str+i);
			if ((p < ptrs[0]) || (p > ptrs[ptrslen-1]))
				continue;
			for (unsigned min=0, max=ptrslen-1; (max - min) < ptrslen ;) {
				unsigned j = min + (max - min >> 2);
				if (p == ptrs[j])
					return i;
				if (p > ptrs[j])
					min = j+1;
				else
					max = j-1;
			}
		}
	return -1;
}
EOC

def scanptrs(raw, hash, ptrsz=$ptrsz)
	off = raw.length
	if ptrsz == 4
		ptrs = hash.keys.sort.pack('L*')
	else
		ptrs = hash.keys.sort.pack('Q*')
	end
	loop do
		if ptrsz == 4
			off = Metasm::DynLdr.scanptrs32(raw, off, ptrs, hash.length)
			break if off < 0
			yield [off, hash[raw[off, 4].unpack('L')[0]]]
		else
			off = Metasm::DynLdr.scanptrs64(raw, off, ptrs, hash.length)
			break if off < 0
			yield [off, hash[raw[off, 8].unpack('Q')[0]]]
		end
	end
end


# regexp to match class names from the binary
vclass_names = ['\w+st', 'renderer(_\w+)?', '\w*Screen\w*']
vclass_names_re = '(' + vclass_names.join('|') + ')'

strings = {}

if dasm.program.shortname == 'coff'
	$is_windows = true

	# MSVC2010 vtable:

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

	# .?AVclassst@@ / .?AUstructst@@
	
	# MSVC2015 x64 vtable:
	# vtable-8     dq typeinfoptr
	#
	# typeinfoptr  dd ?
	#              dd 0
	#              dd 0
	#              dd rva mangled_classname_ptr
	#
	# mangled_classname_ptr dq ?
	#                       dq 0
	#                       db ".?AVbuilding_bedst@@"

	dasm.pattern_scan(/\.\?A[UV]#{vclass_names_re}@@/) { |addr|
		key = addr - 2*$ptrsz
		key -= dasm.program.optheader.image_base if $ptrsz == 8
		strings[key] = dasm.decode_strz(addr)
	}

	def demangle_str(s)
		s[4, s.length-6]
	end

	classname_offset = 0xc
else
	$is_windows = false

	# gcc vtable:

	# vtable-4  typeinfoptr
	# vtable    vfunc0
	# vtable+4  vfunc1
	# ...
	#
	# typeinfoptr   parent?
	# typeinfoptr+4 mangled_classname_ptr


	dasm.pattern_scan(/\d+#{vclass_names_re}\0/) { |addr|
		strings[addr] = dasm.decode_strz(addr)
	}

	def demangle_str(s)
		len = s[/^\d+/]
		s[len.length, len.to_i]
	end

	classname_offset = $ptrsz

	gcc_hint = true
end


# find all pointers to what looks like mangled structure name ("06unitst")
file_raw = File.open(binpath, 'rb') { |fd| fd.read }

sptr = {}
ptrsz = $ptrsz
ptrsz = 4 if $is_windows and $ptrsz == 8
scanptrs(file_raw, strings, ptrsz) { |off, str|
	vaddr = dasm.fileoff_to_addr(off) - classname_offset
	sptr[vaddr] = str
}

# find [address, length] of the .text section
text = (dasm.section_info.assoc('.text') || dasm.section_info.assoc('__text')).values_at(1, 2)
plt = dasm.section_info.assoc('.plt').values_at(1, 2) rescue nil

# vtable
vtable = {}
scanptrs(file_raw, sptr) { |off, str|
	vaddr = dasm.fileoff_to_addr(off) + $ptrsz

	# check that we have an actual function pointer here (eg into .text)
	vf = dasm.decode_dword(vaddr)
	next if not vf.kind_of?(Integer)
	if vf == 0 or (vf >= text[0] and vf < text[0] + text[1]) or (plt and vf >= plt[0] and vf < plt[0] + plt[1])
		s = demangle_str(str)
		vtable[s] ||= []
		vtable[s] << vaddr
	end
}

# return the array of virtual functions in a table (sequence of pointers inside .text)
vt_funcs = lambda { |vt_addr|
	out = []
	a = vt_addr
	loop do
		vf = dasm.normalize(dasm.decode_dword(a))
		break if not vf.kind_of?(Integer) or (vf < text[0] and vf != 0) or vf > text[0]+text[1]
		out << vf
		a += $ptrsz
	end
	out.pop while out[-1] == 0
	out
}

def analyse_vfunc(dasm, addr)
	return "" if not $scanargs or addr == 0

	dasm.disassemble_fast(addr)

	argsize = nil
	retsize = nil
	dasm.each_function_block(addr) { |baddr|
		ldi = dasm.block_at(baddr).list.last
		if ldi.opcode.name == 'ret'
			if stk = ldi.instruction.args[0]
				argsize = stk.reduce
			else
				argsize = 0 if $is_windows
			end
			if movdi = dasm.block_at(baddr).list.reverse.find { |di| di.to_s =~ /((mov|xor|or) (al|ax|eax),|set\w+ al)/ }
				retsize = movdi.instruction.args[0].sz/8
			end
		end
	}

	retstr = ""
	retstr = retstr + " argsize='%d'" % argsize if argsize
	retstr = retstr + " retsize='%d'" % retsize if retsize
	return retstr
end

vtable.sort.each { |str, vaddrs|
	if vaddrs.length > 1 and gcc_hint
		# conflict
		# it *seems* that gcc layout is <0> <typeinfo_ptr> <vtable ptr0> <vtable ptr1>, so check that 0
		better = vaddrs.find_all { |va| dasm.decode_dword(va-8) == 0 }
		puts "conflict: original = #{vaddrs.map { |va| '0x%x' % va }.join('|')}, better = #{better.map { |va| '0x%x' % va }.join('|')}" if $VERBOSE
		vaddrs = better if better.length == 1
	end
	if vaddrs.length > 1
		# gcc64bits: looks like all subclasses have a <typeinfo_ptr> <0> which is mistaken for the vtable by the script, drop the entries where the 1st virtual function is the NULL ptr
		# win32 has similar stuff
		better = vaddrs.find_all { |va| dasm.decode_dword(va) != 0 }
		puts "conflict: original = #{vaddrs.map { |va| '0x%x' % va }.join('|')}, better2 = #{better.map { |va| '0x%x' % va }.join('|')}" if $VERBOSE
		vaddrs = better if better.length == 1
	end

	if vaddrs.length != 1
		puts "<!-- CONFLICT vtable-address name='#{str}' value='#{vaddrs.map { |va| '0x%x' % va }.join(' or ')}'/ -->"
	elsif dumpmap
		puts "%08x d vtable_%s" % [vaddrs[0], str]
		if dumpfuncs
			vt_funcs[vaddrs[0]].each_with_index { |vf, idx|
				puts "%08x d vfunc_%s_%x" % [vf, str, $ptrsz*idx]
			}
		end
	elsif dumpfuncs
		puts "<vtable-address name='#{str}' value='#{'0x%x' % vaddrs[0]}'>"
		vt_funcs[vaddrs[0]].each_with_index { |vf, idx|
			arginfo = analyse_vfunc(dasm, vf)
			puts "    <vtable-function index='%d' addr='0x%x'%s/>" % [idx, vf, arginfo]
		}
		puts "</vtable-address>"
	else
		puts "<vtable-address name='#{str}' value='#{'0x%x' % vaddrs[0]}'/>"
	end
}
