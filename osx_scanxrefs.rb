
# returns a list of addresses of pointers to target from the code section
def scan_code_xrefs(dasm, target, threshold=0x400)
	out = dasm.pattern_scan([target].pack('L'))
	if dasm.cpu.size == 64
		out.concat scan_xrefs_rel(dasm, target)
	elsif dasm.program.kind_of?(Metasm::MachO)
		out.concat scan_xrefs_osx(dasm, target, threshold)
	end
	out
end

#
# 64bit code uses rip-relative adressing:
# some_addr:
#   mov rax, [rip + offset - some_addr_next]
# some_addr_next:
#   cmp rax, 0
#
# so the instruction hexadecimal code actually contains only the 32bit offset
# from the end of current instruction to the target address
#
def scan_xrefs_rel(dasm, target)
	if not Metasm::DynLdr.respond_to?(:scan_rel)
		# JIT a method to scan for the relative offset
		# full scan by starting with section_sz = real section size, and
		#  call again with section_sz = addr of last match
		Metasm::DynLdr.new_func_c <<EOC
unsigned scan_rel(unsigned target, char *section_raw, unsigned section_sz) {
	unsigned i;
	unsigned val;
	for (i=section_sz-4 ; i ; --i) {
		val = *(unsigned*)(section_raw+i);
		if (i+4+val == target)
			return i;
	}
	return 0;
}
EOC
		text_edata, @rel_text_base = dasm.get_section_at('entrypoint')
		@rel_text_raw = text_edata.data.to_str

		$stderr.puts 'jitted' if $VERBOSE
	end

	off = @rel_text_raw.length
	delta = target - @rel_text_base

	xref_list = []
	@rel_xref_getip = []
	while off > 0
		off = Metasm::DynLdr.scan_rel(delta, @rel_text_raw, off)
		xref_addr = @rel_text_base + off
		xref_list << xref_addr
	end
	xref_list
end

#
# osx compiler generates truly position-independent code
# we need to find the getip stub (getip:  mov ebx, [esp]  ret)
# a global variable reference will look like
#
#  somefunc:
#   <beginning of function>
#   call getip
#   <stuff>
#   lea reg, [ebx + <addr_global - ret_getip>]
#
# we hope that 'lea' if not too far away from 'call getip' and search for
# an int32 value close to <addr_global - addr_int32> (addr_int32 as an approximation of ret_getip)
#
# so we read every dword in the binary (val), adding its own address
# and checking if the result is close to addr_global.
# we also check that there is a call to getip at the right offset.
#
# while we're at it, store the address of every 'call getip' in the @osx_xref_getip global
#
def scan_xrefs_osx(dasm, target, threshold)
	if not @osx_getip ||= nil
		$stderr.puts 'scan geteip' if $VERBOSE
		@osx_getip = dasm.pattern_scan(/\x8b\x1c\x24\xc3/n)[0]
		raise 'cannot find osx getip' if not @osx_getip
		# actually disassemble the function for backtracking later
		dasm.disassemble(@osx_getip)

		# JIT a method to scan for the relative offset
		# full scan by starting with section_sz = real section size, and
		#  call again with section_sz = addr of last match
		@osx_dldr = Metasm::DynLdr
		@osx_dldr.new_func_c <<EOC
// target = &global - &.text
// threshold = maximum offset between 'lea global' and 'call getip'
unsigned scanaround(unsigned target, char *section_raw, unsigned section_sz, int threshold) {
	unsigned i;
	unsigned val;
	for (i=section_sz-4 ; i ; --i) {
		val = i+4+*(unsigned*)(section_raw+i);
		if (val > target && val < target+threshold)
			return i;
	}
	return 0;
}
EOC

		text_edata, @osx_text_base = dasm.get_section_at(@osx_getip)
		@osx_text_raw = text_edata.data.to_str

		$stderr.puts 'jitted' if $VERBOSE
	end

	off = @osx_text_raw.length
	delta = target - @osx_text_base

	xref_list = []
	@osx_xref_getip = []
	while off > 0
		off = @osx_dldr.scanaround(delta, @osx_text_raw, off, threshold)
		xref_addr = @osx_text_base + off

		# check a matching getip exists
		next if not value = dasm.decode_dword(xref_addr)
		# assume xref_addr is an 'lea reg, [ebx+global-may_getip_ret]'
		may_getip_ret = target - value
		# ensure may_getip_ret is right after a 'call getip'
		next if not getip_off = dasm.decode_dword(may_getip_ret-4)
		next if dasm.decode_byte(may_getip_ret-5) != 0xe8
		next if (getip_off + may_getip_ret) & 0xffffffff != @osx_getip

		xref_list << xref_addr
		@osx_xref_getip << (may_getip_ret-5)
	end
	xref_list
end

