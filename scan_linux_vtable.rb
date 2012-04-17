require 'metasm'

puts 'read file' if $VERBOSE
binpath = ARGV.shift || 'libs/Dwarf_Fortress'
elf = Metasm::AutoExe.decode_file(binpath).disassembler

puts 'scan *st' if $VERBOSE
strings = {}
elf.pattern_scan(/\d+\w+st\0/) { |addr|
	strings[addr] = elf.decode_strz(addr)
}

def demangle_str(s)
	len = s[/^\d+/]
	s[len.length, len.to_i]
end

bin_dwords = File.read(binpath).unpack('L*')

puts 'scan sptr' if $VERBOSE
sptr = {}
bin_dwords.each_with_index { |dw, dw_idx|
	if str = strings.delete(dw)
		vaddr = elf.fileoff_to_addr(dw_idx*4)
		sptr[vaddr-4] = str
	end
}

puts 'scan vtable' if $VERBOSE
xml = []
bin_dwords.each_with_index { |dw, dw_idx|
	if str = sptr.delete(dw)
		vaddr = elf.fileoff_to_addr(dw_idx*4)
		vaddr += 4
		xml << "<vtable-address name='#{demangle_str(str)}' value='0x#{'%x' % vaddr}'/>"
	end
}

puts xml.sort

#puts "not found:", strings.values.sort, sptr.values
