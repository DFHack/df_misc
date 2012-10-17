# metasm disassembler plugin for Dwarf Fortress

# you may want to generate a .map file with vtable & global info first
#  see scan_vtable.rb --map & globalscsv2map.rb
# you'll also need a .h (see generate_c_hdr.rb --stdc [--linux])
# 
# disassemble some code (fast&deep), run the 'imm2off' plugin, then this one
# this plugin uses globals.csv in the current directory

if false
load_map 'globals.map'
parse_c_file 'codegen.h'

load_plugin 'imm2off'		# add xrefs to known labels (from map file)
load_plugin 'stringsxrefs'	# add comments on instrs with pointers to ascii
load_plugin 'demangle_cpp'	# add demangled C++ names in comments
end

# load globals.csv, map label names -> struct name
globals = File.readlines('globals.csv').inject({}) { |h, l|
	u = l.split(',').map { |w| w[1...-1] }
	next h if u[6].empty?
	h.update u[5].gsub(/[^\w]/, '_') => u[6]
}

count = 0

# propagate type info, from globals and vtable_*
prog_binding.each { |name, addr|
	if name =~ /^vtable_(\w+)/
		struct = $1
		each_xref(addr) { |xr|
			if di = di_at(xr.origin) and di.to_s =~ /mov dword ptr \[(\w+)\], #{name}/
				reg = $1.to_sym

				# df code usually assign vtable ptr after some other fields
				# try to walk up a little if safe (current block only)
				addr = di.address
				di.block.list.reverse_each { |ddi|
					next if ddi.address >= addr
					ddi.backtrace_binding ||= @cpu.get_backtrace_binding(ddi)
					break if ddi.backtrace_binding[reg]
					addr = ddi.address
				}

				trace_update_reg_structptr(addr, reg, struct)

				count += 1
			end
		}

	elsif struct = globals[name]
		each_xref(addr) { |xr|
			if di = di_at(xr.origin) and di.to_s =~ /mov (\w+), \[#{name}\]/
				reg = $1.to_sym
				trace_update_reg_structptr(di.address, reg, struct)

				count += 1
			end
		}

	end
}

puts "tweaked #{count} instrs with df types"
