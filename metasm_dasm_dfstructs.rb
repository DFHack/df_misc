# metasm disassembler plugin for Dwarf Fortress

# quickstart:
#  install ruby, and ruby-gtk if on linux
#  create a directory with metasm/, Dwarf_Fortress, globals.csv
#  edit the 'ep' line below, and run
#
# ruby scan_vtable.rb --map Dwarf_Fortress > globals.map
# ruby globalcsv2map.rb globals.csv >> globals.map
# perl codegen_c_hdr.pl dfhack/library/include/df/codegen.out.xml --stdc --linux codegen.h
# ruby -I metasm metasm/samples/disassemble-gui.rb Dwarf_Fortress -P metasm_dasm_dfstructs

# to navigate, use 'g' to go to a specific address
# use ctrl-maj-C to disassemble
# use 't' to define a register as a pointer to a struct
#  eg click on 'eax' somewhere, type 't', and type 'unitst' in the popup
# use 'K' to name stack variables
# use 'k' to toggle string representation / raw numeric value
# 'space' toggles graph view

# drawbacks: no save
# dont disassemble too many things
# dont type 'tab' (will take hours trying to decompile and fail)


# linux 34.11 ctor_viewscreen_layer_militaryst
ep = 0x08cd9290

load_map 'globals.map'
parse_c_file 'codegen.h'

disassemble_fast_deep(ep)
gui.focus_addr(ep, :graph)

load_plugin 'imm2off'		# add xrefs to known labels (from map file)
load_plugin 'stringsxrefs'	# add comments on instrs with pointers to ascii
load_plugin 'demangle_cpp'	# add demangled C++ names in comments
load_plugin 'hl_opcode'


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
