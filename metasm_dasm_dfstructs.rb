# metasm disassembler plugin for Dwarf Fortress

# quickstart:
#  install ruby, and ruby-gtk if on linux
#  run metasm_prepare.rb
#  and ruby -I metasm metasm/samples/disassemble-gui.rb path/to/Dwarf_Fortress -a

# to navigate, use 'g' to go to a specific address
# use ctrl-maj-C to disassemble
# use 't' to define a register as a pointer to a struct
#  eg click on 'eax' somewhere, type 't', and type 'itemst' in the popup
# use 'K' to scan for stack variables for current function
# use 'n' to rename labels/variables
# use 'k' to toggle string representation / raw numeric value
# 'space' toggles graph view

# Warning:
# dont disassemble too many things
# dont type 'tab' (will take hours trying to decompile and fail)



# load globals.csv, map label names -> struct name
$df_globals = File.readlines(File.dirname(program.filename) + '/globals.csv').inject({}) { |h, l|
    u = l.split(',').map { |w| w[1...-1] }
    next h if u[6].empty?
    h.update u[5].gsub(/[^\w]/, '_') => u[6]
}


def df_structs
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

    elsif struct = $df_globals[name]
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
end


# run all this whenever we finish disassembling some new code
last_cnt = 0
self.callback_finished  = proc {
    if last_cnt != @decoded.length
        last_cnt = @decoded.length
        puts 'running df plugins'
        load_plugin 'imm2off'
        puts 'imm2off'
        load_plugin 'stringsxrefs'
        puts 'stringsxrefs'
        load_plugin 'demangle_cpp'
        df_structs
    end
}

# also run now
self.callback_finished[]
