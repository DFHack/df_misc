# prepare stuff for disassembling DF with metasm

# usage:
#  cd df-misc
#  export RUBYLIB=path/to/metasm
#  ruby metasm_prepare.rb path/to/df[.exe] path/to/dfhack

# dfhack must be already compiled, and hold the full df-structures in library/xml,
# including an up-to-date globals.csv

# after running the script, run metasm/samples/disassemble-gui.rb -a path/to/df[.exe]

df = ARGV.shift
dfhack = ARGV.shift

codegenxml = dfhack + '/library/include/df/codegen.out.xml' if dfhack
dfhack = nil unless dfhack and File.exist?(codegenxml)
dfbase = df.chomp('.exe') if df

abort 'usage: prepare.rb df/libs/Dwarf_Fortress dfhack/' if not df or not dfhack

if df =~ /\.exe$/i
	windows = true
	globals = dfhack + '/library/xml/windows/globals.csv'
else
	linux = true
	globals = dfhack + '/library/xml/linux/globals.csv'
end


def redirect_stdout(filename, mode='w')
	old = $stdout.dup
	$stdout.reopen(filename, mode)
	yield
ensure
	$stdout.reopen(old)
end


def vtable_funcs_map(df, map, hdr)
	vtables = File.readlines(map).map { |l| w = l.split; [w[0].to_i(16), w[2]] }

	require 'metasm'
	ENV['METASM_NODECODE_RELOCS'] = '1'
	dasm = Metasm::AutoExe.decode_file(df).disassembler
	dasm.parse_c_file(hdr)

	vtables.each { |addr, name|
		cls = name[/vtable_(.*)/, 1]
		next if not struct = dasm.c_parser.toplevel.struct[cls]
		vt = struct.members.first.type
		vt = vt.members.first.type until vt.pointer?
		vt = vt.type

		vt.members.each { |m|
			off = vt.offsetof(dasm.c_parser, m)
			faddr = dasm.decode_dword(addr+off)
			# TODO full prototype, including return type
			mangled = "_ZN#{cls.length}#{cls}#{m.name.length}#{m.name}E"
			puts '%08x d %s' % [faddr, mangled]
		}
	}
end


system 'cp', globals, File.dirname(dfbase)
system 'cp', 'metasm_dasm_dfstructs.rb', dfbase+'.rb'

chdr = dfbase + '.h'
map = dfbase + '.map'

puts 'codegen C hdr'
cmdline = ['perl', 'codegen_c_hdr.pl', codegenxml, chdr, '--stdc']
cmdline << '--linux' if linux
system *cmdline

puts 'vtables -> map'
redirect_stdout(map) { system 'ruby', 'scan_vtable.rb', '--map', df }

puts 'vtable funcs -> map'
redirect_stdout(map, 'a') { vtable_funcs_map(df, map, chdr) }

puts 'globals -> map'
redirect_stdout(map, 'a') { system 'ruby', 'globalcsv2map.rb', globals }
