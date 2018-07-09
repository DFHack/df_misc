#!/usr/bin/ruby

# generate xml skeleton for a class vtable

# usage: (run from the df_misc/ directory)
#  export RUBYLIB=/path/to/metasm
#  scan_vtable_funcs.rb [--args] [--asm] /path/to/df.exe /path/to/dfhack [class_namest]
#
# last argument is a regexp matched against rtti class names
#
# dfhack must be already compiled (ie uptodate codegen.out.xml)
#
# with --args, can auto-detect function args & return type (for best results run against the windows df binary)
# with --asm, can dump vfuncs asm code (for best results run against the linux df binary & after running ./metasm_prepare.rb)
#
# XXX when run against the linux binary, output will include 2 entries for the class dtor

# sample output:
#    <class-type type-name='general_ref' original-name='general_refst'>
#        <virtual-methods>
#            <vmethod name='unk_1'>
#                <ret-type><int32_t/></ret-type>
#                <int32_t/>
#                <int32_t/>
#                <int32_t/>
#            </vmethod>
#            <vmethod name='unk_2'>
#            </vmethod>
#        </virtual-methods>
#    </class-type>

ARGV.clear if ARGV.delete('-h')
$dump_asm = ARGV.delete('--asm')
$dump_args = ARGV.delete('--args')
df = ARGV.shift
dfhack = ARGV.shift
cls_re = ARGV.shift

codegenxml = dfhack + '/library/include/df/codegen.out.xml' if dfhack
dfhack = nil unless dfhack and File.exist?(codegenxml)
dfbase = df.chomp('.exe') if df
$ptrsz = 4

abort 'usage: prepare.rb df/df.exe dfhack/' if not df or not dfhack


def redirect_stdout(filename, mode='w')
	old = $stdout.dup
	$stdout.reopen(filename, mode)
	yield
ensure
	$stdout.reopen(old)
end


# return the name of the structure member of type 'pointer' at offset <off>
def ptr_name_off(dasm, vt, off)
	return if not vt
	vt.members.each { |m|
		moff = vt.offsetof(dasm.c_parser, m)
		if moff > off
			break
		elsif m.type.pointer?
			return m.name if moff == off
		elsif moff+dasm.c_parser.sizeof(m)
			return ptr_name_off(dasm, m.type, off-moff)
		end
	}
	nil
end

# one vmethod analysis
# with --args:
#  autodetect argument count from 'ret 8' (on windows binary)
#  autodetect return type (if code block with 'ret' contains 'mov al, <whatever>' -> return type = int8_t
# with --asm:
#  dump function asm
# TODO
#  autodetect destructor through rewriting vtable pointer
#  improved asm output (types, etc)
#  improved argument detection (pointers, flags, ...)
#   autodetect read_file write_file through func signature + usage of file_compressor ?

def analyse_vfunc(dasm, cls, addr)
	return if not $dump_asm and not $dump_args

	dasm.disassemble_fast(addr)
	if $dump_asm
		# TODO dasm.set_struct_ptr(:ecx, cls), dasm.make_stackvars
	end

	args = []
	ret = nil
	dasm.each_function_block(addr) { |baddr|
		ldi = dasm.block_at(baddr).list.last
		if ldi.opcode.name == 'ret'
			if stk = ldi.instruction.args[0]
				args = (0...stk.reduce/4).map { 'int32_t' }
			end
			if movdi = dasm.block_at(baddr).list.reverse.find { |di| di.to_s =~ /mov (al|ax|eax),/ }
				ret = "int#{movdi.instruction.args[0].sz}_t"
			end
		end
	}

	puts "                <ret-type><#{ret}/></ret-type>" if ret

	# TODO autoidentify uint8/16/32, pointers, flags
	args.each { |a| puts "                <#{a}/>" }

	if $dump_asm
		$asm_seen ||= {}
		if $asm_seen[addr]
			puts "                <asm seen='%08xh'/>" % addr
		else
			puts "                <asm>"
			$asm_seen[addr] = true
			naddr = addr
			dasm.each_function_block(addr) { |baddr|
				puts if baddr != naddr
				dasm.dump_block(baddr)
				ldi = dasm.block_at(baddr).list.last
				naddr = (ldi.next_addr if !ldi.opcode.props[:stopexec] or ldi.opcode.props[:saveip])
			}
			puts "                </asm>"
		end
	end
end


# dump vfuncs for a given vtable
# TODO handle class inheritance
def dump_vfuncs(dasm, cls, funcs, vt)
	puts "    <class-type type-name='#{cls.chomp('st')}' original-name='#{cls}'>"
	puts "        <virtual-methods>"
	funcs.each_with_index { |faddr, idx|
		off = idx*$ptrsz
		name = ptr_name_off(dasm, vt, off) || "unk_#{off/$ptrsz}"
		puts "            <vmethod name='#{name}'>"
		analyse_vfunc(dasm, cls, faddr)
		puts "            </vmethod>"
	}
	puts "        </virtual-methods>"
	puts "    </class-type>"
end


def vtable_funcs_map(df, map, hdr, cls_re)
	vtables = []
	vfuncs = {}
	File.readlines(map).map { |l|
		w = l.split
		addr, name = [w[0].to_i(16), w[2]]
		case name
		when /^vtable_(.*)$/
			vtables << $1
		when /^vfunc_(.*)_[a-f0-9]+$/
			(vfuncs[$1] ||= []) << addr
		end
	}

	require 'metasm'
	ENV['METASM_NODECODE_RELOCS'] = '1'
	dasm = Metasm::AutoExe.decode_file(df).disassembler
	dasm.parse_c_file(hdr)
	$ptrsz = 8 if dasm.cpu.size == 64
	if $dump_asm
		# load ./metasm_prepare output for prettier asm
		dfrb = df.chomp('.exe') + '.rb'
		dasm.load_plugin(dfrb) if File.exists?(dfrb)
		dfmap = df.chomp('.exe') + '.map'
		dasm.load_map(dfmap) if File.exists?(dfmap)
	end

	vtables.each { |name|
		next if cls_re and name !~ /#{cls_re}/i
		if struct = dasm.c_parser.toplevel.struct[name]
			vt = struct.members.first.type
			vt = vt.members.first.type until vt.pointer?
			vt = vt.type
		end
		dump_vfuncs(dasm, name, vfuncs[name], vt)
	}
end


chdr = '/tmp/df_vfuncscan.h'
map  = '/tmp/df_vfuncscan.map'

$stderr.puts 'codegen C hdr'
cmdline = ['perl', 'codegen_c_hdr.pl', codegenxml, chdr, '--stdc']
cmdline << '--linux' if df !~ /\.exe$/i
system *cmdline

$stderr.puts 'vtables -> map'
redirect_stdout(map) { system 'ruby', 'scan_vtable.rb', '--map', '--dumpfuncs', df }

$stderr.puts 'vtable funcs'
vtable_funcs_map(df, map, chdr, cls_re)

File.unlink(chdr) rescue nil
File.unlink(map) rescue nil

