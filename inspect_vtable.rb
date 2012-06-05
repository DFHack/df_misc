require 'metasm'

# argument: binary, address of a vtable
# it lists vmethods inside, with the number of instructions in the method
# useful to check for added/moved vmethods in a new df version

dumpasm = ARGV.delete '--asm'

abort 'usage: inspect_vtable DwarfFortress.exe 0x121212' if ARGV.length < 2

binpath = ARGV.shift

ENV['METASM_NODECODE_RELOCS'] = '1'
dasm = Metasm::AutoExe.decode_file(binpath).disassembler

text = dasm.section_info.find { |n, a, l, i| n == '.text' }.values_at(1, 2)

ARGV.each { |va|
	vaddr = Integer(va)
	puts "<vtable-address value='#{'0x%x' % vaddr}'/>"

	i = 0
	loop do
		vf = dasm.decode_dword(vaddr)
		break if vf < text[0] or vf > text[0]+text[1]
		ninsns = 0
		dasm.disassemble_fast(vf)
		dasm.each_function_block(vf) { |baddr, bto|
			ninsns += dasm.block_at(baddr).list.length
		}
		puts "    <vtable-function index='%d' addr='0x%x' ninsns='%d'/>" % [i, vf, ninsns]
		puts dasm.flatten_graph(vf) if dumpasm
		vaddr += 4
		i += 1
	end

	puts "</vtable-address>"
}
