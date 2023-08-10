require 'metasm'

$: << File.dirname(__FILE__)
require 'osx_scanxrefs'

# metasm script to find the 'keybinding' static variable inside the
# statically-linked libgraphics on windows and osx
#
# searches for 'update_keydisplay' function from the 'Space' and 'Tab' xrefs, and extract the address from there
#
# assume the 1st conditional jump after 'Tab' depends on [dereferencing on windows] keybinding+4

ENV['METASM_NODECODE_RELOCS'] = '1'

puts 'read file' if $VERBOSE
binpath = ARGV.shift || 'Dwarf Fortress.exe'
dasm = Metasm::AutoExe.decode_file(binpath).disassembler

puts 'scan "Tab" string' if $VERBOSE
tab = dasm.pattern_scan(/Tab\0/)[0]

addrs = scan_code_xrefs(dasm, tab) if tab
raise 'no "Tab"' if not tab or addrs.empty?
# windows has 2 xrefs (ctor?), the bad one has no branches

if defined? @osx_xref_getip
    puts "getip %x" % @osx_xref_getip.first if $VERBOSE
    dasm.disassemble_fast_deep @osx_xref_getip.first
end

puts "Tab xrefs: #{addrs.map { |a| a.to_s(16) }.join(', ')}" if $VERBOSE

keydisplay = []
addrs.each { |addr|
    dasm.disassemble_fast addr+4

    # assume the 1st 'cmp' we'll encounter depends on keybinding+4
    cmp = nil

    b = dasm.block_including(addr+4)
    8.times {
        to = b.to_subfuncret || b.to_normal
        if to.length > 1
            cmp = b.list.find { |di| di.opcode.name == 'cmp' }
            break
        end
        b = dasm.block_at(to[0])
    }

    next if not cmp
    puts cmp if $VERBOSE

    # find which arg we can resolve
    arg = cmp.instruction.args.find { |a|
        val = dasm.backtrace(a.symbolic, cmp.address)
        val != [] and val[0] != Metasm::Expression::Unknown
    }.symbolic

    # XXX windows does: cmp eax, [keydisplay-4], but on osx: cmp eax, keydisplay-4
    arg = arg.pointer if arg.kind_of?(Metasm::Indirection)
    keydisplay << dasm.normalize(dasm.backtrace(arg, cmp.address)) - 4
}

if keydisplay.length != 1
    puts "<!-- keydisplay #{keydisplay.map { |i| i.to_s(16) }.join(',')} -->"
else
    puts "<global-address name='keydisplay' value='0x#{'%08x' % keydisplay[0]}'/>"
end
