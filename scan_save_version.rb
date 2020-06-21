require 'metasm'

binpath = ARGV.shift
abort "usage: scan_save_version.rb /path/to/df_exe" if not binpath

ENV['METASM_NODECODE_RELOCS'] = '1'
dasm = Metasm::AutoExe.decode_file(binpath).disassembler

MAGIC1 = "\x78\x56\x34\x12"
MAGIC2 = "\x21\x43\x65\x87"
MAGIC1.force_encoding('BINARY')
MAGIC2.force_encoding('BINARY')
if dasm.cpu.size == 64
    $ptrsz = 8
    MAGIC = MAGIC1 + MAGIC1 + MAGIC2 + MAGIC2
else
    $ptrsz = 4
    MAGIC = MAGIC1 + MAGIC2
end

off = dasm.pattern_scan(MAGIC).first

if not off
    abort "Cannot find magic bytes"
end

off += $ptrsz + $ptrsz

while true
    ptr_str = dasm.decode_dword(off)
    off += $ptrsz
    ptr_var = dasm.decode_dword(off)
    off += $ptrsz
    if ptr_str == 0
        abort "Cannot find 'version' global"
    end
    name = dasm.decode_strz(ptr_str)
    if name == 'version'
        version_addr = ptr_var
        break
    end
end

unless dasm.program.shortname == "elf" and $ptrsz == 8
    abort "Currently this script only supports 64-bit Linux"
end

beginroutine = dasm.program.symbols.find { |s| s.name == '_Z12beginroutinev' }
if not beginroutine
    abort "Could not find beginroutine symbol"
end

dasm.disassemble_fast(beginroutine.value)
dasm.block_at(beginroutine.value).list.each { |op|
    next unless op.opcode.name == 'mov'
    dasm.cpu.get_xrefs_w(dasm, op).each { |w|
        next unless w[1] == 4
        next unless w[0].eql? Metasm::Expression[version_addr]

        puts Metasm::Expression[op.instruction.args[1]].reduce
    }
}
