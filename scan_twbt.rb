require 'metasm'

$: << File.dirname(__FILE__)
require 'osx_scanxrefs'

binpath = ARGV.shift
vtoff = ARGV.shift
vtoff = Integer(vtoff) if vtoff
abort 'usage: ruby scan_twbt.rb DwarfFortress.exe 0x121212' unless binpath and vtoff

ENV['METASM_NODECODE_RELOCS'] = '1'
dasm = Metasm::AutoExe.decode_file(binpath).disassembler

$ptrsz = dasm.cpu.size / 8

# statically accessible code
dasm.program.disassemble_fast_deep

# code called from viewscreen_dwarfmodest::render
render = dasm.decode_dword(vtoff + 2 * $ptrsz)
dasm.disassemble_fast_deep(render)

$is_windows = dasm.program.shortname == 'coff'
$is_linux = dasm.program.shortname == 'elf'
$is_osx = dasm.program.shortname == 'macho'

def find_string(dasm, str)
    addrs = dasm.pattern_scan(str)
    abort "Found #{addrs.length} instances of string: #{str.inspect}" if addrs.length != 1
    return addrs[0]
end

def find_functions_referencing(dasm, target)
    funcs = []
    scan_code_xrefs(dasm, target).each { |ref|
        next unless di = dasm.di_including(ref)
        funcs << dasm.find_function_start(di.address)
    }
    return funcs
end

def write_symbol(name, addrs)
    if addrs.length == 1
        puts "<global-address name='#{name}' value='0x#{'%08x' % addrs[0]}'/>"
    else
		puts "<!-- CONFLICT global-address name='#{name}' value='#{addrs.map { |a| '0x%x' % a }.join(' or ')}'/ -->"
    end
end

if $is_windows or $is_osx
    # 1. Windows & macOS only
    # Find a function that references string "Tileset not found".
    # The address of this function is A_LOAD_MULTI_PDIM.
    str = find_string(dasm, "Tileset not found\0")
    addrs = find_functions_referencing(dasm, str)
    write_symbol('twbt_load_multi_pdim', addrs)
end

# 2. Find a function that references string "Here we have".
# Rename it to render_map. Its address is A_RENDER_MAP.
str = find_string(dasm, "Here we have \0")
render_map = find_functions_referencing(dasm, str)
write_symbol('twbt_render_map', render_map)

# 3. Find a function that references string "Following".
# Rename it to dwarfmode_render_main.
str = find_string(dasm, "Following \0")
dwarfmode_render_main = find_functions_referencing(dasm, str)

# 4. Find a call of render_map from dwarfmode_render_main. The address of the call instruction is p_dwarfmode_render.

# 5. Open a list of references to render_map. There will be a function referencing it four times. The addresses of the four call instructions are p_advmode_render.

# 5+. At each of the four addresses there are either call, call (Windows) or call, mov, call / call, lea, call (Linux and macOS) instructions. Make sure that the total length of these instructions matches values specified for each address in p_advmode_render.

# 6. Go to any of the four call instructions from the last step. The address of a function called right after render_map is A_RENDER_UPDOWN (use function address, not a call instruction address).

# 7. Look for 0x30000000 in disassembly in the second half of the code, closer to the end.
#
# You need to find the following code:
# compare with 0x7
# jump ADDR
# compare with 0x2
# jump ANOTHER_ADDR
# compare with 0x30000000
# jump THE_SAME_ADDR
#
# Go to the address after the comparison with 0x30000000. Look for the first call instruction after that point, address of the called function is p_render_lower_levels. On Windows it may be a jmp instruction instead.

if $is_windows or $is_osx
    # 8. Windows & macOS only
    # Find references to SDL_GetTicks, look for a function that calls
    # SDL_GetTicks in its very beginning and then again after some time.
    # Go to its end, and look for the following code:
    #
    # call  SDL_SemPost
    # ...
    # call  SDL_SemPost
    # ...
    # call  SOME_ADDRESS
    # ...
    # call  ANOTHER_ADDRESS    <---- You need this instruction
    # ...
    # call  [rax+...]
    # ...
    # call  SDL_SemWait
    # ...
    # add   ..., 0x1 or inc ...
    # ...
    # call  SDL_SemPost
    #
    # Address of that call instruction above is p_display.
    #
    # p_display is not required on Linux. This may cause problems though, so better would be to build a special version of libgraphics.so with a call to renderer->display() removed.
end
