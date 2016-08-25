require 'metasm'

$: << File.dirname(__FILE__)
require 'osx_scanxrefs'

# metasm script to find standing orders offsets
# tested in 34.11 win/linux, fails on osx

# code has pattern:
#  mov moo, a_current_zone_orders
#  ...
#  cmp byte [zone_drinking], 1
#  jnz moo
#  mov eax, a_zoneonlydrinking

# disable decoding of relocs, takes a while for win binary ASLR aware
ENV['METASM_NODECODE_RELOCS'] = '1'

puts 'read file' if $VERBOSE
binpath = ARGV.shift || 'Dwarf Fortress.exe'
dasm = Metasm::AutoExe.decode_file(binpath).disassembler

puts 'scan headers' if $VERBOSE

# strings must start exactly as found in the binary (may be shortened)
list = {
    # standing order subscreen
    'Current Standing Orders' => {
        # string in binary => name of global ('standing_orders_' prefix)
        ': Announce all job cancellations' => 'job_cancel_announce',
        ' Gather Animals' => 'gather_animals',
        ' Gather Food' => 'gather_food',
        ' Gather Furniture' => 'gather_furniture',
        ' Gather Bodies' => 'gather_bodies',
        ' Gather Minerals' => 'gather_minerals',
        ' Gather Wood' => 'gather_wood',
        ' All Harvest' => 'farmer_harvest',
        ': Mix Food' => 'mix_food',
    },
    'Current Refuse Orders' => {
        ' Gather Refuse' => 'gather_refuse',
        '   From Outside' => 'gather_refuse_outside',    # gather From Outside
        ': Gather Vermin Remains' => 'gather_vermin_remains',
        ' Dump Corpses' => 'dump_corpses',
        ' Dump Skulls' => 'dump_skulls',
        ' Dump Bones' => 'dump_bones',
        ' Dump Shells' => 'dump_shells',
        ' Dump Skins' => 'dump_skins',
        ' Dump Hair/Wool' => 'dump_hair',
        ' Dump Other' => 'dump_other',
    },

    'Current Forbid Orders' => {
        ': Forbid used ammunition' => 'forbid_used_ammo',
        ': Forbid your dead' => 'forbid_own_dead',
        ': Forbid your death items' => 'forbid_own_dead_items',
        ': Forbid other non-hunted' => 'forbid_other_nohunt',
        ': Forbid other death items' => 'forbid_other_dead_items',
    },

    'Current Workshop Orders' => {
        ': Auto Loom All Thread' => 'auto_loom',
        ': Use Dyed Cloth' => 'use_dyed_cloth',
        ': Auto Collect Webs' => 'auto_collect_webs',
        ': Auto Slaughter' => 'auto_slaughter',
        ': Auto Butcher' => 'auto_butcher',
        ': Auto Fishery' => 'auto_fishery',
        ': Auto Kitchen' => 'auto_kitchen',
        ': Auto Tan' => 'auto_tan',
        ': Auto Kiln' => 'auto_kiln',
        ': Auto Smelter' => 'auto_smelter',
        ': Auto Other' => 'auto_other',
    },
   
    'Current Zone Orders' => {
        ': Zone-Only Drinking' => 'zoneonly_drink',
        ': Zone-Only Fishing' => 'zoneonly_fish',
    },
}

list.each { |header, strings|
    puts "scan #{header.inspect}" if $VERBOSE
    hdr_addr = dasm.pattern_scan(header)[0]
    if not hdr_addr
        puts "cant find #{header.inspect}"
        next
    end

    codes = scan_code_xrefs(dasm, hdr_addr, 0x40000)
    code = codes[0]
    if not code
        puts "cant find xref to #{header.inspect}"
        next
    end
    puts "code at %x" % code if $VERBOSE
    if defined? @osx_xref_getip
        puts "getip at %x" % @osx_xref_getip[0] if $VERBOSE
        dasm.disassemble_fast_deep(@osx_xref_getip[0])
    else
        dasm.disassemble_fast(code+4)
    end

    xml = []
    strings.each { |str, global|
        nextaddr = dasm.pattern_scan(str, hdr_addr, 0x10000)[0]
        if not nextaddr
            puts "cant find string #{header.inspect} #{str.inspect} after %x" % hdr_addr
            next
        end
        str_addr = nextaddr

        xr = dasm.pattern_scan([str_addr].pack('L'), code, 0x10000)[0]
        if not xr
            puts "no xref to #{header.inspect} #{str.inspect}"
            next
        end

        begin

        # we are now at the 'mov eax, a_zoneonlydrinking'
        xr_block = dasm.block_including(xr)
        # move up to the 'jz' block
        cmp = mrm = nil
        while xr_block.to_normal.to_a.length != 2 or not cmp = xr_block.list.reverse.find { |op|
            mrm = op.instruction.args.grep(Metasm::Ia32::ModRM)[0]
        } or mrm.sz != 8
            from = (xr_block.from_subfuncret || xr_block.from_normal)[0]
            xr_block = dasm.block_at(from)
        end
        # find the condition
        #puts xr_block.list if $VERBOSE
        addr = dasm.backtrace(mrm.symbolic.target, cmp.address)[0].reduce

        xml << "<global-address name='standing_orders_#{global}' value='0x#{'%08x' % addr}'/>"

        rescue
            puts "failed for #{str}: #$!, #{$!.message}"
        end

    }
    puts xml.sort_by { |s| s[/value=.*/] }
}
