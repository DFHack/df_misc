require 'metasm'

# metasm script to dump the global table added by Toady for 0.44.1

# the table begins by dd 0x12345678 0x87654321 (32-bit) or dd 0x12345678 0x12345678 0x87654321 0x87654321 (64-bit)
# then a succession of [<ptr to string with global name> <ptr to global variable>]

dump_fmt = 'xml'
dump_fmt = 'idc' if ARGV.delete '--idc'

Dfhack_names = {
	"point" => "selection_rect",
	"menuposition" => "ui_menu_width",
	"itemmade" => "created_item_type",
	"itemmade_subtype" => "created_item_subtype",
	"itemmade_subcat1" => "created_item_mattype",
	"itemmade_subcat2" => "created_item_matindex",
	"itemmade_number" => "created_item_count",
	"mainview" => "map_renderer",
	"title2" => "title_spaced",
	"event_flow" => "flows",
	"plot_event" => "timed_events",
	"plotinfo" => "ui",
	"adventure" => "ui_advmode",
	"buildreq" => "ui_build_selector",
	"buildjob_type" => "ui_building_assign_type",
	"buildjob_selected" => "ui_building_assign_is_marked",
	"buildjob_unit" => "ui_building_assign_units",
	"buildjob_item" => "ui_building_assign_items",
	"looklist" => "ui_look_list",
	"game" => "ui_sidebar_menus",
	"year" => "cur_year",
	"season_count" => "cur_year_tick",
	"precise_phase" => "cur_year_tick_advmode",
	"season_timer" => "cur_season_tick",
	"season" => "cur_season",
	"cur_weather" => "current_weather",
	"assignbuildingjobs" => "process_jobs",
	"assigndesjobs" => "process_dig",
	"paused" => "pause_state",
	"modeunit" => "ui_selected_unit",
	"modeview" => "ui_unit_view_mode",
	"modepage" => "ui_look_cursor",
	"modeitem" => "ui_building_item_cursor",
	"addingtask" => "ui_workshop_in_add",
	"modejob" => "ui_workshop_job_cursor",
	"buildjob_assignroom" => "ui_building_in_assign",
	"buildjob_sizeroom" => "ui_building_in_resize",
	"addingtask_sub" => "ui_lever_target_type",
	"buildjob_sizerad" => "ui_building_resize_radius",
	"scrollx" => "window_x",
	"scrolly" => "window_y",
	"scrollz" => "window_z",
	"DEBUG_CONTINUOUS" => "debug_nopause",
	"DEBUG_NOMOOD" => "debug_nomoods",
	"DEBUG_SAFEDWARVES" => "debug_combat",
	"DEBUG_NOANIMALS" => "debug_wildlife",
	"DEBUG_NOTHIRST" => "debug_nodrink",
	"DEBUG_NOHUNGER" => "debug_noeat",
	"DEBUG_NOSLEEP" => "debug_nosleep",
	"DEBUG_VISIBLEAMBUSHERS" => "debug_showambush",
	"DEBUG_QUICKMODE_MINING" => "debug_fastmining",
	"DEBUG_NEVERBERSERK" => "debug_noberserk",
	"DEBUG_MEGAFAST" => "debug_turbospeed",
	"gamemode_cansave" => "save_on_exit",
	"standingorder_butcher" => "standing_orders_auto_butcher",
	"standingorder_collect_web" => "standing_orders_auto_collect_webs",
	"standingorder_fishery" => "standing_orders_auto_fishery",
	"standingorder_kiln" => "standing_orders_auto_kiln",
	"standingorder_kitchen" => "standing_orders_auto_kitchen",
	"standingorder_loom" => "standing_orders_auto_loom",
	"standingorder_other" => "standing_orders_auto_other",
	"standingorder_slaughter" => "standing_orders_auto_slaughter",
	"standingorder_smelter" => "standing_orders_auto_smelter",
	"standingorder_tan" => "standing_orders_auto_tan",
	"standingorder_gatherrefuse_chasm_bones" => "standing_orders_dump_bones",
	"standingorder_gatherrefuse_chasm_corpses" => "standing_orders_dump_corpses",
	"standingorder_gatherrefuse_chasm_strand_tissue" => "standing_orders_dump_hair",
	"standingorder_gatherrefuse_chasm_othernonmetal" => "standing_orders_dump_other",
	"standingorder_gatherrefuse_chasm_shell" => "standing_orders_dump_shells",
	"standingorder_gatherrefuse_chasm_skins" => "standing_orders_dump_skins",
	"standingorder_gatherrefuse_chasm_skulls" => "standing_orders_dump_skulls",
	"standingorder_allharvest" => "standing_orders_farmer_harvest",
	"standingorder_autoforbid_other_items" => "standing_orders_forbid_other_dead_items",
	"standingorder_autoforbid_other_corpse" => "standing_orders_forbid_other_nohunt",
	"standingorder_autoforbid_your_corpse" => "standing_orders_forbid_own_dead",
	"standingorder_autoforbid_your_items" => "standing_orders_forbid_own_dead_items",
	"standingorder_autoforbid_projectile" => "standing_orders_forbid_used_ammo",
	"standingorder_gatheranimals" => "standing_orders_gather_animals",
	"standingorder_gatherbodies" => "standing_orders_gather_bodies",
	"standingorder_gatherfood" => "standing_orders_gather_food",
	"standingorder_gatherfurniture" => "standing_orders_gather_furniture",
	"standingorder_gatherstone" => "standing_orders_gather_minerals",
	"standingorder_gatherrefuse" => "standing_orders_gather_refuse",
	"standingorder_gatherrefuse_outside" => "standing_orders_gather_refuse_outside",
	"standingorder_gatherrefuse_outside_vermin" => "standing_orders_gather_vermin_remains",
	"standingorder_gatherwood" => "standing_orders_gather_wood",
	"standingorder_mixfoods" => "standing_orders_mix_food",
	"standingorder_dyed_clothes" => "standing_orders_use_dyed_cloth",
	"standingorder_zone_drinking" => "standing_orders_zoneonly_drink",
	"standingorder_zone_fishing" => "standing_orders_zoneonly_fish",
	"option_exceptions" => "standing_orders_job_cancel_announce",
	"next_art_imagechunk_global_id" => "art_image_chunk_next_id",
	"next_civ_global_id" => "entity_next_id",
	"next_histeventcol_global_id" => "hist_event_collection_next_id",
	"next_histevent_global_id" => "hist_event_next_id",
	"next_histfig_global_id" => "hist_figure_next_id",
	"next_nem_global_id" => "nemesis_next_id",
	"next_unitchunk_global_id" => "unit_chunk_next_id",
}

Dfhack_noname = {
	'jobvalue' => true,
	'jobvalue_setter' => true,
	'linelim' => true,
	'line' => true,
	'linechar' => true,
	'cur_rain' => true,
	'cur_snow' => true,
	'cur_rain_counter' => true,
	'cur_snow_counter' => true,
	'weathertimer' => true,
	'modeseason' => true,
	'selectingtaskobject' => true,
	'buildjob_mastering' => true,
	'buildjob_give_to' => true,
	'buildjob_popback' => true,
	'buildjob_building' => true,
	'buildjob_flowx' => true,
	'buildjob_flowy' => true,
	'buildjob_flowz' => true,
	'buildjob_item1' => true,
	'squadcount' => true,
	'modestation' => true,
	'unitprintstack' => true,
	'unitprintstack_cur' => true,
	'unitprintstack_start' => true,
	'unitprintstack_clear' => true,
	'olookx' => true,
	'olooky' => true,
	'olookz' => true,
	'oscrollx' => true,
	'oscrolly' => true,
	'oscrollz' => true,
	'page' => true,
	'dunginv_relitem' => true,
	'dunginv' => true,
	'dunginv_inv' => true,
	'dunginv_depth' => true,
	'dunginv_flag' => true,
	'dunginv_index' => true,
	'throwitem' => true,
	'dung_target' => true,
	'dung_targlist' => true,
	'interactitem' => true,
	'interactinvslot' => true,
	'dung_attackmode' => true,
	'dung_dodgemode' => true,
	'dung_chargedefendmode' => true,
	'dung_swimmode' => true,
	'handleannounce' => true,
	'preserveannounce' => true,
	'updatelightstate' => true,
	'dung_buildinginteract' => true,
	'soul_next_id' => true,
	'task_next_id' => true,
	'manucomp' => true,
	'manucomp2' => true,
	'filecomp_buffer' => true,
	'filecomp_buffer2' => true,
	'filecomp_buffer_aux' => true,
	'filecomp_buffer2_aux' => true,
	'DEBUG_SHOW_RIVER' => true,
	'DEBUG_FASTCAVEIN' => true,
	'DEBUG_ALWAYSHAPPY' => true,
	'DEBUG_DISABLEHUMANCARAVAN' => true,
	'DEBUG_GAMELOG' => true,
	'mt_index' => true,
	'mt_cur_buffer' => true,
	'mt_virtual_buffer' => true,
	'mt_buffer' => true,
	'mt_virtual_seed_type' => true,
}

def dfhack_names(n)
	if dn = Dfhack_names[n]
		return dn
	elsif Dfhack_noname[n]
	else
		case n
		when /^index[12]_\d+$/
			# discard
		when /^next_(.*)_global_id/
			$1 + '_next_id'
		#when /^standingorder/
		else
			n
		end
	end
end

ENV['METASM_NODECODE_RELOCS'] = '1'
dump_raw = true if ARGV.delete '--raw'
binpath = ARGV.shift || 'Dwarf Fortress.exe'
dasm = Metasm::AutoExe.decode_file(binpath).disassembler
if dasm.cpu.size == 64
	bits = 64
else
	bits = 32
end

MAGIC1 = "\x78\x56\x34\x12"
MAGIC2 = "\x21\x43\x65\x87"
MAGIC1.force_encoding('BINARY') rescue nil
MAGIC2.force_encoding('BINARY') rescue nil
table_start = dasm.pattern_scan(MAGIC1).find { |off|
	dasm.read_raw_data(off, 8) == MAGIC1 + MAGIC2 or
	dasm.read_raw_data(off, 16) == MAGIC1 + MAGIC1 + MAGIC2 + MAGIC2
}

if not table_start
	abort "Cannot find magic bytes"
end

$stderr.puts "Global table starts at #{Metasm::Expression[table_start]}"

off = table_start + 2*bits/8
out = []
while true
	ptr_str = dasm.decode_dword(off)
	off += bits/8
	ptr_var = dasm.decode_dword(off)
	off += bits/8
	break if ptr_str == 0
	name = dasm.decode_strz(ptr_str)
	name = dfhack_names(name) if not dump_raw
	next if not name

	case dump_fmt
	when 'xml'
		out << "<global-address name='#{name}' value='0x#{'%08x' % ptr_var}'/>"
	when 'idc'
		out << ('MakeName(0x%08X, "%s");' % [ptr_var, '_' + name.gsub(/[^\w]/, '_')])
	end
end

puts out

