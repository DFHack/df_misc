# create an idc script from globals.csv

# converts a global.csv file into an ida script to define the address of globals
# to be used with codegen_c_hdr.pl

def parse_line(l)
	el = l.split(',')
	return if el[1] != '"0"'	# only top-level names
	return if el[2][1, 2] != '0x'
	addr = el[2][1...-1].to_i(16)
	return if el[3].include?('.')	# skip bitfields
	size = el[3][1...-1].to_i(16)
	# return if size <= 4	# keep only (big) structures
	name = el[5][1...-1]
	'MakeName(0x%08X, "%s");' % [addr, '_' + name.gsub(/[^\w]/, '_')]
end

if defined?($script_args)
	# ran as a dfhack ruby script: arg = full path to globals.csv, output in globals.csv.idc
	csvname = $script_args.first
	outname = csvname + '.idc'
	File.open(csvname, 'rb') { |rfd|
		File.open(outname, 'wb') { |wfd|
			rfd.each_line { |l|
				if ol = parse_line(l)
					wfd.puts(ol)
				end
			}
		}
	}
	puts "saved #{outname}"
else
	ARGF.each_line { |l|
		if ol = parse_line(l)
			puts ol
		end
	}
end
