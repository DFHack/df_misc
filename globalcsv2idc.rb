#!/usr/bin/ruby

# convert a global.csv file into an ida script to define the address of globals
# combine with codegen_c_hdr

ARGF.each_line { |l|
	el = l.split(',')
	next if el[1] != '"0"'	# only top-level names
	next if el[2][1, 2] != '0x'
	addr = el[2][1...-1].to_i(16)
	next if el[3].include?('.')	# skip bitfields
	size = el[3][1...-1].to_i(16)
	# next if size <= 4	# keep only (big) structures
	name = el[5][1...-1]
	puts 'MakeName(0x%08X, "%s");' % [addr, '_' + name.gsub(/[^\w]/, '_')]
}
