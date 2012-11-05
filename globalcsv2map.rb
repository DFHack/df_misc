#!/usr/bin/ruby

# convert a global.csv file into a .map (linux system.map style)

seen = {}
ARGF.each_line { |l|
	el = l.split(',')
	addr = el[2][1...-1].to_i(16)
	next if addr == 0
	next if el[3].include?('.')	# skip bitfields
	name = el[5][1...-1]
	if !seen[addr]
		seen[addr] = true
		puts "%08x d %s" % [addr, name.gsub(/[^\w]/, '_')]
	end

	if el[4] == '"stl-vector"'
		puts "%08x d %s" % [addr+4, name.gsub(/[^\w]/, '_')+'_endvec']
	end
}
