#!/usr/bin/ruby

# convert a global.csv file into a .map (linux system.map style)

ARGF.each_line { |l|
	el = l.split(',')
	addr = el[2][1...-1]
	name = el[5][1...-1]
	puts "%08x d %s" % [addr.to_i(16), name.gsub(/[^\w]/, '_')]
}
