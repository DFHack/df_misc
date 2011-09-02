module DFHack

puts "starting"

suspend {
	curs = cursor()
	puts "cursor pos: #{curs.x} #{curs.y} #{curs.z}"
	m = Map.new
	puts "mapnew"
	if b = m.block(curs.x/16, curs.y/16, curs.z)
		puts "got block"
		puts "design = %x" %  b.designation(curs.x, curs.y)
		# dig
		b.designation_set(curs.x, curs.y, b.designation(curs.x, curs.y) | 0x10)
	else
		puts "no block here"
	end
}

puts "done"

end

