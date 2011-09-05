module DFHack

class Map
	DESIGNATION = { :none => 0, :dig => 1, :updown => 2, :channel => 3, :ramp => 4, :down => 5, :up => 6 }

	class Block
		def dig(x, y, type=:dig)
			old = designation(x, y)
			old &= ~0x70
			old |= (DESIGNATION[type] || type) << 4
			designation_set(x, y, old)
			self.flags |= 1
		end
	end

	def dig(x, y, z, type=:dig)
		if b = block(x/16, y/16, z)
			b.dig(x, y, type)
		end
	end
end

puts "starting"

suspend {

	curs = cursor()
	puts "cursor pos: #{curs.x} #{curs.y} #{curs.z}"

	m = Map.new

	if b = m.block(curs.x/16, curs.y/16, curs.z)
		puts "designation = %x" %  b.designation(curs.x, curs.y)
		b.dig(curs.x, curs.y)
		b.flags |= 0x1	# mark dig pending

		m.veins(curs.x/16, curs.y/16, curs.z).each { |v|
			puts "blockvein #{v[0]} #{v[1].unpack('v*').map { |s| '%04x' % s }.join(' ')}"
		}
	else
		puts "no block here"
	end
}

puts "done"

end
