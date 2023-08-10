module DFHack
class Coord
    attr_accessor :x, :y, :z
    def initialize(x, y, z)
        @x = x; @y = y; @z = z
    end

    def ==(o)
        o.class == self.class and o.x == self.x and o.y == self.y and o.z == self.z
    end

    def ===(o)
        o == self or (o.respond_to?(:pos) and o.pos == self)
    end

    def to_s
        "x=#@x, y=#@y, z=#@z"
    end

    def inspect
        "#<Coord #{@x}, #{@y}, #{@z}>"
    end
end


class Map
    class Block
        DESIGNATION = { :none => 0, :dig => 1, :updown => 2, :channel => 3, :ramp => 4, :down => 5, :up => 6 }
        HIDDEN = 0x200

        def dig(x=DFHack.cursor, y=nil, type=:dig)
            if x.kind_of? Coord
                type = y if y
                x, y = x.x, x.y
            end

            old = designation(x, y)
            old &= ~0x70
            old |= (DESIGNATION[type] || type) << 4
            designation_set(x, y, old)
            self.flags |= 1
        end

        def reveal
            self.designationmap = self.designationmap.unpack('v*').map { |t| t & ~HIDDEN }.pack('v*')
        end

        def matname(idx)
            @@matino ||= DFHack.mat_inorganic
            if idx >= 0 and m = @@matino[idx]
                m.name
            end
        end

        def basemat(x=DFHack.cursor, y=nil)
            if x.kind_of? Coord
                x, y = x.x, x.y
            end

            @@map_geology ||= Map.new.read_geology
            x &= 15
            y &= 15
            des = designation(x, y)
            geolayer_idx = (des >> 10) & 0xf
            biome_idx    = (des >> 17) & 0xf
            idx = @@map_geology[region_offset(biome_idx)][geolayer_idx]
            matname(idx)
        end

        def veinmat(x=DFHack.cursor, y=nil)
            if x.kind_of? Coord
                x, y = x.x, x.y
            end

            x &= 15
            y &= 15
            # the right one is the last
            mat = nil
            veins.each { |v|
                if v.assignment.unpack('v*')[y] & (1 << x) != 0
                    mat = matname(v.type)
                end
            }
            mat
        end

        def dumpveins(pos=DFHack.cursor)
            veins.each { |v|
                DFHack.puts "vein #{v.type}", v.assignment.unpack('v*').map { |v| (' %016b' % v).reverse }
            }
        end
    end

    if !instance_methods.map { |im| im.to_sym }.include? :oldblock
    alias oldblock block
    def block(x=DFHack.cursor, y=nil, z=nil)
        if x.kind_of? Coord
            x, y, z = x.x, x.y, x.z
        end
        oldblock(x, y, z)
    end
    end

    def dig(x, y, z, type=:dig)
        if b = block(x, y, z)
            b.dig(x, y, type)
        end
    end
end

class Creature
    def dead?
        flags1 & 2 == 2
    end

    def alive?
        !dead?
    end

    def matcre
        @@matcre ||= DFHack.mat_creatures
    end

    def racerawname
        matcre[race].name
    end

    def casterawname
        matcre[race].castename(sex)
    end
end

class << self
    def cursor=(c)
        case c
        when Array; x, y, z = c
        when Coord; x, y, z = c.x, c.y, c.z
        else; raise 'bad cursor coords'
        end
        cursor_set(x, y, z)
    end

    def view=(c)
        case c
        when Array; x, y, z = c
        when Coord; x, y, z = c.x, c.y, c.z
        else; raise 'bad cursor coords'
        end
        view_set(x, y, z)
    end

    def suspend
        if block_given?
            begin
                suspendraw
                yield
            ensure
                resume
            end
        else
            suspendraw
        end
    end

    def puts(*a)
        a.flatten.each { |l|
            print_str(l.to_s.chomp + "\n")
        }
    end

    def puts_err(*a)
        a.flatten.each { |l|
            print_err(l.to_s.chomp + "\n")
        }
    end

    def creature_by_id(id)
        creatures.find { |c| c.id == id }
    end

    def test
        puts "starting"

        suspend {

            c = cursor()
            puts "cursor pos: #{c}"

            m = Map.new

            if b = m.block(c)
                puts "designation = %x" %  b.designation(c.x, c.y)
                b.dig(c, :updown)
                b.reveal

                b.dumpveins
            else
                puts "no block here"
            end
        }

        puts "done"
    end

    # catsplosion !
    def catsplosion(racecheck=/^CAT$/, onlyfemales=true)
        suspend {
            creatures.each { |c|
                if c.alive? and c.racerawname =~ racecheck and (!onlyfemales or c.casterawname == 'FEMALE')
                    if c.pregnancy_timer > 0
                        c.pregnancy_timer = rand(100)

                        puts "catsplosed #{c.id} #{c.racerawname}"
                    end
                end
            }
        }
    end
end

end

# load user-specified startup file
load 'ruby_custom.rb' if File.exist?('ruby_custom.rb')
