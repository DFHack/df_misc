require 'metasm'

class MemSnap
    attr_accessor :dbg, :offlist
    def initialize(id)
        @dbg = Metasm::OS.current.find_process(id).debugger
        @dbg.continue while (@dbg.check_target ; @dbg.state == :stopped)
        @file = {}
    end

    def snap
        puts "snap..."
        if @dbg.state == :running and @dbg.shortname == 'lindbg'
            broke = true
            @dbg.tid = @dbg.pid
            @dbg.break
            @dbg.check_target until @dbg.tid == @dbg.pid and @dbg.state == :stopped
        end
        snap = {}
        @dbg.mappings.each { |base, len, prot, name|
            next if name !~ /ortress|heap/
            snap[base] = @dbg.memory.get_page(base, len)
            @file[base] = name
        }
        @dbg.check_target
        @dbg.each_tid { @dbg.continue } if broke
        puts "done"
        snap
    end

    def snap_cmp(s1, s2, &b)
        (s1.keys | s2.keys).sort.each { |k|
            v1 = s1[k]
            v2 = s2[k]
            if not v2
                if not v1
                    puts "wtf #{'%x' % k}"
                    next
                end
                puts "rm  mapping at #{'%x' % k} #{'%x' % v1.length}"
                next
            elsif not v1
                puts "new mapping at #{'%x' % k} #{'%x' % v2.length}"
                next
            elsif v1.length != v2.length
                puts "new mapsize at #{'%x' % k} #{'%x' % v1.length} -> #{'%x' % v2.length}"
                v1 = v1[0, v2.length]
                v2 = v2[0, v1.length]
            end

            if offlist
                # TODO only check addresses in the list
            else
                next if v1 == v2
                puts "diff at #{'%x' % k} #{@file[k]}"
                bindiff(k, v1, v2, &b)
            end
        }
    end

    class BinDiff < Metasm::DynLdr
        new_func_c <<EOF
int bindiffasm(char *p1 __attribute__((register(esi))), char *p2 __attribute__((register(edi))), int len __attribute__((register(ecx))));
int bindiff(char *p1, char *p2, int start, int len) {
    int lenleft = bindiffasm(p1+start, p2+start, len-start);
    return len-lenleft-1;
}

asm {
bindiffasm:
repz cmpsb
mov eax, ecx
ret
}
EOF
    end
    def bindiff(addr, v1, v2)
        off = -1
        len = v1.length
        while off+1 < len
            off = BinDiff.bindiff(v1, v2, off+1, len)
            yield(addr+off, v1[off], v2[off]) if off != len
        end
    end
end

if $0 == __FILE__
    s = MemSnap.new(ARGV.shift)
    s1 = s.snap
    ignore = {}
    while (puts "(i)gnore diffs, (q)uit, show (d)iffs" ; l = $stdin.gets)
        case l.chomp.downcase
        when 'i'
            s2 = s.snap
            s.snap_cmp(s1, s2) { |a, c1, c2| puts "ignore %08x" % a unless ignore[a] ; ignore[a] = true }
        when 'q'; break
        # TODO option to log addresses with changed values in s.offlist
        else
            s2 = s.snap
            s.snap_cmp(s1, s2) { |a, c1, c2| puts "%08x  %02x -> %02x" % [a, c1, c2] unless ignore[a] }
        end
    end
    s.dbg.detach
    s.dbg.run_forever
end
