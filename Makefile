default: ruby.plug.so

tthread.o: ../library/depends/tthread/tinythread.cpp
	gcc -fPIC -O2 -I ../library/depends/tthread/ -c -o $@ $<

ruby.plug.so: tthread.o ruby.cpp
	gcc -W -Wall -Wno-unused-parameter -lruby1.8 -std=c++0x -fPIC -O2 -DLINUX_BUILD -I ../library/include/ -I ../library/depends/tthread/ -I /usr/lib/ruby/1.8/i486-linux/ -shared -o $@ $^
	cp $@ ruby.rb ../../df_linux_31_25/hack/plugins/

%.plug.so: %.cpp
	gcc -W -Wall -Wno-unused-parameter -std=c++0x -fPIC -O2 -DLINUX_BUILD -I ../library/include/ -I /usr/lib/ruby/1.8/i486-linux/ -shared -o $@ $^
	cp $@ ../../df_linux_31_25/hack/plugins/
