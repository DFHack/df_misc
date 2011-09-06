default: ruby.plug.so

tthread.o: ../library/depends/tthread/tinythread.cpp
	gcc -fPIC -O2 -I ../library/depends/tthread/ -c -o $@ $<

%.plug.so: tthread.o %.cpp
	gcc -lruby1.8 -std=c++0x -fPIC -O2 -DLINUX_BUILD -I ../library/include/ -I ../library/depends/tthread/ -I /usr/lib/ruby/1.8/i486-linux/ -shared -o $@ $^
	cp $@ ../../df_linux_31_25/hack/plugins/
