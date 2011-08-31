default: ruby.plug.so

%.plug.so: %.cpp
	g++ -lruby1.8 -std=c++0x -fPIC -DLINUX_BUILD -I ../library/include/ -I /usr/lib/ruby/1.8/i486-linux/ -shared -o $@ $<
	cp $@ ../../df_linux_31_25/hack/plugins/
