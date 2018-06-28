require 'open-uri'
require 'shellwords'

# run df-misc scripts when a new DF release is announced
# downloads the binaries and save helper xmls

# usage: cd dev/df-structures ; git pull <reset commit> ; ruby ../df-misc/newrelease.rb

struct_path = '.'
misc_path = File.dirname(__FILE__)
tmp_path = File.expand_path("~/tmp/")
base_url = 'http://www.bay12games.com/dwarves/'

if ARGV.empty?
puts "read bay12 homepage"
page = open(base_url).read

# <a href="df_34_10_win_s.zip">Windows (No Music)</a><a href="df_34_10_linux.tar.bz2">Linux</a>
lin_binary_url = page[/<a href="(.*?)">linux<\/a>/i, 1]
win_binary_url = page[/<a href="(.*?)">windows<\/a>/i, 1]
osx_binary_url = page[/<a href="(.*?)">mac<\/a>/i, 1]

version = win_binary_url[/df_(.*)_win\.zip/, 1]

puts "latest version: #{version}"
else
	version = ARGV.shift
	lin_binary_url = "df_#{version}_linux.zip"
	win_binary_url = "df_#{version}_win.zip"
	osx_binary_url = "df_#{version}_osx.zip"
end

[64, 32].each { |bits|
	if bits == 32
		version += '_32bits'
		lin_binary_url.sub!(/.tar.bz2$/, '32.tar.bz2') rescue nil
		win_binary_url.sub!(/.zip$/, '32.zip')
		osx_binary_url.sub!(/.tar.bz2$/, '32.tar.bz2')
	end

lin_tmp = File.join(tmp_path, "df_lin_#{version}")
if lin_binary_url and not File.directory?(lin_tmp)
	puts "dl linux #{lin_binary_url}"
	Dir.mkdir(lin_tmp)
	File.open(lin_tmp + '/' + lin_binary_url, 'w') { |fd| fd.write open(base_url + lin_binary_url).read } rescue nil
	puts "extracting"
	Dir.chdir(lin_tmp) { system 'tar', 'xf', lin_binary_url }
	Dir.entries(File.join(lin_tmp, 'df_linux')).each { |e| next if e == '.' or e == '..' ; File.rename(File.join(lin_tmp, 'df_linux', e), File.join(lin_tmp, e)) }
	Dir.rmdir(lin_tmp+'/df_linux')
end
lin_bin = File.join(lin_tmp, 'libs', 'Dwarf_Fortress')
lin_bin = nil if not File.file?(lin_bin)
lin_lib = File.join(lin_tmp, 'libs', 'libgraphics.so')
lin_lib = nil if not File.file?(lin_lib)

win_tmp = File.join(tmp_path, "df_win_#{version}")
if win_binary_url and not File.directory?(win_tmp)
	puts "dl windows #{win_binary_url}"
	Dir.mkdir(win_tmp)
	File.open(win_tmp + '/' + win_binary_url, 'w') { |fd| fd.write open(base_url + win_binary_url).read } rescue nil
	puts "extracting"
	Dir.chdir(win_tmp) { system 'unzip', '-q', win_binary_url }
end
win_bin = File.join(win_tmp, 'Dwarf Fortress.exe')
win_bin = nil if not File.file?(win_bin)

osx_tmp = File.join(tmp_path, "df_osx_#{version}")
if osx_binary_url and not File.directory?(osx_tmp)
	puts "dl osx #{osx_binary_url}"
	Dir.mkdir(osx_tmp)
	File.open(osx_tmp + '/' + osx_binary_url, 'w') { |fd| fd.write open(base_url + osx_binary_url).read } rescue nil
	puts "extracting"
	Dir.chdir(osx_tmp) { system 'tar', 'xf', osx_binary_url }
	Dir.entries(osx_tmp+'/df_osx').each { |e| next if e == '.' or e == '..' ; File.rename osx_tmp+'/df_osx/'+e, osx_tmp+'/'+e }
	Dir.rmdir(osx_tmp+'/df_osx')
end
osx_bin = File.join(osx_tmp, 'dwarfort.exe')
osx_bin = nil if not File.file?(osx_bin)


# TODO patch globals.xml directly
if lin_bin and not File.file?("lin_#{version}_globals.xml")
puts "lin_globals"
lin_globals = `ruby #{misc_path}/dump_df_globals.rb #{lin_bin.shellescape}`
File.open("lin_#{version}_globals.xml", 'w') { |fd| fd.puts lin_globals }
end

if win_bin and not File.file?("win_#{version}_globals.xml")
puts "win_globals"
win_globals = `ruby #{misc_path}/dump_df_globals.rb #{win_bin.shellescape}`
File.open("win_#{version}_globals.xml", 'w') { |fd| fd.puts win_globals }
end

if osx_bin and not File.file?("osx_#{version}_globals.xml")
puts "osx_globals"
osx_globals = `ruby #{misc_path}/dump_df_globals.rb #{osx_bin.shellescape}`
File.open("osx_#{version}_globals.xml", 'w') { |fd| fd.puts osx_globals }
end


if lin_bin and lin_lib and not File.file?("lin_#{version}_vtable.xml")
puts "lin_vtable"
lin_vtable = `ruby #{misc_path}/scan_vtable.rb #{lin_bin.shellescape} #{lin_lib.shellescape}`
File.open("lin_#{version}_vtable.xml", 'w') { |fd| fd.puts lin_vtable }
end

if win_bin and not File.file?("win_#{version}_vtable.xml")
puts "win_vtable"
win_vtable = `ruby #{misc_path}/scan_vtable.rb #{win_bin.shellescape}`
File.open("win_#{version}_vtable.xml", 'w') { |fd| fd.puts win_vtable }
end

if osx_bin and not File.file?("osx_#{version}_vtable.xml")
puts "osx_vtable"
osx_vtable = `ruby #{misc_path}/scan_vtable.rb #{osx_bin.shellescape}`
File.open("osx_#{version}_vtable.xml", 'w') { |fd| fd.puts osx_vtable }
end


if lin_bin and not File.file?("lin_#{version}_ctors.xml")
puts "lin_ctors"
lin_ctors = `ruby #{misc_path}/scan_ctors.rb #{lin_bin.shellescape}`
File.open("lin_#{version}_ctors.xml", 'w') { |fd| fd.puts lin_ctors }
end

if osx_bin and not File.file?("osx_#{version}_ctors.xml")
puts "osx_ctors"
osx_ctors = `ruby #{misc_path}/scan_ctors_osx.rb #{osx_bin.shellescape}`
File.open("osx_#{version}_ctors.xml", 'w') { |fd| fd.puts osx_ctors }
end


if win_bin and not File.file?("win_#{version}_keydisplay.xml")
puts "win_keydisplay"
win_keydisplay = `ruby #{misc_path}/scan_keydisplay.rb #{win_bin.shellescape}`
File.open("win_#{version}_keydisplay.xml", 'w') { |fd| fd.puts win_keydisplay }
end

if osx_bin and not File.file?("osx_#{version}_keydisplay.xml")
puts "osx_keydisplay"
osx_keydisplay = `ruby #{misc_path}/scan_keydisplay.rb #{osx_bin.shellescape}`
File.open("osx_#{version}_keydisplay.xml", 'w') { |fd| fd.puts osx_keydisplay }
end


if lin_bin and not File.file?("lin_#{version}_startdwarfcount.xml")
puts "lin_startdwarfcount"
sizeunit_lin = `perl get_sizeofunit.pl ../dfhack/library/include/df/codegen.out.xml linux #{bits}`
lin_startdwarfcount = `ruby #{misc_path}/scan_startdwarfcount.rb #{lin_bin.shellescape} #{sizeunit_lin}`
File.open("lin_#{version}_startdwarfcount.xml", 'w') { |fd| fd.puts lin_startdwarfcount }
end

if win_bin and not File.file?("win_#{version}_startdwarfcount.xml")
puts "win_startdwarfcount"
sizeunit_win = `perl get_sizeofunit.pl ../dfhack/library/include/df/codegen.out.xml windows #{bits}`
win_startdwarfcount = `ruby #{misc_path}/scan_startdwarfcount.rb #{win_bin.shellescape} #{sizeunit_win}`
File.open("win_#{version}_startdwarfcount.xml", 'w') { |fd| fd.puts win_startdwarfcount }
end

if osx_bin and not File.file?("osx_#{version}_startdwarfcount.xml")
puts "osx_startdwarfcount"
sizeunit_lin ||= `perl get_sizeofunit.pl ../dfhack/library/include/df/codegen.out.xml linux #{bits}`
osx_startdwarfcount = `ruby #{misc_path}/scan_startdwarfcount.rb #{osx_bin.shellescape} #{sizeunit_lin}`
File.open("osx_#{version}_startdwarfcount.xml", 'w') { |fd| fd.puts osx_startdwarfcount }
end


if win_bin and not File.file?(win_bin + '.bak')
puts "win_patchmalloc"
system 'ruby', misc_path+'/df_patchmalloc.rb', win_bin
end

puts "done, archives in #{tmp_path}/df_{lin,win,osx}_#{version}"
}
