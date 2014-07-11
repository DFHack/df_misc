require 'open-uri'
require 'shellwords'

# run df-misc scripts when a new DF release is announced
# downloads the binaries and save helper xmls

# usage: cd dev/df-structures ; git pull <reset commit> ; ruby ../df-misc/newrelease.rb

struct_path = '.'
misc_path = File.dirname(__FILE__)
tmp_path = File.expand_path("~/tmp/")
base_url = 'http://www.bay12games.com/dwarves/'

puts "read bay12 homepage"
page = open(base_url).read

# <a href="df_34_10_win_s.zip">Windows (No Music)</a><a href="df_34_10_linux.tar.bz2">Linux</a>
lin_binary_url = page[/<a href="(.*?)">linux<\/a>/i, 1]
win_binary_url = page[/<a href="(.*?)">windows \(no music\)<\/a>/i, 1]
osx_binary_url = page[/<a href="(.*?)">mac \(intel\)<\/a>/i, 1]

version = lin_binary_url[/df_(.*)_linux\.tar\.bz2/, 1]

puts "latest version: #{version}"

lin_tmp = File.join(tmp_path, "df_lin_#{version}")
if not File.directory?(lin_tmp)
	puts "dl linux #{lin_binary_url}"
	Dir.mkdir(lin_tmp)
	File.open(lin_tmp + '/' + lin_binary_url, 'w') { |fd| fd.write open(base_url + lin_binary_url).read }
	puts "extracting"
	Dir.chdir(lin_tmp) { system 'tar', 'xf', lin_binary_url }
	Dir.entries(lin_tmp+'/df_linux').each { |e| next if e == '.' or e == '..' ; File.rename lin_tmp+'/df_linux/'+e, lin_tmp+'/'+e }
	Dir.rmdir(lin_tmp+'/df_linux')
end
lin_bin = File.join(lin_tmp, 'libs', 'Dwarf_Fortress')

win_tmp = File.join(tmp_path, "df_win_#{version}")
if not File.directory?(win_tmp)
	puts "dl windows #{win_binary_url}"
	Dir.mkdir(win_tmp)
	File.open(win_tmp + '/' + win_binary_url, 'w') { |fd| fd.write open(base_url + win_binary_url).read }
	puts "extracting"
	Dir.chdir(win_tmp) { system 'unzip', '-q', win_binary_url }
end
win_bin = File.join(win_tmp, 'Dwarf Fortress.exe')

osx_tmp = File.join(tmp_path, "df_osx_#{version}")
if not File.directory?(osx_tmp)
	puts "dl osx #{osx_binary_url}"
	Dir.mkdir(osx_tmp)
	File.open(osx_tmp + '/' + osx_binary_url, 'w') { |fd| fd.write open(base_url + osx_binary_url).read }
	puts "extracting"
	Dir.chdir(osx_tmp) { system 'tar', 'xf', osx_binary_url }
	Dir.entries(osx_tmp+'/df_osx').each { |e| next if e == '.' or e == '..' ; File.rename osx_tmp+'/df_osx/'+e, osx_tmp+'/'+e }
	Dir.rmdir(osx_tmp+'/df_osx')
end
osx_bin = File.join(osx_tmp, 'dwarfort.exe')


# TODO patch globals.xml directly
puts "lin_vtable"
lin_vtable = `ruby #{misc_path}/scan_vtable.rb #{lin_bin.shellescape}`
File.open("lin_#{version}_vtable.xml", 'w') { |fd| fd.puts lin_vtable }

puts "win_vtable"
win_vtable = `ruby #{misc_path}/scan_vtable.rb #{win_bin.shellescape}`
File.open("win_#{version}_vtable.xml", 'w') { |fd| fd.puts win_vtable }

puts "osx_vtable"
osx_vtable = `ruby #{misc_path}/scan_vtable.rb #{osx_bin.shellescape}`
File.open("osx_#{version}_vtable.xml", 'w') { |fd| fd.puts osx_vtable }


puts "lin_ctors"
lin_ctors = `ruby #{misc_path}/scan_ctors.rb #{lin_bin.shellescape}`
File.open("lin_#{version}_ctors.xml", 'w') { |fd| fd.puts lin_ctors }

puts "osx_ctors"
osx_ctors = `ruby #{misc_path}/scan_ctors_osx.rb #{osx_bin.shellescape}`
File.open("osx_#{version}_ctors.xml", 'w') { |fd| fd.puts osx_ctors }


puts "lin_nextid"
lin_nextid = `ruby #{misc_path}/scan_nextid.rb #{lin_bin.shellescape}`
File.open("lin_#{version}_nextid.xml", 'w') { |fd| fd.puts lin_nextid }

puts "win_nextid"
win_nextid = `ruby #{misc_path}/scan_nextid.rb #{win_bin.shellescape}`
File.open("win_#{version}_nextid.xml", 'w') { |fd| fd.puts win_nextid }

puts "osx_nextid"
osx_nextid = `ruby #{misc_path}/scan_nextid_osx.rb #{osx_bin.shellescape}`
File.open("osx_#{version}_nextid.xml", 'w') { |fd| fd.puts osx_nextid }


puts "lin_standingorders"
lin_standingorders = `ruby #{misc_path}/scan_standingorders.rb #{lin_bin.shellescape}`
File.open("lin_#{version}_standingorders.xml", 'w') { |fd| fd.puts lin_standingorders }

puts "win_standingorders"
win_standingorders = `ruby #{misc_path}/scan_standingorders.rb #{win_bin.shellescape}`
File.open("win_#{version}_standingorders.xml", 'w') { |fd| fd.puts win_standingorders }


puts "win_keydisplay"
win_keydisplay = `ruby #{misc_path}/scan_keydisplay.rb #{win_bin.shellescape}`
File.open("win_#{version}_keydisplay.xml", 'w') { |fd| fd.puts win_keydisplay }

puts "osx_keydisplay"
osx_keydisplay = `ruby #{misc_path}/scan_keydisplay.rb #{osx_bin.shellescape}`
File.open("osx_#{version}_keydisplay.xml", 'w') { |fd| fd.puts osx_keydisplay }

# startdwarfcount

if not File.file?(win_bin + '.bak')
	puts "win_patchmalloc"
	system 'ruby', misc_path+'/df_patchmalloc.rb', win_bin
end

puts "done, archives in #{tmp_path}/df_{lin,win,osx}_#{version}"
