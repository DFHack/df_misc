#!/usr/bin/ruby

# tweak a new linux install's data/init/ files

Dir.chdir('data/init') unless File.exist?('announcements.txt')

raw = File.read('announcements.txt')
%w[DIG_CANCEL_WARM DIG_CANCEL_DAMP BIRTH_CITIZEN
STRANGE_MOOD MADE_ARTIFACT NAMED_ARTIFACT ARTIFACT_BEGUN].each { |n|
	# rm pause+focus on common events
	raw.sub!("#{n}:A_D:D_D:P:R", "#{n}:A_D:D_D")
}
File.open('announcements.txt', 'w') { |fd| fd.write raw }

raw = File.read('d_init.txt')
raw.sub!('AUTOSAVE:NONE', 'AUTOSAVE:YEARLY')
raw.sub!('INITIAL_SAVE:NO', 'INITIALSSAVE:YES')
raw.sub!('EMBARK_RECTANGLE:4:4', 'EMBARK_RECTANGLE:3:3')
raw.sub!('COFFIN_NO_PETS_DEFAULT:NO', 'COFFIN_NO_PETS_DEFAULT:YES')
raw.sub!('POPULATION_CAP:200', 'POPULATION_CAP:40')
raw.sub!('BABY_CHILD_CAP:100:1000', 'BABY_CHILD_CAP:4:10')
raw.sub!('SHOW_FLOW_AMOUNTS:NO', 'SHOW_FLOW_AMOUNTS:YES')
File.open('d_init.txt', 'w') { |fd| fd.write raw }

raw = File.read('init.txt')
raw.sub!('SOUND:YES', 'SOUND:NO')
raw.sub!('INTRO:YES', 'INTRO:NO')
raw.sub!('curses_640x300', 'curses_800x600')
raw.sub!('FPS:NO', 'FPS:YES')
raw.sub!('FPS_CAP:100', 'FPS_CAP:30')
raw.sub!('G_FPS_CAP:50', 'G_FPS_CAP:30')
File.open('init.txt', 'w') { |fd| fd.write raw }
