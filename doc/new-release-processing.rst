Basic process for processing a new DF release

for windows:

* obtain release versions

  * steam (use steam client)
  * itch (download from store)
  * classic (download from bay12)

* for each release edition, construct symbols stanza and add to `symbols.xml`

  * extract timestamp using ghidra
  * run scan_vtable.rb and dumpdf_globals.rb
  * write initial `symbols.xml` to local temporary
  * do initial ghidra analysis, skipping switch and parameter propagation

    * use temporary `symbols.xml` created in prior step
    * use codegen from last good version of DF
    * manually determine location of `steam_mod_manager` and `game_extra`

  * update temporary `symbols.xml` with these locations

* add new `symbols.xml` stanzas to versions to df-structures and commit
* complete initial ghidra analysis on steam edition

for linux:

* add a symbol-table with the correct md5-hash
* install DFHack
* run devel/dump-offsets, paste into the symbol table and add a newline
* run devel/scan-vtables, paste into the symbol table
  * `./dfhack-run devel/scan-vtables | ansifilter  | LANG=C sort`

downloading depots directly from steam:
* `steam://open/console`
* in steam, use console command, where `xxxxx`` is the manifest ID for the release of interest (use SteamDB)
  * `download_depot 975370 975372 xxxxx` for windows
  * `download_depot 975370 975373 xxxxx` for linux
