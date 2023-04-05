Basic process for processing a new DF release

- obtain release versions
-- steam (use steam client)
-- itch (download from store)
-- classic (download from bay12)

- for each release edition, construct symbols stanza and add to `symbols.xml`
-- extract timestamp using ghidra
-- run scan_vtable.rb and dumpdf_globals.rb
-- write initial `symbols.xml` to local temporary
-- do initial ghidra analysis, skipping switch and parameter propagation
--- use temporary `symbols.xml` created in prior step
--- use codegen from last good version of DF
-- manually determine location of `steam_mod_manager` and `game_extra`
-- update temporary `symbols.xml` with these locations

- add new `symbols.xml` stanzas to versions to df-structures and commit
- complete initial ghidra analysis on steam edition

