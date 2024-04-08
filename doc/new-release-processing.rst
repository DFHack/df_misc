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

* run ``md5sum dwarfort`` to get the hash of the main DF executable
* add a fragment like this to the Linux section of the ``symbols.xml`` file
  (use ``ITCH`` or ``CLASSIC`` instead of ``STEAM`` as appropriate)::

    <symbol-table name='v0.50.12 linux64 STEAM' os-type='linux'>
        <md5-hash value='c7dcc28bc714daff32f6f53c95542faf'/>
    </symbol-table>

* install DFHack to the DF directory
* run ``./dfhack`` from a terminal
* run ``devel/dump-offsets`` at the ``[DFHack]#`` prompt, copy the output into
  the ``symbol-table`` element in ``symbols.xml`` and add a newline
* from a different terminal in the DF directory, run::

    ./dfhack-run devel/scan-vtables | ansifilter | LANG=C sort

* copy the output into the ``symbol-table`` element in ``symbols.xml``
* close DF
* reinstall DFHack so the updated ``hack/symbols.xml`` file is in place
* relaunch DF and verify that DFHack functionality works as expected
* remove ``symbol-table`` elements that are no longer relevant for this DF
  version

downloading depots directly from steam:

* `steam://open/console`
* in steam, use console command, where `xxxxx` is the manifest ID for the release
  of interest (use `SteamDB <https://steamdb.info/app/975370/depots/>`__)
  * `download_depot 975370 975372 xxxxx` for windows
  * `download_depot 975370 975373 xxxxx` for linux
