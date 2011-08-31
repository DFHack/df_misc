// foo
// vim:sw=4:expandtab

#include <iostream>
#include <vector>
#include <map>
#include <stddef.h>
#include <assert.h>
#include <string.h>
using namespace std;
#include <dfhack/Core.h>
#include <dfhack/Console.h>
#include <dfhack/Export.h>
#include <dfhack/PluginManager.h>
#include <dfhack/modules/Maps.h>
#include <dfhack/TileTypes.h>
using namespace DFHack;

#include <ruby.h>

DFhackCExport command_result df_rubyinit (Core * c);
DFhackCExport command_result df_rubyload (Core * c, vector <string> & parameters);
DFhackCExport command_result df_rubyeval (Core * c, vector <string> & parameters);

DFhackCExport const char * plugin_name ( void )
{
    return "ruby";
}

DFhackCExport command_result plugin_init ( Core * c, std::vector <PluginCommand> &commands)
{
    if (df_rubyinit(c) == CR_FAILURE)
        return CR_FAILURE;

    commands.clear();

    commands.push_back(PluginCommand("rb_load",
                                     "Ruby interpreter. Loads the given ruby script.",
                                     df_rubyload));

    commands.push_back(PluginCommand("rb_eval",
                                     "Ruby interpreter. Eval() a ruby string.",
                                     df_rubyeval));

    return CR_OK;
}

DFhackCExport command_result plugin_shutdown ( Core * c )
{
    ruby_finalize();
    return CR_OK;
}

DFhackCExport command_result df_rubyinit (Core * c)
{
    ruby_init();
    ruby_init_loadpath();
    ruby_script("dfhack");

    /*
    uint32_t x_max,y_max,z_max;
    uint32_t num_blocks = 0;
    uint32_t bytes_read = 0;
    DFHack::designations40d designations;
    DFHack::tiletypes40d tiles;
    DFHack::tiletypes40d tilesAbove;

    //DFHack::TileRow *ptile;
    int32_t oldT, newT;

    bool dirty= false;
    int count=0;
    int countbad=0;
    c->Suspend();
    DFHack::Maps *Mapz = c->getMaps();

    // init the map
    if (!Mapz->Start())
    {
        c->con.printerr("Can't init map.\n");
        c->Resume();
        return CR_FAILURE;
    }

    Mapz->getSize(x_max,y_max,z_max);

    uint8_t zeroes [16][16] = {0};

    // walk the map
    for (uint32_t x = 0; x< x_max;x++)
    {
        for (uint32_t y = 0; y< y_max;y++)
        {
            for (uint32_t z = 0; z< z_max;z++)
            {
                if (Mapz->getBlock(x,y,z))
                {
                    dirty= false;
                    Mapz->ReadDesignations(x,y,z, &designations);
                    Mapz->ReadTileTypes(x,y,z, &tiles);
                    if (Mapz->getBlock(x,y,z+1))
                    {
                        Mapz->ReadTileTypes(x,y,z+1, &tilesAbove);
                    }
                    else
                    {
                        memset(&tilesAbove,0,sizeof(tilesAbove));
                    }

                    for (uint32_t ty=0;ty<16;++ty)
                    {
                        for (uint32_t tx=0;tx<16;++tx)
                        {
                            //Only the remove ramp designation (ignore channel designation, etc)
                            oldT = tiles[tx][ty];
                            if ( DFHack::designation_default == designations[tx][ty].bits.dig
                                    && DFHack::RAMP==DFHack::tileShape(oldT))
                            {
                                //Current tile is a ramp.
                                //Set current tile, as accurately as can be expected
                                newT = DFHack::findSimilarTileType(oldT,DFHack::FLOOR);

                                //If no change, skip it (couldn't find a good tile type)
                                if ( oldT == newT) continue;
                                //Set new tile type, clear designation
                                tiles[tx][ty] = newT;
                                designations[tx][ty].bits.dig = DFHack::designation_no;

                                //Check the tile above this one, in case a downward slope needs to be removed.
                                if ( DFHack::RAMP_TOP == DFHack::tileShape(tilesAbove[tx][ty]) )
                                {
                                    tilesAbove[tx][ty] = 32;
                                }
                                dirty= true;
                                ++count;
                            }
                            // ramp fixer
                            else if(DFHack::RAMP!=DFHack::tileShape(oldT) && DFHack::RAMP_TOP == DFHack::tileShape(tilesAbove[tx][ty]))
                            {
                                tilesAbove[tx][ty] = 32;
                                countbad++;
                                dirty = true;
                            }
                        }
                    }
                    //If anything was changed, write it all.
                    if (dirty)
                    {
                        Mapz->WriteDesignations(x,y,z, &designations);
                        Mapz->WriteTileTypes(x,y,z, &tiles);
                        if (Mapz->getBlock(x,y,z+1))
                        {
                            Mapz->WriteTileTypes(x,y,z+1, &tilesAbove);
                        }
                        dirty = false;
                    }
                }
            }
        }
    }
    c->Resume();
    if(count)
        c->con.print("Found and changed %d tiles.\n",count);
    if(countbad)
        c->con.print("Fixed %d bad down ramps.\n",countbad);
    */
    return CR_OK;
}

DFhackCExport command_result df_rubyload (Core * c, vector <string> & parameters)
{
    if (parameters.size() == 1 && (parameters[0] == "help" || parameters[0] == "?"))
    {
        c->con.print( "This command loads the ruby script whose path is given as parameter, and run it.\n");
        return CR_OK;
    }
    int state=0;
    rb_load_protect(rb_str_new2(parameters[0].c_str()), Qfalse, &state);
    return state ? CR_FAILURE : CR_OK;
}

DFhackCExport command_result df_rubyeval (Core * c, vector <string> & parameters)
{
    if (parameters.size() == 1 && (parameters[0] == "help" || parameters[0] == "?"))
    {
        c->con.print("This command executes an arbitrary ruby statement.\n");
        return CR_OK;
    }

    string full = "";
    int state=0;

    for (int i=0 ; i<parameters.size() ; ++i) {
	    full += parameters[i];
	    full += " ";
    }
    c->con.print("eval('%s')\n", full.c_str());
    rb_eval_string_protect(full.c_str(), &state);
    return state ? CR_FAILURE : CR_OK;
}
