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
#include <dfhack/modules/Gui.h>
#include <dfhack/extra/MapExtras.h>
#include <dfhack/TileTypes.h>
using namespace DFHack;

#include <ruby.h>

DFhackCExport command_result df_rubyinit (Core * c);
DFhackCExport command_result df_rubyload (Core * c, vector <string> & parameters);
DFhackCExport command_result df_rubyeval (Core * c, vector <string> & parameters);
static void ruby_dfhack_bind(void);

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
    // initialize the ruby interpreter
    ruby_init();
    ruby_init_loadpath();
    // default value for the $0 "current script name"
    ruby_script("dfhack");

    // create the ruby objects to map DFHack to ruby methods
    ruby_dfhack_bind();
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

    if (state)
        rb_eval_string_protect("DFHack.puts_err \"#{$!.class}: #{$!.message}\", *$!.backtrace[0, 6]", &state);

    return CR_OK;
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

    rb_eval_string_protect(full.c_str(), &state);

    if (state)
        rb_eval_string_protect("DFHack.puts_err \"#{$!.class}: #{$!.message}\", *$!.backtrace[0, 6]", &state);

    return CR_OK;
}




static VALUE rb_cDFHack;
static VALUE rb_cCoord;

static inline Core& getcore(void)
{
    return Core::getInstance();
}

static VALUE df_newcoord(int x, int y, int z)
{
    rb_funcall(rb_cCoord, rb_intern("new"), 3, INT2FIX(x), INT2FIX(y), INT2FIX(z));
}


static VALUE rb_dfsuspend(VALUE self)
{
    VALUE ret = Qtrue;
    getcore().Suspend();
    if (rb_block_given_p() == Qtrue) {
        ret = rb_yield(Qnil);
        getcore().Resume();
    }
    return ret;
}

static VALUE rb_dfresume(VALUE self)
{
    getcore().Resume();
    return Qtrue;
}

static VALUE rb_dfputs(VALUE self, VALUE args)
{
    Console &con = getcore().con;
    VALUE s;

    if (rb_ary_entry(args, 0) == Qnil)
        con.print("\n");
    else
        while ((s = rb_ary_shift(args)) != Qnil)
            con.print("%s\n", rb_string_value_ptr(&s));

    return Qnil;
}

static VALUE rb_dfputs_err(VALUE self, VALUE args)
{
    Console &con = getcore().con;
    VALUE s;

    while ((s = rb_ary_shift(args)) != Qnil)
        con.printerr("%s\n", rb_string_value_ptr(&s));

    return Qnil;
}


static VALUE rb_guicursor(VALUE self)
{
    int x, y, z;
    getcore().getGui()->getCursorCoords(x, y, z);
    return df_newcoord(x, y, z);
}

static VALUE rb_guicursorset(VALUE self, VALUE x, VALUE y, VALUE z)
{
    getcore().getGui()->setCursorCoords(FIX2INT(x), FIX2INT(y), FIX2INT(z));
    return Qtrue;
}

static VALUE rb_guiview(VALUE self)
{
    int x, y, z;
    getcore().getGui()->getViewCoords(x, y, z);
    return df_newcoord(x, y, z);
}

static VALUE rb_guiviewset(VALUE self, VALUE x, VALUE y, VALUE z)
{
    getcore().getGui()->setViewCoords(FIX2INT(x), FIX2INT(y), FIX2INT(z));
    return Qtrue;
}


static void ruby_dfhack_bind(void) {

    rb_cDFHack = rb_define_class("DFHack", rb_cObject);
    rb_cCoord = rb_eval_string(
            "class DFHack::Coord\n"
            " attr_accessor :x, :y, :z\n"
            " def initialize(x, y, z)\n"
            "  @x = x; @y = y; @z = z\n"
            " end\n"
            " self\n"
            "end");

    rb_define_singleton_method(rb_cDFHack, "suspend", RUBY_METHOD_FUNC(rb_dfsuspend), 0);
    rb_define_singleton_method(rb_cDFHack, "resume", RUBY_METHOD_FUNC(rb_dfresume), 0);
    rb_define_singleton_method(rb_cDFHack, "puts", RUBY_METHOD_FUNC(rb_dfputs), -2);
    rb_define_singleton_method(rb_cDFHack, "puts_err", RUBY_METHOD_FUNC(rb_dfputs_err), -2);
    rb_define_singleton_method(rb_cDFHack, "cursor", RUBY_METHOD_FUNC(rb_guicursor), 0);
    rb_define_singleton_method(rb_cDFHack, "cursor_set", RUBY_METHOD_FUNC(rb_guicursorset), 3);
    rb_eval_string(
            "def DFHack.cursor=(c)\n"
            " case c\n"
            " when Array; x, y, z = c\n"
            " when DFHack::Coord; x, y, z = c.x, c.y, c.z\n"
            " else; raise 'bad cursor coords'\n"
            " end\n"
            " cursor_set(x, y, z)\n"
            "end");
    rb_define_singleton_method(rb_cDFHack, "view", RUBY_METHOD_FUNC(rb_guiview), 0);
    rb_define_singleton_method(rb_cDFHack, "view_set", RUBY_METHOD_FUNC(rb_guiviewset), 3);
    rb_eval_string(
            "def DFHack.view=(c)\n"
            " case c\n"
            " when Array; x, y, z = c\n"
            " when DFHack::Coord; x, y, z = c.x, c.y, c.z\n"
            " else; raise 'bad cursor coords'\n"
            " end\n"
            " view_set(x, y, z)\n"
            "end");

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
}

