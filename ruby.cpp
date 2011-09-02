// foo
// vi:expandtab:sw=4

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



// helper functions
static VALUE rb_cDFHack;
static VALUE rb_cCoord;
static VALUE rb_cMap;
static VALUE rb_cMapBlock;


static inline Core& getcore(void)
{
    return Core::getInstance();
}

static VALUE df_newcoord(int x, int y, int z)
{
    rb_funcall(rb_cCoord, rb_intern("new"), 3, INT2FIX(x), INT2FIX(y), INT2FIX(z));
}

// data_wrap_struct free() noop
static void nop(void*) {}


// DFHack methods
static VALUE rb_dfresume(VALUE self)
{
    getcore().Resume();
    return Qtrue;
}

static VALUE rb_dfsuspend(VALUE self)
{
    VALUE ret = Qtrue;
    getcore().Suspend();
    if (rb_block_given_p() == Qtrue) {
        ret = rb_ensure(RUBY_METHOD_FUNC(rb_yield), Qnil, RUBY_METHOD_FUNC(rb_dfresume), self);
    }
    return ret;
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



// Gui methods
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



// Maps methods
static VALUE rb_mapnew(VALUE self)
{
    Maps *map = getcore().getMaps();
    if (!map->Start())
        rb_raise(rb_eRuntimeError, "map_start");
    return Data_Wrap_Struct(rb_cMap, 0, nop, map);
}

static VALUE rb_mapstartfeat(VALUE self)
{
    Maps *map;
    Data_Get_Struct(self, Maps, map);
    if (!map->StartFeatures())
        rb_raise(rb_eRuntimeError, "map_startfeatures");
    return Qtrue;
}

static VALUE rb_mapstopfeat(VALUE self)
{
    Maps *map;
    Data_Get_Struct(self, Maps, map);
    if (!map->StopFeatures())
        rb_raise(rb_eRuntimeError, "map_stopfeatures");
    return Qtrue;
}

static VALUE rb_mapsize(VALUE self)
{
    Maps *map;
    Data_Get_Struct(self, Maps, map);
    uint32_t x, y, z;

    map->getSize(x, y, z);

    return df_newcoord(x, y, z);
}

static VALUE rb_mapblock(VALUE self, VALUE x, VALUE y, VALUE z)
{
    Maps *map;
    Data_Get_Struct(self, Maps, map);
    df_block *block;

    block = map->getBlock(FIX2INT(x), FIX2INT(y), FIX2INT(z));
    if (!block)
        return Qnil;

    return Data_Wrap_Struct(rb_cMapBlock, 0, nop, block);
}




static VALUE rb_blockread(VALUE self)
{
    df_block *block;
    Data_Get_Struct(self, df_block, block);

    return rb_str_new((char*)block, sizeof(*block));
}

static VALUE rb_blockwrite(VALUE self, VALUE rawdata)
{
    df_block *block;
    Data_Get_Struct(self, df_block, block);
    char *ptr;

    ptr = rb_string_value_ptr(&rawdata);

    memcpy(block, ptr, sizeof(*block));

    return Qtrue;
}

static VALUE rb_blockttype(VALUE self, VALUE x, VALUE y)
{
    df_block *block;
    Data_Get_Struct(self, df_block, block);

    x = FIX2INT(x) & 15;
    y = FIX2INT(y) & 15;
    return INT2FIX(block->tiletype[x][y]);
}

static VALUE rb_blockttypeset(VALUE self, VALUE x, VALUE y, VALUE tt)
{
    df_block *block;
    Data_Get_Struct(self, df_block, block);

    x = FIX2INT(x) & 15;
    y = FIX2INT(y) & 15;
    block->tiletype[x][y] = FIX2INT(tt);

    return Qtrue;
}

static VALUE rb_blockdesign(VALUE self, VALUE x, VALUE y)
{
    df_block *block;
    Data_Get_Struct(self, df_block, block);

    x = FIX2INT(x) & 15;
    y = FIX2INT(y) & 15;
    return INT2FIX(block->designation[x][y].whole);
}

static VALUE rb_blockdesignset(VALUE self, VALUE x, VALUE y, VALUE tt)
{
    df_block *block;
    Data_Get_Struct(self, df_block, block);

    x = FIX2INT(x) & 15;
    y = FIX2INT(y) & 15;
    block->designation[x][y].whole = FIX2INT(tt);

    return Qtrue;
}



// done
static void ruby_dfhack_bind(void) {

    rb_cDFHack = rb_define_module("DFHack");
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
    rb_define_singleton_method(rb_cDFHack, "view", RUBY_METHOD_FUNC(rb_guiview), 0);
    rb_define_singleton_method(rb_cDFHack, "view_set", RUBY_METHOD_FUNC(rb_guiviewset), 3);
    rb_eval_string(
            "def DFHack.cursor=(c)\n"
            " case c\n"
            " when Array; x, y, z = c\n"
            " when DFHack::Coord; x, y, z = c.x, c.y, c.z\n"
            " else; raise 'bad cursor coords'\n"
            " end\n"
            " cursor_set(x, y, z)\n"
            "end"
    );
    rb_eval_string(
            "def DFHack.view=(c)\n"
            " case c\n"
            " when Array; x, y, z = c\n"
            " when DFHack::Coord; x, y, z = c.x, c.y, c.z\n"
            " else; raise 'bad cursor coords'\n"
            " end\n"
            " view_set(x, y, z)\n"
            "end"
    );

    rb_cMap = rb_define_class_under(rb_cDFHack, "Map", rb_cObject);
    rb_define_singleton_method(rb_cMap, "new", RUBY_METHOD_FUNC(rb_mapnew), 0);
    rb_define_method(rb_cMap, "startfeatures", RUBY_METHOD_FUNC(rb_mapstartfeat), 0);
    rb_define_method(rb_cMap, "stopfeatures", RUBY_METHOD_FUNC(rb_mapstopfeat), 0);
    rb_define_method(rb_cMap, "size", RUBY_METHOD_FUNC(rb_mapsize), 0);         // size in 16x16 blocks
    rb_define_method(rb_cMap, "block", RUBY_METHOD_FUNC(rb_mapblock), 3);

    rb_cMapBlock = rb_define_class_under(rb_cMap, "Block", rb_cObject);
    rb_define_method(rb_cMapBlock, "readraw", RUBY_METHOD_FUNC(rb_blockread), 0);
    rb_define_method(rb_cMapBlock, "writeraw", RUBY_METHOD_FUNC(rb_blockwrite), 1);
    rb_define_method(rb_cMapBlock, "tiletype", RUBY_METHOD_FUNC(rb_blockttype), 2);
    rb_define_method(rb_cMapBlock, "tiletype=", RUBY_METHOD_FUNC(rb_blockttypeset), 3);
    rb_define_method(rb_cMapBlock, "designation", RUBY_METHOD_FUNC(rb_blockdesign), 2);
    rb_define_method(rb_cMapBlock, "designation=", RUBY_METHOD_FUNC(rb_blockdesignset), 3);
}

