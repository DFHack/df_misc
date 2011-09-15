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
#include <dfhack/VersionInfo.h>
#include <dfhack/modules/Creatures.h>
#include <dfhack/modules/Maps.h>
#include <dfhack/modules/Gui.h>
#include <dfhack/extra/MapExtras.h>
#include <dfhack/TileTypes.h>
using namespace DFHack;
#include "tinythread.h"
using namespace tthread;

#include <ruby.h>

static void df_rubythread(void*);
static command_result df_rubyload (Core * c, vector <string> & parameters);
static command_result df_rubyeval (Core * c, vector <string> & parameters);
static void ruby_dfhack_bind(void);

// inter-thread communication stuff
enum RB_command {
    RB_IDLE,
    RB_INIT,
    RB_DIE,
    RB_LOAD,
    RB_EVAL,
    RB_CUSTOM,
};
mutex *m_irun;
mutex *m_mutex;
static RB_command r_type;
static const char *r_command;
static command_result r_result;
static thread *r_thread;

// dfhack interface
DFhackCExport const char * plugin_name ( void )
{
    return "ruby";
}

DFhackCExport command_result plugin_init ( Core * c, std::vector <PluginCommand> &commands)
{
    m_irun = new mutex();
    m_mutex = new mutex();
    r_type = RB_INIT;

    r_thread = new thread(df_rubythread, 0);

    while (r_type != RB_IDLE)
	    this_thread::yield();

    m_irun->lock();

    if (r_result == CR_FAILURE)
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
    m_mutex->lock();
    if (!r_thread)
        return CR_OK;

    r_type = RB_DIE;
    r_command = 0;
    m_irun->unlock();

    r_thread->join();

    delete r_thread;
    r_thread = 0;
    delete m_irun;
    m_mutex->unlock();
    delete m_mutex;

    return CR_OK;
}

static command_result df_rubyload(Core * c, vector <string> & parameters)
{
    command_result ret;

    if (parameters.size() == 1 && (parameters[0] == "help" || parameters[0] == "?"))
    {
        c->con.print("This command loads the ruby script whose path is given as parameter, and run it.\n");
        return CR_OK;
    }

    // serialize 'accesses' to the ruby thread
    m_mutex->lock();
    if (!r_thread)
        // raced with plugin_shutdown ?
        return CR_OK;

    r_type = RB_LOAD;
    r_command = parameters[0].c_str();
    m_irun->unlock();

    // could use a condition_variable or something...
    while (r_type != RB_IDLE)
	    this_thread::yield();
    // XXX non-atomic with previous r_type change check
    ret = r_result;

    m_irun->lock();
    m_mutex->unlock();

    return ret;
}

static command_result df_rubyeval(Core * c, vector <string> & parameters)
{
    command_result ret;

    if (parameters.size() == 1 && (parameters[0] == "help" || parameters[0] == "?"))
    {
        c->con.print("This command executes an arbitrary ruby statement.\n");
        return CR_OK;
    }

    string full = "";

    for (unsigned i=0 ; i<parameters.size() ; ++i) {
        full += parameters[i];
        full += " ";
    }

    m_mutex->lock();
    if (!r_thread)
        return CR_OK;

    r_type = RB_EVAL;
    r_command = full.c_str();
    m_irun->unlock();

    while (r_type != RB_IDLE)
	    this_thread::yield();

    ret = r_result;

    m_irun->lock();
    m_mutex->unlock();

    return ret;
}



// ruby thread code
static void dump_rb_error(void)
{
    Console &con = Core::getInstance().con;
    VALUE s, err;

    err = rb_gv_get("$!");

    s = rb_funcall(err, rb_intern("class"), 0);
    s = rb_funcall(s, rb_intern("name"), 0);
    con.printerr("E: %s: ", rb_string_value_ptr(&s));

    s = rb_funcall(err, rb_intern("message"), 0);
    con.printerr("%s\n", rb_string_value_ptr(&s));

    err = rb_funcall(err, rb_intern("backtrace"), 0);
    for (int i=0 ; i<8 ; ++i)
        if ((s = rb_ary_shift(err)) != Qnil)
            con.printerr(" %s\n", rb_string_value_ptr(&s));
}

// ruby thread main loop
static void df_rubythread(void *p)
{
    int state, running;

    // initialize the ruby interpreter
    ruby_init();
    ruby_init_loadpath();
    // default value for the $0 "current script name"
    ruby_script("dfhack");

    // create the ruby objects to map DFHack to ruby methods
    ruby_dfhack_bind();

    r_result = CR_OK;
    r_type = RB_IDLE;

    running = 1;
    while (running) {
        // wait for new command
        m_irun->lock();

        switch (r_type) {
        case RB_IDLE:
        case RB_INIT:
            break;

        case RB_DIE:
            running = 0;
            ruby_finalize();
            break;

        case RB_LOAD:
            state = 0;
            rb_load_protect(rb_str_new2(r_command), Qfalse, &state);
            if (state)
                dump_rb_error();
            break;

        case RB_EVAL:
            state = 0;
            rb_eval_string_protect(r_command, &state);
            if (state)
                dump_rb_error();
            break;

        case RB_CUSTOM:
            // TODO handle ruby custom commands
            break;
        }

        r_result = CR_OK;
        r_type = RB_IDLE;
        m_irun->unlock();
        this_thread::yield();
    }
}



// ruby classes
static VALUE rb_cDFHack;
static VALUE rb_cCoord;
static VALUE rb_cWrapData;
static VALUE rb_cCreature;
static VALUE rb_cMap;
static VALUE rb_cMapBlock;
static VALUE rb_cMapVein;
static VALUE rb_cPlant;
static VALUE rb_cMatCreature;
static VALUE rb_cMatInorganic;
static VALUE rb_cMatOrganic;


// helper functions
static inline Core& getcore(void)
{
    return Core::getInstance();
}

static VALUE df_newcoord(int x, int y, int z)
{
    return rb_funcall(rb_cCoord, rb_intern("new"), 3, INT2FIX(x), INT2FIX(y), INT2FIX(z));
}

// defines two C functions to access a numeric field from ruby
#define NUMERIC_ACCESSOR(funcname, type, fieldname)               \
    static VALUE rb_ ## funcname (VALUE self) {                   \
        type *var;                                                \
        Data_Get_Struct(self, type, var);                         \
        return rb_uint2inum(var->fieldname);                      \
    }                                                             \
    static VALUE rb_ ## funcname ## set (VALUE self, VALUE val) { \
        type *var;                                                \
        Data_Get_Struct(self, type, var);                         \
        var->fieldname = rb_num2ulong(val);                       \
        return Qtrue;                                             \
    }

// defines two C functions to access a boolean field from ruby
#define FLAG_ACCESSOR(funcname, type, fieldname)                        \
    static VALUE rb_ ## funcname (VALUE self) {                         \
        type *var;                                                      \
        Data_Get_Struct(self, type, var);                               \
        return (var->fieldname ? Qtrue : Qfalse);                       \
    }                                                                   \
    static VALUE rb_ ## funcname ## set (VALUE self, VALUE val) {       \
        type *var;                                                      \
        Data_Get_Struct(self, type, var);                               \
        var->fieldname = ((val == Qtrue || val == INT2FIX(1)) ? 1 : 0); \
        return Qtrue;                                                   \
    }


// DFHack methods
static VALUE rb_dfresume(VALUE self)
{
    getcore().Resume();
    return Qtrue;
}

static VALUE rb_dfsuspend(VALUE self)
{
    getcore().Suspend();
    return Qtrue;
}

static VALUE rb_dfgetversion(VALUE self)
{
    return rb_str_new2(getcore().vinfo->getVersion().c_str());
}

static VALUE rb_dfprint_str(VALUE self, VALUE s)
{
    Console &con = getcore().con;
    con.print("%s", rb_string_value_ptr(&s));
    return Qnil;
}

static VALUE rb_dfprint_err(VALUE self, VALUE s)
{
    Console &con = getcore().con;
    con.printerr("%s", rb_string_value_ptr(&s));
    return Qnil;
}

// raw memory access
// WARNING: may cause game crash ! double-check your addresses !
static VALUE rb_dfmemread(VALUE self, VALUE addr, VALUE len)
{
    return rb_str_new((char*)rb_num2ulong(addr), rb_num2ulong(len));
}

static VALUE rb_dfmemwrite(VALUE self, VALUE addr, VALUE raw)
{
    // no stable api for raw.length between rb1.8/rb1.9 ...
    int strlen = FIX2INT(rb_funcall(raw, rb_intern("length"), 0));

    memcpy((void*)rb_num2ulong(addr), rb_string_value_ptr(&raw), strlen);

    return Qtrue;
}

// raw c++ wrappers
// return the nth element of a vector
static VALUE rb_dfvectorat(VALUE self, VALUE vect_addr, VALUE idx)
{
    vector<uint32_t> *v = (vector<uint32_t>*)rb_num2ulong(vect_addr);
    return rb_uint2inum(v->at(FIX2INT(idx)));
}

// return a c++ string as a ruby string (nul-terminated)
static VALUE rb_dfreadstring(VALUE self, VALUE str_addr)
{
    string *s = (string*)rb_num2ulong(str_addr);
    return rb_str_new2(s->c_str());
}

// raw Memory.xml access
// getoffset("Materials", "inorganics")
static VALUE rb_dfgetaddress(VALUE self, VALUE group, VALUE off)
{
    OffsetGroup *grp = getcore().vinfo->getGroup(rb_string_value_ptr(&group));
    unsigned long ret = grp->getAddress(rb_string_value_ptr(&off));
    return rb_uint2inum(ret);
}




/* XXX this needs a custom DFHack::Plugin subclass to pass the cmdname to invoke(), to match the ruby callback
// register a ruby method as dfhack console command
// usage: DFHack.register("moo", "this commands prints moo on the console") { DFHack.puts "moo !" }
static VALUE rb_dfregister(VALUE self, VALUE name, VALUE descr)
{
    commands.push_back(PluginCommand(rb_string_value_ptr(&name),
                rb_string_value_ptr(&descr),
                df_rubycustom));

    return Qtrue;
}
*/
static VALUE rb_dfregister(VALUE self, VALUE name, VALUE descr)
{
    rb_raise(rb_eRuntimeError, "not implemented");
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

// return the array of all Plants on the map
static VALUE rb_dfvegetation(VALUE self)
{
    DFHack::Vegetation *veg = getcore().getVegetation();
    if (!veg->all_plants)
        return Qnil;

    VALUE ret = rb_ary_new();
    for (unsigned i=0 ; i<veg->all_plants->size() ; ++i)
        rb_ary_push(ret, Data_Wrap_Struct(rb_cPlant, 0, 0, veg->all_plants->at(i)));

    return ret;
}

#include "df_creature.h"
// return the array of all Creatures
static VALUE rb_dfcreatures(VALUE self)
{
    OffsetGroup *ogc = getcore().vinfo->getGroup("Creatures");
    vector <df_creature*> *v = (vector<df_creature*>*)ogc->getAddress("vector");

    VALUE ret = rb_ary_new();
    for (unsigned i=0 ; i<v->size() ; ++i)
        rb_ary_push(ret, Data_Wrap_Struct(rb_cCreature, 0, 0, v->at(i)));

    return ret;
}

static VALUE rb_dfmatcreatures(VALUE self)
{
    OffsetGroup *ogc = getcore().vinfo->getGroup("Materials");
    auto v = (vector<df_creature_material*>*)ogc->getAddress("creature_type_vector");

    VALUE ret = rb_ary_new();
    for (unsigned i=0 ; i<v->size() ; ++i)
        rb_ary_push(ret, Data_Wrap_Struct(rb_cMatCreature, 0, 0, v->at(i)));

    return ret;
}

static VALUE rb_dfmatinorganic(VALUE self)
{
    OffsetGroup *ogc = getcore().vinfo->getGroup("Materials");
    auto v = (vector<df_inorganic_material*>*)ogc->getAddress("inorganics");

    VALUE ret = rb_ary_new();
    for (unsigned i=0 ; i<v->size() ; ++i)
        rb_ary_push(ret, Data_Wrap_Struct(rb_cMatInorganic, 0, 0, v->at(i)));

    return ret;
}

struct df_organic_material {
    std::string name;
    // TODO
};

static VALUE rb_dfmatorganic(VALUE self)
{
    OffsetGroup *ogc = getcore().vinfo->getGroup("Materials");
    auto v = (vector<df_organic_material*>*)ogc->getAddress("organics_all");

    VALUE ret = rb_ary_new();
    for (unsigned i=0 ; i<v->size() ; ++i)
        rb_ary_push(ret, Data_Wrap_Struct(rb_cMatOrganic, 0, 0, v->at(i)));

    return ret;
}

static VALUE rb_getlaborname(VALUE self, VALUE idx)
{
    return rb_str_new2(getcore().vinfo->getLabor(FIX2INT(idx)).c_str());
}

static VALUE rb_getskillname(VALUE self, VALUE idx)
{
    return rb_str_new2(getcore().vinfo->getSkill(FIX2INT(idx)).c_str());
}


// Maps methods
static VALUE rb_mapnew(VALUE self)
{
    Maps *map = getcore().getMaps();
    if (!map->Start())
        rb_raise(rb_eRuntimeError, "map_start");
    return Data_Wrap_Struct(rb_cMap, 0, 0, map);
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

// DF map size (in tiles)
static VALUE rb_mapsize(VALUE self)
{
    Maps *map;
    Data_Get_Struct(self, Maps, map);
    uint32_t x, y, z;

    map->getSize(x, y, z);

    return df_newcoord(x*16, y*16, z);
}

// returns the Block at xyz (tile coords)
static VALUE rb_mapblock(VALUE self, VALUE x, VALUE y, VALUE z)
{
    Maps *map;
    Data_Get_Struct(self, Maps, map);
    df_block *block;

    block = map->getBlock(FIX2INT(x)/16, FIX2INT(y)/16, FIX2INT(z));
    if (!block)
        return Qnil;

    return Data_Wrap_Struct(rb_cMapBlock, 0, 0, block);
}

// return an array of array of geology layer indexes (used to get base rock material)
static VALUE rb_mapreadgeology(VALUE self)
{
    Maps *map;
    Data_Get_Struct(self, Maps, map);
    std::vector<std::vector<uint16_t>> v;
    std::vector<uint16_t> *vv;

    if (!map->ReadGeology(v))
        return Qnil;

    VALUE ret = rb_ary_new();
    VALUE elem;
    for (unsigned i=0 ; i<v.size() ; ++i) {
        vv = &v.at(i);
        elem = rb_ary_new();
        for (unsigned ii=0 ; ii<vv->size() ; ++ii) {
            rb_ary_push(elem, INT2FIX(vv->at(ii)));
        }
        rb_ary_push(ret, elem);
    }

    return ret;
}



// return the address of the struct in DF memory (for raw memread/write)
static VALUE rb_memaddr(VALUE self)
{
    void *data;
    Data_Get_Struct(self, void, data);

    return rb_uint2inum((uint32_t)data);
}




// return the coords of the block in the map (in tile units)
static VALUE rb_blockpos(VALUE self)
{
    df_block *block;
    Data_Get_Struct(self, df_block, block);
    
    return df_newcoord(block->map_x, block->map_y, block->map_z);
}

// change tile type of tile (x%16, y%16) (uint16)
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

static VALUE rb_blocktname(VALUE self, VALUE x, VALUE y)
{
    df_block *block;
    Data_Get_Struct(self, df_block, block);
    int tile;

    x = FIX2INT(x) & 15;
    y = FIX2INT(y) & 15;

    tile = block->tiletype[x][y];

    const char *name = tileName(tile);
    if (name)
        return rb_str_new2(name);
    else
        return Qnil;
}

static VALUE rb_blocktshape(VALUE self, VALUE x, VALUE y)
{
    df_block *block;
    Data_Get_Struct(self, df_block, block);
    int tile;

    x = FIX2INT(x) & 15;
    y = FIX2INT(y) & 15;

    tile = block->tiletype[x][y];

    const char *name = TileShapeString[tileShape(tile)];
    if (name)
        return rb_str_new2(name);
    else
        return Qnil;
}

static VALUE rb_blocktmat(VALUE self, VALUE x, VALUE y)
{
    df_block *block;
    Data_Get_Struct(self, df_block, block);
    int tile;

    x = FIX2INT(x) & 15;
    y = FIX2INT(y) & 15;

    tile = block->tiletype[x][y];

    const char *name = TileMaterialString[tileMaterial(tile)];
    if (name)
        return rb_str_new2(name);
    else
        return Qnil;
}

// change designation of tile (x%16, y%16) (uint32)
/* 0000_0007 water level
   0000_0070 designated job for the tile
   0none 1dig 2updownstair 3channel 4ramp 5downstair 6upstair 7?
   0000_0180 flag job? 8smooth 10engrave
   0000_0200 hidden (fog of war)
   0001_c000 10outside 8light 4subterranean
   0020_0000 water level = magma ('lava' when outdoor)
 */
static VALUE rb_blockdesign(VALUE self, VALUE x, VALUE y)
{
    df_block *block;
    Data_Get_Struct(self, df_block, block);

    x = FIX2INT(x) & 15;
    y = FIX2INT(y) & 15;
    return rb_uint2inum(block->designation[x][y].whole);
}

static VALUE rb_blockdesignset(VALUE self, VALUE x, VALUE y, VALUE tt)
{
    df_block *block;
    Data_Get_Struct(self, df_block, block);

    x = FIX2INT(x) & 15;
    y = FIX2INT(y) & 15;
    block->designation[x][y].whole = rb_num2ulong(tt);

    return Qtrue;
}

// returns the raw block designation chunk (16*16*uint32)
static VALUE rb_blockdesignmap(VALUE self)
{
    df_block *block;
    Data_Get_Struct(self, df_block, block);

    return rb_str_new((char*)block->designation, sizeof(block->designation));
}

static VALUE rb_blockdesignmapset(VALUE self, VALUE raw)
{
    df_block *block;
    Data_Get_Struct(self, df_block, block);

    memcpy(block->designation, rb_string_value_ptr(&raw), sizeof(block->designation));

    return Qtrue;
}

NUMERIC_ACCESSOR(blockflags, df_block, flags)

// returns the array of Map::Veins
static VALUE rb_blockveins(VALUE self)
{
    df_block *block;
    Maps *map;
    VALUE ret;
    std::vector <DFHack::t_vein *> veins;

    map = getcore().getMaps();
    if (!map->Start())
        rb_raise(rb_eRuntimeError, "map_start");

    Data_Get_Struct(self, df_block, block);
    
    map->SortBlockEvents(block->map_x/16, block->map_y/16, block->map_z, &veins);

    ret = rb_ary_new();

    for (unsigned i=0 ; i<veins.size() ; ++i)
        rb_ary_push(ret, Data_Wrap_Struct(rb_cMapVein, 0, 0, veins.at(i)));

    return ret;
}

static VALUE rb_blockregoffset(VALUE self, VALUE idx)
{
    df_block *block;
    Data_Get_Struct(self, df_block, block);

    idx = FIX2INT(idx);
    if (idx >= sizeof(block->region_offset))
        return Qnil;
    else
        return INT2FIX(block->region_offset[idx]);
}



// Map::Vein
NUMERIC_ACCESSOR(veintype, t_vein, type)
NUMERIC_ACCESSOR(veinflags, t_vein, flags)

// access the vein assignment bitmap (16*uint16, bit = assign[y] & (1<<x))
static VALUE rb_veinassign(VALUE self)
{
    t_vein *vein;
    Data_Get_Struct(self, t_vein, vein);

    return rb_str_new((char*)vein->assignment, sizeof(vein->assignment));
}

static VALUE rb_veinassignset(VALUE self, VALUE raw)
{
    t_vein *vein;
    Data_Get_Struct(self, t_vein, vein);

    memcpy(vein->assignment, rb_string_value_ptr(&raw), sizeof(vein->assignment));

    return Qtrue;
}


    // Vegetation
static VALUE rb_plantpos(VALUE self)
{
    df_plant *plant;
    Data_Get_Struct(self, df_plant, plant);

    return df_newcoord(plant->x, plant->y, plant->z);
}

    NUMERIC_ACCESSOR(plantmaterial, df_plant, material)
    FLAG_ACCESSOR(plantisshrub, df_plant, is_shrub)
    FLAG_ACCESSOR(plantisburning, df_plant, is_burning)
    NUMERIC_ACCESSOR(plantgrowcounter, df_plant, grow_counter)
NUMERIC_ACCESSOR(planthitpoints, df_plant, hitpoints)




static VALUE rb_creapos(VALUE self)
{
    df_creature *crea;
    Data_Get_Struct(self, df_creature, crea);

    return df_newcoord(crea->x, crea->y, crea->z);
}

static VALUE rb_creaname(VALUE self)
{
    df_creature *crea;
    Data_Get_Struct(self, df_creature, crea);

    string &name = crea->name.first_name;        // TODO decode_df_name(crea->name);
    return rb_str_new2(name.c_str());
}

// returns the full table of labors (uint8[96])
static VALUE rb_crealabors(VALUE self)
{
    df_creature *crea;
    Data_Get_Struct(self, df_creature, crea);

    return rb_str_new((char*)crea->labors, sizeof(crea->labors));
}

static VALUE rb_crealaborsset(VALUE self, VALUE tt)
{
    df_creature *crea;
    Data_Get_Struct(self, df_creature, crea);

    memcpy(crea->labors, rb_string_value_ptr(&tt), sizeof(crea->labors));

    return Qtrue;
}

// returns the full table of physical_attributes ([uint32*5]*6)
// strength, agility, toughness, endurance, recuperation, disease_resistance
static VALUE rb_creaattribs(VALUE self)
{
    df_creature *crea;
    Data_Get_Struct(self, df_creature, crea);

    return rb_str_new((char*)crea->physical, sizeof(crea->physical));
}

static VALUE rb_creaattribsset(VALUE self, VALUE tt)
{
    df_creature *crea;
    Data_Get_Struct(self, df_creature, crea);

    memcpy(crea->physical, rb_string_value_ptr(&tt), sizeof(crea->physical));

    return Qtrue;
}

// returns the full table of skills (ary of [id, rating, xp, unknown(String)])
static VALUE rb_creaskills(VALUE self)
{
    df_creature *crea;
    Data_Get_Struct(self, df_creature, crea);

    auto &v = crea->current_soul->skills;
    VALUE ret = rb_ary_new();

    for (unsigned i=0 ; i<v.size() ; ++i) {
        VALUE elem = rb_ary_new();
        rb_ary_push(elem, rb_uint2inum(v.at(i)->id));
        rb_ary_push(elem, rb_uint2inum(v.at(i)->rating));
        rb_ary_push(elem, rb_uint2inum(v.at(i)->experience));
        rb_ary_push(elem, rb_uint2inum(v.at(i)->unk_c));
        rb_ary_push(elem, rb_uint2inum(v.at(i)->rusty));
        rb_ary_push(elem, rb_uint2inum(v.at(i)->unk_14));
        rb_ary_push(elem, rb_uint2inum(v.at(i)->unk_18));
        rb_ary_push(elem, rb_uint2inum(v.at(i)->unk_1c));
        rb_ary_push(ret, elem);
    }

    return ret;
}

static VALUE rb_creaskillsset(VALUE self, VALUE tt)
{
    df_creature *crea;
    Data_Get_Struct(self, df_creature, crea);

    VALUE elem;
    auto &v = crea->current_soul->skills;

    tt = rb_ary_dup(tt);

    for (unsigned i=0 ; i<v.size() ; ++i)
        delete v.at(i);
    v.clear();

    while ((elem = rb_ary_shift(tt)) != Qnil) {
        df_skill *sk = new df_skill();
        elem = rb_ary_dup(elem);

        sk->id = rb_num2ulong(rb_ary_shift(elem));
        sk->rating = rb_num2ulong(rb_ary_shift(elem));
        sk->experience = rb_num2ulong(rb_ary_shift(elem));
        sk->unk_c = rb_num2ulong(rb_ary_shift(elem));
        sk->rusty = rb_num2ulong(rb_ary_shift(elem));
        sk->unk_14 = rb_num2ulong(rb_ary_shift(elem));
        sk->unk_18 = rb_num2ulong(rb_ary_shift(elem));
        sk->unk_1c = rb_num2ulong(rb_ary_shift(elem));

        v.push_back(sk);
    }

    return Qtrue;
}

    NUMERIC_ACCESSOR(crearace, df_creature, race)
    NUMERIC_ACCESSOR(creaid, df_creature, id)
NUMERIC_ACCESSOR(creaciv, df_creature, civ)

    NUMERIC_ACCESSOR(creaflags1, df_creature, flags1.whole)
    NUMERIC_ACCESSOR(creaflags2, df_creature, flags2.whole)
NUMERIC_ACCESSOR(creaflags3, df_creature, flags3.whole)

NUMERIC_ACCESSOR(creamood, df_creature, mood)

    NUMERIC_ACCESSOR(creasex, df_creature, sex)
    NUMERIC_ACCESSOR(creacaste, df_creature, caste)
    NUMERIC_ACCESSOR(creapregtimer, df_creature, pregnancy_timer)
NUMERIC_ACCESSOR(creagraspimpair, df_creature, able_grasp_impair)



static VALUE rb_matcrename(VALUE self)
{
    df_creature_material *matcre;
    Data_Get_Struct(self, df_creature_material, matcre);

    return rb_str_new2(matcre->rawname.c_str());
}

static VALUE rb_matcrecastename(VALUE self, VALUE idx)
{
    df_creature_material *matcre;
    Data_Get_Struct(self, df_creature_material, matcre);
    std::vector<df_creature_mat_caste*> &v = matcre->castes;

    if (FIX2INT(idx) < v.size())
        return rb_str_new2(v.at(FIX2INT(idx))->name.c_str());
    else
        return Qnil;
}


static VALUE rb_matinoname(VALUE self)
{
    df_inorganic_material *matino;
    Data_Get_Struct(self, df_inorganic_material, matino);

    return rb_str_new2(matino->Inorganic_ID.c_str());
}


static VALUE rb_matorgname(VALUE self)
{
    df_organic_material *matorg;
    Data_Get_Struct(self, df_organic_material, matorg);

    return rb_str_new2(matorg->name.c_str());
}


// done
static void ruby_dfhack_bind(void) {
    rb_cDFHack = rb_define_module("DFHack");

    rb_define_singleton_method(rb_cDFHack, "suspendraw", RUBY_METHOD_FUNC(rb_dfsuspend), 0);
    rb_define_singleton_method(rb_cDFHack, "resume", RUBY_METHOD_FUNC(rb_dfresume), 0);
    rb_define_singleton_method(rb_cDFHack, "version", RUBY_METHOD_FUNC(rb_dfgetversion), 0);
    rb_define_singleton_method(rb_cDFHack, "print_str", RUBY_METHOD_FUNC(rb_dfprint_str), 1);
    rb_define_singleton_method(rb_cDFHack, "print_err", RUBY_METHOD_FUNC(rb_dfprint_err), 1);
    rb_define_singleton_method(rb_cDFHack, "memread", RUBY_METHOD_FUNC(rb_dfmemread), 2);
    rb_define_singleton_method(rb_cDFHack, "memwrite", RUBY_METHOD_FUNC(rb_dfmemwrite), 2);
    rb_define_singleton_method(rb_cDFHack, "vectorat", RUBY_METHOD_FUNC(rb_dfvectorat), 2);
    rb_define_singleton_method(rb_cDFHack, "readstring", RUBY_METHOD_FUNC(rb_dfreadstring), 1);
    rb_define_singleton_method(rb_cDFHack, "getaddress", RUBY_METHOD_FUNC(rb_dfgetaddress), 2);
    rb_define_singleton_method(rb_cDFHack, "register_dfcommand", RUBY_METHOD_FUNC(rb_dfregister), 2);

    rb_define_singleton_method(rb_cDFHack, "cursor", RUBY_METHOD_FUNC(rb_guicursor), 0);
    rb_define_singleton_method(rb_cDFHack, "cursor_set", RUBY_METHOD_FUNC(rb_guicursorset), 3);
    rb_define_singleton_method(rb_cDFHack, "view", RUBY_METHOD_FUNC(rb_guiview), 0);
    rb_define_singleton_method(rb_cDFHack, "view_set", RUBY_METHOD_FUNC(rb_guiviewset), 3);
    rb_define_singleton_method(rb_cDFHack, "vegetation", RUBY_METHOD_FUNC(rb_dfvegetation), 0);
    rb_define_singleton_method(rb_cDFHack, "creatures", RUBY_METHOD_FUNC(rb_dfcreatures), 0);
    rb_define_singleton_method(rb_cDFHack, "mat_creatures", RUBY_METHOD_FUNC(rb_dfmatcreatures), 0);
    rb_define_singleton_method(rb_cDFHack, "mat_inorganic", RUBY_METHOD_FUNC(rb_dfmatinorganic), 0);
    rb_define_singleton_method(rb_cDFHack, "mat_organic", RUBY_METHOD_FUNC(rb_dfmatorganic), 0);
    rb_define_singleton_method(rb_cDFHack, "laborname", RUBY_METHOD_FUNC(rb_getlaborname), 1);
    rb_define_singleton_method(rb_cDFHack, "skillname", RUBY_METHOD_FUNC(rb_getskillname), 1);

    rb_cCoord = rb_define_class_under(rb_cDFHack, "Coord", rb_cObject);

    // defines reader/writer functions
#define ACCESSOR(cls, method, func) \
    rb_define_method(cls, method, RUBY_METHOD_FUNC(rb_ ## func), 0); \
    rb_define_method(cls, method "=", RUBY_METHOD_FUNC(rb_ ## func ## set), 1)

    rb_cWrapData = rb_define_class_under(rb_cDFHack, "WrapData", rb_cObject);
    rb_define_method(rb_cWrapData, "memaddr", RUBY_METHOD_FUNC(rb_memaddr), 0);

    rb_cMap = rb_define_class_under(rb_cDFHack, "Map", rb_cWrapData);
    rb_define_singleton_method(rb_cMap, "new", RUBY_METHOD_FUNC(rb_mapnew), 0);
    rb_define_method(rb_cMap, "startfeatures", RUBY_METHOD_FUNC(rb_mapstartfeat), 0);
    rb_define_method(rb_cMap, "stopfeatures", RUBY_METHOD_FUNC(rb_mapstopfeat), 0);
    rb_define_method(rb_cMap, "size", RUBY_METHOD_FUNC(rb_mapsize), 0);         // size in 16x16 blocks
    rb_define_method(rb_cMap, "block", RUBY_METHOD_FUNC(rb_mapblock), 3);
    rb_define_method(rb_cMap, "read_geology", RUBY_METHOD_FUNC(rb_mapreadgeology), 0);

    rb_cMapBlock = rb_define_class_under(rb_cMap, "Block", rb_cWrapData);
    rb_define_method(rb_cMapBlock, "pos", RUBY_METHOD_FUNC(rb_blockpos), 0);
    rb_define_method(rb_cMapBlock, "tiletype", RUBY_METHOD_FUNC(rb_blockttype), 2);
    rb_define_method(rb_cMapBlock, "tiletype_set", RUBY_METHOD_FUNC(rb_blockttypeset), 3);
    rb_define_method(rb_cMapBlock, "designation", RUBY_METHOD_FUNC(rb_blockdesign), 2);
    rb_define_method(rb_cMapBlock, "designation_set", RUBY_METHOD_FUNC(rb_blockdesignset), 3);
    rb_define_method(rb_cMapBlock, "tilename", RUBY_METHOD_FUNC(rb_blocktname), 2);
    rb_define_method(rb_cMapBlock, "tileshape", RUBY_METHOD_FUNC(rb_blocktshape), 2);
    rb_define_method(rb_cMapBlock, "tilemat", RUBY_METHOD_FUNC(rb_blocktmat), 2);
    ACCESSOR(rb_cMapBlock, "designationmap", blockdesignmap);
    ACCESSOR(rb_cMapBlock, "flags", blockflags);
    rb_define_method(rb_cMapBlock, "veins", RUBY_METHOD_FUNC(rb_blockveins), 0);
    rb_define_method(rb_cMapBlock, "region_offset", RUBY_METHOD_FUNC(rb_blockregoffset), 1);

    rb_cMapVein = rb_define_class_under(rb_cMap, "Vein", rb_cWrapData);
    ACCESSOR(rb_cMapVein, "type", veintype);
    ACCESSOR(rb_cMapVein, "flags", veinflags);
    ACCESSOR(rb_cMapVein, "assignment", veinassign);

    rb_cPlant = rb_define_class_under(rb_cDFHack, "Plant", rb_cWrapData);
    rb_define_method(rb_cPlant, "pos", RUBY_METHOD_FUNC(rb_plantpos), 0);
    ACCESSOR(rb_cPlant, "material", plantmaterial);
    ACCESSOR(rb_cPlant, "is_shrub", plantisshrub);
    ACCESSOR(rb_cPlant, "is_burning", plantisburning);
    ACCESSOR(rb_cPlant, "grow_counter", plantgrowcounter);
    ACCESSOR(rb_cPlant, "hitpoints", planthitpoints);

    rb_cCreature = rb_define_class_under(rb_cDFHack, "Creature", rb_cWrapData);
    rb_define_method(rb_cCreature, "pos", RUBY_METHOD_FUNC(rb_creapos), 0);
    rb_define_method(rb_cCreature, "name", RUBY_METHOD_FUNC(rb_creaname), 0);
    ACCESSOR(rb_cCreature, "labors", crealabors);
    ACCESSOR(rb_cCreature, "attribs", creaattribs);
    ACCESSOR(rb_cCreature, "skills", creaskills);
    ACCESSOR(rb_cCreature, "race", crearace);
    ACCESSOR(rb_cCreature, "id", creaid);
    ACCESSOR(rb_cCreature, "civ", creaciv);
    ACCESSOR(rb_cCreature, "mood", creamood);
    ACCESSOR(rb_cCreature, "flags1", creaflags1);
    ACCESSOR(rb_cCreature, "flags2", creaflags2);
    ACCESSOR(rb_cCreature, "flags3", creaflags3);
    ACCESSOR(rb_cCreature, "sex", creasex);
    ACCESSOR(rb_cCreature, "caste", creacaste);
    ACCESSOR(rb_cCreature, "pregnancy_timer", creapregtimer);
    ACCESSOR(rb_cCreature, "able_grasp_impaired", creagraspimpair);

    rb_cMatCreature = rb_define_class_under(rb_cDFHack, "MatCreature", rb_cWrapData);
    rb_define_method(rb_cMatCreature, "name", RUBY_METHOD_FUNC(rb_matcrename), 0);
    rb_define_method(rb_cMatCreature, "castename", RUBY_METHOD_FUNC(rb_matcrecastename), 1);   // idx = creature.sex

    rb_cMatInorganic = rb_define_class_under(rb_cDFHack, "MatInorganic", rb_cWrapData);
    rb_define_method(rb_cMatInorganic, "name", RUBY_METHOD_FUNC(rb_matinoname), 0);

    rb_cMatOrganic = rb_define_class_under(rb_cDFHack, "MatOrganic", rb_cWrapData);
    rb_define_method(rb_cMatOrganic, "name", RUBY_METHOD_FUNC(rb_matorgname), 0);


    // load the default ruby-level definitions
    int state=0;
    rb_load_protect(rb_str_new2("./hack/plugins/ruby.rb"), Qfalse, &state);
    if (state)
        dump_rb_error();
}
