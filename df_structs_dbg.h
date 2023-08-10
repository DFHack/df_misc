#ifdef __METASM__
typedef __int8 int8_t;
typedef unsigned __int8 uint8_t;
typedef __int16 int16_t;
typedef unsigned __int16 uint16_t;
typedef __int32 int32_t;
typedef unsigned __int32 uint32_t;
#endif

#ifdef __cplusplus

#define vector(i) std::vector<i>

#elif !defined(LINUX)

#define vector(i) struct { i* ptr; i* endptr; i* endalloc; int pad; }
typedef struct string {
    union {
        char buf[16];
        char *ptr;
    };
    int len;
    int capa;
    int pad;
} string;

#else

#define vector(i) struct { i* ptr; i* endptr; i* endalloc; }
typedef struct string {
    char* ptr;
} string;

#endif

typedef struct df_name {
    string first_name;
    string nick_name;
    int32_t words[7];
    int16_t parts_of_speech[7];
    int32_t language;
    int16_t unk;
    int8_t has_name;
    int8_t pad;
} df_name;


typedef union t_creaturflags1
{
    uint32_t whole;
#ifndef NO_CREATURE_FLAGS
    struct
    {
        unsigned int move_state : 1;       //!( 0 : Can the dwarf move or are they waiting for their movement timer
        unsigned int dead : 1;             //!( 1 : Dead (might also be set for incoming/leaving critters that are alive)
        unsigned int has_mood : 1;         //!( 2 : Currently in mood
        unsigned int had_mood : 1;         //!( 3 : Had a mood already
        unsigned int marauder : 1;         //!( 4 : wide class of invader/inside creature attackers
        unsigned int drowning : 1;         //!( 5 : Is currently drowning
        unsigned int merchant : 1;         //!( 6 : An active merchant
        unsigned int forest : 1;           //!( 7 : used for units no longer linked to merchant/diplomacy, they just try to leave mostly
        unsigned int left : 1;             //!( 8 : left the map
        unsigned int rider : 1;            //!( 9 : Is riding an another creature
        unsigned int incoming : 1;         //!( 10
        unsigned int diplomat : 1;         //!( 11
        unsigned int zombie : 1;           //!( 12
        unsigned int skeleton : 1;         //!( 13
        unsigned int can_swap : 1;         //!( 14: Can swap tiles during movement (prevents multiple swaps)
        unsigned int on_ground : 1;        //!( 15: The creature is laying on the floor, can be conscious
        unsigned int projectile : 1;       //!( 16: Launched into the air? Funny.
        unsigned int active_invader : 1;   //!( 17: Active invader (for organized ones)
        unsigned int hidden_in_ambush : 1; //!( 18
        unsigned int invader_origin : 1;   //!( 19: Invader origin (could be inactive and fleeing)
        unsigned int coward : 1;           //!( 20: Will flee if invasion turns around
        unsigned int hidden_ambusher : 1;  //!( 21: Active marauder/invader moving inward?
        unsigned int invades : 1;          //!( 22: Marauder resident/invader moving in all the way
        unsigned int check_flows : 1;      //!( 23: Check against flows next time you get a chance
        unsigned int ridden : 1;           //!( 24
        unsigned int caged : 1;            //!( 25
        unsigned int tame : 1;             //!( 26
        unsigned int chained : 1;          //!( 27
        unsigned int royal_guard : 1;      //!( 28
        unsigned int fortress_guard : 1;   //!( 29
        unsigned int suppress_wield : 1;   //!( 30: Suppress wield for beatings/etc
        unsigned int important_historical_figure : 1; //!( 31: Is an important historical figure
    } bits;
#endif
} t_creaturflags1;

typedef union t_creaturflags2
{
    uint32_t whole;
#ifndef NO_CREATURE_FLAGS
    struct
    {
        unsigned int swimming : 1;
        unsigned int sparring : 1;
        unsigned int no_notify : 1; //!( Do not notify about level gains (for embark etc)
        unsigned int unused : 1;
        unsigned int calculated_nerves : 1;
        unsigned int calculated_bodyparts : 1;
        unsigned int important_historical_figure : 1; //!( Is important historical figure (slight variation)
        unsigned int killed : 1; //!( Has been killed by kill function (slightly different from dead, not necessarily violent death)
        unsigned int cleanup_1 : 1; //!( Must be forgotten by forget function (just cleanup)
        unsigned int cleanup_2 : 1; //!( Must be deleted (cleanup)
        unsigned int cleanup_3 : 1; //!( Recently forgotten (cleanup)
        unsigned int for_trade : 1; //!( Offered for trade
        unsigned int trade_resolved : 1;
        unsigned int has_breaks : 1;
        unsigned int gutted : 1;
        unsigned int circulatory_spray : 1;
        unsigned int locked_in_for_trading : 1; //!( Locked in for trading (it's a projectile on the other set of flags, might be what the flying was)
        unsigned int slaughter : 1; //!( marked for slaughter
        unsigned int underworld : 1; //!( Underworld creature
        unsigned int resident : 1; //!( Current resident
        unsigned int cleanup_4 : 1; //!( Marked for special cleanup as unused load from unit block on disk
        unsigned int calculated_insulation : 1; //!( Insulation from clothing calculated
        unsigned int visitor_uninvited : 1; //!( Uninvited guest
        unsigned int visitor : 1; //!( visitor
        unsigned int calculated_inventory : 1; //!( Inventory order calculated
        unsigned int vision_good : 1; //!( Vision -- have good part
        unsigned int vision_damaged : 1; //!( Vision -- have damaged part
        unsigned int vision_missing : 1; //!( Vision -- have missing part
        unsigned int breathing_good : 1; //!( Breathing -- have good part
        unsigned int breathing_problem : 1; //!( Breathing -- having a problem
        unsigned int roaming_wilderness_population_source : 1;
        unsigned int roaming_wilderness_population_source_not_a_map_feature : 1;
    } bits;
#endif
} t_creaturflags2;

typedef union t_creaturflags3
{
    uint32_t whole;
#ifndef NO_CREATURE_FLAGS
    struct
    {
        unsigned int unk0 : 1; //!( Is 1 for new and dead creatures, periodicaly set to 0 for non-dead creatures.
        unsigned int unk1 : 1; //!( Is 1 for new creatures, periodically set to 0 for non-dead creatures.
        unsigned int unk2 : 1; //!( Is set to 1 every tick for non-dead creatures.
        unsigned int unk3 : 1; //!( Is periodically set to 0 for non-dead creatures.
        unsigned int announce_titan : 1; //!( Announces creature like an FB or titan.
        unsigned int unk5 : 1;
        unsigned int unk6 : 1;
        unsigned int unk7 : 1;
        unsigned int unk8 : 1; //!( Is set to 1 every tick for non-dead creatures.
        unsigned int unk9 : 1; //!( Is set to 0 every tick for non-dead creatures.
        unsigned int scuttle : 1; //!( Scuttle creature: causes creature to be killed, leaving a behind corpse and generating negative thoughts like a real kill.
        unsigned int unk11 : 1;
        unsigned int ghostly : 1; //!( Creature is a ghost.

        unsigned int unk13_31 : 19;
    } bits;
#endif
} t_creaturflags3;

#define NUM_CREATURE_LABORS 94
#define NUM_CREATURE_TRAITS 30
#define NUM_CREATURE_MENTAL_ATTRIBUTES 13
#define NUM_CREATURE_PHYSICAL_ATTRIBUTES 6

#define MAX_COLORS  15

typedef struct df_attrib
{
    uint32_t unk_0;
    uint32_t unk_4;
    uint32_t unk_8;
    uint32_t unk_c;
    uint32_t unk_10;
    uint32_t unk_14;
    uint32_t unk_18;
} df_attrib;

typedef struct df_skill
{
    uint16_t id;    // 0
    int32_t rating; // 4
    uint32_t experience;    // 8
    uint32_t unk_c;
    uint32_t rusty; // 10
    uint32_t unk_14;
    uint32_t unk_18;
    uint32_t unk_1c;
} df_skill;

typedef struct df_soul
{
    uint32_t creature_id;
    df_name name;   // 4
    uint32_t race;
    uint8_t sex;
    uint8_t pad_75;
    uint16_t unk_76;
    int32_t unk_78;
    int32_t unk_7c;
    int32_t unk_80;
    int32_t unk_84;
    int32_t unk_88_new;
    int32_t unk_8c_new;
    int32_t unk_90_new;
    int32_t unk_94_new;
    df_attrib mental[NUM_CREATURE_MENTAL_ATTRIBUTES];       // 88..1f3
    vector(df_skill*) skills; // 1f4;
    vector(void*) likes;
    uint16_t traits[NUM_CREATURE_TRAITS];   // 214
    vector(int16_t*) unk_250;  // 1 pointer to 2 shorts
    vector(uint32_t) unk_260;
} df_soul;

typedef struct df_reference {
    void *vtable;
    uint32_t id;
} df_reference;

typedef struct df_jobref {
    uint32_t unk_0;
    struct df_job* task;
    uint32_t unk_8;
} df_jobref;

typedef struct df_item {    // item_woodst etc
    void *vtable;
    int16_t x;
    int16_t y;
    int16_t z;
    int16_t pad_a;
    uint32_t flags;
    uint32_t age;
    uint32_t id;
    vector(df_jobref*) inuse;
    vector(void*) refs;    // general_ref_building_holderst, general_ref_unit_ownerst, general_ref_contained_in_itemst, ...

    uint16_t unk_38;    // material info ?
    uint16_t pad_3a;
    uint32_t unk_3c;
    uint16_t pad_40;
    uint16_t unk_42;

    uint16_t unk_44;
    uint16_t unk_46;
    uint16_t unk_48;    // 60000 * 4
    uint16_t unk_4a;
    uint16_t unk_4c;
    uint16_t unk_4e;

    uint32_t unk_50;
    uint32_t unk_54;
    uint32_t stack_size;    // 58
    uint32_t unk_5c;
    uint32_t unk_60;
    void *splatter;        // 64: vector(df_contaminant*)

    uint16_t temperature;
    uint16_t temperature_fraction;
    uint16_t unk_6c;
    uint16_t pad_6e;
    uint32_t unk_70;

    uint32_t unk_74;
    uint32_t unk_78;
    uint32_t unk_7c;
} df_item;

struct item_drinkst {
    df_item i;

    uint16_t material;
    uint16_t pad;
    uint32_t material_idx;
};

struct item_seedsst {
    df_item i;

    uint32_t age;    // 80: determite growth state
    uint32_t unk_84;
};

struct item_plantst {
    df_item i;

    uint32_t age;    // 80: determine withered state
};

// TODO find the base class
struct itemdef_glovesst {
    void **vtable;

    string name_raw;    // ITEM_GLOVES_GLOVES
    uint16_t subtype;
    uint16_t pad;
    string name_singular;    // glove
    string name_plural;    // gloves

    uint32_t unk_5c;
    uint8_t unk_60;
    uint8_t pad_61;
    uint16_t unk_62;

    void *flagarray_ptr_1;    // [0]
    uint32_t flagarray_len_1;
    uint32_t unk_6c;

    void *flagarray_ptr_2;    // [33, 1]
    uint32_t flagarray_len_2;

    uint32_t unk_78;
    uint16_t unk_7c;
    uint16_t unk_7e;
    uint16_t unk_80;
    uint16_t pad_82;
};

struct item_glovesst {
    df_item i;

    uint32_t unk_80;    // race idx ? 241
    uint32_t unk_84;
    int32_t unk_88;
    int32_t unk_8c;

    vector(void*) itemimprovements;    // itemimprovement_threadst / itemimprovement_clothst

    struct itemdef_glovest *itemdef;    // a0

    char *flagarray_ptr;
    uint32_t flagarray_len;
};

typedef struct df_job_link
{
    struct df_job *job;
    struct df_job_link *prev;
    struct df_job_link *next;
} df_job_link;

typedef struct df_job_actor
{
    void *vtable;
    uint32_t id;    // creature id (general_ref_unit_workerst)
            // building id (general_ref_building_holderst when construct building)
} df_job_actor;

typedef struct df_item_wrap
{
    df_item *item;    // item_boulderst, etc
    uint32_t unk_4;
    uint32_t unk_8;
    uint32_t unk_c;
} df_item_wrap;

typedef struct df_job_unk94
{
    int16_t unk_0;
    int16_t unk_2;
    int16_t unk_4;
    int16_t pad_6;
    uint32_t unk_8;
    uint32_t unk_c;
    uint32_t unk_10;
    uint16_t unk_14;
    int16_t pad_16;
    uint32_t unk_18;
    uint32_t unk_1c;
    uint32_t unk_20;
    uint32_t unk_24;
    int32_t unk_28;
    string unk_2c;
    string unk_48;
    int32_t unk_64;
    int32_t unk_68;
    vector(uint32_t) unk_6c;
    int32_t unk_7c;
    int16_t unk_80;
    int16_t pad_82;
} df_job_unk94;

typedef struct df_job
{
    uint32_t job_id;
    df_job_link* job_links;
    int16_t job_type;    // 8: 73 = construct rock coffin, 81 = construct rock block
    int16_t pad_a;
    int32_t unk_c;
    int16_t x;
    int16_t y;
    int16_t z;
    int16_t pad_16;
    int32_t counter;    // 18: job done when reach -1, decremented on df_creature:job_counter
    void* unk_1c;
    struct {
        uint32_t repeat:1;
        uint32_t suspended:1;
        uint32_t unk_4:1;
        uint32_t active:1;    // ?
        uint32_t unk:28;
    } flags;    // 20
    int16_t unk_24;
    int16_t pad_26;
    int32_t unk_28;
    int16_t unk_2c;
    int16_t unk_2e;
    int16_t unk_30;
    int16_t pad_32;
    uint32_t unk_34;
    int32_t unk_38;
    uint32_t unk_3c;
    string unk_40;
    uint32_t unk_5c;
    uint32_t unk_60;
    vector(df_item_wrap*) materials;
    vector(uint32_t) unk_74;
    vector(df_job_actor*) actors;
    vector(df_job_unk94*) unk_94;
} df_job;

typedef struct df_relationship
{
    uint32_t creature_id;
    uint32_t unk_4;    // 30
    uint32_t last_seen;    // ?  increments every job_counter loop
    uint32_t type:2;    // 0=longterm acquaintance, 1=friend, 2=grudge, 3=friend
} df_relationship;

typedef struct df_body_layer
{
    string name;        // 'CHITIN', 'FAT'
    uint32_t unk_1c;
    uint8_t *unk_20;    // ptr to 1 byte, 0 or 1
    uint32_t unk_24;
    uint32_t unk_28;
    uint32_t unk_2c;
    uint32_t unk_30;
    uint32_t unk_34;
    int32_t unk_38;
    int16_t unk_3c;
    uint16_t pad_3e;
    vector(uint32_t) unk_40;
    uint32_t unk_50;
    int32_t unk_54;
    int32_t unk_58;
    int32_t unk_5c;
    int32_t unk_60;
    int32_t unk_64;
    int32_t unk_68;
} df_body_layer;

typedef struct df_body_part
{
    string abbrev;    // 'HD', 'RWING'
    string rawname;        // 'HEAD', 'WING'
    int16_t unk_38;
    uint16_t pad_3a;
    void *unk_3c;
    uint32_t unk_40;
    vector(df_body_layer*) layers;
    uint32_t unk_54;    // 1000
    uint32_t unk_58;    // 1000
    uint32_t unk_5c;
    uint32_t unk_60;
    uint32_t unk_64;    // 500
    uint32_t unk_68;
    int16_t unk_6c;
    vector(string*) name_singular;
    vector(string*) name_plural;
} df_body_part;

typedef struct df_building
{
    void *vtable;
    uint32_t x1;
    uint32_t y1;
    uint32_t x2;
    uint32_t x3;
    uint32_t y2;
    uint32_t y3;
    uint32_t z;
    uint32_t height;
    int16_t material_type;
    uint16_t pad_22;
    int32_t material_index;
    uint8_t *unk_2c;    // room shape?
    uint32_t x_min;    // left
    uint32_t y_min;    // top
    uint32_t x_width;
    uint32_t y_height;
    uint32_t age;
    uint16_t unk_44;
    uint16_t pad_46;
    uint32_t id;
    vector(df_job*) tasks;    // 4c: construct rock bed etc
    vector(uint32_t) unk_5c;
    vector(uint32_t) unk_6c;
    uint8_t is_room;
    uint8_t pad_7d;
    uint16_t pad_7e;
    vector(struct df_building*) covered_buildings;    // other buildings inside the room
    vector(struct df_building*) associated_buildings;    // eg chair -> table
    struct df_creature *owner;    // a0
    vector(uint32_t) unk_a4;
    string unk_b4;    // NOT the building name (bedroom -> n)
    vector(uint32_t) unk_d0;
} df_building;

struct building_doorst {
    struct df_building b;

    uint32_t unk_e0;
    uint32_t unk_e4;
    uint32_t unk_e8;
    uint32_t unk_ec;
    uint32_t unk_f0;
    uint32_t unk_f4;

    struct {
        uint32_t forbid_passage:1;
        uint32_t external:1;
        uint32_t taken_by_invaders:1;
        uint32_t used_by_intruder:1;
        uint32_t closed:1;    // currently open/closed
        uint32_t operated_by_mechanism:1;
        uint32_t pet_passable:1;
        uint32_t unk:25;
    } flags;    // f8
};

struct building_farmplotst {
    struct df_building b;

    uint32_t unk_e0;
    uint32_t unk_e4;
    uint32_t unk_e8;
    uint32_t unk_ec;
    uint32_t unk_f0;
    uint32_t unk_f4;

    uint16_t plantation_program[4];    // per season ; 40 = plump helmet, -1 = nothing
    uint32_t unk_100;
    struct {
        uint32_t season_fert:1;
        uint32_t unk:31;
    } flags;    // 104
    uint8_t unk_108;
    uint8_t pad_109;
    uint16_t pad_10a;
    uint32_t unk_10c;
    uint32_t unk_110;
    uint16_t unk_114;
};

struct building_workshopst {
    struct df_building b;

    uint32_t unk_e0;
    uint32_t unk_e4;
    uint32_t unk_e8;
    uint32_t unk_ec;
    uint32_t unk_f0;
    uint32_t unk_f4;

    uint16_t workshop_type;    // 2 => masonry
    vector(uint32_t) workshop_profile_ids;    // vector of df_creature id
    uint32_t workshop_profile_minproficiency;
    uint32_t workshop_profile_maxproficiency;    // when set, between 0-15 ; when unset =3000
    int32_t unk_114;    // -1
    int32_t unk_118;    // 0
    int32_t unk_11c;    // -1
};

struct building_tradedepotst {
    struct df_building b;

    uint32_t unk_e0;
    uint32_t unk_e4;
    uint32_t unk_e8;
    uint32_t unk_ec;
    uint32_t unk_f0;
    uint32_t unk_f4;

    struct {
        uint32_t trader_requested:1;
        uint32_t anyone_may_trade:1;
        uint32_t unk:30;
    } flags;    // f8
    uint32_t pad_fc;
};

struct building_stockpilest {
    struct df_building b;

    uint32_t category_flags;    // 0xe0

    // all uint8_t here are flags, eg 0/1
    uint8_t animal_empty_cages;
    uint8_t animal_empty_traps;
    uint16_t pad_e6;
    vector(uint8_t) animals;

    vector(uint8_t) food_meat;    // 0xf8
    vector(uint8_t) food_fish;
    vector(uint8_t) food_unprepared_fish;
    vector(uint8_t) food_egg;
    vector(uint8_t) food_plants;
    vector(uint8_t) food_drink_plant;
    vector(uint8_t) food_drink_animal;
    vector(uint8_t) food_cheese_plant;
    vector(uint8_t) food_cheese_animal;
    vector(uint8_t) food_seeds;
    vector(uint8_t) food_leaves;
    vector(uint8_t) food_powder_plant;
    vector(uint8_t) food_powder_creature;
    vector(uint8_t) food_glob;
    vector(uint8_t) food_glob_paste;
    vector(uint8_t) food_glob_pressed;
    vector(uint8_t) food_liquid_plant;
    vector(uint8_t) food_liquid_animal;
    vector(uint8_t) food_liquid_misc;
    uint8_t food_prepared_meals;
    uint8_t pad_229;
    uint16_t pad_22a;

    vector(uint8_t) furniture_type;    // 0x22c
    vector(uint8_t) furniture_other_mats;
    vector(uint8_t) furniture_mats;
    uint8_t furniture_quality_core[7];
    uint8_t furniture_quality_total[7];
    uint8_t furniture_sand_bags;
    uint8_t pad_26b;
    uint32_t pad_26c;

    vector(uint8_t) refuse_type;    // 0x270
    vector(uint8_t) refuse_corpse;
    vector(uint8_t) refuse_body_parts;
    vector(uint8_t) refuse_skulls;
    vector(uint8_t) refuse_bones;
    vector(uint8_t) refuse_shells;
    vector(uint8_t) refuse_teeth;
    vector(uint8_t) refuse_horns;
    vector(uint8_t) refuse_hair;
    uint8_t refuse_fresh_raw_hide;
    uint8_t refuse_rotten_raw_hide;
    uint16_t pad_302;

    vector(uint8_t) stone;    // 0x304

    vector(uint8_t) unk_314;

    vector(uint8_t) ammo_type; // 0x324
    vector(uint8_t) ammo_other_mats;
    vector(uint8_t) ammo_mats;
    uint8_t ammo_quality_core[7];
    uint8_t ammo_quality_total[7];
    uint16_t pad_362;

    vector(uint8_t) coins;    // 0x364

    vector(uint8_t) bars_other_mats;    // 0x374
    vector(uint8_t) blocks_other_mats;
    vector(uint8_t) bars_mats;
    vector(uint8_t) blocks_mats;
    vector(uint8_t) gems_rough_other_mats;
    vector(uint8_t) gems_cut_other_mats;
    vector(uint8_t) gems_rough_mats;
    vector(uint8_t) gems_cut_mats;

    vector(uint8_t) finished_goods_type;    // 0x3f4
    vector(uint8_t) finished_goods_other_mats;
    vector(uint8_t) finished_goods_mats;
    uint8_t finished_goods_quality_core[7];
    uint8_t finished_goods_quality_total[7];
    uint16_t pad_432;

    vector(uint8_t) leather;    // 0x434
    vector(uint8_t) cloth_thread_silk;
    vector(uint8_t) cloth_thread_plant;
    vector(uint8_t) cloth_thread_yarn;
    vector(uint8_t) cloth_thread_metal;
    vector(uint8_t) cloth_cloth_silk;
    vector(uint8_t) cloth_cloth_plant;
    vector(uint8_t) cloth_cloth_yarn;
    vector(uint8_t) cloth_cloth_metal;

    vector(uint8_t) wood;    // 0x4c4

    vector(uint8_t) weapon_weapon_type;
    vector(uint8_t) weapon_trapcomp_type;
    vector(uint8_t) weapon_other_mats;
    vector(uint8_t) weapon_mats;
    uint8_t weapons_quality_core[7];
    uint8_t weapons_quality_total[7];
    uint8_t weapons_usable;
    uint8_t weapons_unusable;

    vector(uint8_t) armor_body;    // 0x524
    vector(uint8_t) armor_head;
    vector(uint8_t) armor_feet;
    vector(uint8_t) armor_hands;
    vector(uint8_t) armor_legs;
    vector(uint8_t) armor_shield;
    vector(uint8_t) armor_other_mats;
    vector(uint8_t) armor_mats;
    uint8_t armor_quality_core[7];
    uint8_t armor_quality_total[7];
    uint8_t armor_usable;
    uint8_t armor_unusable;

    uint8_t allow_organic;    // 0x5b4
    uint8_t allow_inorganic;
    uint16_t pad_5b6;

    uint16_t max_barrels;    // 5b8
    uint16_t max_bins;

    vector(uint32_t) unk_5bc;
    vector(uint32_t) unk_5cc;
    vector(uint32_t) unk_5dc;
    vector(uint16_t) unk_5ec;

    df_building *give_to;
    vector(df_building*) take_from;

    uint32_t stockpile_number;

};

typedef struct df_unit_unk_evt {
    uint16_t type;    // 13 => sober_since: "he needs alcohol to get through the working day" (value=age), 15 => death_seen: "getting used to tragedy" (value=degree)
    uint16_t unk_2;
    uint32_t value;    // may be decremented/incremented every tick (depends on the type)
            // if decrements, evt is deleted at 0
} df_unit_unk_evt;

typedef struct df_unit_recentevent {
    uint16_t type;
    uint16_t pad_2;
    uint32_t age;    // tick count
    int32_t type_param1;    // type=128 (admired a) p1=what (0=seat, 1=bed..)
    uint32_t type_param2;    // type=128 p2=quality (0..50=fine, 150=very fine, 15000=completely sublime)
    uint16_t unk_10;    // set for 'admired a very fine well' / 'made a friend'
    uint16_t unk_12;    // set for 'admired fine well'
} df_unit_recentevent;


typedef struct df_unit_spatter {
    uint16_t material_type;
    uint16_t pad_2;
    int32_t material_subtype;
    int16_t material_state;    // 0=frozen 1=liquid 2=gas 3=powder 4=paste 5=pressed
    int16_t temperature;
    int16_t unk_c;
    int16_t pad_e;
    int32_t quantity;
    int16_t bodypart_idx;
    int16_t unk_16;    // body_plan_index ? cant find stuff if != 1 on a dwarf
} df_unit_spatter;

typedef struct df_creature_pregnancy {
    uint8_t *unk_0;
    uint16_t size_of_unk0;    // dwarf: 32 uint8
    uint16_t pad_6;
    uint16_t *unk_8;
    uint16_t size_of_unk8; // dwarf: 10 uint16
    uint16_t pad_e;
} df_creature_pregnancy;

typedef struct df_creature
{
    df_name name;   // 0
    string custom_profession;  // 6c (MSVC)
    uint16_t profession;     // 88
    uint16_t profession_bis;    // 8a
    uint32_t race;  // 8c
    int16_t x;     // 90
    int16_t y;     // 92
    int16_t z;     // 94

    int16_t unk_x96; // 96
    int16_t unk_y98; // 98
    int16_t unk_z9a; // 9a

    uint32_t unk_9c;
    int16_t unk_a0;
    uint16_t pad_a2;
    uint16_t unk_a4;
    uint16_t unk_a6;

    int16_t dest_x;        // a8
    int16_t dest_y;        // aa
    int16_t dest_z;        // ac
    int16_t unk_ae;        // -1

    vector(uint16_t) path_x;
    vector(uint16_t) path_y;
    vector(uint16_t) path_z;

    t_creaturflags1 flags1;         // e0
    t_creaturflags2 flags2;         // e4
    t_creaturflags3 flags3;         // e8

    int8_t unk_ec;
    uint8_t pad_ed;
    uint16_t pad_ee;
    int32_t unk_f0;
    int16_t unk_f4;
    int16_t pad_f6;
    uint16_t caste;         // f8
    uint8_t sex;            // fa
    uint8_t pad_fb;
    uint32_t id;            // fc
    uint16_t unk_100;
    uint16_t pad_102;
    int32_t unk_104;
    uint32_t civ;           // 108
    int32_t unk_10c;
    int32_t unk_110;
    int32_t unk_114_new;

    vector(uint32_t) unk_114;
    vector(uint32_t) unk_124;
    vector(uint32_t) unk_134;

    uint32_t unk_144;

    vector(void*) unk_148;
    vector(df_reference*) nemesis;    // dwarves have a vector of 1 entry of general_ref_is_nemesisst with their own creature_id     XXX mmh, in fact no

    int32_t squad_index;    // 168: which squad is this dwarf in?
    int32_t squad_position;    // 16c: order inside the squad
    uint32_t unk_170;
    uint32_t draft_timer;    // increments every tick while on duty/carrying order?
    uint16_t unk_178;
    uint16_t pad_17a;

    vector(uint32_t) unk_17c;    // item ids
    vector(uint32_t) unk_18c;
    vector(uint32_t) unk_19c;
    vector(uint32_t) unk_1ac;
    uint32_t pickup_equipment_bit;  // 1bc
    vector(uint32_t) unk_1c0;    // 1c0/1d0: military/civ inventory?
    vector(uint32_t) unk_1d0;
    vector(uint32_t) unk_1e0;

    int32_t unk_1f0;
    int16_t unk_1f4;
    uint16_t pad_1f6;
    int32_t unk_1f8;
    int32_t unk_1fc;
    int32_t unk_200;
    int16_t unk_204;
    uint16_t pad_206;
    uint32_t unk_208;    // damage/fleeing? (hunted creature hit)
    uint32_t unk_20c;

    int16_t mood;           // 210
    uint16_t unk_212;
    uint32_t pregnancy_timer;       // 214
    df_creature_pregnancy* pregnancy_ptr;    // 218
    int16_t unk_21c;
    int16_t unk_21e;
    void* unk_220;    // set on ghost?
    int32_t unk_228_new;
    uint32_t birth_year;    // 224
    uint32_t birth_time;    // 228
    int32_t unk_234_new;
    int32_t unk_238_new;
    uint32_t unk_23c_new;
    uint32_t unk_240_new;
    uint32_t unk_22c;
    uint32_t unk_230;
    struct df_creature* following;    // try to get on the same pos as this creature
    uint16_t unk_238;
    uint16_t pad_23a;
    int32_t unk_23c;
    int32_t married_id;    // 240: not used in relationship screen..
    int32_t mother_id;    // 244: idem
    int32_t father_id;    // 248: idem
    int32_t unk_24c;
    int32_t unk_250;
    int32_t unk_254;
    int32_t unk_258;
    int32_t unk_25c_mother;    // mother id again?
    int32_t lover_id;
    int16_t unk_264;
    int16_t pad_266;
    int32_t unk_268;
    int32_t unk_26c;
    int16_t unk_270;
    int16_t pad_272;
    int32_t unk_274;
    int32_t unk_278;
    int32_t unk_27c;
    int16_t unk_280;
    uint16_t pad_282;
    int32_t unk_284;

    vector(df_item_wrap*) inventory;   // 288 - vector of item pointers
    vector(int32_t) owned_items;  // 298 - vector of item IDs
    vector(uint32_t) unk_2a8;
    vector(df_building*) owned_buildings;    // 2b8 - make room, assign -> added here
    vector(uint32_t) unk_2c8;

    uint32_t unk_2d8;
    uint32_t unk_2dc;
    struct df_creature *hunt_target;    // 2e0
    uint32_t unk_2e4;
    int16_t unk_2e8;    // fight related
    int16_t unk_2ea;    // fight related
    uint16_t unk_2ec;
    uint16_t unk_2ee;
    uint16_t unk_2f0_cntr;    // increments every tick
    uint16_t pad_2f2;
    df_job * current_job;   // 2f4
    uint16_t unk_2f8;
    uint16_t pad_2fa;
    uint32_t unk_2fc;
    uint32_t unk_300;
    uint32_t unk_304;

    vector(uint32_t) unk_308;    // 87*0 ?
    vector(uint32_t) unk_318;
    vector(uint32_t) unk_328;
    vector(uint32_t) unk_338;    // 238*0
    vector(uint32_t) unk_348;    // 238*0
    vector(uint32_t) unk_358;    // 238*0
    vector(uint32_t) unk_368;    // 238*0
    vector(uint32_t) unk_378;    // 238*0
    vector(uint32_t) unk_388;

    uint32_t unk_398;
    int32_t unk_39c;
    int32_t unk_3a0;
    int32_t unk_3a4;
    int32_t unk_3a8;
    int32_t unk_3ac;
    int32_t unk_3b0;
    int32_t unk_3b4;
    int32_t unk_3b8;
    int32_t unk_3bc;
    int32_t unk_3c0;
    void *body_plan;    // vector(df_body_part*)* body_plan;    // points into a giant chunk, raws?
    uint16_t unk_3c8;
    uint16_t pad_3ca;

    df_attrib physical[NUM_CREATURE_PHYSICAL_ATTRIBUTES];   // 3cc..473
    uint32_t unk_474;
    uint32_t unk_478;
    uint32_t unk_47c;
    uint32_t unk_480;
    uint32_t unk_484;
    uint32_t unk_488;

    uint32_t blood_max;
    uint32_t blood_count;   // 490
    uint32_t unk_494;
    vector(df_unit_spatter*) spatters;
    vector(uint16_t) unk_4a8;
    vector(uint16_t) unk_4b8;
    uint32_t unk_4c8;
    vector(int16_t) unk_4cc;
    vector(int32_t) unk_4dc;
    vector(int32_t) unk_4ec;
    vector(int32_t) unk_4fc;
    vector(uint16_t) unk_50c;
    void* unk_51c;
    uint16_t unk_520;
    uint16_t* unk_524;
    uint16_t unk_528;
    uint16_t pad_52a;
    vector(uint32_t) appearance;        // 52c
    int32_t think_counter;    // 53c decrements every job_counter reroll, set when changing jobs
    int32_t job_counter;    // 540 current_job unit/walk done when reach -1, decremented every tick
    int32_t unk_544;    // if set, decrements every job_counter reroll
    int16_t unk_548;
    int16_t pad_54a_new;
    int32_t unk_564_new;
    int16_t winded;
    int16_t stunned;    // 54c decrements every tick, unstun at 0
    int16_t unconscious;
    int16_t unk_550;
    int16_t webbed;
    int16_t unk_x554;       // coords ? (-30.000x3)
    int16_t unk_y556;
    int16_t unk_z558;
    int16_t unk_x55a;       // coords again
    int16_t unk_y55c;
    int16_t unk_z55e;
    int16_t unk_560;
    int16_t unk_562;

    uint32_t unk_564;
    uint32_t unk_568;
    uint32_t unk_56c;
    uint32_t unk_570;
    uint32_t unk_574;
    uint32_t unk_578;
    uint32_t unk_57c;

    uint8_t unk_5a0_new;
    uint8_t pad_5a1_new;
    uint16_t pad_5a2_new;
    string unk_5a4_new;
    string unk_5c0_new;
    string unk_5dc_new;
    uint32_t unk_5f8_new;
    uint32_t unk_5fc_new;
    uint32_t unk_600_new;
    uint32_t unk_604_new;
    vector(uint32_t) unk_608_new;
    vector(uint32_t) unk_618_new;
    uint32_t unk_628_new;
    uint32_t unk_62c_new;
    uint32_t unk_630_new;
    uint32_t unk_634_new;
    vector(uint32_t) unk_638_new;
    vector(uint32_t) unk_648_new;
    vector(uint32_t) unk_658_new;
    uint32_t unk_668_new;
    vector(uint32_t) unk_66c_new;
    vector(uint32_t) unk_67c_new;
    uint32_t unk_68c_new;
    uint32_t unk_690_new;
    uint32_t unk_694_new;
    uint32_t unk_698_new;

    uint32_t unk_580;    // fluctuates a lot, temperature?
    uint32_t unk_584;    // fluctuate
    uint32_t unk_588;    // fluctuate
    uint32_t unk_58c;    // counter, decrement to 0
    uint32_t unk_590;    // same as 58c
    uint32_t unk_594;
    uint32_t unk_598;    // fluctuate
    uint32_t unk_59c;

    vector(df_unit_unk_evt*) unk_5a0_recent_events;    // recent events ? character traits ?
    void* unk_5b0;    //vector(uint32_t)* unk_5b0;    // pointer to 12 vectors (uint32 and uint16)
    uint32_t unk_5b4;       // 0x3e8 (1000)
    uint32_t unk_5b8;       // 0x3e8 (1000)
    vector(uint32_t) unk_5bc;
    vector(uint32_t) unk_5cc;
    int8_t unk_5dc;
    int8_t pad_5dd;
    int16_t pad_5de;
    df_name artifact_name; // 5e0
    vector(df_soul*) souls;      // 64c
    df_soul* current_soul;  // 65c
    vector(uint32_t) unk_660;
    uint8_t labors[NUM_CREATURE_LABORS];    // 670..6cd
    uint16_t pad_6ce;

    vector(uint32_t) unk_6d0;
    vector(uint32_t) unk_6e0;    // item ids?
    vector(df_unit_recentevent*) recent_events;    // 6f0: dined in a legendary dinning room, etc
    vector(uint32_t) unk_700;
    uint32_t happiness;     // 710
    uint16_t unk_714;
    uint16_t pad_716;
    vector(void*) unk_718;
    vector(void*) unk_728;
    vector(df_relationship*) relationships;    // 738
    vector(void*) unk_748;
    uint16_t unk_758;
    int16_t unk_x75a;      // coords (-30000*3)
    int16_t unk_y75c;
    int16_t unk_z75e;
    vector(uint16_t) unk_760;
    vector(uint16_t) unk_770;
    vector(uint16_t) unk_780;
    uint32_t hist_figure_id;        // 790
    uint32_t hist_figure_id_copy_new;    // vampire impersonation?
    uint16_t able_stand;            // 794
    uint16_t able_stand_impair;     // 796
    uint16_t able_grasp;            // 798
    uint16_t able_grasp_impair;     // 79a
    // new: deleted uint32_t unk_79c;
    uint32_t unk_7a0;
    vector(uint32_t*) unk_7a4;
    uint32_t unk_7b4;
    uint32_t unk_7b8;
    uint8_t unk_7bc;
    uint8_t pad_7bd;
    uint16_t pad_7be;
    int32_t unk_7c0;

    vector(uint32_t) unk_7c4;
    vector(uint32_t) unk_7d4;
    vector(uint32_t) unk_7e4;
    vector(uint32_t) unk_7f4;    // combat log?
    vector(uint32_t) unk_804;
    vector(uint32_t) unk_814;

    // new: delete original unk_824 -> unk_840
    vector(void*) unk_940_new;
    vector(void*) unk_950_new;
    uint32_t unk_960_new;    // 960->978 uninit
    uint32_t unk_964_new;
    uint32_t unk_968_new;
    uint32_t unk_96c_new;
    uint32_t unk_970_new;
    uint32_t unk_978_new;
    uint32_t unk_97c_new;
    vector(void*) unk_980_new;
    vector(void*) unk_990_new;
    vector(void*) unk_9a0_new;
    uint32_t unk_9b0_new;    // 0
    uint32_t unk_9b4_new;    // 0x1d1
    uint32_t unk_9b8_new;    // 1
    uint32_t unk_9bc_new;    // 0x1d1
    uint32_t unk_9c0_new;    // 1
    int32_t unk_9c4_new;    // -1

    vector(uint32_t) unk_850;
    vector(uint32_t) unk_860;
    uint32_t unk_870;
    uint32_t unk_874_cntr;    // age ? incremented every tick
    vector(uint8_t) unk_878;
    vector(uint8_t) unk_888;
    vector(uint32_t) unk_898;    // 87*0
    vector(uint8_t) unk_8a8;    // 87*1
    vector(uint16_t) unk_8b8;    // 87*?
    vector(uint16_t) unk_8c8;
    vector(uint16_t) unk_8d8;
    vector(uint32_t) unk_8e8;    // items ids?
    vector(uint16_t) unk_8f8;    // same size as 8e8, soldier related?
    vector(uint32_t) unk_908;    // 238*?

    int32_t unk_918;
    uint16_t unk_91c;    // 91c..922 uninitialized on linux
    uint16_t unk_91e;
    uint16_t unk_920;
    uint16_t unk_922;
    uint32_t unk_924;
    uint32_t unk_928;
    vector(uint16_t) unk_92c;
    uint32_t unk_93c;
} df_creature;



typedef struct bitarray
{
    uint8_t *ptr;
    uint32_t len;
} bitarray;

typedef struct df_block_square_event
{
    void *vtable;
} df_block_square_event;

struct block_square_event_mineralst
{
    df_block_square_event e;

    uint32_t type;
    uint16_t bitmap[16];    // [y] & (1<<x)
};

struct block_square_event_grassst
{
    df_block_square_event e;

    uint32_t type;
    uint8_t intensity[16*16];

};

struct block_square_event_material_spatterst
{
    df_block_square_event e;

    uint16_t mat1;
    uint16_t pad_6;
    uint32_t mat2;
    uint16_t matter_state;
    uint8_t intensity[16*16];    // nopad
    uint16_t unk_10e;    // 0x270f, temperature ?
    uint16_t unk_110;    // 0x27c4, temperature ?
};

struct block_square_event_frozenliquidst    // XXX check name
{
    df_block_square_event e;

    uint16_t original_type[16*16];
};

struct block_square_event_worldconstructionst    // XXX check name
{
    df_block_square_event e;

    uint32_t type;
    uint16_t bitmap[16];
};

typedef struct df_block_effect
{
    uint32_t type;    // 0=miasma, 1-2=mist, 3=dust, 4=magma mist, 5=smoke, 6=dragonfire, 7=fire,
            // 8=web, 9=boiling magma, a=magma vapor, b=ocean wave, c=sea foam
    uint32_t unk_4;

    int16_t cntr;    // counter ? start at 100, -= 15 every 3 tick, set inactive at <=0
    int16_t x;
    int16_t y;
    int16_t z;

    int16_t unk_10;    // coords ?
    int16_t unk_12;
    int16_t unk_14;
    int8_t unk_16;
    int8_t inactive;    // bit 1 -> effect inhibited

    int32_t unk_18;
} df_block_effect;

typedef struct df_block
{
    bitarray flags;
    vector(df_block_square_event*) block_events;

    int32_t unk_18;
    int32_t unk_1c;
    int32_t unk_20;

    int32_t local_feature;  // 24: local feature index
    int32_t global_feature; // 28: global feature index
    int32_t unk_2c;
    int32_t unk_30;    // linux uninit
    int32_t unk_34;
    int32_t unk_38;

    vector(uint32_t) items; // 3c: item ids present in the block
    vector(df_block_effect*) effects;    // 4c: miasma/dust ; vector never shrink?
    int32_t unk_50;    // count effects?
    int32_t unk_54;
    vector(void*) plants;    // 58: vector(df_plant*)

    int16_t map_x;    // 68
    int16_t map_y;
    int16_t map_z;
    int16_t region_x;
    int16_t region_y;    // 70

    // uint16_t pad_72; ?
    uint16_t tiletype[16*16];    // 72
    uint32_t designation[16*16];    //
    uint32_t occupancy[16*16];

    uint8_t unk9[16*16];
    uint32_t pathfinding[16*16];
    uint16_t pathfinding2[16*16];
    uint16_t pathfinding3[16*16];
    uint16_t unk12[16*16];

    uint16_t temperature1[16*16];
    uint16_t temperature2[16*16];

    uint16_t unk13[16*16];
    uint16_t unk14[16*16];

    uint8_t region_offset[9];
} df_block;
