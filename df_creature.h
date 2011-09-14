    // XXX 102 is wrong, with that much there is no space for the std::vector coming after that
    // max = 96
#ifdef NUM_CREATURE_LABORS
#undef NUM_CREATURE_LABORS
#endif
    #define NUM_CREATURE_LABORS 96
    #define NUM_CREATURE_TRAITS 30
    #define NUM_CREATURE_MENTAL_ATTRIBUTES 13
    #define NUM_CREATURE_PHYSICAL_ATTRIBUTES 6

    struct df_attrib {
        uint32_t unk_0;
        uint32_t unk_4;
        uint32_t unk_8;
        uint32_t unk_c;
        uint32_t unk_10;
        uint32_t unk_14;
        uint32_t unk_18;
    };

    struct df_skill {
        uint16_t id;    // 0
        int32_t rating; // 4
        uint32_t experience;    // 8
        uint32_t unk_c;
        uint32_t rusty; // 10
        uint32_t unk_14;
        uint32_t unk_18;
        uint32_t unk_1c;
    };

    struct df_soul
    {
        uint32_t unk_0;
        df_name name;   // 4
        uint32_t unk_70;
        uint16_t unk_74;
        uint16_t unk_76;
        int32_t unk_78;
        int32_t unk_7c;
        int32_t unk_80;
        int32_t unk_84;
        df_attrib mental[NUM_CREATURE_MENTAL_ATTRIBUTES];       // 88..1f3
        std::vector<df_skill*> skills;  // 1f4;
        std::vector<void*> unk_204;     // pointers to 14 0x14-byte structures
        uint16_t traits[NUM_CREATURE_TRAITS];   // 214
        std::vector<int16_t*> unk_250;  // 1 pointer to 2 shorts
        uint32_t unk_260;
        uint32_t unk_264;
        uint32_t unk_268;
        uint32_t unk_26c;
    };

    struct df_creature
    {
        df_name name;   // 0
        std::string custom_profession;  // 6c (MSVC)
        uint8_t profession;     // 88
        uint32_t race;  // 8c
        uint16_t x;     // 90
        uint16_t y;     // 92
        uint16_t z;     // 94

        uint16_t unk_x96; // 96
        uint16_t unk_y98; // 98
        uint16_t unk_z9a; // 9a

        uint32_t unk_9c;
        uint16_t unk_a0;
        int16_t unk_a2;
        uint32_t unk_a4;

        uint16_t dest_x;        // a8
        uint16_t dest_y;        // aa
        uint16_t dest_z;        // ac
        uint16_t unk_ae;        // -1

        std::vector<uint32_t> unk_b0;   // b0->df (3*4 in MSVC) -> 68->8b (3*3 in glibc)
        std::vector<uint32_t> unk_c0;
        std::vector<uint32_t> unk_d0;

        t_creaturflags1 flags1;         // e0
        t_creaturflags2 flags2;         // e4
        t_creaturflags3 flags3;         // e8

        void ** unk_ec;
        int32_t unk_f0;
        int16_t unk_f4;
        int16_t unk_f6;
        uint16_t caste;         // f8
        uint8_t sex;            // fa
        uint32_t id;            // fc
        uint16_t unk_100;
        uint16_t unk_102;
        int32_t unk_104;
        uint32_t civ;           // 108
        uint32_t unk_10c;
        int32_t unk_110;
        
        std::vector<uint32_t> unk_114;
        std::vector<uint32_t> unk_124;
        std::vector<uint32_t> unk_134;

        uint32_t unk_144;

        std::vector<void*> unk_148;
        std::vector<void*> unk_158;

        int32_t unk_168;
        int32_t unk_16c;
        uint32_t unk_170;
        uint32_t unk_174;
        uint16_t unk_178;

        std::vector<uint32_t> unk_17c;
        std::vector<uint32_t> unk_18c;
        std::vector<uint32_t> unk_19c;
        std::vector<uint32_t> unk_1ac;
        uint32_t pickup_equipment_bit;  // 1bc
        std::vector<uint32_t> unk_1c0;
        std::vector<uint32_t> unk_1d0;
        std::vector<uint32_t> unk_1e0;

        int32_t unk_1f0;
        int16_t unk_1f4;
        int32_t unk_1f8;
        int32_t unk_1fc;
        int32_t unk_200;
        int16_t unk_204;
        uint32_t unk_208;
        uint32_t unk_20c;

        int16_t mood;           // 210
        uint32_t pregnancy_timer;       // 214
        void* pregnancy_ptr;    // 218
        int32_t unk_21c;
        uint32_t unk_220;
        uint32_t birth_year;    // 224
        uint32_t birth_time;    // 228
        uint32_t unk_22c;
        uint32_t unk_230;
        uint32_t unk_234;
        uint32_t unk_238;
        int32_t unk_23c;
        int32_t unk_240;
        int32_t unk_244;
        int32_t unk_248;
        int32_t unk_24c;
        int32_t unk_250;
        int32_t unk_254;
        int32_t unk_258;
        int32_t unk_25c;
        int32_t unk_260;
        int16_t unk_264;
        int32_t unk_268;
        int32_t unk_26c;
        int16_t unk_270;
        int32_t unk_274;
        int32_t unk_278;
        int32_t unk_27c;
        int16_t unk_280;
        int32_t unk_284;

        std::vector<void*> inventory;   // 288
        std::vector<uint32_t> owned_items;      // 298
        std::vector<uint32_t> unk_2a8;
        std::vector<uint32_t> unk_2b8;
        std::vector<uint32_t> unk_2c8;

        uint32_t unk_2d8;
        uint32_t unk_2dc;
        uint32_t unk_2e0;
        uint32_t unk_2e4;
        uint32_t unk_2e8;
        uint32_t unk_2ec;
        uint32_t unk_2f0;
        uint32_t current_job;   // 2f4
        uint32_t unk_2f8;
        uint32_t unk_2fc;
        uint32_t unk_300;
        uint32_t unk_304;

        std::vector<uint32_t> unk_308;
        std::vector<uint32_t> unk_318;
        std::vector<uint32_t> unk_328;
        std::vector<uint32_t> unk_338;
        std::vector<uint32_t> unk_348;
        std::vector<uint32_t> unk_358;
        std::vector<uint32_t> unk_368;
        std::vector<uint32_t> unk_378;
        std::vector<uint32_t> unk_388;

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
        uint32_t unk_3c4;
        uint32_t unk_3c8;

        df_attrib physical[NUM_CREATURE_PHYSICAL_ATTRIBUTES];   // 3cc..473
        uint32_t unk_474;
        uint32_t unk_478;
        uint32_t unk_47c;
        uint32_t unk_480;
        uint32_t unk_484;
        uint32_t unk_488;

        uint32_t unk_48c;       // blood_max?
        uint32_t blood_count;   // 490
        uint32_t unk_494;
        std::vector<void*> unk_498;
        std::vector<uint16_t> unk_4a8;
        std::vector<uint16_t> unk_4b8;
        uint32_t unk_4c8;
        std::vector<int16_t> unk_4cc;
        std::vector<int32_t> unk_4dc;
        std::vector<int32_t> unk_4ec;
        std::vector<int32_t> unk_4fc;
        std::vector<uint16_t> unk_50c;
        void* unk_51c;
        uint16_t unk_520;
        uint16_t unk_522;
        uint16_t* unk_524;
        uint16_t unk_528;
        uint16_t unk_52a;
        std::vector<uint32_t> appearance;        // 52c
        int16_t unk_53c;
        int16_t unk_53e;
        int16_t unk_540;
        int16_t unk_542;
        int16_t unk_544;
        int16_t unk_546;
        int16_t unk_548;
        int16_t unk_54a;
        int16_t unk_54c;
        int16_t unk_54e;
        int16_t unk_550;
        int16_t unk_552;
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
        uint32_t unk_580;
        uint32_t unk_584;
        uint32_t unk_588;
        uint32_t unk_58c;
        uint32_t unk_590;
        uint32_t unk_594;
        uint32_t unk_598;
        uint32_t unk_59c;

        std::vector<void*> unk_5a0;
        void* unk_5b0;          // pointer to X (12?) vector<int16_t>
        uint32_t unk_5b4;       // 0x3e8 (1000)
        uint32_t unk_5b8;       // 0x3e8 (1000)
        std::vector<uint32_t> unk_5bc;
        std::vector<uint32_t> unk_5cc;
        int16_t unk_5dc;
        int16_t unk_5de;
        df_name unk_5e0;
        std::vector<df_soul*> souls;      // 64c
        df_soul* current_soul;  // 65c
        std::vector<uint32_t> unk_660;
        uint8_t labors[NUM_CREATURE_LABORS];    // 670..6cf

        std::vector<uint32_t> unk_6d0;
        std::vector<uint32_t> unk_6e0;
        std::vector<uint32_t> unk_6f0;
        std::vector<uint32_t> unk_700;
        uint32_t happiness;     // 710
        uint16_t unk_714;
        uint16_t unk_716;
        std::vector<void*> unk_718;
        std::vector<void*> unk_728;
        std::vector<void*> unk_738;
        std::vector<void*> unk_748;
        uint16_t unk_758;
        uint16_t unk_x75a;      // coords (-30000*3)
        uint16_t unk_y75c;
        uint16_t unk_z75e;
        std::vector<uint16_t> unk_760;
        std::vector<uint16_t> unk_770;
        std::vector<uint16_t> unk_780;
        uint32_t hist_figure_id;        // 790
        uint16_t able_stand;            // 794
        uint16_t able_stand_impair;     // 796
        uint16_t able_grasp;            // 798
        uint16_t able_grasp_impair;     // 79a
        uint32_t unk_79c;
        uint32_t unk_7a0;
        std::vector<void*> unk_7a4;
        uint32_t unk_7b4;
        uint32_t unk_7b8;
        uint32_t unk_7bc;
        int32_t unk_7c0;

        std::vector<uint32_t> unk_7c4;
        std::vector<uint32_t> unk_7d4;
        std::vector<uint32_t> unk_7e4;
        std::vector<uint32_t> unk_7f4;
        std::vector<uint32_t> unk_804;
        std::vector<uint32_t> unk_814;

        uint32_t unk_824;
        void* unk_828;
        void* unk_82c;
        uint32_t unk_830;
        void* unk_834;
        void* unk_838;
        void* unk_83c;

        std::vector<void*> unk_840;
        std::vector<uint32_t> unk_850;
        std::vector<uint32_t> unk_860;
        uint32_t unk_870;
        uint32_t unk_874;
        std::vector<uint8_t> unk_878;
        std::vector<uint8_t> unk_888;
        std::vector<uint32_t> unk_898;
        std::vector<uint8_t> unk_8a8;
        std::vector<uint16_t> unk_8b8;
        std::vector<uint16_t> unk_8c8;
        std::vector<uint32_t> unk_8d8;
        std::vector<uint32_t> unk_8e8;
        std::vector<uint32_t> unk_8f8;
        std::vector<uint32_t> unk_908;

        int32_t unk_918;
        uint16_t unk_91c;
        uint16_t unk_91e;
        uint16_t unk_920;
        uint16_t unk_922;
        uint32_t unk_924;
        uint32_t unk_928;
        std::vector<uint16_t> unk_92c;
        uint32_t unk_93c;
    };



    struct df_creature_mat_caract {
        std::string name;       // beauty
        int16_t value1;
        int16_t value2;
    };

    struct df_creature_mat_caste {
        std::string name;       // FEMALE
        std::string strings[34];        // toad toads toad  14='remains' 15='remains' 16='A squat amphibian..'
        // some more stuff here
    };

    struct df_creature_material {
        std::string rawname;    // TOAD
        std::string name1;      // toad
        std::string name2;      // toads
        std::string name3;      // toad
        std::string unk_4;
        std::string unk_5;
        std::string unk_6;
        std::string unk_7;

        int16_t unk_8[20];

        std::vector<df_creature_mat_caract*> caracts;
        std::vector<uint32_t> unk_a;
        std::vector<df_creature_mat_caste*> castes;
        std::vector<uint32_t> unk_c;

        void *unk_d;
        uint32_t unk_e;
    };
