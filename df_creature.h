    #define NUM_CREATURE_TRAITS 30
    #define NUM_CREATURE_LABORS 102
    #define NUM_CREATURE_MENTAL_ATTRIBUTES 13
    #define NUM_CREATURE_PHYSICAL_ATTRIBUTES 6

    struct df_creature
    {
        df_name name;   // 0
        std::string custom_profession;  // 6c (MSVC)
        uint8_t profession;     // 88
        uint32_t race;  // 8c
        uint16_t x;     // 90
        uint16_t y;     // 92
        uint16_t z;     // 94

        uint16_t unk_x; // 96
        uint16_t unk_y; // 98
        uint16_t unk_z; // 9a

        uint32_t unk_9c;
        uint32_t unk_a0;
        uint32_t unk_a4;

        uint16_t unk_x2;        // a8, -30.000
        uint16_t unk_y2;
        uint16_t unk_z2;
        uint16_t unk_ae;        // -1

        uint32_t unk_b0;
        uint32_t unk_b4;
        uint32_t unk_b8;
        uint32_t unk_bc;
        uint32_t unk_c0;
        uint32_t unk_c4;
        uint32_t unk_c8;
        uint32_t unk_cc;
        uint32_t unk_d0;
        uint32_t unk_d4;
        uint32_t unk_d8;
        uint32_t unk_dc;
        t_creaturflags1 flags_1;        // e0
        t_creaturflags2 flags_2;        // e4
        t_creaturflags3 flags_3;        // e8
        uint32_t unk_ec;
        int32_t unk_f0;
        int32_t unk_f4;
        uint16_t caste;         // f8
        uint8_t sex;            // fa
        uint32_t unk_fc;
        uint32_t unk_100;
        int32_t unk_104;
        uint32_t civ;           // 108
        uint32_t unk_10c;
        uint32_t unk_110;
        uint32_t unk_114;
        uint32_t unk_118;
        int32_t unk_11c;
        uint32_t unk_120;
        uint32_t unk_124;
        uint32_t unk_128;
        uint32_t unk_12c;
        uint32_t unk_130;
        uint32_t unk_134;
        uint32_t unk_138;
        uint32_t unk_13c;
        uint32_t unk_140;
        uint32_t unk_144;
        uint32_t unk_148;
        uint32_t unk_14c;
        uint32_t unk_150;
        uint32_t unk_154;
        std::vector<void*> unk_158;
        int32_t unk_168;
        int32_t unk_16c;
        uint32_t unk_170;
        uint32_t unk_174;
        uint32_t unk_178;
        std::vector<uint32_t> unk_17c;
        uint32_t unk_18c;
        uint32_t unk_190;
        uint32_t unk_194;
        uint32_t unk_198;
        uint32_t unk_19c;
        uint32_t unk_1a0;
        uint32_t unk_1a4;
        uint32_t unk_1a8;
        uint32_t unk_1ac;
        uint32_t unk_1b0;
        uint32_t unk_1b4;
        uint32_t unk_1b8;
        uint32_t pickup_equipment_bit;  // 1bc
        uint32_t unk_1c0;
        uint32_t unk_1c4;
        uint32_t unk_1c8;
        uint32_t unk_1cc;
        uint32_t unk_1d0;
        uint32_t unk_1d4;
        uint32_t unk_1d8;
        uint32_t unk_1dc;
        uint32_t unk_1e0;
        uint32_t unk_1e4;
        uint32_t unk_1e8;
        uint32_t unk_1ec;
        int32_t unk_1f0;
        int16_t unk_1f4;
        int32_t unk_1f8;
        int32_t unk_1fc;
        int32_t unk_200;
        uint32_t unk_204;
        uint32_t unk_208;
        uint32_t unk_20c;
        int16_t mood;           // 210
        uint32_t pregnancy;     // 214
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
        uint32_t unk_264;
        int32_t unk_268;
        int32_t unk_26c;
        int16_t unk_270;
        int32_t unk_274;
        int32_t unk_278;
        int32_t unk_27c;
        int16_t unk_280;
        int32_t unk_284;
        std::vector<void*> inventory;   // 288
        std::vector<uint32_t> unk_298;
        uint32_t unk_2a8;
        uint32_t unk_2ac;
        uint32_t unk_2b0;
        uint32_t unk_2b4;
        std::vector<void*> unk_2b8;
        uint32_t unk_2c8;
        uint32_t unk_2cc;
        uint32_t unk_2d0;
        uint32_t unk_2d4;
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
        uint32_t unk_318;
        uint32_t unk_31c;
        uint32_t unk_320;
        uint32_t unk_324;
        uint32_t unk_328;
        uint32_t unk_32c;
        uint32_t unk_330;
        uint32_t unk_334;
        std::vector<uint32_t> unk_338;
        std::vector<uint32_t> unk_348;
        std::vector<uint32_t> unk_358;
        std::vector<uint32_t> unk_368;
        std::vector<uint32_t> unk_378;
        uint32_t unk_388;
        uint32_t unk_38c;
        uint32_t unk_390;
        uint32_t unk_394;
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
        uint32_t unk_3cc;
        uint32_t unk_3d0;
        uint32_t unk_3d4;
        uint32_t unk_3d8;
        uint32_t unk_3dc;
        uint32_t unk_3e0;
        uint32_t unk_3e4;
        uint32_t unk_3e8;
        uint32_t unk_3ec;
        uint32_t unk_3f0;
        uint32_t unk_3f4;
        uint32_t unk_3f8;
        uint32_t unk_3fc;
        uint32_t unk_400;
        uint32_t unk_404;
        uint32_t unk_408;
        uint32_t unk_40c;
        uint32_t unk_410;
        uint32_t unk_414;
        uint32_t unk_418;
        uint32_t unk_41c;
        uint32_t unk_420;
        uint32_t unk_424;
        uint32_t unk_428;
        uint32_t unk_42c;
        uint32_t unk_430;
        uint32_t unk_434;
        uint32_t unk_438;
        uint32_t unk_43c;
        uint32_t unk_440;
        uint32_t unk_444;
        uint32_t unk_448;
        uint32_t unk_44c;
        uint32_t unk_450;
        uint32_t unk_454;
        uint32_t unk_458;
        uint32_t unk_45c;
        uint32_t unk_460;
        uint32_t unk_464;
        uint32_t unk_468;
        uint32_t unk_46c;
        uint32_t unk_470;
        uint32_t unk_474;
        uint32_t unk_478;
        uint32_t unk_47c;
        uint32_t unk_480;
        uint32_t unk_484;
        uint32_t unk_488;
        uint32_t unk_48c;
        uint32_t blood_count;   // 490
        uint32_t unk_494;
        uint32_t unk_498;
        uint32_t unk_49c;
        uint32_t unk_4a0;
        uint32_t unk_4a4;
        std::vector<uint16_t> unk_4a8;
        std::vector<uint16_t> unk_4b8;
        uint32_t unk_4c8;
        std::vector<int16_t> unk_4cc;
        std::vector<int32_t> unk_4dc;
        std::vector<int32_t> unk_4ec;
        std::vector<int32_t> unk_4fc;
        std::vector<uint16_t> unk_50c;
        void* unk_51c;
        uint32_t unk_520;
        uint16_t* unk_524;
        uint32_t unk_528;
        std::vector<uint32_t> unk_52c;
        uint32_t unk_530;
        uint32_t unk_534;
        uint32_t unk_538;
        uint32_t unk_53c;
        uint32_t unk_540;
        uint32_t unk_544;
        int8_t unk_548;         // TODO recheck those
        int8_t unk_549;
        int8_t unk_54a;
        int8_t winded;          // 54b
        int8_t unk_54c;
        int8_t stunned;         // 54d
        int8_t unk_54e;
        int8_t unconscious;     // 54f
        uint32_t unk_550;
        void* unk_554;
        void* unk_558;
        void* unk_55c;
        int32_t unk_560;
        int8_t unk_564;
        int8_t unk_565;
        int8_t unk_566;
        int8_t extreme_pain;    // 567
        int8_t unk_568;
        int8_t unk_569;
        int8_t unk_56a;
        int8_t nauseous;        // 56b
        int8_t unk_56c;
        int8_t unk_56d;
        int8_t unk_56e;
        int8_t dizzy;           // 56f
        int8_t unk_570;
        int8_t unk_571;
        int8_t unk_572;
        int8_t paralyzed;       // 573
        int8_t unk_574;
        int8_t unk_575;
        int8_t unk_576;
        int8_t numb;            // 577
        int8_t unk_578;
        int8_t unk_579;
        int8_t fever;           // 57a
        int8_t unk_57b;
        int8_t unk_57c;
        int8_t unk_57d;
        int8_t unk_57e;
        int8_t exhausted;       // 57f
        int8_t hunger;          // 580
        int8_t unk_581;
        int8_t unk_582;
        int8_t hunger_state;    // 583
        int8_t thirst;          // 584
        int8_t unk_585;
        int8_t unk_586;
        int8_t dehydrated;      // 587
        int8_t unk_588;
        int8_t tiredness;       // 589
        int8_t drowsy;          // 58a
        int8_t very_drowsy;     // 58b
        int8_t unk_58c;
        int8_t unk_58d;
        int8_t unk_58e;
        int8_t unk_58f;
        uint32_t unk_590;
        uint32_t unk_594;
        uint32_t unk_598;
        uint32_t unk_59c;
        std::vector<void*> unk_5a0;
        void* unk_5b0;
        uint32_t unk_5b4;
        uint32_t unk_5b8;
        uint32_t unk_5bc;
        uint32_t unk_5c0;
        uint32_t unk_5c4;
        uint32_t unk_5c8;
        uint32_t unk_5cc;
        uint32_t unk_5d0;
        uint32_t unk_5d4;
        uint32_t unk_5d8;
        uint32_t unk_5dc;
        uint32_t unk_5e0;
        uint32_t unk_5e4;
        uint32_t unk_5e8;
        uint32_t unk_5ec;
        uint32_t unk_5f0;
        uint32_t unk_5f4;
        uint32_t unk_5f8;
        uint32_t unk_5fc;
        uint32_t unk_600;
        uint32_t unk_604;
        uint32_t unk_608;
        uint32_t unk_60c;
        uint32_t unk_610;
        uint32_t unk_614;
        int32_t unk_618;
        int32_t unk_61c;
        int32_t unk_620;
        int32_t unk_624;
        int32_t unk_628;
        int32_t unk_62c;
        int32_t unk_630;
        uint32_t unk_634;
        uint32_t unk_638;
        uint32_t unk_63c;
        uint32_t unk_640;
        int32_t unk_644;
        int16_t unk_648;
        std::vector<void*> soul_vector; // 64c
        void* current_soul;     // 65c
        uint32_t unk_660;
        uint32_t unk_664;
        uint32_t unk_668;
        uint32_t unk_66c;
        uint8_t labors[NUM_CREATURE_LABORS];    // 670..6d6
        uint32_t unk_6d8;
        uint32_t unk_6dc;
        std::vector<uint32_t> unk_6e0;
        void* unk_6f0;
        void* unk_6f4;
        void* unk_6f8;
        uint32_t unk_6fc;
        uint32_t unk_700;
        uint32_t unk_704;
        uint32_t unk_708;
        uint32_t unk_70c;
        uint32_t happiness;     // 710
        uint32_t unk_714;
        uint32_t unk_718;
        uint32_t unk_71c;
        uint32_t unk_720;
        uint32_t unk_724;
        uint32_t unk_728;
        uint32_t unk_72c;
        uint32_t unk_730;
        uint32_t unk_734;
        std::vector<void*> unk_738;
        uint32_t unk_748;
        uint32_t unk_74c;
        uint32_t unk_750;
        uint32_t unk_754;
        uint32_t unk_758;
        uint32_t unk_75c;
        std::vector<uint16_t> unk_760;
        std::vector<uint16_t> unk_770;
        std::vector<uint16_t> unk_780;
        uint32_t unk_790;
        uint16_t able_stand;    // 794
        uint16_t able_stand_impair;     // 796
        uint16_t able_grasp;    // 798
        uint16_t able_grasp_impair;     // 79a
        uint32_t unk_79c;
        uint32_t unk_7a0;
        std::vector<void*> unk_7a4;
        uint32_t unk_7b4;
        uint32_t unk_7b8;
        uint32_t unk_7bc;
        int32_t unk_7c0;
        uint32_t unk_7c4;
        uint32_t unk_7c8;
        uint32_t unk_7cc;
        uint32_t unk_7d0;
        uint32_t unk_7d4;
        uint32_t unk_7d8;
        uint32_t unk_7dc;
        uint32_t unk_7e0;
        uint32_t unk_7e4;
        uint32_t unk_7e8;
        uint32_t unk_7ec;
        uint32_t unk_7f0;
        uint32_t unk_7f4;
        uint32_t unk_7f8;
        uint32_t unk_7fc;
        uint32_t unk_800;
        uint32_t unk_804;
        uint32_t unk_808;
        uint32_t unk_80c;
        uint32_t unk_810;
        uint32_t unk_814;
        uint32_t unk_818;
        uint32_t unk_81c;
        uint32_t unk_820;
        uint32_t unk_824;
        uint32_t unk_828;
        uint32_t unk_82c;
        uint32_t unk_830;
        uint32_t unk_834;
        uint32_t unk_838;
        uint32_t unk_83c;
        std::vector<void*> unk_840;
        uint32_t unk_850;
        uint32_t unk_854;
        uint32_t unk_858;
        uint32_t unk_85c;
        uint32_t unk_860;
        uint32_t unk_864;
        uint32_t unk_868;
        uint32_t unk_86c;
        uint32_t unk_870;
        uint32_t unk_874;
        std::vector<uint8_t> unk_878;
        std::vector<uint8_t> unk_888;
        std::vector<uint32_t> unk_898;
        std::vector<uint8_t> unk_8a8;
        std::vector<uint16_t> unk_8b8;
        std::vector<uint16_t> unk_8c8;
        std::vector<uint32_t> unk_8d8;
        uint32_t unk_8e8;
        uint32_t unk_8ec;
        uint32_t unk_8f0;
        uint32_t unk_8f4;
        uint32_t unk_8f8;
        uint32_t unk_8fc;
        uint32_t unk_900;
        uint32_t unk_904;
        std::vector<uint32_t> unk_908;
        uint32_t unk_918;
        uint32_t unk_91c;
        uint32_t unk_920;
        uint32_t unk_924;
        uint32_t unk_928;
        uint32_t unk_92c;
        uint32_t unk_930;
        uint32_t unk_934;
        uint32_t unk_938;
        uint32_t unk_93c;
    };
