import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.util.data.DataTypeParser;

/**
 * DFLuaTypes -- creates Lua 5.4 data types under /lua used by DFLuaApply
 * signatures (and useful generally).  Run this FIRST when starting
 * analysis of a new DF build (before df-structures import), so that
 * function signatures referencing these types can transfer via
 * Version Tracking.
 *
 * Layouts are the Lua 5.4.7 internal definitions compiled for x86-64
 * (MSVC): lua.h / lauxlib.h public types plus the lobject.h / lstate.h
 * internals reachable through them.
 *
 * Idempotent: existing types with the same name are left untouched.
 */
public class DFLuaTypes extends GhidraScript {

    static final String CAT = "/lua";

    DataTypeManager dtm;
    DataTypeParser parser;

    DataType dt(String spec) throws Exception {
        DataType t = null;
        try { t = parser.parse(spec, (CategoryPath) null); }
        catch (Exception e) { }
        if (t == null) {
            String base = spec.replace(" *", "");
            t = dtm.getDataType(CAT + "/" + base);
            if (t == null) throw new Exception("cannot parse " + spec);
            int stars = spec.length() - spec.replace("*", "").length();
            for (int i = 0; i < stars; i++) t = new PointerDataType(t);
        }
        return t;
    }

    DataType lua(String name) { return dtm.getDataType(CAT + "/" + name); }

    DataType ptrTo(DataType t) { return new PointerDataType(t); }
    DataType ptr(String spec) throws Exception { return ptrTo(dt(spec)); }
    DataType luap(String name) throws Exception { return ptrTo(dt(name)); }

    boolean have(String name) {
        DataType d = lua(name);
        return d != null && d.getLength() != 0;
    }

    void add(DataType t) {
        String p = t.getCategoryPath() + "/" + t.getName();
        DataType old = dtm.getDataType(p);
        if (old != null) {
            if (old.getLength() == 0 && t.getLength() != 0) {
                try {
                    dtm.replaceDataType(old, t, true);
                    println("redefined " + p);
                } catch (Exception e) {
                    println("replace-failed " + p + " : " + e);
                }
            }
            return;
        }
        dtm.addDataType(t, DataTypeConflictHandler.KEEP_HANDLER);
        println("created " + p);
    }

    StructureDataType st(String name) {
        return new StructureDataType(new CategoryPath(CAT), name, 0, dtm);
    }

    void field(StructureDataType s, int off, String spec, String fname) throws Exception {
        DataType f = dt(spec);
        int need = off + Math.max(1, f.getLength());
        if (s.getLength() < need) s.growStructure(need - s.getLength());
        s.replaceAtOffset(off, f, -1, fname, null);
    }

    void fieldT(StructureDataType s, int off, DataType f, String fname) {
        int need = off + Math.max(1, f.getLength());
        if (s.getLength() < need) s.growStructure(need - s.getLength());
        s.replaceAtOffset(off, f, -1, fname, null);
    }

    UnionDataType un(String name) {
        return new UnionDataType(new CategoryPath(CAT), name, dtm);
    }

    void td(String name, String spec) throws Exception {
        if (have(name)) return;
        add(new TypedefDataType(new CategoryPath(CAT), name, dt(spec), dtm));
    }

    DataType fndef(String name, String ret, String... params) throws Exception {
        FunctionDefinitionDataType fd =
            new FunctionDefinitionDataType(new CategoryPath(CAT + "/fn"), name);
        fd.setReturnType(dt(ret));
        ParameterDefinition[] ps = new ParameterDefinition[params.length];
        for (int i = 0; i < params.length; i++)
            ps[i] = new ParameterDefinitionImpl("param_" + i, dt(params[i]), null);
        fd.setArguments(ps);
        return fd;
    }

    // creates /lua/fn/<name> funcdef + /lua/<name> typedef of a pointer to it
    void fnptr(String name, String ret, String... params) throws Exception {
        if (have(name)) return;
        add(fndef(name, ret, params));
        add(new TypedefDataType(new CategoryPath(CAT), name,
            new PointerDataType(fndef(name, ret, params)), dtm));
    }

    void stub(String name) {
        if (have(name)) return;
        add(new StructureDataType(new CategoryPath(CAT), name, 0, dtm));
    }

    public void run() throws Exception {
        dtm = currentProgram.getDataTypeManager();
        parser = new DataTypeParser(dtm, dtm, null,
            DataTypeParser.AllowedDataTypes.FIXED_LENGTH);

        // ---------- scalar typedefs ----------
        td("lua_Number", "double");
        td("lua_Integer", "long long");
        td("lua_Unsigned", "unsigned long long");
        td("lua_KContext", "long long");          // ptrdiff_t / intptr_t
        td("lu_byte", "unsigned char");
        td("ls_byte", "char");
        td("l_mem", "long long");                 // ptrdiff_t
        td("lu_mem", "unsigned long long");       // size_t
        td("l_uint32", "unsigned int");
        td("l_signalT", "int");                   // sig_atomic_t
        td("Instruction", "unsigned int");

        // ---------- function-pointer types ----------
        // (forward struct stubs first so signatures resolve)
        stub("lua_State"); stub("lua_Debug"); stub("luaL_Reg");
        stub("luaL_Buffer"); stub("luaL_Stream"); stub("lua_longjmp");
        stub("LexState"); stub("FuncState"); stub("Dyndata");
        stub("Vardesc"); stub("expdesc"); stub("LHS_assign");
        stub("ConsControl"); stub("Labeldesc"); stub("Mbuffer");
        stub("ZIO"); stub("LoadState"); stub("DumpState");
        stub("MatchState"); stub("GMatchState"); stub("Rand64");
        stub("GCObject"); stub("TString"); stub("Table"); stub("Proto");
        stub("UpVal"); stub("Udata"); stub("CallInfo");
        stub("global_State"); stub("stringtable"); stub("Upvaldesc");
        stub("LocVar"); stub("AbsLineInfo"); stub("Node");
        stub("CClosure"); stub("LClosure");

        fnptr("lua_CFunction", "int", "lua_State *");
        fnptr("lua_KFunction", "int", "lua_State *", "int", "lua_KContext");
        fnptr("lua_Reader", "char *", "lua_State *", "void *", "unsigned long long *");
        fnptr("lua_Writer", "int", "lua_State *", "void *", "unsigned long long", "void *");
        fnptr("lua_Alloc", "void *", "void *", "void *",
              "unsigned long long", "unsigned long long");
        fnptr("lua_Hook", "void", "lua_State *", "lua_Debug *");
        fnptr("lua_WarnFunction", "void", "void *", "char *", "int");

        // ---------- tagged-value union ----------
        if (!have("Value")) {
            UnionDataType v = un("Value");
            v.add(luap("GCObject"), -1, "gc", null);
            v.add(dt("void *"), -1, "p", null);
            v.add(luap("lua_CFunction"), -1, "f", null);
            v.add(dt("lua_Integer"), -1, "i", null);
            v.add(dt("lua_Number"), -1, "n", null);
            v.add(dt("lu_byte"), -1, "ub", null);
            add(v);
        }

        // ---------- TValue family ----------
        if (!have("TValue")) {
            StructureDataType s = st("TValue");
            field(s, 0x00, "Value", "value_");
            field(s, 0x08, "lu_byte", "tt_");
            add(s);
        }
        if (!have("StackValue")) {
            StructureDataType tb = st("StackValue::_tbclist");
            field(tb, 0x00, "Value", "value_");
            field(tb, 0x08, "lu_byte", "tt_");
            field(tb, 0x0a, "unsigned short", "delta");
            UnionDataType u = un("StackValue");
            u.add(dt("TValue"), -1, "val", null);
            u.add(tb, -1, "tbclist", null);
            add(u);
        }
        td("StkId", "StackValue *");
        if (!have("StkIdRel")) {
            UnionDataType u = un("StkIdRel");
            u.add(dt("StkId"), -1, "p", null);
            u.add(dt("long long"), -1, "offset", null);
            add(u);
        }

        // ---------- GC header object ----------
        if (!have("GCObject")) {
            StructureDataType s = st("GCObject");
            field(s, 0x00, "GCObject *", "next");
            field(s, 0x08, "lu_byte", "tt");
            field(s, 0x09, "lu_byte", "marked");
            add(s);
        }

        // ---------- TString ----------
        if (!have("TString")) {
            UnionDataType u = un("TString::_u");
            u.add(dt("unsigned long long"), -1, "lnglen", null);
            u.add(luap("TString"), -1, "hnext", null);
            StructureDataType s = st("TString");
            field(s, 0x00, "GCObject *", "next");
            field(s, 0x08, "lu_byte", "tt");
            field(s, 0x09, "lu_byte", "marked");
            field(s, 0x0a, "lu_byte", "extra");
            field(s, 0x0b, "lu_byte", "shrlen");
            field(s, 0x0c, "unsigned int", "hash");
            fieldT(s, 0x10, u, "u");
            field(s, 0x18, "char", "contents");
            add(s);
        }

        // ---------- Udata ----------
        if (!have("UValue")) {
            UnionDataType uv = un("UValue");
            uv.add(dt("TValue"), -1, "uv", null);
            uv.add(dt("lua_Number"), -1, "n", null);
            uv.add(dt("void *"), -1, "s", null);
            uv.add(dt("lua_Integer"), -1, "i", null);
            add(uv);
        }
        if (!have("Udata")) {
            StructureDataType s = st("Udata");
            field(s, 0x00, "GCObject *", "next");
            field(s, 0x08, "lu_byte", "tt");
            field(s, 0x09, "lu_byte", "marked");
            field(s, 0x0a, "unsigned short", "nuvalue");
            field(s, 0x10, "unsigned long long", "len");
            field(s, 0x18, "Table *", "metatable");
            field(s, 0x20, "GCObject *", "gclist");
            field(s, 0x28, "UValue", "uv");
            add(s);
        }
        if (!have("Udata0")) {
            StructureDataType s = st("Udata0");
            field(s, 0x00, "GCObject *", "next");
            field(s, 0x08, "lu_byte", "tt");
            field(s, 0x09, "lu_byte", "marked");
            field(s, 0x0a, "unsigned short", "nuvalue");
            field(s, 0x10, "unsigned long long", "len");
            field(s, 0x18, "Table *", "metatable");
            field(s, 0x20, "void *", "bindata");
            add(s);
        }

        // ---------- Proto family ----------
        if (!have("Upvaldesc")) {
            StructureDataType s = st("Upvaldesc");
            field(s, 0x00, "TString *", "name");
            field(s, 0x08, "lu_byte", "instack");
            field(s, 0x09, "lu_byte", "idx");
            field(s, 0x0a, "lu_byte", "kind");
            add(s);
        }
        if (!have("LocVar")) {
            StructureDataType s = st("LocVar");
            field(s, 0x00, "TString *", "varname");
            field(s, 0x08, "int", "startpc");
            field(s, 0x0c, "int", "endpc");
            add(s);
        }
        if (!have("AbsLineInfo")) {
            StructureDataType s = st("AbsLineInfo");
            field(s, 0x00, "int", "pc");
            field(s, 0x04, "int", "line");
            add(s);
        }
        if (!have("Proto")) {
            StructureDataType s = st("Proto");
            field(s, 0x00, "GCObject *", "next");
            field(s, 0x08, "lu_byte", "tt");
            field(s, 0x09, "lu_byte", "marked");
            field(s, 0x0a, "lu_byte", "numparams");
            field(s, 0x0b, "lu_byte", "is_vararg");
            field(s, 0x0c, "lu_byte", "maxstacksize");
            field(s, 0x10, "int", "sizeupvalues");
            field(s, 0x14, "int", "sizek");
            field(s, 0x18, "int", "sizecode");
            field(s, 0x1c, "int", "sizelineinfo");
            field(s, 0x20, "int", "sizep");
            field(s, 0x24, "int", "sizelocvars");
            field(s, 0x28, "int", "sizeabslineinfo");
            field(s, 0x2c, "int", "linedefined");
            field(s, 0x30, "int", "lastlinedefined");
            field(s, 0x38, "TValue *", "k");
            field(s, 0x40, "Instruction *", "code");
            field(s, 0x48, "Proto * *", "p");
            field(s, 0x50, "Upvaldesc *", "upvalues");
            field(s, 0x58, "ls_byte *", "lineinfo");
            field(s, 0x60, "AbsLineInfo *", "abslineinfo");
            field(s, 0x68, "LocVar *", "locvars");
            field(s, 0x70, "TString *", "source");
            field(s, 0x78, "GCObject *", "gclist");
            add(s);
        }

        // ---------- UpVal / closures ----------
        if (!have("UpVal")) {
            UnionDataType v = un("UpVal::_v");
            v.add(luap("TValue"), -1, "p", null);
            v.add(dt("long long"), -1, "offset", null);
            StructureDataType open = st("UpVal::_open");
            field(open, 0x00, "UpVal *", "next");
            field(open, 0x08, "UpVal * *", "previous");
            UnionDataType u = un("UpVal::_u");
            u.add(open, -1, "open", null);
            u.add(dt("TValue"), -1, "value", null);
            StructureDataType s = st("UpVal");
            field(s, 0x00, "GCObject *", "next");
            field(s, 0x08, "lu_byte", "tt");
            field(s, 0x09, "lu_byte", "marked");
            fieldT(s, 0x10, v, "v");
            fieldT(s, 0x18, u, "u");
            add(s);
        }
        if (!have("CClosure")) {
            StructureDataType s = st("CClosure");
            field(s, 0x00, "GCObject *", "next");
            field(s, 0x08, "lu_byte", "tt");
            field(s, 0x09, "lu_byte", "marked");
            field(s, 0x0a, "lu_byte", "nupvalues");
            field(s, 0x10, "GCObject *", "gclist");
            field(s, 0x18, "lua_CFunction", "f");
            field(s, 0x20, "TValue", "upvalue");
            add(s);
        }
        if (!have("LClosure")) {
            StructureDataType s = st("LClosure");
            field(s, 0x00, "GCObject *", "next");
            field(s, 0x08, "lu_byte", "tt");
            field(s, 0x09, "lu_byte", "marked");
            field(s, 0x0a, "lu_byte", "nupvalues");
            field(s, 0x10, "GCObject *", "gclist");
            field(s, 0x18, "Proto *", "p");
            field(s, 0x20, "UpVal *", "upvals");
            add(s);
        }
        if (!have("Closure")) {
            UnionDataType u = un("Closure");
            u.add(dt("CClosure"), -1, "c", null);
            u.add(dt("LClosure"), -1, "l", null);
            add(u);
        }

        // ---------- Table / Node ----------
        if (!have("NodeKey")) {
            StructureDataType s = st("NodeKey");
            field(s, 0x00, "Value", "value_");
            field(s, 0x08, "lu_byte", "tt_");
            field(s, 0x09, "lu_byte", "key_tt");
            field(s, 0x0c, "int", "next");
            field(s, 0x10, "Value", "key_val");
            add(s);
        }
        if (!have("Node")) {
            UnionDataType u = un("Node");
            u.add(dt("NodeKey"), -1, "u", null);
            u.add(dt("TValue"), -1, "i_val", null);
            add(u);
        }
        if (!have("Table")) {
            StructureDataType s = st("Table");
            field(s, 0x00, "GCObject *", "next");
            field(s, 0x08, "lu_byte", "tt");
            field(s, 0x09, "lu_byte", "marked");
            field(s, 0x0a, "lu_byte", "flags");
            field(s, 0x0b, "lu_byte", "lsizenode");
            field(s, 0x0c, "unsigned int", "alimit");
            field(s, 0x10, "TValue *", "array");
            field(s, 0x18, "Node *", "node");
            field(s, 0x20, "Node *", "lastfree");
            field(s, 0x28, "Table *", "metatable");
            field(s, 0x30, "GCObject *", "gclist");
            add(s);
        }

        // ---------- CallInfo / lua_State ----------
        if (!have("stringtable")) {
            StructureDataType s = st("stringtable");
            field(s, 0x00, "TString * *", "hash");
            field(s, 0x08, "int", "nuse");
            field(s, 0x0c, "int", "size");
            add(s);
        }
        if (!have("CallInfo")) {
            StructureDataType l = st("CallInfo::_l");
            field(l, 0x00, "Instruction *", "savedpc");
            field(l, 0x08, "l_signalT", "trap");
            field(l, 0x0c, "int", "nextraargs");
            StructureDataType c = st("CallInfo::_c");
            field(c, 0x00, "lua_KFunction", "k");
            field(c, 0x08, "long long", "old_errfunc");
            field(c, 0x10, "lua_KContext", "ctx");
            UnionDataType u = un("CallInfo::_u");
            u.add(l, -1, "l", null);
            u.add(c, -1, "c", null);
            StructureDataType ti = st("CallInfo::_transferinfo");
            field(ti, 0x00, "unsigned short", "ftransfer");
            field(ti, 0x02, "unsigned short", "ntransfer");
            UnionDataType u2 = un("CallInfo::_u2");
            u2.add(dt("int"), -1, "funcidx", null);
            u2.add(dt("int"), -1, "nyield", null);
            u2.add(dt("int"), -1, "nres", null);
            u2.add(ti, -1, "transferinfo", null);
            StructureDataType s = st("CallInfo");
            field(s, 0x00, "StkIdRel", "func");
            field(s, 0x08, "StkIdRel", "top");
            field(s, 0x10, "CallInfo *", "previous");
            field(s, 0x18, "CallInfo *", "next");
            fieldT(s, 0x20, u, "u");
            fieldT(s, 0x38, u2, "u2");
            field(s, 0x3c, "short", "nresults");
            field(s, 0x3e, "unsigned short", "callstatus");
            add(s);
        }
        if (!have("lua_State")) {
            StructureDataType s = st("lua_State");
            field(s, 0x00, "GCObject *", "next");
            field(s, 0x08, "lu_byte", "tt");
            field(s, 0x09, "lu_byte", "marked");
            field(s, 0x0a, "lu_byte", "status");
            field(s, 0x0b, "lu_byte", "allowhook");
            field(s, 0x0c, "unsigned short", "nci");
            field(s, 0x10, "StkIdRel", "top");
            field(s, 0x18, "global_State *", "l_G");
            field(s, 0x20, "CallInfo *", "ci");
            field(s, 0x28, "StkIdRel", "stack_last");
            field(s, 0x30, "StkIdRel", "stack");
            field(s, 0x38, "UpVal *", "openupval");
            field(s, 0x40, "StkIdRel", "tbclist");
            field(s, 0x48, "GCObject *", "gclist");
            field(s, 0x50, "lua_State *", "twups");
            field(s, 0x58, "lua_longjmp *", "errorJmp");
            field(s, 0x60, "CallInfo", "base_ci");
            field(s, 0xa0, "lua_Hook", "hook");
            field(s, 0xa8, "long long", "errfunc");
            field(s, 0xb0, "l_uint32", "nCcalls");
            field(s, 0xb4, "int", "oldpc");
            field(s, 0xb8, "int", "basehookcount");
            field(s, 0xbc, "int", "hookcount");
            field(s, 0xc0, "l_signalT", "hookmask");
            add(s);
        }

        // ---------- global_State ----------
        if (!have("global_State")) {
            StructureDataType s = st("global_State");
            field(s, 0x00, "lua_Alloc", "frealloc");
            field(s, 0x08, "void *", "ud");
            field(s, 0x10, "l_mem", "totalbytes");
            field(s, 0x18, "l_mem", "GCdebt");
            field(s, 0x20, "lu_mem", "GCestimate");
            field(s, 0x28, "lu_mem", "lastatomic");
            field(s, 0x30, "stringtable", "strt");
            field(s, 0x40, "TValue", "l_registry");
            field(s, 0x50, "TValue", "nilvalue");
            field(s, 0x60, "unsigned int", "seed");
            field(s, 0x64, "lu_byte", "currentwhite");
            field(s, 0x65, "lu_byte", "gcstate");
            field(s, 0x66, "lu_byte", "gckind");
            field(s, 0x67, "lu_byte", "gcstopem");
            field(s, 0x68, "lu_byte", "genminormul");
            field(s, 0x69, "lu_byte", "genmajormul");
            field(s, 0x6a, "lu_byte", "gcstp");
            field(s, 0x6b, "lu_byte", "gcemergency");
            field(s, 0x6c, "lu_byte", "gcpause");
            field(s, 0x6d, "lu_byte", "gcstepmul");
            field(s, 0x6e, "lu_byte", "gcstepsize");
            field(s, 0x70, "GCObject *", "allgc");
            field(s, 0x78, "GCObject * *", "sweepgc");
            field(s, 0x80, "GCObject *", "finobj");
            field(s, 0x88, "GCObject *", "gray");
            field(s, 0x90, "GCObject *", "grayagain");
            field(s, 0x98, "GCObject *", "weak");
            field(s, 0xa0, "GCObject *", "ephemeron");
            field(s, 0xa8, "GCObject *", "allweak");
            field(s, 0xb0, "GCObject *", "tobefnz");
            field(s, 0xb8, "GCObject *", "fixedgc");
            field(s, 0xc0, "GCObject *", "survival");
            field(s, 0xc8, "GCObject *", "old1");
            field(s, 0xd0, "GCObject *", "reallyold");
            field(s, 0xd8, "GCObject *", "firstold1");
            field(s, 0xe0, "GCObject *", "finobjsur");
            field(s, 0xe8, "GCObject *", "finobjold1");
            field(s, 0xf0, "GCObject *", "finobjrold");
            field(s, 0xf8, "lua_State *", "twups");
            field(s, 0x100, "lua_CFunction", "panic");
            field(s, 0x108, "lua_State *", "mainthread");
            field(s, 0x110, "TString *", "memerrmsg");
            fieldT(s, 0x118, new ArrayDataType(luap("TString"), 25, 8), "tmname");
            fieldT(s, 0x1e0, new ArrayDataType(luap("Table"), 9, 8), "mt");
            fieldT(s, 0x228, new ArrayDataType(luap("TString"), 53 * 2, 8), "strcache");
            field(s, 0x578, "lua_WarnFunction", "warnf");
            field(s, 0x580, "void *", "ud_warn");
            add(s);
        }

        // ---------- public API structs ----------
        if (!have("lua_Debug")) {
            StructureDataType s = st("lua_Debug");
            field(s, 0x00, "int", "event");
            field(s, 0x08, "char *", "name");
            field(s, 0x10, "char *", "namewhat");
            field(s, 0x18, "char *", "what");
            field(s, 0x20, "char *", "source");
            field(s, 0x28, "unsigned long long", "srclen");
            field(s, 0x30, "int", "currentline");
            field(s, 0x34, "int", "linedefined");
            field(s, 0x38, "int", "lastlinedefined");
            field(s, 0x3c, "unsigned char", "nups");
            field(s, 0x3d, "unsigned char", "nparams");
            field(s, 0x3e, "char", "isvararg");
            field(s, 0x3f, "char", "istailcall");
            field(s, 0x40, "unsigned short", "ftransfer");
            field(s, 0x42, "unsigned short", "ntransfer");
            fieldT(s, 0x44, new ArrayDataType(dt("char"), 60, 1), "short_src");
            field(s, 0x80, "CallInfo *", "i_ci");
            add(s);
        }
        if (!have("luaL_Reg")) {
            StructureDataType s = st("luaL_Reg");
            field(s, 0x00, "char *", "name");
            field(s, 0x08, "lua_CFunction", "func");
            add(s);
        }
        if (!have("luaL_Buffer")) {
            UnionDataType init = un("luaL_Buffer::_init");
            init.add(new ArrayDataType(dt("char"), 1024, 1), -1, "b", null);
            init.add(dt("void *"), -1, "s", null);
            init.add(dt("lua_Number"), -1, "n", null);
            StructureDataType s = st("luaL_Buffer");
            field(s, 0x00, "char *", "b");
            field(s, 0x08, "unsigned long long", "size");
            field(s, 0x10, "unsigned long long", "n");
            field(s, 0x18, "lua_State *", "L");
            fieldT(s, 0x20, init, "init");
            add(s);
        }
        if (!have("luaL_Stream")) {
            StructureDataType s = st("luaL_Stream");
            field(s, 0x00, "void *", "f");
            field(s, 0x08, "lua_CFunction", "closef");
            add(s);
        }
        if (!have("lua_longjmp")) {
            StructureDataType s = st("lua_longjmp");
            field(s, 0x00, "lua_longjmp *", "previous");
            fieldT(s, 0x08, new ArrayDataType(dt("char"), 256, 1), "b");
            field(s, 0x108, "int", "status");
            add(s);
        }
        if (!have("GCUnion")) {
            UnionDataType u = un("GCUnion");
            u.add(dt("GCObject"), -1, "gc", null);
            u.add(dt("TString"), -1, "ts", null);
            u.add(dt("Udata"), -1, "u", null);
            u.add(dt("Closure"), -1, "cl", null);
            u.add(dt("Table"), -1, "h", null);
            u.add(dt("Proto"), -1, "p", null);
            u.add(dt("lua_State"), -1, "th", null);
            u.add(dt("UpVal"), -1, "upv", null);
            add(u);
        }

        println("=== DFLuaTypes done");
    }
}
