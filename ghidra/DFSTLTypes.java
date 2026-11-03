// DFSTLTypes — creates the MSVC STL-support data types used by DFSTLApply
// signatures (and useful generally).  Run this FIRST when starting analysis
// of a new DF build (before df-structures import), so that function
// signatures referencing these types can transfer via Version Tracking.
// Idempotent: existing types with the same name are left untouched.
//@category DFHack

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.util.data.DataTypeParser;
import java.util.*;

public class DFSTLTypes extends GhidraScript {

    DataTypeManager dtm;
    DataTypeParser parser;

    DataType dt(String spec) throws Exception {
        DataType t = parser.parse(spec, (CategoryPath) null);
        if (t == null) throw new Exception("cannot parse " + spec);
        return t;
    }

    DataType ptr(String spec) throws Exception { return dt(spec + " *"); }
    DataType voidPtr() throws Exception { return ptr("void"); }
    DataType ll() throws Exception { return dt("long long"); }
    DataType ull() throws Exception { return dt("unsigned long long"); }
    DataType i32() throws Exception { return dt("int"); }
    DataType boolt() throws Exception { return dt("bool"); }

    boolean have(String path) {
        return dtm.getDataType(path) != null;
    }

    void add(DataType t) {
        if (have(t.getCategoryPath() + "/" + t.getName())) return;
        dtm.addDataType(t, DataTypeConflictHandler.KEEP_HANDLER);
        println("created " + t.getPathName());
    }

    StructureDataType st(String name, int size) {
        StructureDataType s = new StructureDataType(new CategoryPath("/std"), name, 0, dtm);
        if (size > 0) s.setLength(size);
        return s;
    }

    void field(StructureDataType s, int off, String spec, String fname) throws Exception {
        DataType f = dt(spec);
        int need = off + Math.max(1, f.getLength());
        if (s.getLength() < need) s.growStructure(need - s.getLength());
        s.replaceAtOffset(off, f, -1, fname, null);
    }

    public void run() throws Exception {
        dtm = currentProgram.getDataTypeManager();
        parser = new DataTypeParser(dtm, dtm, null, DataTypeParser.AllowedDataTypes.FIXED_LENGTH);

        // ---------- std::basic_string<char> ----------
        if (!have("/std/std_string")) {
            UnionDataType bx = new UnionDataType(new CategoryPath("/std"), "std_string::_Bx", dtm);
            bx.add(new ArrayDataType(dt("char"), 16, 1), 16, "_Buf", null);
            bx.add(ptr("char"), -1, "_Ptr", null);
            add(bx);
            StructureDataType str = st("std_string", 0);
            field(str, 0x00, "std_string::_Bx", "_Bx");
            field(str, 0x10, "unsigned long long", "_Mysize");
            field(str, 0x18, "unsigned long long", "_Myres");
            add(str);
        }

        // ---------- std::basic_string<char16_t> / wstring ----------
        for (String nm : new String[]{"std_u16string", "std_wstring"}) {
            if (have("/std/" + nm)) continue;
            UnionDataType bx = new UnionDataType(new CategoryPath("/std"), nm + "::_Bx", dtm);
            bx.add(new ArrayDataType(dt("ushort"), 8, 2), 16, "_Buf", null);
            bx.add(ptr("ushort"), -1, "_Ptr", null);
            add(bx);
            StructureDataType str = st(nm, 0);
            field(str, 0x00, nm + "::_Bx", "_Bx");
            field(str, 0x10, "unsigned long long", "_Mysize");
            field(str, 0x18, "unsigned long long", "_Myres");
            add(str);
        }

        // ---------- std::exception ----------
        if (!have("/std/std_exception")) {
            StructureDataType s = st("std_exception", 0);
            field(s, 0x00, "void *", "vftable");
            field(s, 0x08, "char *", "_What");
            field(s, 0x10, "int", "_DoFree");
            add(s);
        }

        // ---------- std::error_condition / error_code ----------
        for (String nm : new String[]{"std_error_condition", "std_error_code"}) {
            if (have("/std/" + nm)) continue;
            StructureDataType s = st(nm, 0);
            field(s, 0x00, "int", "_Errval");
            field(s, 0x08, "void *", "_Cat");
            add(s);
        }

        // ---------- std::_Ref_count_base ----------
        if (!have("/std/std_Ref_count_base")) {
            StructureDataType s = st("std_Ref_count_base", 0);
            field(s, 0x00, "void *", "vftable");
            field(s, 0x08, "long", "_Uses");
            field(s, 0x0c, "long", "_Weaks");
            add(s);
        }

        // ---------- std::_Func_base ----------
        if (!have("/std/std_Func_base")) {
            StructureDataType s = st("std_Func_base", 0);
            field(s, 0x00, "void *", "vftable");
            add(s);
        }

        // ---------- std::function ----------
        if (!have("/std/std_function")) {
            StructureDataType s = st("std_function", 0);
            field(s, 0x00, "void *", "_Impl");
            add(s);
        }

        // ---------- std::shared_ptr (generic) ----------
        if (!have("/std/std_shared_ptr")) {
            StructureDataType s = st("std_shared_ptr", 0);
            field(s, 0x00, "void *", "_Ptr");
            field(s, 0x08, "std_Ref_count_base *", "_Rep");
            add(s);
        }

        // ---------- std::locale::facet ----------
        if (!have("/std/std_locale_facet")) {
            StructureDataType s = st("std_locale_facet", 0);
            field(s, 0x00, "void *", "vftable");
            field(s, 0x08, "long", "_Refs");
            add(s);
        }

        // ---------- std::error_category ----------
        if (!have("/std/std_error_category")) {
            StructureDataType s = st("std_error_category", 0);
            field(s, 0x00, "void *", "vftable");
            add(s);
        }

        // ---------- std::basic_streambuf ----------
        if (!have("/std/std_basic_streambuf")) {
            StructureDataType s = st("std_basic_streambuf", 0);
            field(s, 0x00, "void *", "vftable");
            field(s, 0x08, "char * *", "_Gfirst");
            field(s, 0x10, "char * *", "_Gnext");
            field(s, 0x18, "char * *", "_Glast");
            field(s, 0x20, "int *", "_IGcount");
            field(s, 0x28, "char * *", "_Pfirst");
            field(s, 0x30, "char * *", "_Pnext");
            field(s, 0x38, "char * *", "_Plast");
            field(s, 0x40, "int *", "_IPcount");
            field(s, 0x48, "void *", "_Loc");
            add(s);
        }

        // ---------- std::basic_filebuf ----------
        if (!have("/std/std_basic_filebuf")) {
            StructureDataType s = st("std_basic_filebuf", 0);
            field(s, 0x00, "std_basic_streambuf", "_Base");
            field(s, 0x68, "void *", "_Locale_state");
            field(s, 0x70, "char", "_Buf_back");
            field(s, 0x78, "void *", "_Conversion");
            field(s, 0x80, "void *", "_Myfile");   // FILE*
            add(s);
        }

        // ---------- std::type_info ----------
        if (!have("/std/std_type_info")) {
            StructureDataType s = st("std_type_info", 0);
            field(s, 0x00, "void *", "vftable");
            field(s, 0x08, "void *", "_Data");
            field(s, 0x10, "char", "_Name");
            add(s);
        }

        // ---------- std::unique_lock<std::mutex> ----------
        if (!have("/std/std_unique_lock")) {
            StructureDataType s = st("std_unique_lock", 0);
            field(s, 0x00, "void *", "_Mtx");
            field(s, 0x08, "int", "_Owns");
            add(s);
        }

        // ---------- std::vector (triad) ----------
        if (!have("/std/std_vector_base")) {
            StructureDataType s = st("std_vector_base", 0);
            field(s, 0x00, "void *", "_Myfirst");
            field(s, 0x08, "void *", "_Mylast");
            field(s, 0x10, "void *", "_Myend");
            add(s);
        }

        // ---------- std::locale ----------
        if (!have("/std/std_locale")) {
            StructureDataType s = st("std_locale", 0);
            field(s, 0x00, "void *", "_Ptr");
            add(s);
        }

        // ---------- std::fpos ----------
        if (!have("/std/std_fpos")) {
            StructureDataType s = st("std_fpos", 0);
            field(s, 0x00, "long long", "_Off");
            field(s, 0x08, "long long", "_State");
            add(s);
        }

        // ---------- std::filesystem::filesystem_error ----------
        if (!have("/std/std_filesystem_error")) {
            StructureDataType s = st("std_filesystem_error", 0);
            field(s, 0x00, "std_exception", "_Base");
            field(s, 0x18, "void *", "_Reserved0");
            field(s, 0x20, "std_u16string", "_Path1");
            field(s, 0x40, "std_u16string", "_Path2");
            field(s, 0x60, "std_string", "_Mymsg");
            add(s);
        }

        println("DFSTLTypes done");
    }
}
