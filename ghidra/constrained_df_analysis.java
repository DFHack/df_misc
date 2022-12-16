// TODO
//
// @author Ben Lubar
// @category DFHack

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BiFunction;

import ghidra.app.decompiler.*;
import ghidra.app.decompiler.parallel.*;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.GhidraScript;
import ghidra.docking.settings.SettingsImpl;
import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class constrained_df_analysis extends GhidraScript {
	static final CategoryPath dfCategoryPath = new CategoryPath(CategoryPath.ROOT, "df");

	private DataTypeManager dtm;
	private SymbolTable symtab;

	private static final class Configurer implements DecompileConfigurer {
		@Override
		public void configure(DecompInterface decompiler) {
			decompiler.toggleCCode(false);
			decompiler.toggleJumpLoads(false);
			decompiler.toggleParamMeasures(false);
			decompiler.toggleSyntaxTree(true);
			decompiler.setSimplificationStyle("decompile");
		}
	}

	private abstract class Callback<T> extends DecompilerCallback<T> {
		public Callback() {
			super(currentProgram, new Configurer());
			this.setTimeout(3600);
		}

		@Override
		public final T process(DecompileResults results, TaskMonitor monitor_) throws Exception {
			if (!results.decompileCompleted()) {
				printerr("Decompiling function " + results.getFunction() + " failed: " + results.getErrorMessage());
				return null;
			}

			return process(results);
		}

		public abstract T process(DecompileResults results) throws Exception;
	}

	private abstract class PcodeCallback extends Callback<Void> {
		@Override
		public final Void process(DecompileResults results) throws Exception {
			var hfunc = results.getHighFunction();
			for (var bb : hfunc.getBasicBlocks()) {
				monitor.checkCanceled();

				var it = bb.getIterator();
				while (it.hasNext()) {
					var op = it.next();
					process(results, op);
				}
			}

			return null;
		}

		public abstract void process(DecompileResults results, PcodeOp op) throws Exception;
	}

	@Override
	public AnalysisMode getScriptAnalysisMode() {
		return AnalysisMode.SUSPENDED;
	}

	@Override
	protected void run() throws Exception {
		dtm = currentProgram.getDataTypeManager();
		symtab = currentProgram.getSymbolTable();

		labelGlobalTable();
		fixDemangler();
		determineCallTypes();
	}

	private MemBuffer getMem(Address addr) {
		return new MemoryBufferImpl(currentProgram.getMemory(), addr);
	}

	private String getCString(Address addr, boolean defineData) throws Exception {
		if (addr.getOffset() == 0) {
			return null;
		}

		var buf = getMem(addr);
		int length = TerminatedStringDataType.dataType.getLength(buf, -1);

		if (defineData) {
			var prevData = getDataBefore(addr.add(length));
			if (!prevData.contains(addr)) {
				clearListing(addr, addr.add(length));
				createData(addr, TerminatedStringDataType.dataType);
			}
		}

		return (String) TerminatedStringDataType.dataType.getValue(buf, SettingsImpl.NO_SETTINGS, length);
	}

	private void labelGlobalTable() throws Exception {
		byte[] magicNumber;
		switch (currentProgram.getDefaultPointerSize()) {
		case 4:
			magicNumber = new byte[] { 0x78, 0x56, 0x34, 0x12, 0x21, 0x43, 0x65, (byte) 0x87 };
			break;
		case 8:
			magicNumber = new byte[] { 0x78, 0x56, 0x34, 0x12, 0x78, 0x56, 0x34, 0x12, 0x21, 0x43, 0x65, (byte) 0x87,
					0x21, 0x43, 0x65, (byte) 0x87 };
			break;
		default:
			throw new Exception("unexpected pointer size: " + (currentProgram.getDefaultPointerSize() * 8));
		}

		var tableStart = find(null, magicNumber);
		if (tableStart == null) {
			printerr("no candidate address for global table");
			return;
		}

		var nextTableStart = find(tableStart.next(), magicNumber);
		if (nextTableStart != null) {
			printerr("multiple candidate addresses for global table: " + tableStart + " and " + nextTableStart);
			return;
		}

		createLabel(tableStart, "df_globals_table", false, SourceType.IMPORTED);
		createDwords(tableStart, magicNumber.length / 4);

		var addr = tableStart.add(magicNumber.length);
		var voidp = dtm.getPointer(DataType.VOID);
		var charp = dtm.getPointer(CharDataType.dataType);
		while (true) {
			var nameAddr = (Address) voidp.getValue(getMem(addr), SettingsImpl.NO_SETTINGS, -1);
			var name = getCString(nameAddr, true);
			clearUndefined(addr);
			createData(addr, charp);

			addr = addr.add(voidp.getLength());
			var dataAddr = (Address) voidp.getValue(getMem(addr), SettingsImpl.NO_SETTINGS, -1);

			if (name == null) {
				createData(addr, voidp);
				break;
			}

			clearUndefined(addr);
			createData(addr, dtm.getPointer(labelGlobal(name, dataAddr)));
			addr = addr.add(voidp.getLength());
		}
	}

	private void clearUndefined(Address addr) throws Exception {
		var existing = getDataAt(addr);
		if (existing == null) {
			return;
		}

		var dt = existing.getDataType();
		if (Undefined.isUndefined(dt)) {
			clearListing(addr);
			return;
		}

		if (dt instanceof Pointer) {
			var ptr = (Pointer) dt;
			if (Undefined.isUndefined(ptr.getDataType())) {
				clearListing(addr);
				return;
			}
		}
	}

	private DataType labelGlobal(String name, Address addr) throws Exception {
		monitor.checkCanceled();
		monitor.setMessage("Labelling global: " + name);

		createLabel(addr, name, false, SourceType.IMPORTED);

		var data = getDataAt(addr);
		if (data == null || Undefined.isUndefined(data.getDataType())) {
			var type = getDefaultGlobalType(name);
			if (type == null) {
				printerr("TODO: " + name + " data type");
				return DataType.VOID;
			}

			for (int i = 0; i < type.getLength(); i++) {
				var conflictingData = getDataAt(addr.add(i));
				if (conflictingData != null && Undefined.isUndefined(conflictingData.getDataType())) {
					clearListing(addr.add(i));
				}
			}

			try {
				data = createData(addr, type);
			} catch (Exception ex) {
				throw new Exception(
						"conflict while creating data " + name + " from " + addr + " to " + addr.add(type.getLength()),
						ex);
			}
		}

		return data.getDataType();
	}

	private DataType getDefaultGlobalType(String name) {
		switch (name) {
		case "oscrollx":
		case "oscrolly":
		case "oscrollz":
		case "olookx":
		case "olooky":
		case "olookz":
		case "page":
		case "squadcount":
		case "unitprintstack_start":
		case "unitprintstack_cur":
			return dtm.getDataType(new CategoryPath("/std"), "int32_t");
		case "mt_index":
			return new ArrayDataType(dtm.getDataType(new CategoryPath("/std"), "int32_t"), 10, -1);
		case "mt_virtual_seed_type":
			return new ArrayDataType(dtm.getDataType(new CategoryPath("/std"), "int32_t"), 20, -1);
		case "mt_cur_buffer":
		case "mt_virtual_buffer":
			return dtm.getDataType(new CategoryPath("/std"), "int16_t");
		case "mt_buffer":
			return new ArrayDataType(new ArrayDataType(dtm.getDataType(new CategoryPath("/std"), "uint32_t"), 624, -1),
					10, -1);
		case "filecomp_buffer":
		case "filecomp_buffer_aux":
			return new ArrayDataType(CharDataType.dataType, 20000, -1);
		case "filecomp_buffer2":
		case "filecomp_buffer2_aux":
			return new ArrayDataType(CharDataType.dataType, 80000, -1);
		case "dung_buildinginteract":
			return dtm.getPointer(dtm.getDataType(dfCategoryPath, "buildingst"));
		case "unitprintstack_clear":
			return BooleanDataType.dataType;
		}

		if (name.startsWith("DEBUG_")) {
			return BooleanDataType.dataType;
		}
		if (name.startsWith("index1_") || name.startsWith("index2_")) {
			return CharDataType.dataType;
		}

		return null;
	}

	void fixDemangler() throws Exception {
		var dfNS = getNamespace(null, "df");

		for (var lib : currentProgram.getExternalManager().getExternalLibraryNames()) {
			var libNS = getNamespace(null, lib);
			if (libNS == null) {
				continue;
			}

			var stdNS = getNamespace(libNS, "std");
			if (stdNS != null) {
				var stringNS = getNamespace(stdNS, "basic_string<char,std--char_traits<char>,std--allocator<char>>");
				if (stringNS != null) {
					for (var child : symtab.getChildren(stringNS.getSymbol())) {
						if (child.getSymbolType() == SymbolType.FUNCTION) {
							((Function) child.getObject()).setCallingConvention("__thiscall");
						}
					}
					var repNS = getNamespace(stringNS, "_Rep");
					if (repNS != null) {
						for (var child : symtab.getChildren(repNS.getSymbol())) {
							if (child.getSymbolType() == SymbolType.FUNCTION) {
								((Function) child.getObject()).setCallingConvention("__thiscall");
							}
						}
						repNS.getSymbol().setNameAndNamespace("_string_rep", stdNS, SourceType.IMPORTED);
					}
					stringNS.getSymbol().setName("string", SourceType.IMPORTED);
				}
			}

			Namespace libDFNS = getNamespace(libNS, "df");

			for (var child : symtab.getChildren(libNS.getSymbol())) {
				switch (child.getName(false)) {
				case "df":
					// avoid recursion just in case
					continue;
				case "abbreviate_string":
				case "add_long_to_string":
				case "basic_random":
				case "capitalize_string_first_word":
				case "capitalize_string_words":
				case "convert_long_to_string":
				case "convert_string_to_long":
				case "CreateDirectory":
				case "errorlog_string":
				case "find_directories_by_pattern":
				case "find_directories_by_pattern_with_exception":
				case "find_files_by_pattern":
				case "find_files_by_pattern_with_exception":
				case "gamelog_string":
				case "get_number":
				case "get_ordinal":
				case "GetTickCount":
				case "grab_token_expression":
				case "grab_token_list_as_string":
				case "grab_token_string":
				case "grab_token_string_pos":
				case "grab_variable_token":
				case "itoa":
				case "lower_case_string":
				case "MessageBox":
				case "mt_init":
				case "mt_trandom":
				case "pop_trandom_uniform_seed":
				case "push_trandom_double_seed":
				case "push_trandom_triple_seed":
				case "push_trandom_uniform_seed":
				case "r_num":
				case "replace_token_string":
				case "simplify_string":
				case "standardstringentry":
				case "trandom_twist":
				case "upper_case_string":
					break;
				default:
					if (getNamespace(dfNS, child.getName(false)) != null) {
						for (var child2 : symtab.getChildren(child)) {
							if (child2.getSymbolType() == SymbolType.FUNCTION) {
								((Function) child2.getObject()).setCallingConvention("__thiscall");
							}
						}
						break;
					}
					continue;
				}

				// move into the df namespace for consistency
				if (libDFNS == null) {
					libDFNS = symtab.createNameSpace(libNS, "df", SourceType.IMPORTED);
				}
				child.setNamespace(libDFNS);
			}
		}

		var localStdNS = getNamespace(null, "std");
		if (localStdNS != null) {
			for (var childNS : symtab.getChildren(localStdNS.getSymbol())) {
				if (childNS.getName(false).contains("<")) {
					for (var child : symtab.getChildren(childNS)) {
						if (child.getSymbolType() == SymbolType.FUNCTION) {
							((Function) child.getObject()).setCallingConvention("__thiscall");
						}
					}
				}
			}
		}
	}

	private boolean determineCallTypes() throws Exception {
		boolean anySignatureChanged = false;

		var funcs = new HashSet<Function>();
		var callTypes = new ConcurrentHashMap<Function, CallType>();

		monitor.checkCanceled();

		for (var func : currentProgram.getFunctionManager().getFunctions(true)) {
			if (func.isThunk()) {
				continue;
			}

			if ("__thiscall".equals(func.getCallingConventionName())) {
				funcs.add(func);
			}

			if (!func.getSignatureSource().isLowerPriorityThan(SourceType.IMPORTED)) {
				if (func.hasVarArgs()) {
					// bug; need to figure out why
					func.setVarArgs(false);
					var params = new ArrayList<>(Arrays.asList(func.getParameters()));
					for (int i = 0; i < params.size(); i++) {
						if ("__fn".equals(params.get(i).getName())) {
							while (params.size() > i) {
								params.remove(i);
							}
							func.updateFunction(null, null, params,
									Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.IMPORTED);
							break;
						}
					}
				}
				callTypes.put(func, new CallType(func));
			}
		}

		ParallelDecompiler.decompileFunctions(new CallTypeFinder(callTypes), currentProgram, funcs, monitor);

		for (var calledFunc : callTypes.entrySet()) {
			monitor.checkCanceled();

			var func = calledFunc.getKey();
			var call = calledFunc.getValue();

			if (!func.getSignatureSource().isLowerPriorityThan(SourceType.IMPORTED)) {
				// don't override structures vmethods, but do process them to help catch bugs
				continue;
			}

			var params = call.getParameters();
			if (params == null) {
				continue;
			}

			boolean anyChange = func.getParameterCount() != params.length;
			for (int i = 0; !anyChange && i < params.length; i++) {
				anyChange = !params[i].getDataType().equals(func.getParameter(i).getDataType());
			}

			if (anyChange) {
				anySignatureChanged = true;
				println("updating " + func.getSignature().getPrototypeString() + " -> " + call);
				func.updateFunction(call.getCallingConvention(), call.getReturnVariable(),
						Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.ANALYSIS, params);
			}
		}

		monitor.checkCanceled();
		analyzeChanges(currentProgram);

		// wait for analysis that was started by this to complete before next iteration
		AutoAnalysisManager.getAnalysisManager(currentProgram).waitForAnalysis(null, monitor);

		return anySignatureChanged;
	}

	private DataType mergeVTables(Structure vtt1, Structure vtt2) {
		if (vtt2 == null) {
			return null;
		}

		for (var vtt = vtt1; vtt != null; vtt = getSuperVTable(vtt)) {
			if (vtt.equals(vtt2)) {
				return dtm.getDataType(dfCategoryPath, vtt.getName().substring("vtable_".length()));
			}
		}

		return mergeVTables(vtt1, getSuperVTable(vtt2));
	}

	private Structure getSuperVTable(Structure vtt) {
		if ("_super".equals(vtt.getComponent(0).getFieldName())) {
			return (Structure) vtt.getComponent(0).getDataType();
		}

		return null;
	}

	// immutable. equals and hashcode are by reference.
	private final class CallType {
		public abstract class SimplifiedDataType {
			public SimplifiedDataType merge(SimplifiedDataType other) {
				if (this.equals(other)) {
					return this;
				}

				return null;
			}

			public abstract DataType toDataType();

			@Override
			public boolean equals(Object obj) {
				if (!(obj instanceof SimplifiedDataType)) {
					return false;
				}

				var other = (SimplifiedDataType) obj;
				return DataTypeUtilities.isSameOrEquivalentDataType(toDataType(), other.toDataType());
			}

			@Override
			public int hashCode() {
				return toDataType().hashCode();
			}

			@Override
			public String toString() {
				var sb = new StringBuilder();
				var path = toDataType().getDataTypePath();
				for (var ns : path.getCategoryPath().asArray()) {
					sb.append(ns);
					sb.append("::");
				}
				return sb.append(path.getDataTypeName()).toString();
			}
		}

		public class SimplifiedPointer extends SimplifiedDataType {
			public final SimplifiedDataType target;

			public SimplifiedPointer(SimplifiedDataType target) {
				this.target = target;
			}

			@Override
			public SimplifiedDataType merge(SimplifiedDataType other) {
				var merged = super.merge(other);
				if (merged != null) {
					return merged;
				}

				if (other instanceof SimplifiedPointer) {
					var target = ((SimplifiedPointer) other).target;
					if (this.target instanceof SimplifiedString && target instanceof SimplifiedPointer
							&& ((SimplifiedPointer) target).target instanceof SimplifiedChar) {
						return this;
					}

					merged = this.target.merge(target);
					if (merged != null) {
						return new SimplifiedPointer(merged);
					}
				}

				if (other instanceof SimplifiedUndefined
						&& ((SimplifiedUndefined) other).length == currentProgram.getDefaultPointerSize()) {
					return this;
				}

				if (other instanceof SimplifiedInteger
						&& ((SimplifiedInteger) other).length == currentProgram.getDefaultPointerSize()) {
					return this;
				}

				return null;
			}

			@Override
			public DataType toDataType() {
				return dtm.getPointer(this.target.toDataType());
			}
		}

		public class SimplifiedVoid extends SimplifiedDataType {
			@Override
			public SimplifiedDataType merge(SimplifiedDataType other) {
				var merged = super.merge(other);
				if (merged != null) {
					return merged;
				}

				if (other instanceof SimplifiedStruct || other instanceof SimplifiedClass) {
					return other;
				}

				return null;
			}

			@Override
			public DataType toDataType() {
				return DataType.VOID;
			}
		}

		public class SimplifiedFStream extends SimplifiedDataType {
			@Override
			public DataType toDataType() {
				return dtm.getDataType("/std/fstream");
			}
		}

		public class SimplifiedString extends SimplifiedDataType {
			@Override
			public DataType toDataType() {
				return dtm.getDataType("/std/string");
			}
		}

		public class SimplifiedChar extends SimplifiedDataType {
			@Override
			public DataType toDataType() {
				return CharDataType.dataType;
			}
		}

		public class SimplifiedClass extends SimplifiedDataType {
			public final Structure dt;

			public SimplifiedClass(Structure dt) {
				this.dt = dt;
			}

			@Override
			public SimplifiedDataType merge(SimplifiedDataType other) {
				var merged = super.merge(other);
				if (merged != null) {
					return merged;
				}

				if (other instanceof SimplifiedClass) {
					var vtp1 = (Pointer) this.dt.getComponent(0).getDataType();
					var vtp2 = (Pointer) ((SimplifiedClass) other).dt.getComponent(0).getDataType();
					var mergedType = mergeVTables((Structure) vtp1.getDataType(), (Structure) vtp2.getDataType());
					if (mergedType != null) {
						return from(mergedType);
					}
				}

				return null;
			}

			@Override
			public DataType toDataType() {
				return this.dt;
			}
		}

		public class SimplifiedStruct extends SimplifiedDataType {
			public final Structure dt;

			public SimplifiedStruct(Structure dt) {
				this.dt = dt;
			}

			@Override
			public SimplifiedDataType merge(SimplifiedDataType other) {
				var merged = super.merge(other);
				if (merged != null) {
					return merged;
				}

				if (other instanceof SimplifiedStruct && ((SimplifiedStruct) other).dt.getName().equals("language_name")
						&& this.dt.getNumComponents() > 0 && DataTypeUtilities.isSameOrEquivalentDataType(
								((SimplifiedStruct) other).dt, this.dt.getComponent(0).getDataType())) {
					return other;
				}

				if (other instanceof SimplifiedVector && this.dt.getNumComponents() > 0) {
					var firstField = from(this.dt.getComponent(0).getDataType());
					if (firstField != null) {
						merged = other.merge(firstField);
						if (merged != null) {
							return merged;
						}
						// merge in both directions because this might be complicated
						merged = firstField.merge(other);
						if (merged != null) {
							return merged;
						}
					}
				}

				if (other instanceof SimplifiedInteger && this.dt.getNumComponents() > 0
						&& this.dt.getComponent(0).isBitFieldComponent()
						&& ((SimplifiedInteger) other).length == this.dt.getLength()) {
					return other;
				}

				return null;
			}

			@Override
			public DataType toDataType() {
				return this.dt;
			}
		}

		public class SimplifiedUnion extends SimplifiedDataType {
			public final Union dt;
			private final Set<SimplifiedDataType> members;

			public SimplifiedUnion(Union dt) {
				this.dt = dt;
				this.members = new HashSet<SimplifiedDataType>();
				for (var m : dt.getComponents()) {
					this.members.add(from(m.getDataType()));
				}
			}

			@Override
			public SimplifiedDataType merge(SimplifiedDataType other) {
				var merged = super.merge(other);
				if (merged != null) {
					return merged;
				}

				if (this.members.contains(other)) {
					return this;
				}

				return null;
			}

			@Override
			public DataType toDataType() {
				return this.dt;
			}
		}

		public class SimplifiedVector extends SimplifiedDataType {
			public final SimplifiedDataType element;

			public SimplifiedVector(SimplifiedDataType element) {
				this.element = element;
			}

			@Override
			public SimplifiedDataType merge(SimplifiedDataType other) {
				var merged = super.merge(other);
				if (merged != null) {
					return merged;
				}

				if (other instanceof SimplifiedVector) {
					merged = this.element.merge(((SimplifiedVector) other).element);
					if (merged != null) {
						return new SimplifiedVector(merged);
					}
				}

				if (other instanceof SimplifiedPointer) {
					var target = ((SimplifiedPointer) other).target;
					merged = this.element.merge(target);
					if (merged != null) {
						return new SimplifiedVector(merged);
					}
					merged = target.merge(this.element);
					if (merged != null) {
						return new SimplifiedVector(merged);
					}
				}

				return null;
			}

			@Override
			public DataType toDataType() {
				return dtm.getDataType("/std/vector<" + this.element.toDataType().getName() + ">");
			}
		}

		public class SimplifiedSet extends SimplifiedDataType {
			public final SimplifiedDataType element;

			public SimplifiedSet(SimplifiedDataType element) {
				this.element = element;
			}

			@Override
			public DataType toDataType() {
				return dtm.getDataType("/std/set<" + this.element.toDataType().getName() + ">");
			}
		}

		public class SimplifiedInteger extends SimplifiedDataType {
			public final int length;
			public final boolean signed;

			public SimplifiedInteger(int length, boolean signed) {
				this.length = length;
				this.signed = signed;
			}

			@Override
			public SimplifiedDataType merge(SimplifiedDataType other) {
				var merged = super.merge(other);
				if (merged != null) {
					return merged;
				}

				if (other instanceof SimplifiedInteger && this.length == ((SimplifiedInteger) other).length) {
					return new SimplifiedInteger(this.length, true);
				}

				if (other instanceof SimplifiedUndefined && ((SimplifiedUndefined) other).length == this.length) {
					return this;
				}

				return null;
			}

			@Override
			public DataType toDataType() {
				return dtm.getDataType("/std/" + (this.signed ? "int" : "uint") + (this.length * 8) + "_t");
			}
		}

		public class SimplifiedEnum extends SimplifiedDataType {
			public final Enum dt;
			public final int length;

			public SimplifiedEnum(Enum dt, int length) {
				this.dt = dt;
				this.length = length;
			}

			@Override
			public SimplifiedDataType merge(SimplifiedDataType other) {
				var merged = super.merge(other);
				if (merged != null) {
					return merged;
				}

				if (other instanceof SimplifiedInteger && ((SimplifiedInteger) other).length == this.length) {
					return other;
				}

				if (other instanceof SimplifiedUndefined && ((SimplifiedUndefined) other).length == this.length) {
					return this;
				}

				return null;
			}

			@Override
			public DataType toDataType() {
				if (this.dt.getLength() == length) {
					return this.dt;
				}

				return dtm.getDataType(this.dt.getCategoryPath(), this.dt.getName() + "(" + (length * 8) + "-bit)");
			}
		}

		public class SimplifiedUndefined extends SimplifiedDataType {
			public final int length;

			public SimplifiedUndefined(int length) {
				this.length = length;
			}

			@Override
			public SimplifiedDataType merge(SimplifiedDataType other) {
				if (this.length == 0) {
					return other;
				}

				return super.merge(other);
			}

			@Override
			public DataType toDataType() {
				return Undefined.getUndefinedDataType(length);
			}
		}

		public class SimplifiedUnhandled extends SimplifiedDataType {
			public final DataType dt;

			public SimplifiedUnhandled(DataType dt) {
				this.dt = dt;
			}

			@Override
			public DataType toDataType() {
				return this.dt;
			}

			@Override
			public String toString() {
				return "UNHANDLED( " + super.toString() + " )";
			}
		}

		public SimplifiedDataType from(DataType dt) {
			var origDT = dt;
			if (dt instanceof TypeDef) {
				dt = ((TypeDef) dt).getBaseDataType();
			}

			if (DataTypeUtilities.isSameOrEquivalentDataType(dt, DataType.VOID)) {
				return new SimplifiedVoid();
			}

			if (Undefined.isUndefined(dt)) {
				if (dt == DataType.DEFAULT) {
					return new SimplifiedUndefined(0);
				}
				return new SimplifiedUndefined(dt.getLength());
			}

			if (dt.getPathName().equals("/std/fstream")) {
				return new SimplifiedFStream();
			}

			if (dt.getPathName().equals("/std/string") || dt.getPathName().equals("/std/_string_dataplus")) {
				return new SimplifiedPointer(new SimplifiedChar());
			}

			if (dt.getPathName().equals("/stringvectst")
					|| dt.getPathName().equals("/std/vector<pstringst*,std--allocator<pstringst*>>")) {
				return new SimplifiedVector(new SimplifiedPointer(new SimplifiedString()));
			}

			if (dt.getPathName().equals("/std/vector<unsigned_short,std--allocator<unsigned_short>>")) {
				return new SimplifiedVector(new SimplifiedInteger(2, false));
			}

			if (dt.getPathName().equals("/std/vector<char*,std--allocator<char*>>")) {
				return new SimplifiedVector(new SimplifiedPointer(new SimplifiedChar()));
			}

			if (dt.getPathName().equals("/std/set") || dt.getPathName().equals("/std/set<interface_key>")
					|| dt.getPathName().equals(
							"/std/_Rb_tree<long,long,std--_Identity<long>,std--less<long>,std--allocator<long>>")) {
				var e = dtm.getDataType("/df/enums/interface_key");
				return new SimplifiedSet(new SimplifiedEnum((Enum) e, e.getLength()));
			}

			if (dt instanceof Array) {
				var arr = (Array) dt;
				return from(arr.getDataType());
			}

			if (dt instanceof Pointer) {
				var ptr = (Pointer) dt;
				if (ptr.getDataType().getPathName().equals("/std/string")) {
					return new SimplifiedPointer(new SimplifiedString());
				}
				return new SimplifiedPointer(from(ptr.getDataType()));
			}

			if (dt instanceof CharDataType || dt instanceof AbstractStringDataType) {
				return new SimplifiedChar();
			}

			if (dt instanceof Union) {
				var union = (Union) dt;
				if (union.getCategoryPath().equals(dfCategoryPath)) {
					return new SimplifiedUnion(union);
				}
			}

			if (dt instanceof Structure) {
				var struct = (Structure) dt;
				if (struct.getName().endsWith("]")) {
					return from(new ArrayDataType(struct.getComponent(0).getDataType(), struct.getNumComponents(), -1));
				}
				if (struct.getName().startsWith("ptr_to_") && struct.getNumComponents() == 1
						&& "ptr".equals(struct.getComponent(0).getFieldName())) {
					return from(struct.getComponent(0).getDataType());
				}
				if (struct.getCategoryPath().equals(dfCategoryPath)) {
					if ("_vtable".equals(struct.getComponent(0).getFieldName())) {
						return new SimplifiedClass(struct);
					}
					return new SimplifiedStruct(struct);
				}
				if (struct.getPathName().startsWith("/std/vector<")) {
					if (struct.getNumComponents() == 0) {
						printerr(struct + "");
					}
					var ptr = (Pointer) struct.getComponent(0).getDataType();
					return new SimplifiedVector(from(ptr.getDataType()));
				}
			}

			if (dt instanceof AbstractIntegerDataType) {
				var absint = (AbstractIntegerDataType) dt;
				if (dt == origDT && dt.getLength() == 8) {
					return new SimplifiedUndefined(8);
				}

				return new SimplifiedInteger(absint.getLength(), absint.isSigned());
			}

			if (dt instanceof Enum) {
				var e = (Enum) dt;
				if (e.getCategoryPath().getParent().equals(dfCategoryPath)
						&& e.getCategoryPath().getName().equals("enums")) {
					if (e.getName().endsWith("-bit)")) {
						return new SimplifiedEnum((Enum) dtm.getDataType(e.getCategoryPath(),
								e.getName().substring(0, e.getName().indexOf('('))), e.getLength());
					}

					return new SimplifiedEnum(e, e.getLength());
				}
			}

			printerr("TODO: from( " + origDT + " )");
			return new SimplifiedUnhandled(origDT);
		}

		public final class Arg {
			public final Set<SimplifiedDataType> dt;

			public Arg(DataType dt) {
				this.dt = Set.of(from(dt));
			}

			public Arg(Varnode vn) {
				var def = vn.getDef();
				while (def != null && (def.getOpcode() == PcodeOp.CAST || def.getOpcode() == PcodeOp.INT_ZEXT)) {
					vn = def.getInput(0);
					def = vn.getDef();
				}

				var high = vn.getHigh();
				this.dt = Set.of(from(high.getDataType()));
			}

			public Arg(Parameter param) {
				this.dt = Set.of(from(param.getDataType()));
			}

			public Arg(Arg a, Arg b) {
				if (a == null || b == null) {
					this.dt = null;
					return;
				}

				this.dt = new HashSet<>(a.dt);
				this.dt.addAll(b.dt);
			}

			public Arg(Arg toSimplify) {
				var types = new ArrayList<>(toSimplify.dt);
				for (int i = 0; i < types.size(); i++) {
					var a = types.get(i);
					for (int j = 0; j < types.size(); j++) {
						if (i == j) {
							continue;
						}

						var b = types.get(j);
						var merged = a.merge(b);
						if (merged != null) {
							types.set(i, merged);
							types.remove(j);

							i = -1;
							break;
						}
					}
				}

				this.dt = new HashSet<>(types);
			}

			@Override
			public String toString() {
				var simplified = new Arg(this);
				if (simplified.dt.size() != 1) {
					return "CONFLICT : " + simplified.dt;
				}

				return simplified.dt.iterator().next().toString();
			}
		}

		public final Function func;
		public final Arg[] args;
		public final Arg ret;

		public CallType(PcodeOp call) {
			var funcAddr = call.getInput(0).getAddress();
			this.func = getFunctionAt(funcAddr);
			this.args = new Arg[call.getNumInputs() - 1];
			for (int i = 1; i < call.getNumInputs(); i++) {
				this.args[i - 1] = new Arg(call.getInput(i));
			}
			this.ret = call.getOutput() == null ? new Arg(DataType.VOID) : new Arg(call.getOutput());
		}

		public Parameter[] getParameters() {
			var simplified = new CallType(this);
			var params = new Parameter[simplified.args.length];
			for (int i = 0; i < params.length; i++) {
				if (simplified.args[i].dt.size() != 1) {
					return null;
				}

				try {
					params[i] = new ParameterImpl(null, simplified.args[i].dt.iterator().next().toDataType(),
							currentProgram);
				} catch (InvalidInputException e) {
					printerr("invalid input exception thrown by ParameterImpl constructor: " + e);
					return null;
				}
			}

			return params;
		}

		public Variable getReturnVariable() {
			// TODO
			return null;
		}

		public String getCallingConvention() {
			// TODO
			return null;
		}

		public CallType(Function func) {
			this.func = func;
			this.args = new Arg[func.getParameterCount()];
			for (int i = 0; i < this.args.length; i++) {
				this.args[i] = new Arg(func.getParameter(i));
			}
			this.ret = new Arg(func.getReturn());
		}

		public CallType(CallType a, CallType b) {
			if (!a.func.equals(b.func)) {
				throw new IllegalArgumentException("function must match");
			}

			this.func = a.func;
			this.args = new Arg[Math.max(a.args.length, b.args.length)];
			for (int i = 0; i < this.args.length; i++) {
				var aarg = i < a.args.length ? a.args[i] : null;
				var barg = i < b.args.length ? b.args[i] : null;
				this.args[i] = new Arg(aarg, barg);
			}
			this.ret = new Arg(a.ret, b.ret);

			var simplified = new CallType(this);
			for (int i = 0; i < simplified.args.length; i++) {
				if (simplified.args[i].dt.size() != 1) {
					println(simplified.toString());
					break;
				}
			}
		}

		public CallType(CallType toSimplify) {
			this.func = toSimplify.func;
			this.args = new Arg[toSimplify.args.length];
			for (int i = 0; i < this.args.length; i++) {
				this.args[i] = new Arg(toSimplify.args[i]);
			}
			this.ret = new Arg(toSimplify.ret);
		}

		@Override
		public String toString() {
			var sb = new StringBuilder();
			sb.append(this.ret);
			sb.append(' ');
			sb.append(this.func.getName(true));
			sb.append(" ( ");
			for (int i = 0; i < this.args.length; i++) {
				if (i != 0) {
					sb.append(" , ");
				}
				sb.append(this.args[i]);
			}
			sb.append(" )");
			return sb.toString();
		}
	}

	private final class CallTypeFinder extends PcodeCallback {
		private final ConcurrentHashMap<Function, CallType> callTypes;

		public CallTypeFinder(ConcurrentHashMap<Function, CallType> callTypes) {
			this.callTypes = callTypes;
		}

		@Override
		public void process(DecompileResults results, PcodeOp op) throws Exception {
			if (op.getOpcode() != PcodeOp.CALL) {
				return;
			}

			if (op.getNumInputs() < 2) {
				return;
			}

			var funcAddr = op.getInput(0).getAddress();
			var func = getFunctionAt(funcAddr);
			if (func == null) {
				printerr("TODO: call( " + funcAddr + " )");
				return;
			}

			if (func.isExternal() || func.isThunk()) {
				return;
			}

			final CallType call = new CallType(op);
			callTypes.compute(func, new BiFunction<Function, CallType, CallType>() {
				@Override
				public CallType apply(Function t, CallType u) {
					if (u == null) {
						return call;
					}

					return new CallType(u, call);
				}
			});
		}
	}
}
