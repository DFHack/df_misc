// TODO
//
// @author Ben Lubar
// @category DFHack

import java.util.*;

import ghidra.app.decompiler.*;
import ghidra.app.decompiler.parallel.*;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.GhidraScript;
import ghidra.docking.settings.SettingsImpl;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.*;
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
		propagateThisCalls();
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

	private void propagateThisCalls() throws Exception {
		var funcs = new HashSet<Function>();
		var foundAny = true;
		while (foundAny) {
			foundAny = false;
			monitor.checkCanceled();

			for (var func : currentProgram.getFunctionManager().getFunctions(true)) {
				if (func.isThunk()) {
					continue;
				}

				if ("__thiscall".equals(func.getCallingConventionName())) {
					foundAny = funcs.add(func) || foundAny;
				}
			}

			ParallelDecompiler.decompileFunctions(new ThisCallFinder(), currentProgram, funcs, monitor);

			monitor.checkCanceled();
			analyzeChanges(currentProgram);

			// wait for analysis that was started by this to complete before next iteration
			AutoAnalysisManager.getAnalysisManager(currentProgram).waitForAnalysis(null, monitor);
		}
	}

	private final class ThisCallFinder extends PcodeCallback {
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

			if ("__thiscall".equals(func.getCallingConventionName())) {
				return;
			}

			var thisArg = op.getInput(1).getHigh();
			if (!(thisArg.getDataType() instanceof Pointer)) {
				return;
			}

			var thisArgType = ((Pointer) thisArg.getDataType()).getDataType();
			if (!thisArgType.getCategoryPath().equals(dfCategoryPath)) {
				return;
			}

			if (thisArgType.getName().startsWith("ptr_to_")) {
				return;
			}

			if (!(thisArgType instanceof Structure)) {
				return;
			}

			var thisStruct = (Structure) thisArgType;

			var isClass = "_vtable".equals(thisStruct.getComponent(0).getFieldName());
			var hasParent = isClass
					&& "_super".equals(((Structure) ((Pointer) thisStruct.getComponent(0).getDataType()).getDataType())
							.getComponent(0).getFieldName());

			if (!isClass || !hasParent) {
				println("Identified function @ " + func.getEntryPoint() + " as thiscall on df::"
						+ thisArgType.getName());

				int minArgs = 0;

				if ("file_compressorst".equals(thisArgType.getName())) {
					switch (results.getFunction().getName()) {
					case "write_file":
						minArgs = 1;
					case "read_file":
						func.setName(results.getFunction().getName(), SourceType.ANALYSIS);
						break;
					default:
						break;
					}
				}

				func.setParentNamespace(getNamespace(getNamespace(null, "df"), thisArgType.getName()));
				var params = new ArrayList<Parameter>(Arrays.asList(func.getParameters()));
				if (params.isEmpty()) {
					params.add(new ParameterImpl("this", thisArg.getDataType(), currentProgram));
					for (var i = 2; i < op.getNumInputs(); i++) {
						params.add(new ParameterImpl(null, Undefined.getUndefinedDataType(op.getInput(i).getSize()),
								currentProgram));
					}
				} else {
					params.remove(0);
					params.add(0, new ParameterImpl("this", thisArg.getDataType(), currentProgram));
				}

				for (var i = 1; i < params.size(); i++) {
					var actual = op.getInput(i + 1).getHigh().getDataType();
					if (actual instanceof Pointer && !(params.get(i).getDataType() instanceof Pointer)
							|| isBadPointer((Pointer) params.get(i).getDataType())) {
						params.get(i).setDataType(actual, SourceType.ANALYSIS);
					}
				}

				while (params.size() <= minArgs) {
					params.add(new ParameterImpl(null,
							Undefined.getUndefinedDataType(currentProgram.getDefaultPointerSize()), currentProgram));
				}

				func.updateFunction("__thiscall", func.getReturn(), params,
						Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.ANALYSIS);
			} else {
				printerr("TODO: " + func + " // class " + thisArgType.getName());
			}
		}

		private boolean isBadPointer(Pointer ptr) {
			var dt = ptr.getDataType();
			if (Undefined.isUndefined(dt) || LongDataType.dataType.equals(dt) || DataType.VOID.equals(dt)) {
				return true;
			}

			if (dt instanceof Pointer) {
				return isBadPointer((Pointer) dt);
			}

			return false;
		}
	}
}
