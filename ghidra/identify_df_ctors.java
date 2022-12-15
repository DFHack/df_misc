import java.util.*;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.decompiler.parallel.*;
import ghidra.app.plugin.core.searchmem.SearchData;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.datastruct.ListAccumulator;
import ghidra.util.search.memory.*;
import ghidra.util.task.TaskMonitor;

public class identify_df_ctors extends GhidraScript {
	@Override
	public AnalysisMode getScriptAnalysisMode() {
		return AnalysisMode.SUSPENDED;
	}

	@Override
	protected void run() throws Exception {
		var vtables = getVirtualTypesByVTableAddress();
		if (vtables == null) {
			return;
		}

		fixDemanglerMess();

		var instrAddrs = findPossibleVTableAssignmentInstructions();
		var funcs = findOrCreateContainingFunctions(instrAddrs);

		println("To process: " + funcs.size() + " functions");
		ParallelDecompiler.decompileFunctions(new Callback(vtables), currentProgram, funcs, monitor);
	}

	private Map<Long, DataType> getVirtualTypesByVTableAddress() throws Exception {
		var dtm = currentProgram.getDataTypeManager();
		var dtcVTables = dtm.getCategory(new CategoryPath("/df/vtables"));
		if (dtcVTables == null) {
			printerr("This script should be run after import_df_structures");
			return null;
		}
		var dtc = dtcVTables.getParent();

		var symtab = currentProgram.getSymbolTable();
		var vtables = new HashMap<Long, DataType>();
		for (var vtable : dtcVTables.getDataTypes()) {
			if (vtable instanceof Structure) {
				var syms = symtab.getGlobalSymbols(vtable.getName());
				monitor.checkCanceled();
				if (syms.isEmpty()) {
					printerr("No symbols for " + vtable.getName());
				} else {
					var dt = dtc.getDataType(vtable.getName().substring("vtable_".length()));
					var ptr = dtm.getPointer(dt);
					for (var sym : syms) {
						vtables.put(sym.getAddress().getOffset(), ptr);
					}
				}
			}
		}
		return vtables;
	}

	private void fixDemanglerMess() throws Exception {
		// Ghidra's GNU demangler doesn't correctly identify methods versus namespaced
		// global functions.

		var dtm = currentProgram.getDataTypeManager();
		var dtc = dtm.getCategory(new CategoryPath("/df"));
		var dtcStd = dtm.getCategory(new CategoryPath("/df/std"));
		var stdString = dtcStd.getDataType("string");
		var stdFStream = dtcStd.getDataType("fstream");

		for (var func : currentProgram.getFunctionManager().getExternalFunctions()) {
			if (func.getParentNamespace() instanceof Library) {
				// global namespace
				continue;
			}

			var possibleClass = func.getParentNamespace().getName();
			boolean makeThisCall = false;
			if (possibleClass.startsWith("basic_string<")) {
				dtcStd.addDataType(new TypedefDataType(possibleClass, stdString), DataTypeConflictHandler.KEEP_HANDLER);
				makeThisCall = true;
			} else if (possibleClass.startsWith("basic_ostream<") || possibleClass.startsWith("basic_istream<")
					|| possibleClass.startsWith("basic_fstream<") || possibleClass.startsWith("basic_ofstream<")
					|| possibleClass.startsWith("basic_ios<") || possibleClass.equals("ios_base")) {
				dtcStd.addDataType(new TypedefDataType(possibleClass, stdFStream),
						DataTypeConflictHandler.KEEP_HANDLER);
				makeThisCall = true;
			} else if (dtc.getDataType(possibleClass) != null) {
				makeThisCall = true;
			}

			if (makeThisCall) {
				var oldCC = func.getCallingConventionName();
				if (!oldCC.equals("__thiscall")) {
					func.setCallingConvention("__thiscall");

					if (!oldCC.equals("unknown")) {
						println("Modified external function " + func + " to be __thiscall (was " + oldCC + ")");
					}
				}
			}
		}
	}

	private List<MemSearchResult> findPossibleVTableAssignmentInstructions() throws Exception {
		byte[] searchBytes, searchMask;
		if (currentProgram.getDefaultPointerSize() == 8) {
			// 64-bit. TODO: verify on non-Linux
			searchBytes = new byte[] { 0x48, (byte) 0xc7, 0, 0, 0, 0, 0 };
			searchMask = new byte[] { (byte) 0xff, (byte) 0xff, (byte) 0xf8, 0, 0, 0, 0 };
		} else {
			// 32-bit. TODO: verify on non-Linux
			searchBytes = new byte[] { (byte) 0xc7, 0, 0, 0, 0, 0 };
			searchMask = new byte[] { (byte) 0xff, (byte) 0xf8, 0, 0, 0, 0 };
		}

		var searchData = SearchData.createSearchData("(vtable assignment instruction)", searchBytes, searchMask);
		var searchInfo = new SearchInfo(searchData, 1 << 30, false, true, 1, false,
				new CodeUnitSearchInfo(true, false, true), null);
		var searchAlg = searchInfo.createSearchAlgorithm(currentProgram, currentProgram.getMinAddress(), null);

		println("Searching for instructions that look like vtable assignments...");
		monitor.setMessage("Searching for instructions that look like vtable assignments...");
		var instrAddrs = new ListAccumulator<MemSearchResult>();
		searchAlg.search(instrAddrs, monitor);
		return instrAddrs.asList();
	}

	private Set<Function> findOrCreateContainingFunctions(List<MemSearchResult> addrs) throws Exception {
		println("Finding functions containing " + addrs.size() + " candidate instructions...");
		var funcs = new HashSet<Function>();
		var addrSet = new AddressSet();
		int missing = 0;
		for (var addr : addrs) {
			var func = getFunctionContaining(addr.getAddress());
			if (func == null) {
				addrSet.add(addr.getAddress());
				missing++;
			} else {
				funcs.add(func);
			}
		}

		if (!addrSet.isEmpty()) {
			println(missing + " instructions were not inside functions. "
					+ "Attempting to create functions for these addresses...");
			runCommand(new DisassembleCommand(addrSet, null, true));
			runCommand(new CreateFunctionCmd(null, addrSet, null, SourceType.DEFAULT, true, true));
		}

		for (var addr : addrSet.getAddresses(true)) {
			var instr = getInstructionContaining(addr);
			if (instr != null && !instr.getAddress().equals(addr)) {
				// false positive
				continue;
			}

			var func = getFunctionContaining(addr);
			if (func == null) {
				printerr("Could not find function containing " + addr + " ("
						+ (instr != null ? instr.toString() : "missing instruction") + ")");
			} else {
				funcs.add(func);
			}
		}

		return funcs;
	}

	private final class Callback extends DecompilerCallback<Void> {
		private final Map<Long, DataType> vtables;
		private final int ptrSize = currentProgram.getDefaultPointerSize();

		public Callback(Map<Long, DataType> vtables) {
			super(currentProgram, new Configurer());
			this.setTimeout(3600);
			this.vtables = vtables;
		}

		@Override
		public Void process(DecompileResults results, TaskMonitor monitor_) throws Exception {
			if (!results.decompileCompleted()) {
				printerr(results.getErrorMessage());
				return null;
			}

			var func = results.getFunction();
			var hfunc = results.getHighFunction();

			boolean any = false;
			boolean anyVTable = false;

			for (var bb : hfunc.getBasicBlocks()) {
				if (findVTableAssignments(func, hfunc, bb)) {
					any = true;
				} else if (!any && !anyVTable) {
					var it = bb.getIterator();
					while (it.hasNext()) {
						var pc = it.next();
						for (var in : pc.getInputs()) {
							if (in.isConstant() && in.getSize() == ptrSize && vtables.containsKey(in.getOffset())) {
								anyVTable = true;
								printerr("Missed VTable usage in " + func + " : " + pc.getSeqnum().getTarget());
								printerr(getInstructionAt(pc.getSeqnum().getTarget()) + "");
								printerr(pc + "");
								println();
								break;
							}
						}
						if (anyVTable) {
							break;
						}
					}
				}
			}

			if (!any && anyVTable) {
				printerr("Found no vtable assignments in " + func + " @ " + func.getEntryPoint());
				println(results.getDecompiledFunction().getC());
			}

			return null;
		}

		private boolean findVTableAssignments(Function func, HighFunction hfunc, PcodeBlockBasic bb) throws Exception {
			boolean any = false;
			PcodeOp pc = null;
			var it = bb.getIterator();
			while (it.hasNext()) {
				var prev = pc;
				var cur = it.next();

				if (skipOpcode(cur.getOpcode())) {
					continue;
				}
				pc = cur;

				var vtype = verifyVTableAssignmentOp(func, prev, cur);
				if (vtype == null)
					continue;

				monitor.checkCanceled();
				any = true;

				var reg = cur.getInput(1);
				if (!checkForwardSlice(vtype, reg))
					continue;

				var slice = DecompilerUtils.getBackwardSliceToPCodeOps(reg);
				if (slice.isEmpty()) {
					annotateVTableParam(func, hfunc, vtype, reg, pc.getSeqnum().getTarget());
				} else {
					annotateVTableLocal(func, hfunc, vtype, slice);
				}
			}

			return any;
		}

		private void annotateVTableParam(Function func, HighFunction hfunc, DataType vtype, Varnode reg, Address addr)
				throws Exception {
			var proto = hfunc.getFunctionPrototype();
			HighParam found = null;
			for (int i = 0; i < proto.getNumParams() && found == null; i++) {
				var param = proto.getParam(i);
				if (param.getRepresentative().equals(reg)) {
					found = param;
					break;
				}
			}

			if (found == null) {
				// TODO
				printerr("TODO: couldn't find parameter? " + func + " " + addr + " " + getInstructionAt(addr));
			} else {
				var param = func.getParameter(found.getSlot());
				if (param == null) {
					if (func.getParameters().length == 0 && found.getSlot() == 0
							&& "unknown".equals(func.getCallingConventionName())) {
						println("Changing function " + func + " to thiscall on " + vtype);
						func.updateFunction("__thiscall", func.getReturn(),
								Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, false, SourceType.ANALYSIS);
						func.setParentNamespace(getClassNamespace(vtype));
					} else {
						// TODO
						printerr("TODO: parameter " + func + " " + addr + " " + found.getSlot() + " " + vtype);
					}
				} else if (!isParent(vtype, param.getDataType())) {
					if (!DataTypeUtilities.isSameOrEquivalentDataType(vtype, param.getDataType())) {
						println("Changing type of " + func + " parameter " + param + " from " + param.getDataType()
								+ " to " + vtype);
						param.setDataType(vtype, SourceType.ANALYSIS);
					}
				}
			}
		}

		private Varnode getConstVarnode(Varnode vn) throws Exception {
			if (vn.isConstant()) {
				return vn;
			}
			if (!vn.isUnique()) {
				return null;
			}
			var def = vn.getDef();
			if (def == null) {
				return null;
			}
			if (def.getOpcode() != PcodeOp.PTRSUB) {
				// TODO: others?
				return null;
			}
			if (!def.getInput(0).isConstant() || !def.getInput(1).isConstant()) {
				return null;
			}
			if (def.getInput(0).getSize() != def.getInput(1).getSize()) {
				return null;
			}
			if (def.getInput(0).getOffset() == 0) {
				return def.getInput(1);
			}
			if (def.getInput(1).getOffset() == 0) {
				return def.getInput(0);
			}
			// TODO
			throw new Exception("TODO: " + def);
		}

		private void annotateVTableLocal(Function func, HighFunction hfunc, DataType vtype, Set<PcodeOp> slice)
				throws Exception {
			var mapping = new HashMap<Varnode, Varnode>();
			PcodeOp callOp = null;
			for (var op : slice) {
				if (skipOpcode(op.getOpcode())) {
					continue;
				}

				switch (op.getOpcode()) {
				case PcodeOp.CAST:
					if (op.getInput(0).isUnique()) {
						mapping.put(op.getInput(0), op.getOutput());
					}
					break;
				case PcodeOp.PTRSUB:
					if (op.getInput(2).getOffset() == 0 && op.getOutput().isUnique()) {
						mapping.put(op.getOutput(), op.getInput(0));
					} else {
						// TODO
						printerr("TODO: " + func + " handle " + op);
					}
					break;
				case PcodeOp.CALL:
					if (callOp != null) {
						// TODO
						printerr("TODO: " + func + " multiple calls " + callOp + " / " + op);
					}
					callOp = op;
					break;
				default:
					// TODO
					printerr("TODO: " + func + " handle " + op);
					break;
				}
			}

			if (callOp != null) {
				var reg = mapping.get(callOp.getOutput());
				if (reg.isRegister()) {
					var register = currentProgram.getRegister(reg);
					var variable = new LocalVariableImpl(null,
							(int) callOp.getSeqnum().getTarget().subtract(func.getEntryPoint()), vtype, register,
							currentProgram, SourceType.ANALYSIS);

					for (var existing : func.getLocalVariables(VariableFilter.REGISTER_VARIABLE_FILTER)) {
						if (existing.isEquivalent(variable)) {
							// already have the variable
							return;
						}
					}

					var callDest = getFunctionAt(callOp.getInput(0).getAddress());
					var addedVar = func.addLocalVariable(variable, SourceType.ANALYSIS);
					println("Adding local variable " + addedVar + " to " + func + " (return value at "
							+ callOp.getSeqnum().getTarget() + " of function "
							+ (callDest != null ? callDest.toString() : callOp.toString()) + ")");
				} else {
					// TODO
					printerr("TODO: " + func + " call op (non-register?) " + callOp);
				}
			} else {
				// TODO
				printerr("TODO: " + func + " no CALL");
			}
		}

		private boolean skipOpcode(int opcode) {
			switch (opcode) {
			case PcodeOp.MULTIEQUAL:
			case PcodeOp.INDIRECT:
			case PcodeOp.PIECE:
			case PcodeOp.SUBPIECE:
				return true;
			default:
				return false;
			}
		}

		private GhidraClass getClassNamespace(DataType dt) {
			var ptr = (Pointer) dt;
			var ns = getNamespace(null, "df");
			return (GhidraClass) getNamespace(ns, ptr.getDataType().getName());
		}

		private DataType verifyVTableAssignmentOp(Function func, PcodeOp prev, PcodeOp cur) throws Exception {
			if (cur.getOpcode() != PcodeOp.STORE)
				return null;
			var constInput = getConstVarnode(cur.getInput(2));
			if (constInput == null)
				return null;
			if (constInput.getSize() != ptrSize)
				return null;
			return vtables.get(constInput.getOffset());
		}

		private boolean checkForwardSlice(DataType vtype, Varnode reg) throws Exception {
			var slice = DecompilerUtils.getForwardSliceToPCodeOps(reg);
			for (var op : slice) {
				// this could catch assignments to fields other than the vtable, but we'll say
				// that's okay for now
				if (op.getOpcode() == PcodeOp.STORE) {
					var constInput = getConstVarnode(op.getInput(2));
					if (constInput != null && constInput.getSize() == ptrSize) {
						var laterType = vtables.get(op.getInput(2).getOffset());
						if (laterType == null)
							continue;

						if (laterType.equals(vtype))
							continue;

						if (isParent(vtype, laterType))
							return false;
					}
				}
			}

			return true;
		}

		private Structure getVTable(DataType dt) {
			try {
				var ptr = (Pointer) dt;
				var struct = (Structure) ptr.getDataType();
				var field = struct.getComponent(0);
				var vptr = (Pointer) field.getDataType();
				return (Structure) vptr.getDataType();
			} catch (ClassCastException ex) {
				return null;
			}
		}

		private boolean isParent(DataType a, DataType b) {
			var avtable = getVTable(a);
			var bvtable = getVTable(b);

			if (avtable == null || bvtable == null) {
				return false;
			}

			while (true) {
				if (avtable.equals(bvtable)) {
					return true;
				}

				if ("_super".equals(bvtable.getComponent(0).getFieldName())) {
					bvtable = (Structure) bvtable.getComponent(0).getDataType();
				} else {
					return false;
				}
			}
		}
	}

	public class Configurer implements DecompileConfigurer {
		@Override
		public void configure(DecompInterface decompiler) {
			decompiler.toggleCCode(true);
			decompiler.toggleJumpLoads(false);
			decompiler.toggleParamMeasures(false);
			decompiler.toggleSyntaxTree(true);
		}
	}
}
