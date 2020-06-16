// Defines variables and cleans up branches in Dwarf Fortress functions that return a newly allocated
// value of a type that differs based on a switch statement.
//@author Ben Lubar
//@category DFHack

import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.SourceType;

public class define_df_type_allocate_function extends GhidraScript {

	@Override
	protected void run() throws Exception {
		var func = getFunctionContaining(currentAddress);
		if (func == null) {
			printerr("This script must be called with a function selected.");
			return;
		}

		var result = decompileFunc(func);
		if (!result.decompileCompleted()) {
			printerr("Failed to decompile: " + result.getErrorMessage());
			return;
		}

		start();

		var dtm = currentProgram.getDataTypeManager();
		var dtc = dtm.getRootCategory().getCategory("df");
		var dtcVTable = dtc.getCategory("vtables");
		var symtab = currentProgram.getSymbolTable();
		var addrSpace = currentProgram.getAddressFactory().getDefaultAddressSpace();
		var retReg = currentProgram.getRegister(currentProgram.getAddressFactory().getRegisterSpace().getAddress(0));

		var hf = result.getHighFunction();
		var start = hf.getBasicBlocks().get(0);
		var it = start.getIterator();
		Varnode branchind = null;
		while (it.hasNext()) {
			var pc = it.next();
			if (pc.getOpcode() == PcodeOp.BRANCHIND) {
				branchind = pc.getInput(0);
				break;
			}
		}

		if (branchind == null) {
			printerr("Couldn't find switch statement.");
			return;
		}
		if (!branchind.getAddress().isStackAddress() && !(branchind.getHigh() instanceof HighParam)) {
			printerr("Branch is on a \"" + branchind.getAddress().getAddressSpace() + "\" address (TODO).");
			return;
		}

		boolean createdTypeVar = false;

		var numOuts = start.getOutSize();
		for (var i = 0; i < numOuts; i++) {
			var bb = (PcodeBlockBasic) start.getOut(i);
			it = bb.getIterator();
			Address branch = null;
			Address alloc = null;
			Address vtable = null;
			while (it.hasNext()) {
				var pc = it.next();
				if (pc.getOpcode() == PcodeOp.BRANCH) {
					branch = pc.getSeqnum().getTarget();
				}
				if (pc.getOpcode() == PcodeOp.CALL && alloc == null) {
					alloc = pc.getSeqnum().getTarget();
				}
				if (pc.getOpcode() == PcodeOp.STORE && pc.getInput(1).isRegister() && pc.getInput(1).getOffset() == 0) {
					vtable = pc.getInput(2).getAddress();
				}

				if (!it.hasNext() && branch == null && bb.getOutSize() == 1) {
					bb = (PcodeBlockBasic) bb.getOut(0);
					it = bb.getIterator();
				}
			}

			if (branch != null) {
				getInstructionAt(branch).setFlowOverride(FlowOverride.RETURN);
			}

			if (alloc == null && vtable == null) {
				// the default return-null branch.
				continue;
			}

			var sym = symtab.getPrimarySymbol(addrSpace.getAddress(vtable.getOffset()));
			var symName = sym != null ? sym.getName() : null;
			if (symName.startsWith("vtable_")) {
				var vtdt = dtcVTable.getDataType(symName);
				var svtdt = (Structure) vtdt;
				while (svtdt.getComponent(0).getFieldName().equals("_super")) {
					svtdt = (Structure) svtdt.getComponent(0).getDataType();
				}
				var dt = dtc.getDataType(symName.substring("vtable_".length()));
				ghidra.program.model.data.Enum typeType = null;
				for (var comp : svtdt.getComponents()) {
					if (comp.getFieldName().equals("getType")) {
						var gtfp = (Pointer) comp.getDataType();
						var gtf = (FunctionSignature) gtfp.getDataType();
						typeType = (ghidra.program.model.data.Enum) gtf.getReturnType();
					}
				}

				if (!createdTypeVar) {
					if (branchind.getHigh() instanceof HighParam) {
						var typeParam = new ParameterImpl("type", typeType, branchind.getAddress(), currentProgram,
								SourceType.USER_DEFINED);
						func.replaceParameters(Function.FunctionUpdateType.CUSTOM_STORAGE, false,
								SourceType.USER_DEFINED, typeParam);
					} else {
						var typeVar = new LocalVariableImpl("type", typeType, (int) branchind.getOffset(),
								currentProgram);
						func.addLocalVariable(typeVar, SourceType.USER_DEFINED);
					}
					func.setReturnType(dtm.getPointer(dtc.getDataType(svtdt.getName().substring("vtable_".length()))),
							SourceType.USER_DEFINED);
					createdTypeVar = true;
				}

				var branchVar = new LocalVariableImpl(typeType.getName(i).toLowerCase(),
						(int) alloc.subtract(func.getEntryPoint()), dtm.getPointer(dt), retReg, currentProgram);
				func.addLocalVariable(branchVar, SourceType.USER_DEFINED);
			}
		}

		end(true);
	}

	private DecompileResults decompileFunc(Function func) throws Exception {
		var decompiler = new DecompInterface();
		try {
			decompiler.openProgram(currentProgram);
			return decompiler.decompileFunction(func, 3600, monitor);
		} finally {
			decompiler.dispose();
		}
	}
}
