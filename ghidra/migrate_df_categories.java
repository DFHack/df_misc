// Reorganizes dfhack data types in the current program from the flat /df
// category layout (produced by older versions of import_df_structures.java)
// to the split-category layout used by newer versions:
//
//     /df/bitfields   - bitfield enums
//     /df/unions      - unions (incl. virtual_* base-class unions)
//     /df/structs     - structures and classes
//     /df/vtables     - vtable structures
//     /df/vtables/methods - vtable method function definitions
//     /df/enums       - enums (already correct in the old layout)
//     /df/vectors     - vector<X> and DfArray<X>
//     /df/arrays      - X[<enum>N] indexed-array structures
//     /df/BitArrays   - BitArray<X> and its helper types
//     /df/typedefs    - typedef types
//     /std/filesystem - fsPath and fsFiletime
//
// Pointer and array types follow the category of their element type.
// Types already in the correct category are skipped, so this script is safe
// to run multiple times.
//
// @category DFHack

import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class migrate_df_categories extends GhidraScript {
	private static final CategoryPath DF = new CategoryPath("/df");
	private static final CategoryPath DF_BITFIELDS = new CategoryPath("/df/bitfields");
	private static final CategoryPath DF_UNIONS = new CategoryPath("/df/unions");
	private static final CategoryPath DF_STRUCTS = new CategoryPath("/df/structs");
	private static final CategoryPath DF_VTABLES = new CategoryPath("/df/vtables");
	private static final CategoryPath DF_VMETHODS = new CategoryPath("/df/vtables/methods");
	private static final CategoryPath DF_ENUMS = new CategoryPath("/df/enums");
	private static final CategoryPath DF_VECTORS = new CategoryPath("/df/vectors");
	private static final CategoryPath DF_ARRAYS = new CategoryPath("/df/arrays");
	private static final CategoryPath DF_BITARRAYS = new CategoryPath("/df/BitArrays");
	private static final CategoryPath DF_TYPEDEFS = new CategoryPath("/df/typedefs");
	private static final CategoryPath STD = new CategoryPath("/std");
	private static final CategoryPath STD_FS = new CategoryPath("/std/filesystem");

	private DataTypeManager dtm;

	@Override
	public AnalysisMode getScriptAnalysisMode() {
		return AnalysisMode.SUSPENDED;
	}

	@Override
	protected void run() throws Exception {
		dtm = currentProgram.getDataTypeManager();

		// create the new categories in the same order a fresh import uses
		dtm.createCategory(DF);
		dtm.createCategory(DF_BITFIELDS);
		dtm.createCategory(DF_UNIONS);
		dtm.createCategory(DF_STRUCTS);
		dtm.createCategory(DF_VTABLES);
		dtm.createCategory(DF_VMETHODS);
		dtm.createCategory(DF_ENUMS);
		dtm.createCategory(DF_VECTORS);
		dtm.createCategory(DF_ARRAYS);
		dtm.createCategory(DF_BITARRAYS);
		dtm.createCategory(DF_TYPEDEFS);
		dtm.createCategory(STD_FS);

		List<DataType> types = new ArrayList<>();
		dtm.getAllDataTypes(types);

		monitor.initialize(types.size());
		println("migrating " + types.size() + " data types...");

		// pass 1: named types
		int i = 0;
		for (var dt : types) {
			monitor.checkCancelled();
			monitor.setProgress(++i);
			if (dt instanceof Pointer || dt instanceof Array)
				continue;

			CategoryPath cat = dt.getCategoryPath();
			CategoryPath target = null;
			if (cat.equals(DF)) {
				target = dfCategoryFor(dt);
			} else if (cat.equals(STD)) {
				target = stdCategoryFor(dt);
			}
			if (target != null)
				move(dt, target);
		}

		// pass 2: pointers and arrays follow their element type's category
		for (var dt : types) {
			monitor.checkCancelled();
			monitor.setProgress(++i);
			if (!(dt instanceof Pointer) && !(dt instanceof Array))
				continue;

			CategoryPath cat = dt.getCategoryPath();
			if (!inManagedTree(cat))
				continue;

			DataType base = dt;
			while (base instanceof Pointer || base instanceof Array) {
				if (base instanceof Pointer) {
					base = ((Pointer) base).getDataType();
				} else {
					base = ((Array) base).getDataType();
				}
			}
			move(dt, base.getCategoryPath());
		}

		println("migration complete");
	}

	private boolean inManagedTree(CategoryPath cat) {
		return cat.equals(DF) || cat.equals(STD) || cat.getPath().startsWith("/df/")
				|| cat.getPath().startsWith("/std/");
	}

	private CategoryPath dfCategoryFor(DataType dt) {
		String name = dt.getName();
		if (name.startsWith("BitArray<"))
			return DF_BITARRAYS;
		if (name.startsWith("DfArray<") || name.startsWith("vector<"))
			return DF_VECTORS;
		if (name.contains("[<"))
			return DF_ARRAYS;
		if (dt instanceof ghidra.program.model.data.Enum)
			return DF_BITFIELDS;
		if (dt instanceof Union)
			return DF_UNIONS;
		if (dt instanceof TypeDef)
			return DF_TYPEDEFS;
		if (dt instanceof FunctionDefinition)
			return DF_VMETHODS;
		if (dt instanceof Structure)
			return DF_STRUCTS;
		return null;
	}

	private CategoryPath stdCategoryFor(DataType dt) {
		String name = dt.getName();
		if (name.startsWith("vector<"))
			return DF_VECTORS;
		if (name.equals("fsPath") || name.equals("fsFiletime"))
			return STD_FS;
		return null;
	}

	private void move(DataType dt, CategoryPath target) {
		try {
			if (!dt.getCategoryPath().equals(target)) {
				dt.setCategoryPath(target);
				debugln("moved " + dt.getPathName() + " to " + target);
			}
		} catch (DuplicateNameException e) {
			printerr("could not move " + dt.getPathName() + " to " + target + ": " + e.getMessage());
		}
	}

	private void debugln(String message) {
		if (!ghidra.util.SystemUtilities.isInReleaseMode()) {
			println(message);
		}
	}
}
