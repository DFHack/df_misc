//replaces .conflict types with what they conflicted with, useful for cleaning up after version tracking
//only replaces 100 types per run, so multiple runs may be needed
//@author Kelly Kinkade <kelly.lynn.martin@gmail.com>
//@category Cleanup
//@keybinding
//@menupath
//@toolbar


import util.CollectionUtils;
import java.util.List;
import java.util.stream.Stream;
import java.util.stream.Collectors;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.util.Swing;


public class FixConflicts extends GhidraScript {

	@Override
	protected void run() throws Exception {
		boolean rerun = false;
		DataTypeManager dtm = currentProgram.getDataTypeManager();

		List<DataType> conflicts = CollectionUtils.asStream(dtm.getAllDataTypes())
			.filter(dt -> dt.getName().contains(".conflict"))
			.collect(Collectors.toList());
		int orig = conflicts.size();
		String message = "Fixing Conflicts " + String.valueOf(conflicts.size()) + " of " + String.valueOf(orig);
		println(message);
		int id = dtm.startTransaction("Fixing Conflicts");
		boolean success = false;
		try {
			monitor.initialize(conflicts.size());
			monitor.setMessage(message);
			for (DataType dt : conflicts) {
				monitor.checkCanceled();
				monitor.setMessage(message + ":" + dt.getName());
				if (dt.isDeleted()) {
					monitor.incrementProgress(1);
					continue;
				}
				String name = dt.getName();
				int i = name.indexOf(".conflict");
				if (i == -1) {
					monitor.incrementProgress(1);
					continue;
				}
				name = name.substring(0, i);
				DataType good = dtm.getDataType(dt.getCategoryPath(), name);
				if (good == null) {
					monitor.incrementProgress(1);
					continue;
				}
				dtm.replaceDataType(dt, good, false);
				monitor.incrementProgress(1);
				Swing.allowSwingToProcessEvents();
			}
			success = true;
		} finally {
			dtm.endTransaction(id, success);
		}
	}

}
