// Imports df-structures into Ghidra. This script should always be run on a freshly imported executable. Running it multiple times is likely to fail. For best results, run this script immediately after answering "no" to the prompt that asks if you want to analyze the executable.
//
// To make this script less tedious to run, create a file named import_df_structures.properties in the same directory as this script with the following two lines:
//
//     Select codegen.out.xml Select=[full path to df-structures]/codegen/codegen.out.xml
//     Select symbols.xml Select=[full path to df-structures]/symbols.xml
//
// (Replace [full path to df-structures] with the actual path, of course.) Doing this will also allow this script to be run in headless mode.
//
// @author Ben Lubar
// @category DFHack

import java.io.*;
import java.util.*;

import javax.xml.stream.*;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.label.DemanglerCmd;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.util.demangler.Demangled;
import ghidra.framework.model.DomainFolder;
import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBufferImpl;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.SystemUtilities;
import ghidra.util.task.TaskMonitor;

public class import_df_structures extends GhidraScript {
	private static boolean DEBUG_ENABLED = !SystemUtilities.isInReleaseMode();
	private static final String xmlnsLD = "http://github.com/peterix/dfhack/lowered-data-definition";

	@Override
	public AnalysisMode getScriptAnalysisMode() {
		return AnalysisMode.SUSPENDED;
	}

	private File codegenFile, symbolsFile;
	private CodeGen codegen;
	private Symbols symbols;
	private SymbolTable symbolTable;
	private ghidra.program.model.symbol.SymbolTable symtab;
	private DataTypeManager dtm;
	private Category dtc, dtcStd, dtcEnums, dtcVTables, dtcVMethods;
	private DataType dtUint8, dtUint16, dtUint32, dtUint64;
	private DataType dtInt8, dtInt16, dtInt32, dtInt64;
	private DataType dtInt, dtLong, dtSizeT;
	private DataType dtString, dtFStream, dtVectorBool, dtDeque;
	private Structure classTypeInfo, subClassTypeInfo, vmiClassTypeInfo;
	private Address classVTable, subClassVTable, vmiClassVTable;
	private int baseClassPadding;

	private void debugln(String message) throws Exception {
		if (DEBUG_ENABLED) {
			println(message);
		}
	}

	@Override
	protected void run() throws Exception {
		this.codegenFile = askFile("Select codegen.out.xml", "Select");
		this.symbolsFile = askFile("Select symbols.xml", "Select");

		createStdDataTypes();
		processXMLInputs();
		createdTypes = new HashSet<>();
		this.symbolTable = symbols.findTable(currentProgram);
		println("selected symbol table: " + symbolTable.name);
		preprocessTypes();
		createDataTypes();
		labelVTables();
		labelGlobals();
		annotateGlobalTable();
		cleanUpDemangler();

		updateProgressMajor("Waiting for auto analysis...");
		var am = AutoAnalysisManager.getAnalysisManager(currentProgram);
		am.setIgnoreChanges(false); // change from SUSPENDED to ENABLED mode
		am.reAnalyzeAll(null); // force full program analysis
		am.waitForAnalysis(AnalysisPriority.CODE_ANALYSIS.priority(), monitor);

		setThunkNamespaces();
	}

	private void updateProgressMajor(String message) throws Exception {
		monitor.checkCanceled();

		monitor.initialize(TaskMonitor.NO_PROGRESS_VALUE);
		monitor.setMessage(message);
		println(message);
	}

	private DataType createDataType(Category category, DataType dt) throws Exception {
		monitor.checkCanceled();

		dt = category.addDataType(dt, DataTypeConflictHandler.REPLACE_HANDLER);
		debugln("created data type " + category.getName() + "::" + dt.getName());

		// for convenience, make sure pointer types are created
		var dtp = dtm.getPointer(dt);
		dtm.addDataType(dtp, DataTypeConflictHandler.KEEP_HANDLER);
		var dtpp = dtm.getPointer(dtp);
		dtm.addDataType(dtpp, DataTypeConflictHandler.KEEP_HANDLER);

		return dt;
	}

	private DataType createDataType(Category category, String name, DataType dt) throws Exception {
		return createDataType(category, new TypedefDataType(name, dt));
	}

	private DataType createVectorType(DataType target) throws Exception {
		if (target == null)
			target = DataType.DEFAULT;
		if (BooleanDataType.dataType.isEquivalent(target))
			target = dtInt8;
		var name = "vector<" + target.getName() + ">";

		var existing = dtcStd.getDataType(name);
		if (existing != null)
			return existing;

		var ptr = dtm.getPointer(target);

		// this code was a workaround for a defect in ghidra 9 which has been fixed in ghidra 10
		
		/*
		if (target instanceof Pointer) {
			var base = ((Pointer) target).getDataType();
			Structure ptr_wrapper = new StructureDataType("ptr_to_" + base.getName(), 0);
			ptr_wrapper = (Structure) dtm.getCategory(base.getCategoryPath()).addDataType(ptr_wrapper,
					DataTypeConflictHandler.REPLACE_HANDLER);
			ptr_wrapper.setToDefaultAligned();
			ptr_wrapper.setPackingEnabled(true);
			ptr_wrapper.add(target, "ptr", null);
			ptr = dtm.getPointer(ptr_wrapper);
		}
		 */

		var vec = new StructureDataType(name, 0);
		vec.setToDefaultAligned();
		vec.setPackingEnabled(true);
		
		vec.add(ptr, "_M_start", null);
		vec.add(ptr, "_M_finish", null);
		vec.add(ptr, "_M_end_of_storage", null);

		return createDataType(dtcStd, vec);
	}

	private DataType createSetType(DataType target) throws Exception {
		if (target == null)
			target = DataType.DEFAULT;

		var name = "set<" + target.getName() + ">";
		var existing = dtcStd.getDataType(name);
		if (existing != null && !existing.isNotYetDefined())
			return existing;

		Structure node = new StructureDataType("_Rb_tree_node<" + target.getName() + ">", 0);
		node.setToDefaultAligned();
		node.setPackingEnabled(true);
		node = (Structure) createDataType(dtcStd, node);

		var set = new StructureDataType(name, 0);
		set.setToDefaultAligned();
		set.setPackingEnabled(true);

		if (baseClassPadding == 1) {
			// GCC

			set.add(Undefined1DataType.dataType, "_M_key_compare", null);

			Structure nodeBase = new StructureDataType("_Rb_tree_node_base<" + target.getName() + ">", 0);
			nodeBase.setToDefaultAligned();
			nodeBase.setPackingEnabled(true);
			nodeBase = (Structure) createDataType(dtcStd, nodeBase);
			nodeBase.add(BooleanDataType.dataType, "_M_color", null);
			nodeBase.add(dtm.getPointer(node), "_M_parent", null);
			nodeBase.add(dtm.getPointer(node), "_M_left", null);
			nodeBase.add(dtm.getPointer(node), "_M_right", null);
			node.add(nodeBase, "_M_base", null);

			set.add(nodeBase, "_M_header", null);
		} else {
			// MSVC

			node.add(dtm.getPointer(node), "_Left", null);
			node.add(dtm.getPointer(node), "_Parent", null);
			node.add(dtm.getPointer(node), "_Right", null);
			node.add(BooleanDataType.dataType, "_Color", null);
			node.add(BooleanDataType.dataType, "_Isnil", null);

			set.add(dtm.getPointer(node), "_Myhead", null);
		}

		node.add(target, "_M_value_field", null);

		set.add(dtSizeT, "_M_node_count", null);

		return createDataType(dtcStd, set);
	}

	private DataType createDfArrayType(DataType target) throws Exception {
		if (target == null)
			target = DataType.DEFAULT;
		var ptr = dtm.getPointer(target);
		var name = "DfArray<" + target.getName() + ">";

		var existing = dtc.getDataType(name);
		if (existing != null)
			return existing;

		var arr = new StructureDataType(name, 0);
		arr.setToDefaultAligned();
		arr.setPackingEnabled(true);
		arr.add(ptr, "ptr", null);
		arr.add(dtInt, "length", null);

		return createDataType(dtc, arr);
	}

	private void createStdDataTypes() throws Exception {
		symtab = currentProgram.getSymbolTable();
		dtm = currentProgram.getDataTypeManager();
		dtc = dtm.createCategory(new CategoryPath("/df"));

		updateProgressMajor("creating stdlib types...");
		dtcStd = dtm.getRootCategory().createCategory("std");
		this.dtUint8 = createDataType(dtcStd, "uint8_t", AbstractIntegerDataType.getUnsignedDataType(1, dtm));
		this.dtUint16 = createDataType(dtcStd, "uint16_t", AbstractIntegerDataType.getUnsignedDataType(2, dtm));
		this.dtUint32 = createDataType(dtcStd, "uint32_t", AbstractIntegerDataType.getUnsignedDataType(4, dtm));
		this.dtUint64 = createDataType(dtcStd, "uint64_t", AbstractIntegerDataType.getUnsignedDataType(8, dtm));
		this.dtInt8 = createDataType(dtcStd, "int8_t", AbstractIntegerDataType.getSignedDataType(1, dtm));
		this.dtInt16 = createDataType(dtcStd, "int16_t", AbstractIntegerDataType.getSignedDataType(2, dtm));
		this.dtInt32 = createDataType(dtcStd, "int32_t", AbstractIntegerDataType.getSignedDataType(4, dtm));
		this.dtInt64 = createDataType(dtcStd, "int64_t", AbstractIntegerDataType.getSignedDataType(8, dtm));
		this.dtSizeT = createDataType(dtcStd, "size_t",
				AbstractIntegerDataType.getUnsignedDataType(currentProgram.getDefaultPointerSize(), dtm));
		this.dtInt = createDataType(dtcStd, "int", AbstractIntegerDataType.getSignedDataType(4, dtm));

		var stringDataType = new StructureDataType("string", 0);
		var bitVecDataType = new StructureDataType("vector<bool>", 0);
		var fStreamDataType = new StructureDataType("fstream", 0);
		var dequeDataType = new StructureDataType("deque", 0);
		stringDataType.setToDefaultAligned();
		stringDataType.setPackingEnabled(true);
		bitVecDataType.setToDefaultAligned();
		bitVecDataType.setPackingEnabled(true);
		fStreamDataType.setToDefaultAligned();
		fStreamDataType.setPackingEnabled(true);
		dequeDataType.setToDefaultAligned();
		dequeDataType.setPackingEnabled(true);
		
		boolean isElf = false;
		switch (currentProgram.getExecutableFormat()) {
		case "Executable and Linking Format (ELF)":
			isElf = true;
			// fallthrough
		case "Mac OS X Mach-O":
			this.dtLong = createDataType(dtcStd, "long",
					AbstractIntegerDataType.getSignedDataType(currentProgram.getDefaultPointerSize(), dtm));

			var rep = new StructureDataType("_string_rep", 0);
			rep.setToDefaultAligned();
			rep.setPackingEnabled(true);
			rep.add(dtSizeT, "_M_length", null);
			rep.add(dtSizeT, "_M_capacity", null);
			rep.add(dtInt, "_M_refcount", null);
			createDataType(dtcStd, rep);

			var dataPlus = new UnionDataType("_string_dataplus");
			dataPlus.setToDefaultAligned();
			dataPlus.setPackingEnabled(true);
			dataPlus.add(dtm.getPointer(rep));
			dataPlus.add(dtm.getPointer(TerminatedStringDataType.dataType));
			createDataType(dtcStd, dataPlus);

			stringDataType.add(dataPlus, "_M_p", null);

			var biterator = new StructureDataType("_bit_iterator", 0);
			biterator.setToDefaultAligned();
			biterator.setPackingEnabled(true);
			biterator.add(dtm.getPointer(dtSizeT), "_M_p", null);
			biterator.add(dtUint32, "_M_offset", null);
			createDataType(dtcStd, biterator);

			bitVecDataType.add(biterator, "_M_start", null);
			bitVecDataType.add(biterator, "_M_finish", null);
			bitVecDataType.add(dtm.getPointer(dtSizeT), "_M_end_of_storage", null);

			fStreamDataType.setExplicitMinimumAlignment(currentProgram.getDefaultPointerSize());
			fStreamDataType.add(Undefined.getUndefinedDataType(61 * currentProgram.getDefaultPointerSize() + 40));

			dequeDataType.setExplicitMinimumAlignment(currentProgram.getDefaultPointerSize());
			dequeDataType.add(Undefined.getUndefinedDataType(10 * currentProgram.getDefaultPointerSize()));

			this.baseClassPadding = 1;

			Structure typeInfo = new StructureDataType("type_info", 0);
			typeInfo.setToDefaultAligned();
			typeInfo.setPackingEnabled(true);
			typeInfo.add(dtm.getPointer(DataType.DEFAULT), "_vtable", null);
			typeInfo.add(dtm.getPointer(TerminatedStringDataType.dataType), "__name", null);
			typeInfo = (Structure) createDataType(dtcStd, typeInfo);

			var dtcABI = dtm.getRootCategory().createCategory("__cxxabiv1");
			this.classTypeInfo = new StructureDataType("__class_type_info", 0);
			this.classTypeInfo.setToDefaultAligned();
			this.classTypeInfo.setPackingEnabled(true);
			this.classTypeInfo.add(typeInfo, "_super", null);
			this.classTypeInfo = (Structure) createDataType(dtcABI, this.classTypeInfo);

			this.subClassTypeInfo = new StructureDataType("__si_class_type_info", 0);
			this.subClassTypeInfo.setToDefaultAligned();
			this.subClassTypeInfo.setPackingEnabled(true);
			this.subClassTypeInfo.add(typeInfo, "_super", null);
			this.subClassTypeInfo.add(dtm.getPointer(this.classTypeInfo), "__base_type", null);
			this.subClassTypeInfo = (Structure) createDataType(dtcABI, this.subClassTypeInfo);

			Structure baseClassTypeInfo = new StructureDataType("__base_class_type_info", 0);
			baseClassTypeInfo.setToDefaultAligned();
			baseClassTypeInfo.setPackingEnabled(true);
			baseClassTypeInfo.add(dtm.getPointer(this.classTypeInfo), "__base_type", null);
			baseClassTypeInfo.add(dtSizeT, "__offset_flags", null);
			baseClassTypeInfo = (Structure) createDataType(dtcABI, baseClassTypeInfo);

			this.vmiClassTypeInfo = new StructureDataType("__vmi_class_type_info", 0);
			this.vmiClassTypeInfo.setToDefaultAligned();
			this.vmiClassTypeInfo.setPackingEnabled(true);
			this.vmiClassTypeInfo.add(typeInfo, "_super", null);
			this.vmiClassTypeInfo.add(dtUint32, "__flags", null);
			this.vmiClassTypeInfo.add(dtUint32, "__base_count", null);
			this.vmiClassTypeInfo.add(new ArrayDataType(baseClassTypeInfo, 1, -1), "__base_info", null);
			this.vmiClassTypeInfo = (Structure) createDataType(dtcABI, this.vmiClassTypeInfo);

			this.classVTable = getSymbols((isElf ? "" : "_") + "_ZTVN10__cxxabiv117__class_type_infoE", null).get(0)
					.getAddress().add(2 * currentProgram.getDefaultPointerSize());
			this.subClassVTable = getSymbols((isElf ? "" : "_") + "_ZTVN10__cxxabiv120__si_class_type_infoE", null)
					.get(0).getAddress().add(2 * currentProgram.getDefaultPointerSize());
			this.vmiClassVTable = getSymbols((isElf ? "" : "_") + "_ZTVN10__cxxabiv121__vmi_class_type_infoE", null)
					.get(0).getAddress().add(2 * currentProgram.getDefaultPointerSize());

			break;
		case "Portable Executable (PE)":
			this.dtLong = createDataType(dtcStd, "long", AbstractIntegerDataType.getSignedDataType(4, dtm));

			var stringVal = new UnionDataType("_string_val");
			stringVal.setToDefaultAligned();
			stringVal.setPackingEnabled(true);
			stringVal.add(StringDataType.dataType, 16, "_Buf", null);
			stringVal.add(dtm.getPointer(TerminatedStringDataType.dataType), "_Ptr", null);

			stringDataType.add(createDataType(dtcStd, stringVal), "_Bx", null);
			stringDataType.add(dtSizeT, "_Mysize", null);
			stringDataType.add(dtSizeT, "_Myres", null);

			bitVecDataType.setExplicitMinimumAlignment(currentProgram.getDefaultPointerSize());
			bitVecDataType.add(Undefined.getUndefinedDataType(4 * currentProgram.getDefaultPointerSize()));

			fStreamDataType.setExplicitMinimumAlignment(currentProgram.getDefaultPointerSize());
			fStreamDataType.add(Undefined.getUndefinedDataType(22 * currentProgram.getDefaultPointerSize() + 104));

			dequeDataType.setExplicitMinimumAlignment(currentProgram.getDefaultPointerSize());
			dequeDataType.add(Undefined.getUndefinedDataType(5 * currentProgram.getDefaultPointerSize()));

			this.baseClassPadding = currentProgram.getDefaultPointerSize();

			break;
		default:
			throw new Exception("unexpected exe format " + currentProgram.getExecutableFormat());
		}
		this.dtFStream = createDataType(dtcStd, fStreamDataType);
		this.dtString = createDataType(dtcStd, stringDataType);
		this.dtVectorBool = createDataType(dtcStd, bitVecDataType);
		this.dtDeque = createDataType(dtcStd, dequeDataType);
		this.dtcEnums = dtc.createCategory("enums");
		this.dtcVTables = dtc.createCategory("vtables");
		this.dtcVMethods = dtcVTables.createCategory("methods");

		// some types that are created by the demangler
		var dtcDemangler = dtm.getRootCategory().createCategory("Demangler");
		createDataType(dtcDemangler, "pstringst", dtString);
		createDataType(dtcDemangler, "stringvectst", createVectorType(dtm.getPointer(dtString)));
		createDataType(dtcDemangler, "svector", createVectorType(dtm.getPointer(CharDataType.dataType)));
		var dtcDemanglerStd = dtcDemangler.createCategory("std");
		createDataType(dtcDemanglerStd, "basic_string", dtString);

		// we don't have interface_key yet because we haven't read the XML yet. make a
		// fake one.
		DataType fakeInterfaceKeySet = new StructureDataType("set<interface_key>", 0);
		fakeInterfaceKeySet = dtcStd.addDataType(fakeInterfaceKeySet, DataTypeConflictHandler.KEEP_HANDLER);
		createDataType(dtcDemanglerStd, "set", fakeInterfaceKeySet);
		DataType fakeInterfaceKeyNode = new StructureDataType("_Rb_tree_node<interface_key>", 0);
		fakeInterfaceKeyNode = dtcStd.addDataType(fakeInterfaceKeyNode, DataTypeConflictHandler.KEEP_HANDLER);
		createDataType(dtcDemanglerStd, "_Rb_tree_node", fakeInterfaceKeyNode);
	}

	private void processXMLInputs() throws Exception {
		updateProgressMajor("Parsing codegen.out.xml...");
		processXMLInput(this.codegenFile);
		updateProgressMajor("Parsing symbols.xml...");
		processXMLInput(this.symbolsFile);
	}

	private interface IHasName {
		void setName(String name);
	}

	private interface IHasValue {
		void setValue(long value);
	}

	private interface IHasStringValue {
		void setValue(String value);
	}

	private interface ILoweredData {
		void setMeta(String meta);

		void setSubtype(String subtype);
	}

	private interface IHasAnonName {
		void setAnonName(String name);
	}

	private interface IHasTypeName {
		void setTypeName(String name);

		void setBaseType(String name);
	}

	private interface IOwnsType {
		TypeDef getOwnedType();
	}

	private interface IHasFields {
		List<TypeDef.Field> getFields();
	}
	
	private interface IHasComment {
		void setComment(String comment);
		String getComment();
	}
	
	private interface IHasInitValue {
		void setInitValue(String initValue);
	}

	private static abstract class NameHaver implements IHasName {
		public boolean hasName;
		public String name;

		@Override
		public void setName(String name) {
			if (name.startsWith("in_")) {
				// in_RegisterName is assumed by a lot of Ghidra scripts to be an automatic
				// name, so things like in_play get changed to _in_play to avoid having Ghidra
				// get confused.
				name = "_" + name;
			}
			this.hasName = true;
			this.name = name;
		}
	}

	private static abstract class NameValueHaver extends NameHaver implements IHasValue {
		public boolean hasValue;
		public long value;

		@Override
		public void setValue(long value) {
			this.hasValue = true;
			this.value = value;
		}
	}

	private static abstract class AnonNameHaver extends NameHaver implements IHasAnonName {
		public boolean hasAnonName;
		public String anonName;

		@Override
		public void setAnonName(String name) {
			this.hasAnonName = true;
			this.anonName = name;
		}
	}

	private static class CodeGen {
		public final Map<String, TypeDef> typesByName = new HashMap<>();
		public final List<TypeDef> types = new ArrayList<>();
		public final List<TypeDef.Field> globals = new ArrayList<>();
	}

	private static class TypeDef implements ILoweredData, IOwnsType, IHasFields, IHasComment {
		public static class EnumItem extends NameValueHaver implements IHasComment {
			public String comment;
			
			@Override
			public void setComment(String comment) {
				this.comment = comment;
			}

			@Override
			public String getComment() {
				return this.comment;
			}
		}

		public static class Field extends AnonNameHaver 
		implements ILoweredData, IOwnsType, IHasTypeName, IHasComment, IHasInitValue {
			public String typeName;
			public String baseType;
			public TypeDef ownedType;
			public String meta = "";
			public String subtype = "";
			public int size;
			public boolean hasCount;
			public int count;
			public Field item;
			public String indexEnum;
			public boolean forceEnumSize;
			public String comment = "";
			public String initValue = "";

			@Override
			public void setMeta(String meta) {
				this.meta = meta;
			}

			@Override
			public void setSubtype(String subtype) {
				this.subtype = subtype;
			}

			@Override
			public void setTypeName(String name) {
				this.typeName = name;
			}

			@Override
			public void setBaseType(String name) {
				this.baseType = name;
			}

			@Override
			public TypeDef getOwnedType() {
				if (this.ownedType == null)
					this.ownedType = new TypeDef();
				return this.ownedType;
			}

			@Override
			public void setComment(String comment) {
				this.comment = comment;
			}

			@Override
			public String getComment() {
				// Append initValue if appropriate.
				if (this.initValue == null || this.initValue.equals("")) {
					return this.comment;
				}
				
				return this.comment + " (init-value: " + this.initValue + ")";
			}
			
			@Override
			public void setInitValue(String initValue) {
				this.initValue = initValue;
			}
		}

		public static class VMethod extends AnonNameHaver implements IHasFields, IHasComment {
			public final List<Field> arguments = new ArrayList<>();
			public Field returnType;
			public boolean isDestructor;
			public String comment = "";

			@Override
			public List<Field> getFields() {
				return arguments;
			}

			@Override
			public void setComment(String comment) {
				this.comment = comment;
			}

			@Override
			public String getComment() {
				return this.comment;
			}
		}

		public String typeName;
		public String originalName;
		public String inheritsFrom;
		public String baseType;
		public String meta = "";
		@SuppressWarnings("unused")
		public String subtype = "";
		public String comment = "";
		public boolean isUnion;
		public boolean hasSubClasses;
		public final List<Field> fields = new ArrayList<>();
		public final List<EnumItem> enumItems = new ArrayList<>();
		public final List<VMethod> vmethods = new ArrayList<>();
		private long enumItemsMin = 0;
		private long enumItemsMax = 0;

		public String getName() {
			if (originalName != null) {
				return originalName;
			}
			return typeName;
		}

		@Override
		public void setMeta(String meta) {
			this.meta = meta;
		}

		@Override
		public void setSubtype(String subtype) {
			this.subtype = subtype;
		}

		@Override
		public TypeDef getOwnedType() {
			return this;
		}

		@Override
		public List<Field> getFields() {
			return fields;
		}
		
		@Override
		public void setComment(String comment) {
			this.comment = comment;
		}

		@Override
		public String getComment() {
			return this.comment;
		}
		
		public int enumRequiredBits() {
			if (enumItemsMin == 0 && enumItemsMax == 0) {
				long prevValue = -1;
				for (var ei : enumItems) {
					long value;
					if (ei.hasValue) {
						value = ei.value;
					} else {
						value = prevValue + 1;
					}
					prevValue = value;
					if (enumItemsMin > value) {
						enumItemsMin = value;
					}
					if (enumItemsMax < value) {
						enumItemsMax = value;
					}
				}
			}

			long requiredBits = Math.max(Long.highestOneBit(-enumItemsMin), Long.highestOneBit(enumItemsMax));
			if (enumItemsMin < 0 || requiredBits == 0) {
				requiredBits++;
			}
			return (int) requiredBits;
		}

	}

	private static class Symbols {
		public final List<SymbolTable> tables = new ArrayList<>();

		public SymbolTable findTable(Program currentProgram) throws Exception {
			long actualTS = 0;
			if (currentProgram.getExecutableFormat().equals("Portable Executable (PE)")) {
				// TODO: is there a *good* way to do this with Ghidra APIs?
				var dosHeader = currentProgram.getListing().getDataAt(currentProgram.getImageBase());
				var dosHeaderType = (Structure) dosHeader.getBaseDataType();
				DataTypeComponent ntHeaderOffsetField = null;
				for (var dosHeaderField : dosHeaderType.getComponents()) {
					if (dosHeaderField.getFieldName().equals("e_lfanew")) {
						ntHeaderOffsetField = dosHeaderField;
						break;
					}
				}
				var ntHeaderOffset = dosHeader.getUnsignedInt(ntHeaderOffsetField.getOffset());
				var ntHeaderAddr = currentProgram.getImageBase().add(ntHeaderOffset);
				var ntHeader = currentProgram.getListing().getDataAt(ntHeaderAddr);
				var ntHeaderType = (Structure) ntHeader.getBaseDataType();
				for (var ntHeaderField : ntHeaderType.getComponents()) {
					if (ntHeaderField.getFieldName().equals("FileHeader")) {
						var fileHeader = ntHeader.getComponent(ntHeaderField.getOrdinal());
						var fileHeaderType = (Structure) fileHeader.getDataType();
						for (var fileHeaderField : fileHeaderType.getComponents()) {
							if (fileHeaderField.getFieldName().equals("TimeDateStamp")) {
								actualTS = fileHeader.getUnsignedInt(fileHeaderField.getOffset());
								break;
							}
						}

						break;
					}
				}
			}
			var actualMD5 = currentProgram.getExecutableMD5();
			if (actualMD5 == null) {
				actualMD5 = "";
			}

			for (var table : tables) {
				if (table.hasBinaryTimestamp) {
					if (table.binaryTimestamp != actualTS)
						continue;
				}
				if (table.hasMD5Hash) {
					if (!table.md5Hash.equalsIgnoreCase(actualMD5))
						continue;
				}
				return table;
			}
			throw new Exception(
					"could not find a relevant symbol table for the current program. is df-structures up to date?");
		}
	}

	private static class SymbolTable extends NameHaver {
		public static class VTableAddress extends NameValueHaver {
			public boolean hasMangledName;
			public String mangledName;
			public boolean hasOffset;
			public long offset;
		}

		public static class GlobalAddress extends NameValueHaver {
		}

		public class BinaryTimestamp implements IHasValue {
			@Override
			public void setValue(long value) {
				hasBinaryTimestamp = true;
				binaryTimestamp = value;
			}
		}

		public class MD5Hash implements IHasStringValue {
			@Override
			public void setValue(String value) {
				hasMD5Hash = true;
				md5Hash = value;
			}
		}

		public boolean hasBinaryTimestamp;
		public long binaryTimestamp;
		public boolean hasMD5Hash;
		public String md5Hash;
		public final List<VTableAddress> vtables = new ArrayList<>();
		public final List<GlobalAddress> globals = new ArrayList<>();

		public BinaryTimestamp newBinaryTimestamp() {
			return new BinaryTimestamp();
		}

		public MD5Hash newMD5Hash() {
			return new MD5Hash();
		}
	}

	private void processXMLInput(File file) throws Exception {
		var factory = XMLInputFactory.newDefaultFactory();
		var inputStream = new FileInputStream(file);
		var reader = factory.createXMLStreamReader(inputStream);

		var stack = new Stack<>();

		while (reader.hasNext()) {
			int tag = reader.next();
			switch (tag) {
			case XMLStreamConstants.START_ELEMENT:
				// shared variable namespace
				SymbolTable st;
				SymbolTable.VTableAddress vta;
				TypeDef.VMethod vm;

				if (reader.getNamespaceURI() == null) {
					switch (reader.getLocalName()) {
					case "enum-item":
						var ei = new TypeDef.EnumItem();
						((IOwnsType) stack.peek()).getOwnedType().enumItems.add(ei);
						stack.push(ei);
						break;
					case "virtual-methods":
						stack.push(stack.peek());
						break;
					case "vmethod":
						vm = new TypeDef.VMethod();
						((IOwnsType) stack.peek()).getOwnedType().vmethods.add(vm);
						stack.push(vm);
						break;
					case "ret-type":
						vm = (TypeDef.VMethod) stack.peek();
						vm.returnType = new TypeDef.Field();
						stack.push(vm.returnType);
						break;
					case "comment":
						// ignore (for now)
						stack.push(null);
						break;
					case "data-definition":
						this.symbols = new Symbols();
						stack.push(this.symbols);
						break;
					case "symbol-table":
						st = new SymbolTable();
						this.symbols.tables.add(st);
						stack.push(st);
						break;
					case "binary-timestamp":
						st = (SymbolTable) stack.peek();
						stack.push(st.newBinaryTimestamp());
						break;
					case "md5-hash":
						st = (SymbolTable) stack.peek();
						stack.push(st.newMD5Hash());
						break;
					case "global-address":
						st = (SymbolTable) stack.peek();
						var ga = new SymbolTable.GlobalAddress();
						st.globals.add(ga);
						stack.push(ga);
						break;
					case "vtable-address":
						st = (SymbolTable) stack.peek();
						vta = new SymbolTable.VTableAddress();
						st.vtables.add(vta);
						stack.push(vta);
						break;
					default:
						printerr("Unhandled XML element name: " + reader.getLocalName());
						// fallthrough
					case "enum-attr":
					case "item-attr":
					case "code-helper":
					case "extra-include":
					case "custom-methods":
					case "cmethod":
						// ignore
						stack.push(null);
						continue;
					}
				} else if (reader.getNamespaceURI().equals(xmlnsLD)) {
					switch (reader.getLocalName()) {
					case "data-definition":
						this.codegen = new CodeGen();
						stack.push(this.codegen);
						break;
					case "global-type":
						var gtype = new TypeDef();
						((CodeGen) stack.peek()).types.add(gtype);
						stack.push(gtype);
						break;
					case "global-object":
						var gobj = new TypeDef.Field();
						((CodeGen) stack.peek()).globals.add(gobj);
						stack.push(gobj);
						break;
					case "field":
						var field = new TypeDef.Field();
						if (stack.peek() instanceof IHasFields)
							((IHasFields) stack.peek()).getFields().add(field);
						else
							((IOwnsType) stack.peek()).getOwnedType().fields.add(field);
						stack.push(field);
						break;
					case "item":
						var item = new TypeDef.Field();
						((TypeDef.Field) stack.peek()).item = item;
						stack.push(item);
						break;
					default:
						printerr("Unhandled XML element name: ld:" + reader.getLocalName());
						stack.push(null);
						continue;
					}
				} else {
					printerr("Unhandled XML element namespace: " + reader.getNamespaceURI());
					stack.push(null);
					continue;
				}

				for (int i = 0; i < reader.getAttributeCount(); i++) {
					if (!reader.isAttributeSpecified(i))
						continue;
					if (reader.getAttributeNamespace(i) == null) {
						switch (reader.getAttributeLocalName(i)) {
						case "type-name":
							if (stack.peek() instanceof IHasTypeName)
								((IHasTypeName) stack.peek()).setTypeName(reader.getAttributeValue(i));
							else
								((IOwnsType) stack.peek()).getOwnedType().typeName = reader.getAttributeValue(i);
							break;
						case "base-type":
							if (stack.peek() instanceof IHasTypeName)
								((IHasTypeName) stack.peek()).setBaseType(reader.getAttributeValue(i));
							else
								((IOwnsType) stack.peek()).getOwnedType().baseType = reader.getAttributeValue(i);
							break;
						case "last-value":
							// ignore
							break;
						case "union-tag-field":
						case "union-tag-attr":
							// ignore
							break;
						case "name":
							((IHasName) stack.peek()).setName(reader.getAttributeValue(i));
							break;
						case "value":
							if (stack.peek() instanceof IHasStringValue)
								((IHasStringValue) stack.peek()).setValue(reader.getAttributeValue(i));
							else
								((IHasValue) stack.peek()).setValue(Long.decode(reader.getAttributeValue(i)));
							break;
						case "ref-target":
							// ignore
							break;
						case "pointer-type":
							// ignore
							break;
						case "comment":
							((IHasComment) stack.peek()).setComment(reader.getAttributeValue(i));
							break;
						case "init-value":
							((IHasInitValue) stack.peek()).setInitValue(reader.getAttributeValue(i));
							break;
						case "count":
							((TypeDef.Field) stack.peek()).hasCount = true;
							((TypeDef.Field) stack.peek()).count = Integer.decode(reader.getAttributeValue(i));
							break;
						case "aux-value":
							// ignore
							break;
						case "since":
							// ignore
							break;
						case "refers-to":
							// ignore
							break;
						case "ret-type":
							// ignore (this becomes an element)
							break;
						case "is-destructor":
							((TypeDef.VMethod) stack.peek()).isDestructor = true;
							break;
						case "inherits-from":
							((IOwnsType) stack.peek()).getOwnedType().inheritsFrom = reader.getAttributeValue(i);
							break;
						case "index-enum":
							if (!(stack.peek() instanceof TypeDef))
								((TypeDef.Field) stack.peek()).indexEnum = reader.getAttributeValue(i);
							break;
						case "instance-vector":
							// ignore
							break;
						case "key-field":
							// ignore
							break;
						case "original-name":
							((IOwnsType) stack.peek()).getOwnedType().originalName = reader.getAttributeValue(i);
							break;
						case "is-union":
							((IOwnsType) stack.peek()).getOwnedType().isUnion = Boolean
									.parseBoolean(reader.getAttributeValue(i));
							break;
						case "is-array":
							// ignore
							break;
						case "is-list":
							// ignore
							break;
						case "default-value":
							// ignore
							break;
						case "use-key-name":
							// ignore
							break;
						case "index-refers-to":
							// ignore
							break;
						case "size":
							((TypeDef.Field) stack.peek()).size = Integer.decode(reader.getAttributeValue(i));
							break;
						case "has-bad-pointers":
							// ignore
							break;
						case "custom-methods":
							// ignore
							break;
						case "filename":
							// ignore
							break;
						case "item-type":
							// ignore (becomes an element)
							break;
						case "df-list-link-type":
							// ignore
							break;
						case "df-list-link-field":
							// ignore
							break;
						case "os-type":
							// ignore (symbols)
							break;
						case "offset":
							vta = (SymbolTable.VTableAddress) stack.peek();
							vta.hasOffset = true;
							vta.offset = Long.decode(reader.getAttributeValue(i));
							break;
						case "mangled":
							vta = (SymbolTable.VTableAddress) stack.peek();
							vta.hasMangledName = true;
							vta.mangledName = reader.getAttributeValue(i);
							break;
						default:
							printerr("Unhandled XML attribute name: " + reader.getAttributeLocalName(i));
							continue;
						}
					} else if (reader.getAttributeNamespace(i).equals(xmlnsLD)) {
						switch (reader.getAttributeLocalName(i)) {
						case "meta":
							((ILoweredData) stack.peek()).setMeta(reader.getAttributeValue(i));
							break;
						case "level":
							// ignore
							break;
						case "subtype":
							((ILoweredData) stack.peek()).setSubtype(reader.getAttributeValue(i));
							break;
						case "typedef-name":
							((IOwnsType) stack.peek()).getOwnedType().typeName = reader.getAttributeValue(i);
							break;
						case "is-container":
							// ignore
							break;
						case "bits":
							// ignore
							break;
						case "unsigned":
							// ignore
							break;
						case "anon-name":
							((IHasAnonName) stack.peek()).setAnonName(reader.getAttributeValue(i));
							break;
						case "enum-size-forced":
							((TypeDef.Field) stack.peek()).forceEnumSize = true;
							break;
						case "in-union":
							// ignore
							break;
						case "anon-compound":
							((IOwnsType) stack.peek()).getOwnedType().typeName = "anon_compound_"
									+ reader.getLocation().getCharacterOffset();
							break;
						default:
							printerr("Unhandled XML attribute name: ld:" + reader.getAttributeLocalName(i));
							continue;
						}
					} else {
						printerr("Unhandled XML attribute namespace: " + reader.getAttributeNamespace(i));
						continue;
					}
				}
				break;
			case XMLStreamConstants.END_ELEMENT:
				stack.pop();
				break;
			case XMLStreamConstants.CHARACTERS:
				// ignore (for now)
				break;
			case XMLStreamConstants.COMMENT:
				// ignore
				break;
			case XMLStreamConstants.END_DOCUMENT:
				// ignore
				break;
			case XMLStreamConstants.CDATA:
				// ignore
				break;
			default:
				throw new Exception("Unhandled XML type: " + tag);
			}
		}
	}

	private void preprocessTypes() throws Exception {
		var toAdd = new ArrayList<TypeDef>();
		for (var gobj : codegen.globals) {
			findAnonymousTypes(toAdd, "", gobj);
		}
		for (var gtype : codegen.types) {
			findAnonymousTypes(toAdd, gtype);
		}
		codegen.types.addAll(toAdd);

		for (var t : codegen.types) {
			codegen.typesByName.put(t.typeName, t);
			if (t.originalName != null)
				codegen.typesByName.put(t.originalName, t);
		}

		boolean foundAny = true;
		while (foundAny) {
			foundAny = false;

			for (var t : codegen.types) {
				if (!"class-type".equals(t.meta))
					continue;

				var parent = codegen.typesByName.get(t.inheritsFrom);
				if (parent != null && !parent.hasSubClasses) {
					parent.hasSubClasses = true;
					foundAny = true;
				}
			}
		}
	}

	private void createDataTypes() throws Exception {
		updateProgressMajor("Creating data types...");
		monitor.initialize(codegen.types.size());
		int i = 0;
		for (var t : codegen.types) {
			monitor.checkCanceled();
			monitor.setMessage("Creating data types ("+ t.getName() +")...");
			createDataType(t);
			i++;
			monitor.setProgress(i);
		}
	}
	
	private void findAnonymousTypes(List<TypeDef> toAdd, TypeDef parent) throws Exception {
		var prefix = parent.getName() + "__SCOPE__";
		for (var field : parent.fields) {
			findAnonymousTypes(toAdd, prefix, field);
		}
	}

	private void findAnonymousTypes(List<TypeDef> toAdd, String prefix, TypeDef.Field field) throws Exception {
		for (var f = field; f != null; f = f.item) {
			if (f.ownedType != null) {
				if (f.ownedType.getName() == null)
					throw new Exception("unnamed typed field " + prefix + f.name);
				if (f.meta.equals("compound")) {
					f.ownedType.baseType = f.baseType;
					if (f.subtype.isEmpty())
						f.ownedType.meta = "struct-type";
					else
						f.ownedType.meta = f.subtype + "-type";
				} else if (f.meta.equals("static-array")) {
					f.ownedType.meta = f.meta;
					var af = new TypeDef.Field();
					af.meta = f.meta;
					af.indexEnum = f.indexEnum;
					af.hasCount = f.hasCount;
					af.count = f.count;
					af.item = f.item;
					f.ownedType.fields.add(af);
				}
				f.ownedType.typeName = prefix + f.ownedType.typeName;
				f.typeName = f.ownedType.typeName;
				toAdd.add(f.ownedType);
				findAnonymousTypes(toAdd, f.ownedType);
			}
		}
	}

	private HashSet<String> createdTypes;

	private DataType createDataType(TypeDef t) throws Exception {
		if (t.meta.equals("enum-type")) {
			int minSize = t.enumRequiredBits();
			minSize = (minSize + 7) / 8;
			for (int size = 8; size >= minSize; size /= 2) {
				getOrCreateEnumDataType(t, size);
			}
			return getOrCreateEnumDataType(t, 0);
		}
		if (createdTypes.contains(t.getName()) ) {
			var existing = dtc.getDataType(t.getName());
			if (existing != null)
				return existing;
		}

		createdTypes.add(t.getName());
		
		DataType n;
		switch (t.meta) {
		case "bitfield-type":
			n = createBitfieldDataType(t);
			break;
		case "struct-type":
			n = createStructDataType(t);
			break;
		case "class-type":
			n = createClassDataType(t);
			break;
		case "static-array":
			n = createDataType(dtc, t.getName(), getDataType(t.fields.get(0)));
			break;
		default:
			throw new Exception("Unhandled type meta for " + t.getName() + ": " + t.meta);
		}
		return n;
}

	private DataType getOrCreateEnumDataType(TypeDef t, int size) throws Exception {
		var name = t.getName();
		if (size != 0) {
			name += "(" + (size * 8) + "-bit)";
		}
		if (createdTypes.contains(t.getName()) ) {
			var existing = dtcEnums.getDataType(t.getName());
			if (existing != null)
				return existing;
		}
		
		createdTypes.add(t.getName());

		if (size == 0) {
			if (t.baseType == null || t.baseType.isEmpty()) {
				size = 4;
			} else {
				size = dtcStd.getDataType(t.baseType).getLength();
			}
		}

		DataType n = createEnumDataType(t, name, size);
		return n;
	}

	private DataType getDataType(String name) throws Exception {
		if (name == null)
			return null;

		return createDataType(codegen.typesByName.get(name));
	}

	private DataType getDataType(TypeDef.Field f) throws Exception {
		switch (f.meta) {
		case "primitive":
			switch (f.subtype) {
			case "stl-string":
				return dtString;
			case "stl-fstream":
				return dtFStream;
			}
			break;
		case "container":
			switch (f.subtype) {
			case "stl-vector":
				return createVectorType(f.item == null ? null : getDataType(f.item));
			case "stl-bit-vector":
				return dtVectorBool;
			case "stl-set":
				return createSetType(f.item == null ? null : getDataType(f.item));
			case "stl-deque":
				return dtcStd.addDataType(new TypedefDataType(
						"deque<" + (f.item == null ? DataType.DEFAULT : getDataType(f.item)).getName() + ">", dtDeque),
						DataTypeConflictHandler.REPLACE_HANDLER);
			case "df-flagarray":
				return createBitArrayType(f.indexEnum);
			case "df-array":
				return createDfArrayType(f.item == null ? null : getDataType(f.item));
			case "df-linked-list":
				return getDataType(f.typeName);
			}
			break;
		case "number":
			switch (f.subtype) {
			case "bool":
				return BooleanDataType.dataType;
			case "s-float":
				return Float4DataType.dataType;
			case "d-float":
				return Float8DataType.dataType;
			case "int8_t":
				return dtInt8;
			case "int16_t":
				return dtInt16;
			case "int32_t":
				return dtInt32;
			case "int64_t":
				return dtInt64;
			case "uint8_t":
				return dtUint8;
			case "uint16_t":
				return dtUint16;
			case "uint32_t":
				return dtUint32;
			case "uint64_t":
				return dtUint64;
			case "long":
				return dtLong;
			}
			break;
		case "pointer":
			if (f.item == null)
				return dtm.getPointer(DataType.DEFAULT);

			return dtm.getPointer(getDataType(f.item));
		case "global":
		case "compound":
			if (f.forceEnumSize) {
				return getOrCreateEnumDataType(codegen.typesByName.get(f.typeName),
						dtcStd.getDataType(f.baseType).getLength());
			}
			return getDataType(f.typeName);
		case "static-array":
			if (f.hasCount)
				return createArrayDataType(getDataType(f.item), f.count, f.indexEnum);
			var enumItems = codegen.typesByName.get(f.indexEnum).enumItems;
			return createArrayDataType(getDataType(f.item), enumItems.size() + (int) enumItems.get(0).value,
					f.indexEnum);
		case "bytes":
			switch (f.subtype) {
			case "padding":
				return new ArrayDataType(Undefined1DataType.dataType, f.size, 1);
			case "static-string":
				return StringDataType.dataType;
			}
			break;
		}
		throw new Exception("Unhandled field meta/subtype: " + f.meta + "/" + f.subtype);
	}

	private DataType createBitArrayType(String enumName) throws Exception {
		var name = "BitArray<" + (enumName == null ? "" : enumName) + ">";
		var dt = dtc.getDataType(name);
		if (dt != null)
			return dt;

		DataType bitsType = Undefined1DataType.dataType;
		if (enumName != null) {
			Structure bitsStruct = new StructureDataType(name + "_bits", 0);
			bitsStruct.setToDefaultAligned();
			bitsStruct.setPackingEnabled(true);
			bitsStruct = (Structure) dtc.addDataType(bitsStruct, DataTypeConflictHandler.REPLACE_HANDLER);

			var et = this.codegen.typesByName.get(enumName);
			et.enumRequiredBits(); // ensure enumItemsMax is set
			var bytes = (int) et.enumItemsMax / 8 + 1;
			var byteEnums = new ghidra.program.model.data.Enum[bytes];
			for (int i = 0; i < bytes; i++) {
				var byteEnum = new EnumDataType(name + "_bits_" + i, 1);
				byteEnum.add("none_of_" + enumName, 0);
				byteEnums[i] = (ghidra.program.model.data.Enum) dtc.addDataType(byteEnum,
						DataTypeConflictHandler.REPLACE_HANDLER);
				bitsStruct.add(byteEnums[i], "bits_" + i, null);
			}

			long prevValue = -1;
			for (var ei : et.enumItems) {
				long value = ei.hasValue ? ei.value : (prevValue + 1);
				var valueName = ei.hasName ? ei.name : ("_unk_" + value);
				prevValue = value;
				byteEnums[(int) (value / 8)].add(enumName + "_" + valueName, 1 << (value % 8));
			}

			bitsType = bitsStruct;
		}

		var bitArrayDataType = new StructureDataType(name, 0);
		bitArrayDataType.setToDefaultAligned();
		bitArrayDataType.setPackingEnabled(true);
		bitArrayDataType.add(dtm.getPointer(bitsType), "ptr", null);
		bitArrayDataType.add(dtInt, "count", null);

		return createDataType(dtc, bitArrayDataType);
	}
	
	// Set a DataType's description based on its corresponding IHasComment implementation's comment field
	private void addDescriptionToDataType(DataType dt, IHasComment tHasComment) throws Exception {
		String comment = tHasComment.getComment();
		if (comment == null || comment.isEmpty()) {
			return;
		}
		
		try {
			dt.setDescription(comment);
			debugln("Set description '" + comment + "' on " + dt.getName() + " DataType");
		} catch (UnsupportedOperationException exception) {
			printerr("Couldn't set description '" + comment + "' on " + dt.getName() + " DataType");
			printerr(exception.getMessage());
		}
	}

	private DataType createArrayDataType(DataType item, int count, String indexEnumName) throws Exception {
		if (indexEnumName == null) {
			return new ArrayDataType(item, count, 0);
		}

		if (item instanceof Array) {
			Structure wrapper = new StructureDataType(item.getName() + "_wrapper", 0);
			wrapper = (Structure) dtm.getCategory(item.getCategoryPath()).addDataType(wrapper,
					DataTypeConflictHandler.REPLACE_HANDLER);
			wrapper.setToDefaultAligned();
			wrapper.setPackingEnabled(true);
			wrapper.add(item, "array", null);
			item = wrapper;
		}

		var indexEnum = codegen.typesByName.get(indexEnumName);
		if (indexEnum == null) {
			printerr("missing index-enum type " + indexEnumName);
			return createArrayDataType(item, count, null);
		}

		var names = new String[count];
		long prevValue = -1;
		for (var ei : indexEnum.enumItems) {
			long value;
			if (ei.hasValue) {
				value = ei.value;
			} else {
				value = prevValue + 1;
			}
			prevValue = value;
			if (ei.hasName && value >= 0 && value < names.length) {
				names[(int) value] = ei.name;
			}
		}

		var dt = new StructureDataType(item.getName() + "[<" + indexEnumName + ">" + count + "]", 0);
		dt.setToDefaultAligned();
		dt.setPackingEnabled(true);
		for (int i = 0; i < count; i++) {
			String indexEnumComment = i < indexEnum.enumItems.size() ? indexEnum.enumItems.get(i).getComment() : null;
			if (names[i] == null) {
				dt.add(item, indexEnumName + "_anon_" + i, indexEnumComment);
			} else {
				dt.add(item, names[i], indexEnumComment);
			}
		}
		return dtc.addDataType(dt, DataTypeConflictHandler.REPLACE_HANDLER);
	}

	private DataType createEnumDataType(TypeDef t, String name, int size) throws Exception {
		var et = new EnumDataType(name, size);

		long prevValue = -1;
		for (var ei : t.enumItems) {
			long value = ei.hasValue ? ei.value : prevValue + 1;
			String key = ei.hasName ? ei.name : "_unk_" + value;
			et.add(key, value, ei.getComment());
			prevValue = value;
		}
		
		addDescriptionToDataType(et, t);

		return createDataType(dtcEnums, et);
	}

	private void addStructField(Composite st, TypeDef t, TypeDef.Field f) throws Exception {
		String name = null;
		if (f.hasName)
			name = f.name;
		else if (f.hasAnonName)
			name = t.typeName + "_" + f.anonName;

		st.add(getDataType(f), f.size, name, f.getComment());
	}

	private void addStructFields(Composite st, TypeDef t) throws Exception {
		if (t.inheritsFrom != null) {
			addStructFields(st, codegen.typesByName.get(t.inheritsFrom));

			DataTypeComponent lastComponent = st.getComponent(st.getNumComponents() - 1);
			int componentLength = lastComponent.getOffset() + lastComponent.getLength();
			int pastAlignment = componentLength % this.baseClassPadding;
			if (pastAlignment != 0) {
				st.add(new ArrayDataType(Undefined1DataType.dataType, this.baseClassPadding - pastAlignment, 1), null,
						"base class padding for " + t.getName());
			}
		}

		for (var f : t.fields) {
			addStructField(st, t, f);
		}
	}

	private DataType createStructDataType(TypeDef t) throws Exception {
		Composite st = t.isUnion ? new UnionDataType(t.getName()) : new StructureDataType(t.getName(), 0);
		// add early to avoid recursion
		st = (Composite) dtc.addDataType(st, DataTypeConflictHandler.REPLACE_HANDLER);
		st.setToDefaultAligned();
		st.setPackingEnabled(true);

		addDescriptionToDataType(st, t);
		addStructFields(st, t);

		return createDataType(dtc, st);
	}

	private DataType createMethodDataType(String name, TypeDef t, TypeDef.VMethod vm) throws Exception {
		var ft = new FunctionDefinitionDataType(name);
		ft.setGenericCallingConvention(GenericCallingConvention.thiscall);

		if (vm.returnType != null)
			ft.setReturnType(getDataType(vm.returnType));
		else if (!vm.hasAnonName)
			ft.setReturnType(DataType.VOID);

		var args = new ParameterDefinition[vm.arguments.size() + 1];
		args[0] = new ParameterDefinitionImpl("this", dtm.getPointer(createDataType(t)), null);
		for (int i = 0; i < vm.arguments.size(); i++) {
			var arg = vm.arguments.get(i);
			String aname = null;
			if (arg.hasName)
				aname = arg.name;
			else if (arg.hasAnonName)
				aname = arg.anonName;
			args[i + 1] = new ParameterDefinitionImpl(aname, getDataType(arg), null);
		}
		ft.setArguments(args);
		ft.setComment(vm.getComment());

		return createDataType(dtcVMethods, ft);
	}

	private DataType createVTableDataType(TypeDef t) throws Exception {
		var vtName = "vtable_" + t.getName();
		if (createdTypes.contains(vtName)) {
			var existing = dtcVTables.getDataType(vtName);
			if (existing != null)
				return existing;
		}
		createdTypes.add(vtName);

		Structure st = new StructureDataType(vtName, 0);
		// add early to avoid recursion
		st = (Structure) dtcVTables.addDataType(st, DataTypeConflictHandler.REPLACE_HANDLER);
		st.setToDefaultAligned();
		st.setPackingEnabled(true);

		if (t.inheritsFrom != null) {
			st.add(createVTableDataType(codegen.typesByName.get(t.inheritsFrom)), "_super", t.getComment());
		}

		for (var vm : t.vmethods) {
			String mname = null;
			if (vm.isDestructor) {
				mname = "~" + t.getName();
				if (baseClassPadding == 1) {
					// GCC
					var mt = dtm.getPointer(createMethodDataType(t.getName() + "::" + mname, t, vm));
					st.add(mt, mname, vm.getComment());
					st.add(mt, mname + "(deleting)", vm.getComment());
				} else {
					// MSVC
					if (vm.arguments.isEmpty()) {
						var arg = new TypeDef.Field();
						arg.meta = "number";
						arg.subtype = "bool";
						arg.hasName = true;
						arg.name = "deleting";
						vm.arguments.add(arg);
					}
					var mt = dtm.getPointer(createMethodDataType(t.getName() + "::" + mname, t, vm));
					st.add(mt, mname, vm.getComment());
				}
				continue;
			}

			if (vm.hasName)
				mname = vm.name;
			else if (vm.hasAnonName)
				mname = t.getName() + "_" + vm.anonName;
			st.add(dtm.getPointer(createMethodDataType(t.getName() + "::" + mname, t, vm)), mname, vm.getComment());
		}

		DataType vTableDT = createDataType(dtcVTables, st);
		addDescriptionToDataType(vTableDT, t);
		
		return vTableDT;
	}

	private Union findOrCreateBaseClassUnion(TypeDef t) throws Exception {
		var typeName = "virtual_" + t.getName();
		if (createdTypes.contains(typeName)) {
			var existing = (Union) dtc.getDataType(typeName);
			if (existing != null)
				return (Union) existing;
		}
		createdTypes.add(typeName);

		var ut = new UnionDataType(typeName);
		dtc.addDataType(ut, DataTypeConflictHandler.REPLACE_HANDLER);
		ut.add(createDataType(t), t.getName(), t.getName());
		addDescriptionToDataType(ut, t);
		return (Union) createDataType(dtc, ut);
	}

	private void addToBaseClassUnion(TypeDef t, Structure st) throws Exception {
		if (t.inheritsFrom == null)
			return;

		var self = t.hasSubClasses ? findOrCreateBaseClassUnion(t) : st;
		var parent = findOrCreateBaseClassUnion(codegen.typesByName.get(t.inheritsFrom));
		parent.add(self);
	}

	private DataType createClassDataType(TypeDef t) throws Exception {
		Structure st = new StructureDataType(t.getName(), 0);
		// add early to avoid recursion
		st = (Structure) dtc.addDataType(st, DataTypeConflictHandler.REPLACE_HANDLER);
		st.setToDefaultAligned();
		st.setPackingEnabled(true);
		st.add(dtm.getPointer(createVTableDataType(t)), "_vtable", null);
		addStructFields(st, t);

		st = (Structure) createDataType(dtc, st);
		st.setToDefaultAligned();
		st.setPackingEnabled(true);

		addToBaseClassUnion(t, st);

		return st;
	}

	private DataType createBitfieldDataType(TypeDef t) throws Exception {
		var bt = t.baseType == null ? dtUint32 : dtcStd.getDataType(t.baseType);

		var et = new EnumDataType(t.getName(), bt.getLength());
		et.add("none_of_" + t.getName(), 0);
		long mask = 1;
		for (var f : t.fields) {
			String name = null;
			if (f.hasName)
				name = t.getName() + "_" + f.name;
			else if (f.hasAnonName)
				name = t.getName() + "_" + f.anonName;

			if (name == null) {
				mask = mask << 1;
				continue;
			}

			if (f.hasCount) {
				long count = 1 << f.count;
				if (f.typeName == null) {
					for (long i = 0; i < count; i++) {
						et.add(name + "_" + i, mask * i);
					}
				} else {
					count--;
					var e = (ghidra.program.model.data.Enum) getDataType(f.typeName);
					for (var v : e.getValues()) {
						if ((v & count) != count) {
							continue;
						}

						et.add(name + "_" + e.getName(v), mask * v, f.getComment());
					}
				}

				mask = mask << f.count;
				continue;
			}

			et.add(name, mask);
			mask = mask << 1;
		}

		DataType bitFieldDT = createDataType(dtc, et);
		addDescriptionToDataType(bitFieldDT, t);
		
		return bitFieldDT;
	}

	private void cleanOverlappingData(Data data) throws Exception {
		var listing = currentProgram.getListing();
		if (!data.isDefined() || Undefined.isUndefined(data.getDataType())) {
			listing.clearCodeUnits(data.getMinAddress(), data.getMaxAddress(), false, monitor);
			return;
		}

		var syms = symtab.getSymbols(data.getAddress());
		boolean anyImportant = false;
		for (var sym : syms) {
			if (sym.getSource().isHigherPriorityThan(SourceType.IMPORTED)) {
				anyImportant = true;
				break;
			}
		}

		if (!anyImportant) {
			listing.clearCodeUnits(data.getMinAddress(), data.getMaxAddress(), false, monitor);
		} else {
			printerr("overlapping " + data.getDataType().getName() + " "
					+ (syms.length > 0 ? syms[0].getName() : "(unnamed)"));
		}
	}
	
	private void cleanExistingData(Address addr, DataType dt) throws Exception {
		var listing = currentProgram.getListing();
		
		// If data is zero length, we don't need to check (probably)
		if (dt.isZeroLength()) {
			return;
		}
		
		// Need to check if the area of data we want to label is already defined within the listing database
		// First, we check for overlapping data that starts before our data's first address
		// Like so:
		//       | New Data |
		// | Old Data |
		// TODO: Check if existing data is the same as the data we are setting. If not, prompt user for which one to keep
		DataIterator backwardsDataIt = listing.getData(addr, false);
		while (backwardsDataIt.hasNext()) {
			Data prev = backwardsDataIt.next();
			// Check if the start of our data (addr) is before prev's maxAddress
			if (addr.compareTo(prev.getMaxAddress()) <= 0) {
				cleanOverlappingData(prev);
			}
			else {
				break;
			}
		}

		// Secondly, we check for overlapping data that begins within our data's range
		// Like so:
		// | New Data |
		//       | Old Data |		
		DataIterator forwardsDataIt = listing.getData(addr, true);
		Address maxAddr = addr.add(dt.getLength());
		while (forwardsDataIt.hasNext()) {
			Data next = forwardsDataIt.next();
			// Check if the end of our data (maxAddr) is before next's minAddress
			if (maxAddr.compareTo(next.getMinAddress()) >= 0) {
				cleanOverlappingData(next);
			}
			else {
				break;
			}
		}
	}

	private Data labelData(Address addr, DataType dt, String name, int size) throws Exception {
		debugln("labelling " + addr + " as " + name + " (" + dt.getCategoryPath().getName() + "::" + dt.getName()
				+ ") ");
		
		cleanExistingData(addr, dt);
		var listing = currentProgram.getListing();
		Data data = null;
		try {
			data = listing.createData(addr, dt, size);
		} catch (CodeUnitInsertionException ex) {
			println("error while labelling " + addr + " as " + name + " (" + dt.getCategoryPath().getName() + "::"
					+ dt.getName() + ")");
			printerr(ex.getMessage());
		}
		createLabel(addr, name, true, SourceType.IMPORTED);

		return data;
	}

	private void labelVMethods(Address addr, GhidraClass cls, Structure st) throws Exception {
		for (var field : st.getComponents()) {
			if ("_super".equals(field.getFieldName())) {
				labelVMethods(addr, cls, (Structure) field.getDataType());
				continue;
			}

			Address fnaddr;
			if (currentProgram.getDefaultPointerSize() == 4) {
				fnaddr = toAddr(currentProgram.getMemory().getInt(addr.add(field.getOffset())));
			} else {
				fnaddr = toAddr(currentProgram.getMemory().getLong(addr.add(field.getOffset())));
			}

			var funcType = (FunctionDefinition) ((Pointer) field.getDataType()).getDataType();
			var cmd = new CreateFunctionCmd(field.getFieldName(), fnaddr, null, SourceType.IMPORTED);
			Function func;
			if (cmd.applyTo(currentProgram)) {
				func = cmd.getFunction();
			} else {
				func = currentProgram.getListing().getFunctionAt(fnaddr);
				if (func != null && !func.getSignatureSource().isLowerPriorityThan(SourceType.IMPORTED)) {
					func = null;
				}
			}
			if (func != null) {
				func.setName(field.getFieldName(), SourceType.IMPORTED);
				func.setParentNamespace(cls);
				var ret = new ReturnParameterImpl(funcType.getReturnType(), currentProgram);
				var params = new ArrayList<Variable>();
				boolean first = true;
				for (var arg : funcType.getArguments()) {
					if (first) {
						first = false;
						continue;
					}
					params.add(new ParameterImpl(arg.getName(), arg.getDataType(), currentProgram));
				}

				func.updateFunction("__thiscall", ret, params,
						Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true, SourceType.IMPORTED);
			} else {
				symtab.createLabel(fnaddr, field.getFieldName(), cls, SourceType.IMPORTED);
			}
		}
	}

	private void labelTypeInfoPointer(Address addr, String name) throws Exception {
		var defaultPointerType = dtm.getPointer(DataType.DEFAULT);
		var tiAddr = (Address) defaultPointerType.getValue(new MemoryBufferImpl(currentProgram.getMemory(), addr), null,
				-1);
		var tiVTAddr = (Address) defaultPointerType.getValue(new MemoryBufferImpl(currentProgram.getMemory(), tiAddr),
				null, -1);

		Data ti;
		if (tiVTAddr.getOffset() == this.classVTable.getOffset()) {
			ti = labelData(tiAddr, this.classTypeInfo, "type_info_" + name, -1);
		} else if (tiVTAddr.getOffset() == this.subClassVTable.getOffset()) {
			ti = labelData(tiAddr, this.subClassTypeInfo, "type_info_" + name, -1);
		} else if (tiVTAddr.getOffset() == this.vmiClassVTable.getOffset()) {
			ti = labelData(tiAddr, this.vmiClassTypeInfo, "type_info_" + name, -1);
			if (((Scalar) ti.getComponent(2).getValue()).getValue() != 1) { // __base_count
				printerr("Unexpected __base_count for vmi type info pointer at " + addr);
			}
		} else {
			printerr("Could not determine typeinfo pointer type at " + addr);
			return;
		}

		createData(addr.subtract(defaultPointerType.getLength()), dtSizeT);
		createData(addr, dtm.getPointer(ti.getDataType()));
	}

	private void labelVTable(Namespace ns, Address addr, GhidraClass cls, DataType dt) throws Exception {
		labelData(addr, dt, dt.getName(), 0);
		labelVMethods(addr, cls, (Structure) dt);
		if (this.classTypeInfo != null) {
			labelTypeInfoPointer(addr.subtract(currentProgram.getDefaultPointerSize()), cls.getName());
		}
	}

	private void labelVTables() throws Exception {
		updateProgressMajor("Labelling vtables...");
		monitor.initialize(symbolTable.vtables.size());

		Namespace ns = null;

		int i = 0;
		for (var vt : symbolTable.vtables) {
			monitor.setProgress(i++);

			if (!vt.hasName)
				continue;

			var dt = dtcVTables.getDataType("vtable_" + vt.name);
			if (dt == null)
				continue;

			var cls = (GhidraClass) symtab.getNamespace(vt.name, ns);
			if (cls == null)
				cls = symtab.createClass(ns, vt.name, SourceType.IMPORTED);

			long offset = vt.hasOffset ? vt.offset : 0;

			if (vt.hasValue) {
				labelVTable(ns, toAddr(vt.value + offset), cls, dt);
			}

			if (vt.hasMangledName) {
				var syms = symtab.getGlobalSymbols(vt.mangledName);
				if (syms.isEmpty())
					continue;

				for (var s : syms) {
					labelVTable(ns, s.getAddress().add(offset), cls, dt);
				}
			}
		}

		for (var dt : codegen.types) {
			if ("struct-type".equals(dt.meta) && !dt.getName().contains("::")) {
				if (symtab.getNamespace(dt.getName(), ns) == null) {
					symtab.createClass(ns, dt.getName(), SourceType.IMPORTED);
				}
			}
		}
	}

	private void labelGlobals() throws Exception {
		updateProgressMajor("Labelling globals...");
		monitor.initialize(codegen.globals.size());

		var addrs = new HashMap<String, Address>();

		for (var g : symbolTable.globals) {
			if (!g.hasName)
				continue;
			if (!g.hasValue)
				continue;

			addrs.put(g.name, toAddr(g.value));
		}

		int i = 0;
		for (var gobj : codegen.globals) {
			monitor.setProgress(i++);

			if (!gobj.hasName)
				continue;
			if (!addrs.containsKey(gobj.name))
				continue;

			var dt = getDataType(gobj.item);
			if (dt == null)
				throw new Exception("missing data type for global " + gobj.name);

			labelData(addrs.get(gobj.name), dt, gobj.name, gobj.item.size);
		}
	}

	private void annotateGlobalTable() throws Exception {
		updateProgressMajor("Annotating global table...");

		var stringPointer = dtm.getPointer(TerminatedStringDataType.dataType);
		var voidPointer = dtm.getPointer(DataType.VOID);
		Structure globalTableEntryType = new StructureDataType("global_variable_table_entry", 0);

		globalTableEntryType.setToDefaultAligned();
		globalTableEntryType.setPackingEnabled(true);
		globalTableEntryType.add(stringPointer, "name", "");
		globalTableEntryType.add(voidPointer, "addr", "");
		globalTableEntryType = (Structure) dtc.addDataType(globalTableEntryType,
				DataTypeConflictHandler.REPLACE_HANDLER);

		Structure globalTableType = new StructureDataType("global_variable_table", 0);
		globalTableType.setToDefaultAligned();
		globalTableType.setPackingEnabled(true);
		byte[] magic;
		globalTableType.add(DWordDataType.dataType, "magic1", "12345678h");
		if (currentProgram.getDefaultPointerSize() == 4) {
			globalTableType.add(DWordDataType.dataType, "magic2", "87654321h");
			magic = new byte[] { 0x78, 0x56, 0x34, 0x12, 0x21, 0x43, 0x65, (byte) 0x87 };
		} else {
			globalTableType.add(DWordDataType.dataType, "magic2", "12345678h");
			globalTableType.add(DWordDataType.dataType, "magic3", "87654321h");
			globalTableType.add(DWordDataType.dataType, "magic4", "87654321h");
			magic = new byte[] { 0x78, 0x56, 0x34, 0x12, 0x78, 0x56, 0x34, 0x12, 0x21, 0x43, 0x65, (byte) 0x87, 0x21,
					0x43, 0x65, (byte) 0x87 };
		}
		globalTableType = (Structure) dtc.addDataType(globalTableType, DataTypeConflictHandler.REPLACE_HANDLER);

		var mem = currentProgram.getMemory();
		var start = mem.findBytes(mem.getMinAddress(), magic, null, true, monitor);
		var addr = start;
		while (true) {
			monitor.checkCanceled();
			addr = addr.addNoWrap(globalTableEntryType.getLength());
			long nameAddr = mem.getLong(addr);
			long dataAddr;
			if (currentProgram.getDefaultPointerSize() == 4) {
				dataAddr = nameAddr >>> 32;
				nameAddr = nameAddr & 0xffffffffL;
			} else {
				dataAddr = mem.getLong(addr.addNoWrap(8));
			}

			if (nameAddr == 0) {
				break;
			}

			var buf = new MemoryBufferImpl(mem, toAddr(nameAddr));
			var nameLength = TerminatedStringDataType.dataType.getLength(buf, -1);
			var name = (String) TerminatedStringDataType.dataType.getValue(buf, null, nameLength);
			var data = toAddr(dataAddr);
			if (name != null && !symtab.hasSymbol(data)) {
				createLabel(data, name, false, SourceType.IMPORTED);
			}
		}

		globalTableType.add(new ArrayDataType(globalTableEntryType,
				(int) addr.subtract(start) / globalTableEntryType.getLength(), -1), "entries", "");

		labelData(start, globalTableType, "global_table", -1);
	}

	private void cleanUpDemangler() throws Exception {
		var em = currentProgram.getExternalManager();

		ensureExternalLibraries(em);

		fixupDemangledNames(currentProgram.getGlobalNamespace());

		for (var libName : em.getExternalLibraryNames()) {
			var lib = em.getExternalLibrary(libName);
			fixupDemangledNames(lib);
		}
	}

	private void ensureExternalLibraries(ExternalManager em) throws Exception {
		// ensure external libraries are attached to files
		for (var libName : em.getExternalLibraryNames()) {
			if (em.getExternalLibraryPath(libName) == null) {
				if (libName.equals("libgraphics.so")) {
					var libGraphicsFile = currentProgram.getDomainFile().getParent().getFile(libName);
					if (libGraphicsFile != null) {
						println("attaching libgraphics.so external location");
						em.setExternalPath(libName, libGraphicsFile.getPathname(), false);
					} else {
						printerr("could not find libgraphics.so in the same folder as this program!");
					}
				} else if (!libName.equals(Library.UNKNOWN)) {
					var locations = new ArrayList<String>();
					findLibrary(locations, libName, getProjectRootFolder());
					if (locations.size() == 1) {
						println("attaching " + libName + " external location");
						em.setExternalPath(libName, locations.get(0), false);
					} else if (locations.isEmpty()) {
						printerr("missing external location for " + libName);
					} else {
						printerr("multiple possible external libraries for " + libName + ":");
						for (var loc : locations) {
							printerr("\t" + loc);
						}
					}
				}
			}
		}
	}

	private void fixupDemangledNames(Namespace global) throws Exception {
		for (var sym : symtab.getChildren(global.getSymbol())) {
			var addr = sym.getAddress();
			var name = sym.getName();
			var cmd = new DemanglerCmd(addr, name);
			runCommand(cmd);
			var demangled = cmd.getDemangledObject();
			if (demangled == null) {
				continue;
			}
			var syms = symtab.getSymbols(addr);
			for (var s : syms) {
				if (s != sym && !s.getName().equals(name)) {
					sym = s;
					break;
				}
			}
			var ns = ensureDemangledClass(demangled.getNamespace(), global);
			if (ns.getSymbol().getSymbolType() == global.getSymbol().getSymbolType()
					&& !sym.getName().startsWith("operator.") && !Character.isUpperCase(sym.getName().charAt(0))
					&& !sym.getName().equals("itoa")) {
				var dfns = ns;
				if (dfns == null) {
					dfns = ns;
				}
				ns = dfns;
			}
			if (ns.getSymbol().getSymbolType() == SymbolType.CLASS
					&& ns.getParentNamespace().getSymbol().getSymbolType() == SymbolType.LIBRARY) {
				println(ns.getName());
			}
			sym.setNamespace(ns);
			if (sym.getName().equals("basic_string")) {
				sym.setName("string", SourceType.IMPORTED);
			} else if (sym.getName().equals("~basic_string")) {
				sym.setName("~string", SourceType.IMPORTED);
			}
			if (sym.getName(true).equals("std::_string_rep::_S_empty_rep_storage")) {
				clearListing(addr);
				var dt = dtcStd.getDataType("_string_rep");
				createData(addr, dt);
				createAsciiString(addr.add(dt.getLength()), 8);
				createLabel(addr.add(dt.getLength()), "_S_empty_data", ns, false, SourceType.IMPORTED);
			}
			if (sym.getSymbolType() == SymbolType.FUNCTION) {
				var func = (Function) sym.getObject();
				for (var param : func.getParameters()) {
					if (param.getDataType() instanceof Pointer) {
						var ptr = (Pointer) param.getDataType();
						if (ptr.getDataType() instanceof ghidra.program.model.data.TypeDef) {
							var typedef = (ghidra.program.model.data.TypeDef) ptr.getDataType();
							if (typedef.getCategoryPath().isAncestorOrSelf(new CategoryPath("/Demangler"))) {
								param.setDataType(dtm.getPointer(typedef.getBaseDataType()), param.getSource());
							}
						} else if (ns.getName().equals("set<interface_key>") && DataTypeUtilities
								.isSameOrEquivalentDataType(LongDataType.dataType, ptr.getDataType())) {
							param.setDataType(dtm.getPointer(dtcEnums.getDataType("interface_key")), param.getSource());
						}
					}
				}
				if (ns instanceof GhidraClass
						&& (!sym.getName().equals("create") || !ns.getName().equals("viewscreen_movieplayerst")))
					func.setCallingConvention("__thiscall");
				else
					func.setCallingConvention("default");
			}
		}
	}

	private Namespace ensureDemangledClass(Demangled namespace, Namespace global) throws Exception {
		if (namespace == null) {
			return global;
		}
		var parent = ensureDemangledClass(namespace.getNamespace(), global);
		var name = namespace.getName();
		if (parent.getSymbol().getSymbolType() == global.getSymbol().getSymbolType() && (name.endsWith("st")
				|| name.startsWith("renderer_") || name.equals("textures") || name.equals("KeybindingScreen"))) {
			var dfns = parent;
			if (dfns == null) {
				dfns = parent;
			}
			parent = dfns;
		}
		// special case: these are in the STL
		if (name.equals("std") || name.startsWith("__cxx")) {
			var ns = symtab.getNamespace(namespace.getName(), global);
			if (ns == null) {
				ns = symtab.createNameSpace(parent, namespace.getName(), SourceType.IMPORTED);
			}
			return ns;
		}
		if (name.equals("_Rep") && parent.getName().equals("string") && parent.getParentNamespace() != null
				&& parent.getParentNamespace().getName().equals("std")
				&& parent.getParentNamespace().getParentNamespace() == global) {
			parent = parent.getParentNamespace();
			name = "_string_rep";
		}
		if (name.startsWith("basic_string<char") || name.equals("basic_string")) {
			name = "string";
		}
		if (name.startsWith("basic_fstream<char") || name.equals("basic_fstream")) {
			name = "fstream";
		}
		if (name.startsWith("_Rb_tree<long")) {
			name = "set<interface_key>";
		}
		var cls = symtab.getNamespace(name, parent);
		if (cls == null) {
			return symtab.createClass(parent, name, SourceType.IMPORTED);
		}
		if (cls instanceof GhidraClass) {
			return cls;
		}
		// we need to move the contents of this namespace to the actual class
		cls.getSymbol().setName(name + "__CLASS", SourceType.USER_DEFINED);
		var realClass = symtab.createClass(parent, name, SourceType.IMPORTED);
		for (var child : symtab.getChildren(cls.getSymbol())) {
			child.setNamespace(realClass);
		}
		cls.getSymbol().delete();
		return realClass;
	}

	private void setThunkNamespaces() throws Exception {
		updateProgressMajor("Fixing up thunk namespaces...");
		for (var fn : currentProgram.getFunctionManager().getFunctions(true)) {
			if (!fn.isThunk()) {
				continue;
			}

			var thunked = fn.getThunkedFunction(true);
			var root = fn.getParentNamespace();
			while (root.getSymbol().getSymbolType() != SymbolType.GLOBAL
					&& root.getSymbol().getSymbolType() != SymbolType.LIBRARY) {
				root = root.getParentNamespace();
			}
			var parent = buildMatchingNamespaceChain(root, thunked.getParentNamespace());
			fn.setParentNamespace(parent);
		}
	}

	private Namespace buildMatchingNamespaceChain(Namespace root, Namespace target) throws Exception {
		if (target.getSymbol().getSymbolType() == SymbolType.GLOBAL
				|| target.getSymbol().getSymbolType() == SymbolType.LIBRARY) {
			return root;
		}
		var parent = buildMatchingNamespaceChain(root, target.getParentNamespace());
		var ns = symtab.getNamespace(target.getName(), parent);
		if (target.getSymbol().getSymbolType() == SymbolType.CLASS) {
			if (ns == null) {
				return symtab.createClass(parent, target.getName(), SourceType.IMPORTED);
			}
			if (!(ns instanceof GhidraClass)) {
				throw new Exception("expected " + ns.getName(true) + " to be a class to match " + target.getName(true));
			}
			return ns;
		}
		if (target.getSymbol().getSymbolType() == SymbolType.NAMESPACE) {
			if (ns == null) {
				return symtab.createNameSpace(parent, target.getName(), SourceType.IMPORTED);
			}
			if (ns instanceof GhidraClass) {
				throw new Exception(
						"expected " + ns.getName(true) + " to be a namespace to match " + target.getName(true));
			}
			return ns;
		}
		throw new Exception("unexpected symbol type: " + target.getSymbol().getSymbolType());
	}

	private void findLibrary(List<String> locations, String name, DomainFolder folder) {
		var file = folder.getFile(name);
		if (file != null) {
			var md = file.getMetadata();
			if (md.get("Executable Format").equals(currentProgram.getExecutableFormat())
					&& md.get("Address Size").equals(Integer.toString(currentProgram.getDefaultPointerSize() * 8))) {
				locations.add(file.getPathname());
			}
		}

		for (var sub : folder.getFolders()) {
			findLibrary(locations, name, sub);
		}
	}
}
