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
// It also renames entities that newer importers name differently:
//   - enum values use the enum-item's original-name when present
//   - enum-indexed array type names embed the enum's original-name
//     (e.g. int32_t[<unit_thought_type>281] -> int32_t[<circumstance_type>281])
//   - BitArray<X> / _bits / _bits_N names and their entries likewise
//   - virtual methods (vtable fields, Class::method definitions, and the
//     labeled functions) use the vmethod's original-name when present
//
// The rename passes require codegen.out.xml from df-structures. To avoid the
// file prompt (e.g. for headless use), put a migrate_df_categories.properties
// file next to this script containing:
//     Select codegen.out.xml Select=[full path to df-structures]/codegen/codegen.out.xml
//
// @category DFHack

import java.io.*;
import java.util.*;
import java.util.regex.*;

import javax.xml.stream.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

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

	private static final String xmlnsLD = "http://github.com/peterix/dfhack/lowered-data-definition";
	private static final String[] ENUM_SIZE_SUFFIXES = { "", "(8-bit)", "(16-bit)", "(32-bit)", "(64-bit)" };
	private static final Pattern ANGLE_INDEX = Pattern.compile("\\[<([^>]+)>");
	private static final Pattern BITARRAY_NAME = Pattern.compile("^BitArray<([^>]+)>.*");

	private DataTypeManager dtm;
	private SymbolTable symtab;
	private List<DataType> types;

	private static class ItemInfo {
		String name, orig;
		boolean hasValue;
		long value;
	}

	private static class VMethodInfo {
		String name, orig, anonName;
		boolean isDestructor;
	}



	private static class TypeInfo {
		String typeName, originalName, meta, inheritsFrom;
		final List<ItemInfo> items = new ArrayList<>();
		final List<VMethodInfo> vmethods = new ArrayList<>();

		String resolvedName() {
			return originalName != null ? originalName : typeName;
		}
	}

	@Override
	public AnalysisMode getScriptAnalysisMode() {
		return AnalysisMode.SUSPENDED;
	}

	@Override
	protected void run() throws Exception {
		dtm = currentProgram.getDataTypeManager();
		symtab = currentProgram.getSymbolTable();

		File codegenFile = askFile("Select codegen.out.xml", "Select");
		List<TypeInfo> typeInfos = parseCodeGen(codegenFile);
		var byTypeName = new HashMap<String, TypeInfo>();
		var byResolved = new HashMap<String, TypeInfo>();
		for (var ti : typeInfos) {
			if (ti.typeName != null)
				byTypeName.put(ti.typeName, ti);
			if (ti.resolvedName() != null)
				byResolved.put(ti.resolvedName(), ti);
		}

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

		types = new ArrayList<>();
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

		var rawToResolved = new HashMap<String, String>();
		for (var ti : typeInfos) {
			if (ti.typeName != null && ti.originalName != null && !ti.originalName.equals(ti.typeName))
				rawToResolved.put(ti.typeName, ti.originalName);
		}

		println("renaming for original-name attributes...");
		renameEnumValues(typeInfos);
		renameCompositeTypeNames(byTypeName);
		renameStructFieldsAndBitArrayEntries(rawToResolved, byResolved);
		renameVMethods(typeInfos, byTypeName);

		println("migration complete");
	}

	private List<TypeInfo> parseCodeGen(File file) throws Exception {
		var typeInfos = new ArrayList<TypeInfo>();
		var factory = XMLInputFactory.newDefaultFactory();
		var reader = factory.createXMLStreamReader(new FileInputStream(file));
		var stack = new Stack<String>();
		TypeInfo cur = null;

		while (reader.hasNext()) {
			int tag = reader.next();
			if (tag == XMLStreamConstants.START_ELEMENT) {
				String local = reader.getLocalName();
				boolean ld = xmlnsLD.equals(reader.getNamespaceURI());
				String parent = stack.isEmpty() ? null : stack.peek();
				String grandparent = stack.size() < 2 ? null : stack.get(stack.size() - 2);

				if (ld && local.equals("global-type")) {
					cur = new TypeInfo();
					for (int i = 0; i < reader.getAttributeCount(); i++) {
						String an = reader.getAttributeLocalName(i);
						String av = reader.getAttributeValue(i);
						if (reader.getAttributeNamespace(i) == null) {
							switch (an) {
							case "type-name":
								cur.typeName = av;
								break;
							case "original-name":
								cur.originalName = av;
								break;
							case "inherits-from":
								cur.inheritsFrom = av;
								break;
							}
						} else if (reader.getAttributeNamespace(i).equals(xmlnsLD) && an.equals("meta")) {
							cur.meta = av;
						}
					}
					typeInfos.add(cur);
				} else if (!ld && local.equals("enum-item") && cur != null && "global-type".equals(parent)) {
					var it = new ItemInfo();
					for (int i = 0; i < reader.getAttributeCount(); i++) {
						if (reader.getAttributeNamespace(i) != null)
							continue;
						switch (reader.getAttributeLocalName(i)) {
						case "name":
							it.name = reader.getAttributeValue(i);
							break;
						case "original-name":
							it.orig = reader.getAttributeValue(i);
							break;
						case "value":
							it.hasValue = true;
							it.value = Long.decode(reader.getAttributeValue(i));
							break;
						}
					}
					cur.items.add(it);
				} else if (!ld && local.equals("vmethod") && cur != null && "virtual-methods".equals(parent)
						&& "global-type".equals(grandparent)) {
					var vm = new VMethodInfo();
					for (int i = 0; i < reader.getAttributeCount(); i++) {
						if (reader.getAttributeNamespace(i) != null)
							continue;
						switch (reader.getAttributeLocalName(i)) {
						case "name":
							vm.name = reader.getAttributeValue(i);
							break;
						case "original-name":
							vm.orig = reader.getAttributeValue(i);
							break;
						case "is-destructor":
							vm.isDestructor = Boolean.parseBoolean(reader.getAttributeValue(i));
							break;
						}
						if (reader.getAttributeNamespace(i) != null && reader.getAttributeNamespace(i).equals(xmlnsLD)
								&& reader.getAttributeLocalName(i).equals("anon-name"))
							vm.anonName = reader.getAttributeValue(i);
					}
					cur.vmethods.add(vm);
				}
				stack.push(local);
			} else if (tag == XMLStreamConstants.END_ELEMENT) {
				if (!stack.isEmpty()) {
					if (stack.pop().equals("global-type"))
						cur = null;
				}
			}
		}
		return typeInfos;
	}

	// rename enum values to their original-name
	private void renameEnumValues(List<TypeInfo> typeInfos) throws Exception {
		Category enumsCat = dtm.getCategory(DF_ENUMS);
		if (enumsCat == null)
			return;

		for (var ti : typeInfos) {
			monitor.checkCancelled();
			if (!"enum-type".equals(ti.meta) || ti.items.isEmpty())
				continue;

			Map<Long, String> valToOrig = new HashMap<>();
			long prev = -1;
			for (var it : ti.items) {
				long v = it.hasValue ? it.value : prev + 1;
				prev = v;
				if (it.orig != null && !it.orig.equals(it.name))
					valToOrig.put(v, it.orig);
			}
			if (valToOrig.isEmpty())
				continue;

			for (String suffix : ENUM_SIZE_SUFFIXES) {
				DataType dtd = enumsCat.getDataType(ti.resolvedName() + suffix);
				if (!(dtd instanceof ghidra.program.model.data.Enum))
					continue;
				var e = (ghidra.program.model.data.Enum) dtd;
				for (var en : valToOrig.entrySet()) {
					String curName = e.getName(en.getKey());
					if (curName != null && !curName.equals(en.getValue())) {
						String comment = e.getComment(curName);
						e.remove(curName);
						try {
							e.add(en.getValue(), en.getKey(), comment);
						} catch (Exception ex) {
							printerr("could not rename enum value " + curName + " in " + e.getName() + ": "
									+ ex.getMessage());
						}
					}
				}
			}
		}
	}

	// rename types whose generated names embed a raw (dfhack) enum type name:
	// X[<enumname>N] array structs and BitArray<enumname>* helper types
	private void renameCompositeTypeNames(Map<String, TypeInfo> byTypeName) throws Exception {
		for (var dt : types) {
			monitor.checkCancelled();
			String n = dt.getName();
			String nn = n;

			var bm = BITARRAY_NAME.matcher(nn);
			if (bm.matches()) {
				TypeInfo ti = byTypeName.get(bm.group(1));
				if (ti != null)
					nn = "BitArray<" + ti.resolvedName() + ">" + nn.substring(nn.indexOf('>') + 1);
			}

			var m = ANGLE_INDEX.matcher(nn);
			StringBuffer sb = new StringBuffer();
			while (m.find()) {
				TypeInfo ti = byTypeName.get(m.group(1));
				m.appendReplacement(sb,
						Matcher.quoteReplacement("[<" + (ti != null ? ti.resolvedName() : m.group(1)) + ">"));
			}
			m.appendTail(sb);
			nn = sb.toString();

			if (!nn.equals(n))
				renameType(dt, nn);
		}
	}

	// rename fields of enum-indexed array structs (enum item names and
	// <enum>_anon_i) and entries of BitArray<enum>_bits_i enums
	private void renameStructFieldsAndBitArrayEntries(Map<String, String> rawToResolved,
			Map<String, TypeInfo> byResolved) throws Exception {
		for (var dt : types) {
			monitor.checkCancelled();
			String n = dt.getName();

			if (dt instanceof Structure && n.contains("[<")) {
				String enumRef = lastEnumRef(n);
				TypeInfo ti = enumRef == null ? null : byResolved.get(enumRef);
				Map<String, String> itemMap = ti == null ? Map.of() : itemRenameMap(ti);
				for (var comp : ((Structure) dt).getComponents()) {
					String fn = comp.getFieldName();
					if (fn == null)
						continue;
					String mapped = itemMap.get(fn);
					if (mapped != null) {
						setFieldName(comp, mapped);
						continue;
					}
					int anonIdx = fn.indexOf("_anon_");
					if (anonIdx > 0) {
						String resolved = rawToResolved.get(fn.substring(0, anonIdx));
						if (resolved != null)
							setFieldName(comp, resolved + fn.substring(anonIdx));
					}
				}
			} else if (dt instanceof ghidra.program.model.data.Enum) {
				var bm = BITARRAY_NAME.matcher(n);
				if (!bm.matches() || !n.contains("_bits_"))
					continue;
				String enumRef = bm.group(1);
				TypeInfo ti = byResolved.get(enumRef);
				if (ti == null)
					continue;
				var e = (ghidra.program.model.data.Enum) dt;
				Map<String, String> itemMap = itemRenameMap(ti);
				String resolved = ti.resolvedName();
				var nameToValue = nameToValue(e);
				for (String en : e.getNames()) {
					String newName = null;
					if (en.equals("none_of_" + ti.typeName)) {
						newName = "none_of_" + resolved;
					} else {
						for (String prefix : new String[] { ti.typeName, resolved }) {
							if (prefix != null && en.startsWith(prefix + "_")) {
								String itemPart = en.substring(prefix.length() + 1);
								String mapped = itemMap.get(itemPart);
								newName = resolved + "_" + (mapped != null ? mapped : itemPart);
								break;
							}
						}
					}
					if (newName != null && !newName.equals(en))
						renameEnumEntry(e, nameToValue, en, newName);
				}
			}
		}
	}

	private Map<String, Long> nameToValue(ghidra.program.model.data.Enum e) {
		var map = new HashMap<String, Long>();
		for (long v : e.getValues())
			for (String n : e.getNames(v))
				map.put(n, v);
		return map;
	}

	private void renameEnumEntry(ghidra.program.model.data.Enum e, Map<String, Long> nameToValue,
			String oldName, String newName) {
		Long v = nameToValue.get(oldName);
		if (v == null)
			return;
		String comment = e.getComment(oldName);
		e.remove(oldName);
		try {
			e.add(newName, v, comment);
		} catch (Exception ex) {
			printerr("could not rename enum entry " + oldName + " in " + e.getName() + ": " + ex.getMessage());
		}
	}

	// rename vmethod function definitions, vtable struct fields, and labeled
	// functions/labels to their original-name
	private void renameVMethods(List<TypeInfo> typeInfos, Map<String, TypeInfo> byTypeName) throws Exception {
		Category methodsCat = dtm.getCategory(DF_VMETHODS);
		Category vtCat = dtm.getCategory(DF_VTABLES);
		var global = currentProgram.getGlobalNamespace();

		for (var ti : typeInfos) {
			monitor.checkCancelled();

			// merged name->orig map for this class including inherited methods
			Map<String, String> renames = new LinkedHashMap<>();
			var visited = new HashSet<TypeInfo>();
			for (TypeInfo c = ti; c != null && visited.add(c); c = byTypeName.get(c.inheritsFrom)) {
				String cname = c.resolvedName();
				for (var vm : c.vmethods) {
					if (vm.orig == null || vm.isDestructor)
						continue;
					String dfname = vm.name != null ? vm.name
							: (vm.anonName != null ? cname + "_" + vm.anonName : null);
					if (dfname != null && !dfname.equals(vm.orig))
						renames.putIfAbsent(dfname, vm.orig);
				}
			}
			if (renames.isEmpty())
				continue;

			String cls = ti.resolvedName();

			// function definition + vtable struct field (only for own vmethods)
			for (var vm : ti.vmethods) {
				if (vm.orig == null || vm.isDestructor)
					continue;
				String dfname = vm.name != null ? vm.name
						: (vm.anonName != null ? cls + "_" + vm.anonName : null);
				if (dfname == null || dfname.equals(vm.orig))
					continue;
				if (methodsCat != null) {
					DataType fd = methodsCat.getDataType(cls + "::" + dfname);
					if (fd != null)
						renameType(fd, cls + "::" + vm.orig);
				}
				if (vtCat != null) {
					DataType vtd = vtCat.getDataType("vtable_" + cls);
					if (vtd instanceof Structure) {
						for (var comp : ((Structure) vtd).getComponents())
							if (dfname.equals(comp.getFieldName()))
								setFieldName(comp, vm.orig);
					}
				}
			}

			// functions/labels in the class namespace (own + inherited methods)
			var ns = findNamespace(cls, global);
			if (ns == null)
				continue;
			for (var e : renames.entrySet()) {
				for (var s : symtab.getSymbols(e.getKey(), ns)) {
					try {
						s.setName(e.getValue(), SourceType.IMPORTED);
					} catch (DuplicateNameException | InvalidInputException ex) {
						printerr("could not rename symbol " + cls + "::" + e.getKey() + ": " + ex.getMessage());
					}
				}
			}
		}
	}

	private Namespace findNamespace(String name, Namespace global) throws Exception {
		var ns = symtab.getNamespace(name, global);
		if (ns != null)
			return ns;
		if (!name.contains("::"))
			return null;
		ns = global;
		for (String part : name.split("::")) {
			ns = symtab.getNamespace(part, ns);
			if (ns == null)
				return null;
		}
		return ns;
	}

	private String lastEnumRef(String name) {
		String last = null;
		var m = ANGLE_INDEX.matcher(name);
		while (m.find())
			last = m.group(1);
		return last;
	}

	private Map<String, String> itemRenameMap(TypeInfo ti) {
		Map<String, String> map = new HashMap<>();
		for (var it : ti.items)
			if (it.orig != null && it.name != null && !it.orig.equals(it.name))
				map.put(it.name, it.orig);
		return map;
	}

	private void renameType(DataType dt, String newName) {
		try {
			dt.setNameAndCategory(dt.getCategoryPath(), newName);
		} catch (DuplicateNameException | InvalidNameException e) {
			printerr("could not rename " + dt.getPathName() + " to " + newName + ": " + e.getMessage());
		}
	}

	private void setFieldName(DataTypeComponent comp, String newName) {
		try {
			comp.setFieldName(newName);
		} catch (DuplicateNameException e) {
			printerr("could not rename field " + comp.getFieldName() + ": " + e.getMessage());
		}
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
