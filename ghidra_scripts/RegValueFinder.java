// Sucht Registry-Wertnamen (ASCII / UTF-16LE) im geladenen Programm, folgt allen
// Referenzen darauf und dekompiliert die Funktionen, die sie verwenden.
//
// Aufruf (headless):
//   analyzeHeadless <projDir> <projName> -process <datei> -noanalysis
//       -scriptPath <dieser Ordner> -postScript RegValueFinder.java <names.txt> <out.json> [maxRefs]
//
// names.txt: ein Wertname pro Zeile (UTF-8).
//@category NvRegDecomp

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;

public class RegValueFinder extends GhidraScript {

	private static final int MIN_LEN = 3;
	private static final int MAX_CODE_CHARS = 400_000;
	private static final int MAX_TABLE_FUNCS = 4;

	private int maxRefs = 40;
	private DecompInterface decomp;

	/** name.lower() -> Originalname */
	private final Map<String, String> wanted = new HashMap<>();
	/** name.lower() -> gefundene Strings */
	private final Map<String, List<StrHit>> hits = new LinkedHashMap<>();
	/** Zieladresse (offset) -> Liste von (fromAddr, kind) aus Byte-Scans */
	private final Map<Long, List<Object[]>> scanRefs = new HashMap<>();
	/** Funktion (entry) -> dekompilierter Code */
	private final Map<Address, FuncInfo> funcs = new LinkedHashMap<>();

	private static class StrHit {
		Address addr;
		String enc;
		boolean exact;
		String text;
	}

	private static class FuncInfo {
		Function f;
		List<String> lines = new ArrayList<>();
		List<Address[]> lineAddrs = new ArrayList<>(); // min/max je Zeile (kann null sein)
		String error;
		List<String> callers = new ArrayList<>();
		List<String> callees = new ArrayList<>();
	}

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length < 2) {
			printerr("Argumente: <names.txt> <out.json> [maxRefs]");
			return;
		}
		Path namesFile = Paths.get(args[0]);
		Path outFile = Paths.get(args[1]);
		if (args.length > 2) {
			maxRefs = Integer.parseInt(args[2].trim());
		}

		for (String line : Files.readAllLines(namesFile, StandardCharsets.UTF_8)) {
			String n = line.replace("﻿", "").trim();
			if (!n.isEmpty()) {
				wanted.put(n.toLowerCase(Locale.ROOT), n);
			}
		}
		println("RegValueFinder: " + wanted.size() + " Namen, Programm " + currentProgram.getName());

		monitor.setMessage("Suche Strings");
		findStrings();
		println("Strings gefunden fuer " + hits.size() + " Namen");

		defineStrings();
		scanForUnresolvedRefs();

		decomp = new DecompInterface();
		DecompileOptions opts = new DecompileOptions();
		decomp.setOptions(opts);
		decomp.toggleCCode(true);
		decomp.toggleSyntaxTree(true);
		decomp.setSimplificationStyle("decompile");
		if (!decomp.openProgram(currentProgram)) {
			printerr("Decompiler konnte nicht geoeffnet werden: " + decomp.getLastMessage());
		}

		try {
			writeJson(outFile);
		}
		finally {
			decomp.dispose();
		}
		println("RegValueFinder: fertig -> " + outFile);
	}

	// ------------------------------------------------------------------ Suche

	private static boolean isPrint(byte b) {
		return b >= 0x20 && b <= 0x7e;
	}

	private void findStrings() throws Exception {
		Memory mem = currentProgram.getMemory();
		for (MemoryBlock b : mem.getBlocks()) {
			if (monitor.isCancelled()) {
				return;
			}
			if (!b.isInitialized() || b.getSize() > Integer.MAX_VALUE) {
				continue;
			}
			byte[] buf = new byte[(int) b.getSize()];
			try {
				b.getBytes(b.getStart(), buf);
			}
			catch (MemoryAccessException e) {
				continue;
			}
			scanUtf16(b, buf);
			scanAscii(b, buf);
		}
	}

	private void scanUtf16(MemoryBlock b, byte[] buf) {
		int n = buf.length;
		int i = 0;
		while (i + 1 < n) {
			if (isPrint(buf[i]) && buf[i + 1] == 0) {
				int j = i;
				StringBuilder sb = new StringBuilder();
				while (j + 1 < n && isPrint(buf[j]) && buf[j + 1] == 0) {
					sb.append((char) buf[j]);
					j += 2;
				}
				if (sb.length() >= MIN_LEN) {
					consider(b.getStart().add(i), "utf16", sb.toString());
				}
				i = j;
			}
			else {
				i++;
			}
		}
	}

	private void scanAscii(MemoryBlock b, byte[] buf) {
		int n = buf.length;
		int i = 0;
		while (i < n) {
			if (isPrint(buf[i])) {
				int j = i;
				while (j < n && isPrint(buf[j])) {
					j++;
				}
				if (j - i >= MIN_LEN) {
					consider(b.getStart().add(i), "ascii",
						new String(buf, i, j - i, StandardCharsets.US_ASCII));
				}
				i = j;
			}
			else {
				i++;
			}
		}
	}

	private void consider(Address a, String enc, String s) {
		String low = s.toLowerCase(Locale.ROOT);
		if (wanted.containsKey(low)) {
			addHit(low, a, enc, true, s);
			return;
		}
		if (s.length() > 400) {
			return;
		}
		// Teilstrings wie "Name=%d" oder "...\\Name"
		int step = enc.equals("utf16") ? 2 : 1;
		int start = -1;
		for (int k = 0; k <= low.length(); k++) {
			char c = k < low.length() ? low.charAt(k) : ' ';
			boolean ident = Character.isLetterOrDigit(c) || c == '_';
			if (ident && start < 0) {
				start = k;
			}
			else if (!ident && start >= 0) {
				String tok = low.substring(start, k);
				if (tok.length() >= 6 && wanted.containsKey(tok)) {
					addHit(tok, a.add((long) start * step), enc, false, s);
				}
				start = -1;
			}
		}
	}

	private void addHit(String low, Address a, String enc, boolean exact, String text) {
		List<StrHit> l = hits.computeIfAbsent(low, k -> new ArrayList<>());
		if (l.size() >= 20) {
			return;
		}
		StrHit h = new StrHit();
		h.addr = a;
		h.enc = enc;
		h.exact = exact;
		h.text = text;
		l.add(h);
	}

	/** Legt fuer exakte Treffer String-Daten an, damit der Decompiler L"Name" zeigt. */
	private void defineStrings() {
		for (List<StrHit> l : hits.values()) {
			for (StrHit h : l) {
				if (!h.exact || getDataAt(h.addr) != null || getInstructionContaining(h.addr) != null) {
					continue;
				}
				try {
					if (h.enc.equals("utf16")) {
						createUnicodeString(h.addr);
					}
					else {
						createAsciiString(h.addr);
					}
				}
				catch (Exception e) {
					// ueberlappende Daten o.ae. - ignorieren
				}
			}
		}
	}

	/**
	 * Fallback fuer Strings ohne Referenzen (z.B. Analyse unvollstaendig):
	 * sucht absolute Zeiger und RIP-relative LEA-Befehle auf die Stringadresse.
	 */
	private void scanForUnresolvedRefs() throws Exception {
		Set<Long> targets = new HashSet<>();
		for (List<StrHit> l : hits.values()) {
			for (StrHit h : l) {
				if (getReferencesTo(h.addr).length == 0) {
					targets.add(h.addr.getOffset());
				}
			}
		}
		if (targets.isEmpty()) {
			return;
		}
		println("Byte-Scan nach Zeigern/LEA fuer " + targets.size() + " Strings ohne Referenzen");
		int ptrSize = currentProgram.getDefaultPointerSize();
		for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
			if (monitor.isCancelled()) {
				return;
			}
			if (!b.isInitialized() || b.getSize() > Integer.MAX_VALUE) {
				continue;
			}
			byte[] buf = new byte[(int) b.getSize()];
			try {
				b.getBytes(b.getStart(), buf);
			}
			catch (MemoryAccessException e) {
				continue;
			}
			long base = b.getStart().getOffset();
			// absolute Zeiger (Tabellen)
			for (int i = 0; i + ptrSize <= buf.length; i += ptrSize) {
				long v = 0;
				for (int k = ptrSize - 1; k >= 0; k--) {
					v = (v << 8) | (buf[i + k] & 0xffL);
				}
				if (targets.contains(v)) {
					addScanRef(v, b.getStart().add(i), "pointer-scan");
				}
			}
			// x64: [REX.W] 8D /r mit RIP-relativer Adressierung (LEA reg, [rip+disp32])
			if (b.isExecute() && ptrSize == 8) {
				for (int i = 0; i + 7 <= buf.length; i++) {
					int rex = buf[i] & 0xff;
					if ((rex & 0xf0) != 0x40 || (buf[i + 1] & 0xff) != 0x8d ||
						(buf[i + 2] & 0xc7) != 0x05) {
						continue;
					}
					int disp = (buf[i + 3] & 0xff) | ((buf[i + 4] & 0xff) << 8) |
						((buf[i + 5] & 0xff) << 16) | ((buf[i + 6] & 0xff) << 24);
					long target = base + i + 7 + disp;
					if (targets.contains(target)) {
						addScanRef(target, b.getStart().add(i), "lea-scan");
					}
				}
			}
		}
	}

	private void addScanRef(long target, Address from, String kind) {
		scanRefs.computeIfAbsent(target, k -> new ArrayList<>()).add(new Object[] { from, kind });
	}

	// ------------------------------------------------------------ Dekompilierung

	private FuncInfo decompile(Function f) {
		FuncInfo fi = funcs.get(f.getEntryPoint());
		if (fi != null) {
			return fi;
		}
		fi = new FuncInfo();
		fi.f = f;
		funcs.put(f.getEntryPoint(), fi);
		monitor.setMessage("Dekompiliere " + f.getName());
		try {
			DecompileResults res = decomp.decompileFunction(f, 90, monitor);
			if (res == null || !res.decompileCompleted() || res.getCCodeMarkup() == null) {
				fi.error = res == null ? "keine Ergebnisse" : res.getErrorMessage();
			}
			else {
				int total = 0;
				for (ClangLine line : DecompilerUtils.toLines(res.getCCodeMarkup())) {
					StringBuilder sb = new StringBuilder(line.getIndentString());
					Address min = null;
					Address max = null;
					for (ClangToken t : line.getAllTokens()) {
						sb.append(t.getText());
						Address tmin = t.getMinAddress();
						Address tmax = t.getMaxAddress();
						if (tmin != null && (min == null || tmin.compareTo(min) < 0)) {
							min = tmin;
						}
						if (tmax != null && (max == null || tmax.compareTo(max) > 0)) {
							max = tmax;
						}
					}
					total += sb.length() + 1;
					if (total > MAX_CODE_CHARS) {
						fi.lines.add("/* ... gekuerzt ... */");
						fi.lineAddrs.add(null);
						break;
					}
					fi.lines.add(sb.toString());
					fi.lineAddrs.add(min == null ? null : new Address[] { min, max == null ? min : max });
				}
			}
		}
		catch (Exception e) {
			fi.error = e.toString();
		}
		try {
			for (Function c : f.getCallingFunctions(monitor)) {
				if (fi.callers.size() >= 15) {
					break;
				}
				fi.callers.add(c.getName() + "@" + c.getEntryPoint());
			}
			for (Function c : f.getCalledFunctions(monitor)) {
				if (fi.callees.size() >= 40) {
					break;
				}
				fi.callees.add(c.getName() + "@" + c.getEntryPoint());
			}
		}
		catch (Exception e) {
			// ignorieren
		}
		return fi;
	}

	/** Zeilennummern (0-basiert), die zur Adresse gehoeren oder den Namen/die Adresse enthalten. */
	private List<Integer> matchLines(FuncInfo fi, Address from, String name, Address strAddr) {
		List<Integer> res = new ArrayList<>();
		String lowName = name.toLowerCase(Locale.ROOT);
		String hex = Long.toHexString(strAddr.getOffset()).toLowerCase(Locale.ROOT);
		for (int i = 0; i < fi.lines.size(); i++) {
			Address[] r = fi.lineAddrs.get(i);
			String low = fi.lines.get(i).toLowerCase(Locale.ROOT);
			boolean byAddr = r != null && from != null && from.compareTo(r[0]) >= 0 && from.compareTo(r[1]) <= 0;
			if (byAddr || low.contains(lowName) || low.contains(hex)) {
				res.add(i);
			}
		}
		return res;
	}

	// ------------------------------------------------------------------ Ausgabe

	private void writeJson(Path out) throws Exception {
		StringBuilder sb = new StringBuilder(1 << 20);
		sb.append("{\n");
		kv(sb, "file", currentProgram.getExecutablePath()).append(",\n");
		kv(sb, "program", currentProgram.getName()).append(",\n");
		kv(sb, "imageBase", currentProgram.getImageBase().toString()).append(",\n");
		sb.append("\"pointerSize\":").append(currentProgram.getDefaultPointerSize()).append(",\n");
		sb.append("\"notFound\":[");
		boolean first = true;
		for (Map.Entry<String, String> e : wanted.entrySet()) {
			if (!hits.containsKey(e.getKey())) {
				if (!first) {
					sb.append(',');
				}
				first = false;
				str(sb, e.getValue());
			}
		}
		sb.append("],\n\"values\":[\n");

		int done = 0;
		first = true;
		for (Map.Entry<String, List<StrHit>> e : hits.entrySet()) {
			if (monitor.isCancelled()) {
				break;
			}
			String name = wanted.get(e.getKey());
			monitor.setMessage("Wert " + (++done) + "/" + hits.size() + ": " + name);
			if (!first) {
				sb.append(",\n");
			}
			first = false;
			writeValue(sb, name, e.getValue());
		}
		sb.append("\n],\n\"functions\":{\n");
		first = true;
		for (FuncInfo fi : funcs.values()) {
			if (!first) {
				sb.append(",\n");
			}
			first = false;
			str(sb, fi.f.getEntryPoint().toString()).append(":{");
			kv(sb, "name", fi.f.getName()).append(',');
			kv(sb, "entry", fi.f.getEntryPoint().toString()).append(',');
			kv(sb, "signature", fi.f.getPrototypeString(false, false)).append(',');
			if (fi.error != null) {
				kv(sb, "error", fi.error).append(',');
			}
			sb.append("\"callers\":");
			strList(sb, fi.callers).append(",\"callees\":");
			strList(sb, fi.callees).append(",\"code\":");
			str(sb, String.join("\n", fi.lines));
			sb.append('}');
		}
		sb.append("\n}\n}\n");
		Files.write(out, sb.toString().getBytes(StandardCharsets.UTF_8));
	}

	private void writeValue(StringBuilder sb, String name, List<StrHit> strs) throws Exception {
		sb.append('{');
		kv(sb, "name", name).append(",\"strings\":[");
		for (int i = 0; i < strs.size(); i++) {
			StrHit h = strs.get(i);
			if (i > 0) {
				sb.append(',');
			}
			sb.append('{');
			kv(sb, "address", h.addr.toString()).append(',');
			kv(sb, "encoding", h.enc).append(',');
			sb.append("\"exact\":").append(h.exact).append(',');
			kv(sb, "text", h.text);
			sb.append('}');
		}
		sb.append("],\"refs\":[");
		int count = 0;
		boolean firstRef = true;
		for (StrHit h : strs) {
			List<Object[]> refs = new ArrayList<>();
			for (Reference r : getReferencesTo(h.addr)) {
				refs.add(new Object[] { r.getFromAddress(), "xref:" + r.getReferenceType().getName() });
			}
			List<Object[]> scanned = scanRefs.get(h.addr.getOffset());
			if (scanned != null) {
				refs.addAll(scanned);
			}
			for (Object[] r : refs) {
				if (count++ >= maxRefs) {
					break;
				}
				if (!firstRef) {
					sb.append(',');
				}
				firstRef = false;
				writeRef(sb, name, h, (Address) r[0], (String) r[1]);
			}
		}
		sb.append("]}");
	}

	private void writeRef(StringBuilder sb, String name, StrHit h, Address from, String kind) throws Exception {
		sb.append('{');
		kv(sb, "string", h.addr.toString()).append(',');
		kv(sb, "from", from.toString()).append(',');
		kv(sb, "kind", kind).append(',');
		Function f = getFunctionContaining(from);
		if (f != null) {
			FuncInfo fi = decompile(f);
			kv(sb, "function", f.getName()).append(',');
			kv(sb, "entry", f.getEntryPoint().toString()).append(',');
			sb.append("\"lines\":");
			intList(sb, matchLines(fi, from, name, h.addr));
		}
		else {
			// Datenreferenz, typischerweise ein Eintrag in einer Registry-Tabelle
			// { L"Name", Typ, Default, &Variable, ... }
			sb.append("\"data\":{");
			Data d = getDataContaining(from);
			if (d != null) {
				kv(sb, "dataType", d.getDataType().getDisplayName()).append(',');
				Data top = d;
				while (top.getParent() != null) {
					top = top.getParent();
				}
				kv(sb, "container", top.getMinAddress() + " " + top.getDataType().getDisplayName()).append(',');
			}
			kv(sb, "bytesAfter", hexDump(from, 48)).append(',');
			kv(sb, "bytesBefore", hexDump(from.subtract(Math.min(24, from.getOffset())), 24)).append(',');
			Address tableRef = findTableBase(from);
			sb.append("\"tableFunctions\":[");
			if (tableRef != null) {
				int n = 0;
				Set<Address> seen = new HashSet<>();
				for (Reference r : getReferencesTo(tableRef)) {
					Function tf = getFunctionContaining(r.getFromAddress());
					if (tf == null || !seen.add(tf.getEntryPoint())) {
						continue;
					}
					if (n++ >= MAX_TABLE_FUNCS) {
						break;
					}
					FuncInfo fi = decompile(tf);
					if (n > 1) {
						sb.append(',');
					}
					sb.append('{');
					kv(sb, "function", tf.getName()).append(',');
					kv(sb, "entry", tf.getEntryPoint().toString()).append(',');
					sb.append("\"lines\":");
					intList(sb, matchLines(fi, r.getFromAddress(), name, tableRef));
					sb.append('}');
				}
			}
			sb.append("],");
			kv(sb, "tableBase", tableRef == null ? "" : tableRef.toString());
			sb.append("}");
		}
		sb.append('}');
	}

	/** Geht vom Tabelleneintrag rueckwaerts bis zur ersten Adresse, auf die referenziert wird. */
	private Address findTableBase(Address from) {
		int step = currentProgram.getDefaultPointerSize();
		Address a = from;
		for (int i = 0; i < 0x4000 / step; i++) {
			if (getReferencesTo(a).length > 0) {
				for (Reference r : getReferencesTo(a)) {
					if (getFunctionContaining(r.getFromAddress()) != null) {
						return a;
					}
				}
			}
			try {
				a = a.subtract(step);
			}
			catch (Exception e) {
				return null;
			}
			if (getMemoryBlock(a) == null) {
				return null;
			}
		}
		return null;
	}

	private String hexDump(Address a, int len) {
		StringBuilder sb = new StringBuilder();
		try {
			byte[] b = getBytes(a, len);
			for (int i = 0; i < b.length; i++) {
				if (i > 0) {
					sb.append(i % 8 == 0 ? " | " : " ");
				}
				sb.append(String.format("%02x", b[i] & 0xff));
			}
		}
		catch (Exception e) {
			sb.append("?");
		}
		return sb.toString();
	}

	// ------------------------------------------------------------------- JSON

	private static StringBuilder str(StringBuilder sb, String s) {
		sb.append('"');
		if (s != null) {
			for (int i = 0; i < s.length(); i++) {
				char c = s.charAt(i);
				switch (c) {
					case '"': sb.append("\\\""); break;
					case '\\': sb.append("\\\\"); break;
					case '\n': sb.append("\\n"); break;
					case '\r': sb.append("\\r"); break;
					case '\t': sb.append("\\t"); break;
					default:
						if (c < 0x20) {
							sb.append(String.format("\\u%04x", (int) c));
						}
						else {
							sb.append(c);
						}
				}
			}
		}
		return sb.append('"');
	}

	private static StringBuilder kv(StringBuilder sb, String k, String v) {
		str(sb, k).append(':');
		return str(sb, v);
	}

	private static StringBuilder strList(StringBuilder sb, List<String> l) {
		sb.append('[');
		for (int i = 0; i < l.size(); i++) {
			if (i > 0) {
				sb.append(',');
			}
			str(sb, l.get(i));
		}
		return sb.append(']');
	}

	private static StringBuilder intList(StringBuilder sb, List<Integer> l) {
		sb.append('[');
		for (int i = 0; i < l.size(); i++) {
			if (i > 0) {
				sb.append(',');
			}
			sb.append(l.get(i));
		}
		return sb.append(']');
	}
}
