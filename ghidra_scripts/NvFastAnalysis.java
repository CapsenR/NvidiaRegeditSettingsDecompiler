// Pre-Script: schaltet sehr langsame Analyzer ab, damit grosse Treiber wie
// nvlddmkm.sys in akzeptabler Zeit analysiert werden. Die fuer das Finden von
// String-Referenzen noetigen Analyzer bleiben aktiv.
//@category NvRegDecomp

import ghidra.app.script.GhidraScript;

public class NvFastAnalysis extends GhidraScript {

	private static final String[] DISABLE = {
		"Decompiler Parameter ID",
		"Aggressive Instruction Finder",
		"Condense Filler Bytes",
		"Variadic Function Signature Override",
		"PDB Universal",
		"PDB MSDIA",
	};

	@Override
	public void run() throws Exception {
		for (String opt : DISABLE) {
			try {
				setAnalysisOption(currentProgram, opt, "false");
				println("Analyzer deaktiviert: " + opt);
			}
			catch (Exception e) {
				// Option existiert in dieser Ghidra-Version nicht
			}
		}
	}
}
