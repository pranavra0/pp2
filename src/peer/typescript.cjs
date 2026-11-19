const path = require("node:path");

function compile() {
    const entry = path.resolve(process.argv[1]);
    const aliases = new Map(Object.entries(JSON.parse(process.argv[2])));
    let ts;
    try {
        ts = require(require.resolve("typescript", { paths: [path.dirname(entry), process.cwd()] }));
    } catch {
        throw new Error("TypeScript is missing. Run npm ci in the pp2 checkout or install typescript in your project.");
    }

    const options = {
        target: ts.ScriptTarget.ES2022,
        module: ts.ModuleKind.ES2022,
        moduleResolution: ts.ModuleResolutionKind.Bundler,
        lib: ["lib.es2022.d.ts"],
        types: [],
        strict: true,
        noUncheckedIndexedAccess: true,
        verbatimModuleSyntax: true,
        noEmitOnError: true,
        newLine: ts.NewLineKind.LineFeed,
    };
    const program = ts.createProgram([entry], options);
    const diagnostics = ts.getPreEmitDiagnostics(program);
    function check(diagnostics) {
        if (diagnostics.length === 0) return;
        throw new Error(ts.formatDiagnostics(diagnostics, {
            getCanonicalFileName: name => name,
            getCurrentDirectory: () => process.cwd(),
            getNewLine: () => "\n",
        }).trimEnd());
    }
    check(diagnostics);

    const module = program.getSourceFile(entry);
    if (!module || module.isDeclarationFile) throw new Error("expected an executable TypeScript module");
    let output;
    const emitted = program.emit(module, (filename, text) => {
        if (/\.(?:m?js)$/.test(filename)) output = text;
    });
    check(emitted.diagnostics);
    if (output === undefined) throw new Error("expected an executable TypeScript module");

    const file = ts.createSourceFile(entry, output, ts.ScriptTarget.ES2022, true, ts.ScriptKind.JS);
    const edits = [];
    function visit(node) {
        let specifier;
        if (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) {
            specifier = node.moduleSpecifier;
        } else if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) {
            specifier = node.arguments[0];
        }
        if (specifier && ts.isStringLiteralLike(specifier)) {
            const linked = aliases.get(specifier.text);
            if (linked) {
                edits.push({ start: specifier.getStart(file), end: specifier.end, replacement: JSON.stringify(linked) });
            } else if (!/^pp2:[a-f0-9]{64}$/.test(specifier.text)) {
                throw new Error("link runtime import " + JSON.stringify(specifier.text) + " with SPECIFIER=HASH");
            }
        }
        ts.forEachChild(node, visit);
    }
    visit(file);
    for (const { start, end, replacement } of edits.reverse()) {
        output = output.slice(0, start) + replacement + output.slice(end);
    }
    return output;
}

try {
    process.stdout.write(compile());
} catch (error) {
    process.stderr.write(error.message + "\n");
    process.exitCode = 1;
}
