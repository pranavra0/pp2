const path = require("node:path");
const fs = require("node:fs");

function compiler(entry) {
    let ts;
    try {
        ts = require(require.resolve("typescript", { paths: [path.dirname(entry), process.cwd()] }));
    } catch {
        throw new Error("TypeScript is missing. Run npm ci in the pp2 checkout or install typescript in your project.");
    }

    return ts;
}

function options(ts) {
    return {
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
}

function check(ts, diagnostics) {
    if (diagnostics.length === 0) return;
    throw new Error(ts.formatDiagnostics(diagnostics, {
        getCanonicalFileName: name => name,
        getCurrentDirectory: () => process.cwd(),
        getNewLine: () => "\n",
    }).trimEnd());
}

function emit(ts, program, entry) {
    const module = program.getSourceFile(entry);
    if (!module || module.isDeclarationFile) throw new Error("expected an executable TypeScript module");
    let output;
    const emitted = program.emit(module, (filename, text) => {
        if (/\.(?:m?js)$/.test(filename)) output = text;
    });
    check(ts, emitted.diagnostics);
    if (output === undefined) throw new Error("expected an executable TypeScript module");

    return output;
}

function imports(ts, entry, source, link, literalOnly) {
    const file = ts.createSourceFile(entry, source, ts.ScriptTarget.ES2022, true, ts.ScriptKind.JS);
    if (file.parseDiagnostics.length) {
        throw new Error(entry + ": " + ts.flattenDiagnosticMessageText(file.parseDiagnostics[0].messageText, "\n"));
    }
    const edits = [];
    function visit(node) {
        let specifier;
        if (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) {
            specifier = node.moduleSpecifier;
        } else if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) {
            specifier = node.arguments[0];
            if (literalOnly && (!specifier || !ts.isStringLiteralLike(specifier))) {
                throw new Error(entry + ": expected a literal dynamic import");
            }
        }
        if (specifier && ts.isStringLiteralLike(specifier)) {
            const linked = link(specifier.text);
            if (linked !== undefined) {
                edits.push({ start: specifier.getStart(file), end: specifier.end, linked });
            }
        }
        ts.forEachChild(node, visit);
    }
    visit(file);
    return edits;
}

function compile(ts, entry, aliases) {
    const program = ts.createProgram([entry], options(ts));
    check(ts, ts.getPreEmitDiagnostics(program));
    let output = emit(ts, program, entry);
    const edits = imports(ts, entry, output, specifier => {
        if (aliases.has(specifier)) return aliases.get(specifier);
        if (!/^pp2:[a-f0-9]{64}$/.test(specifier)) {
            throw new Error("link runtime import " + JSON.stringify(specifier) + " with SPECIFIER=HASH");
        }
    }, false);
    for (const { start, end, linked } of edits.reverse()) {
        output = output.slice(0, start) + JSON.stringify(linked) + output.slice(end);
    }
    return output;
}

function graph(ts, entry) {
    const settings = {...options(ts), allowJs: true, noEmitForJsFiles: true};
    let program;
    const modules = [];
    const visited = new Map();
    let bytes = 0;

    function visit(filename) {
        if (visited.has(filename)) {
            const index = visited.get(filename);
            if (index === null) throw new Error("cyclic runtime import at " + filename);
            return index;
        }
        if (visited.size >= 32) throw new Error("module graph exceeds 32 modules");
        visited.set(filename, null);
        if (fs.statSync(filename).size > 256 * 1024) throw new Error("module exceeds 256 KiB: " + filename);
        let source;
        if (/\.m?ts$/.test(filename)) {
            if (program === undefined) {
                program = ts.createProgram([entry], settings);
                check(ts, ts.getPreEmitDiagnostics(program));
            }
            source = emit(ts, program, filename);
        } else {
            source = new TextDecoder("utf-8", {fatal: true}).decode(fs.readFileSync(filename));
        }
        bytes += Buffer.byteLength(source);
        if (bytes > 512 * 1024) throw new Error("module graph exceeds 512 KiB");
        const edits = imports(ts, filename, source, specifier => {
            if (specifier.startsWith("./") || specifier.startsWith("../")) {
                const resolved = ts.resolveModuleName(specifier, filename, settings, ts.sys).resolvedModule;
                if (resolved && !/\.d\.m?ts$/.test(resolved.resolvedFileName)
                    && /\.m?[jt]s$/.test(resolved.resolvedFileName)) {
                    return visit(resolved.resolvedFileName);
                }
            }
            throw new Error(filename + ": expected a relative JavaScript or TypeScript import, got " + JSON.stringify(specifier));
        }, true);
        const parts = [];
        let end = 0;
        for (const edit of edits) {
            parts.push(source.slice(end, edit.start), edit.linked);
            end = edit.end;
        }
        parts.push(source.slice(end));
        const index = modules.length;
        modules.push(parts);
        visited.set(filename, index);
        return index;
    }
    visit(entry);
    return JSON.stringify(modules);
}

try {
    const entry = path.resolve(process.argv[1]);
    const ts = compiler(entry);
    const mode = process.argv[2];
    process.stdout.write(mode === "graph" ? graph(ts, entry) : compile(ts, entry, new Map(Object.entries(JSON.parse(mode)))));
} catch (error) {
    process.stderr.write(error.message + "\n");
    process.exitCode = 1;
}
