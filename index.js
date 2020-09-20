/* eslint-disable max-depth */
// Require Node.js Files
import fs from "fs/promises";
import path from "path";

// Require Third-party Dependencies
import builtins from "builtins";
import { klona } from "klona/json";

// CONSTANTS
const kDirectoryToAnalyze = "F:\\Code\\fraxken\\npm-security-fetcher\\results\\packages";
const kNodeBuiltins = new Set(builtins());

async function readJSON(location) {
    const buf = await fs.readFile(location);

    return JSON.parse(buf.toString());
}

function getDefaultWarning() {
    return klona({
        "encoded-literal": 0,
        "unsafe-import": 0,
        "unsafe-regex": 0,
        "unsafe-stmt": 0,
        "unsafe-assign": 0,
        "short-identifiers": 0,
        "suspicious-literal": 0,
        "obfuscated-code": 0
    });
}

async function main() {
    const files = await fs.readdir(kDirectoryToAnalyze, { withFileTypes: true });
    const jsonFiles = files
        .filter((dirent) => dirent.isFile() && path.extname(dirent.name, ".json"))
        .map((dirent) => dirent.name);

    const globalStats = {
        nodeDeps: new Set(),
        warnings: getDefaultWarning()
    };
    const projectsStats = {
        fileCount: [],
        warnings: []
    };
    const encodedLiterals = new Set();
    const criticalWarnings = [];

    for (const fileName of jsonFiles) {
        console.log(fileName);
        const result = await readJSON(path.join(kDirectoryToAnalyze, fileName));
        projectsStats.fileCount.push(Object.keys(result).length);

        for (const { warnings, deps } of Object.values(result)) {
            deps.filter((name) => kNodeBuiltins.has(name)).forEach((depName) => globalStats.nodeDeps.add(depName));
            const projectWarnings = getDefaultWarning();

            for (const { kind, value } of warnings) {
                globalStats.warnings[kind] = ++globalStats.warnings[kind];
                projectWarnings[kind] = ++projectWarnings[kind];

                if (kind === "encoded-literal") {
                    encodedLiterals.add(value);
                }
                else if (kind === "suspicious-literal" || kind === "obfuscated-code" || kind === "short-identifiers") {
                    if (kind === "suspicious-literal" && value < 10) {
                        continue;
                    }
                    criticalWarnings.push({ kind, value, fileName });
                }
            }

            projectsStats.warnings.push(projectWarnings);
        }
    }

    globalStats.nodeDeps = [...globalStats.nodeDeps];
    const results = {
        globalStats,
        criticalWarnings,
        encodedLiterals: [...encodedLiterals],
        projectsStats
    };
    await fs.writeFile("./result.json", JSON.stringify(results, null, 2));
}
main().catch(console.error);
