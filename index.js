/* eslint-disable max-depth */
// Require Node.js Files
import fs from "fs/promises";
import path from "path";

// Require Third-party Dependencies
import builtins from "builtins";
import FrequencySet from "frequency-set";
import { klona } from "klona/json";

// CONSTANTS
const kDirectoryToAnalyze = "F:\\Code\\fraxken\\npm-security-fetcher\\results\\packages";
const kNodeBuiltins = new Set(builtins());
const kDefaultWarningsKeys = new Set(Object.keys(getDefaultWarning()));
const kTrackedWarningsKind = new Set(["suspicious-literal", "obfuscated-code", "short-identifiers"]);
const kTrackedNodeLibs = new Set(["async_hooks"]);

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

function setToJSON(uSet) {
    return Object.fromEntries(uSet.toJSON().sort((left, right) => right[1] - left[1]));
}

function generateWarning(pkgFileName, fileName, kind, value) {
    const pkgFullName = path.basename(pkgFileName, ".json").replace("__", "/");

    const warning = { kind, url: `https://unpkg.com/browse/${pkgFullName}/${fileName.replace(/#/g, "/")}` };
    if (value) {
        warning.value = value;
    }

    return warning;
}

async function main() {
    const files = await fs.readdir(kDirectoryToAnalyze, { withFileTypes: true });
    const jsonFiles = files
        .filter((dirent) => dirent.isFile() && path.extname(dirent.name, ".json"))
        .map((dirent) => dirent.name);

    const globalStats = {
        nodeDeps: new FrequencySet(),
        unsafeStmt: new FrequencySet(),
        unsafeAssign: new FrequencySet(),
        warnings: getDefaultWarning()
    };
    const projectsStats = {
        fileCount: [],
        warnings: []
    };
    const encodedLiterals = new FrequencySet();
    const trackedNodeLibs = [];
    const criticalWarnings = [];

    for (const pkgFileName of jsonFiles) {
        console.log(pkgFileName);
        const result = await readJSON(path.join(kDirectoryToAnalyze, pkgFileName));
        projectsStats.fileCount.push(Object.keys(result).length);

        for (const [fileName, { warnings, deps }] of Object.entries(result)) {
            for (const name of deps) {
                if (kNodeBuiltins.has(name)) {
                    globalStats.nodeDeps.add(name);
                    if (kTrackedNodeLibs.has(name)) {
                        trackedNodeLibs.push(generateWarning(pkgFileName, fileName, name));
                    }
                }
            }
            const projectWarnings = getDefaultWarning();

            for (const { kind, value } of warnings) {
                globalStats.warnings[kind] = ++globalStats.warnings[kind];
                projectWarnings[kind] = ++projectWarnings[kind];

                if (kind === "encoded-literal") {
                    encodedLiterals.add(value);
                }
                else if (kind === "unsafe-stmt") {
                    globalStats.unsafeStmt.add(value);
                }
                else if (kind === "unsafe-assign") {
                    globalStats.unsafeAssign.add(value);
                }

                if (kTrackedWarningsKind.has(kind)) {
                    criticalWarnings.push(generateWarning(pkgFileName, fileName, kind, value));
                }
            }

            projectsStats.warnings.push(projectWarnings);
        }
    }

    await fs.mkdir("./results", { recursive: true });

    globalStats.nodeDeps = setToJSON(globalStats.nodeDeps);
    globalStats.unsafeAssign = setToJSON(globalStats.unsafeAssign);
    globalStats.unsafeStmt = setToJSON(globalStats.unsafeStmt);
    await fs.writeFile("./results/global-stats.json", JSON.stringify(globalStats, null, 2));
    await fs.writeFile("./results/encoded-literals.json", JSON.stringify(setToJSON(encodedLiterals), null, 2));
    await fs.writeFile("./results/warnings.json", JSON.stringify(criticalWarnings, null, 2));
    await fs.writeFile("./results/nodejs-libs.json", JSON.stringify(trackedNodeLibs, null, 2));

    const averageFileByProject = projectsStats.fileCount.reduce((curr, prev) => curr + prev, 0) / projectsStats.fileCount.length;
    const averageWarningsByProject = projectsStats.warnings.reduce((curr, prev) => {
        for (const key of kDefaultWarningsKeys) {
            curr[key] += prev[key];
        }

        return curr;
    }, getDefaultWarning());
    for (const key of kDefaultWarningsKeys) {
        averageWarningsByProject[key] = (averageWarningsByProject[key] / projectsStats.warnings.length).toFixed(5);
    }

    const statsByProjects = {
        averageFileByProject,
        averageWarningsByProject
    };
    await fs.writeFile("./results/stats-by-projects.json", JSON.stringify(statsByProjects, null, 2));
}
main().catch(console.error);
