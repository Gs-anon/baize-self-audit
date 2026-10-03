// ============================================================================
// baize-self-audit — 白泽静态权限画像审计器（只读）
//
// 用途：对工作区内已安装的第三方 DSH 插件目录做纯静态扫描，输出权限画像报告。
// 红线（白泽构建宪法第四章 + 本插件安全约束）：
//   1. 只读    —— 仅 node:fs 的 readdirSync / readFileSync / statSync，无任何写入；
//   2. 不执行  —— 不加载、不求值、不运行被扫描目录中的任何代码；
//   3. 不联网  —— 无任何网络模块引用，审计完全离线；
//   4. 零依赖  —— 仅 Node.js 内置模块（node:fs / node:path / node:url）；
//   5. 不触系统 —— 不读取环境变量、不改注册表 / 启动项 / 系统配置。
// 自检：加载时扫描自身源码，若出现上述任何被禁止的模块引用，拒绝加载。
// ============================================================================

import { readdirSync, readFileSync, statSync } from "node:fs";
import { basename, extname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const name = "baize-self-audit";
export const inject = ["tools"];

const re = (pattern, flags = "") => new RegExp(pattern, flags);

// ---------- 加载期自检（红线执行器） ----------
// 所有检测规则均以字符串构建并即时编译，字符串与注释会在自检前被剥离，
// 因此规则本身不会触发误报；而任何真实引入的被禁止模块引用都无法逃过检查。

const COMMENT_OR_STRING = re(
  "'(?:[^'\\\\]|\\\\.)*'|\"(?:[^\"\\\\]|\\\\.)*\"|`(?:[^`\\\\]|\\\\.)*`|//[^\\n]*|/\\*[\\s\\S]*?\\*/",
  "g"
);

const FORBIDDEN = [
  ["\\bchild_process\\b", "子进程模块"],
  ["\\bexecSync\\b|\\bexecFileSync\\b|\\bspawnSync\\b", "同步子进程调用"],
  ["\\beval\\b", "动态求值 eval"],
  ["\\bnew\\s+Function\\b", "动态求值 new Function"],
  ["(?:^|[^\\w$.])Function\\s*\\(", "动态求值 Function"],
  ["\\bvm\\b", "动态求值 vm"],
  ["\\bprocess\\.env\\b", "环境变量读取"],
  ["\\bfetch\\b", "网络 fetch"],
  ["\\baxios\\b|\\bWebSocket\\b|\\bundici\\b", "网络库"],
  ["\\bhttp\\b|\\bhttps\\b|\\bnet\\b|\\bdns\\b|\\btls\\b|\\bdgram\\b", "网络模块"],
  ["\\bworker_threads\\b", "工作线程"],
  ["\\bwriteFileSync\\b|\\bwriteFile\\b|\\bappendFileSync\\b|\\bappendFile\\b|\\bcreateWriteStream\\b|\\bunlinkSync\\b|\\bunlink\\b|\\brm\\b|\\brmSync\\b|\\brenameSync\\b|\\brename\\b|\\bmkdirSync\\b|\\bmkdir\\b|\\bchmodSync\\b|\\bchmod\\b|\\btruncateSync\\b|\\btruncate\\b|\\bcopyFileSync\\b|\\bcopyFile\\b|\\bsymlinkSync\\b|\\bsymlink\\b|\\bwriteSync\\b|\\bfs\\.(?:write|append|unlink|rm|rename|mkdir|chmod|truncate|symlink|copyFile|createWriteStream)", "文件写入"]
];

function selfCheck() {
  let source;
  try {
    source = readFileSync(fileURLToPath(import.meta.url), "utf8");
  } catch (error) {
    throw new Error("baize-self-audit 拒绝加载：无法读取自身源码完成安全自检");
  }
  const stripped = source.replace(COMMENT_OR_STRING, "");
  for (const [pattern, label] of FORBIDDEN) {
    if (re(pattern).test(stripped)) {
      throw new Error("baize-self-audit 拒绝加载：自身源码包含被禁止的引用（" + label + "）");
    }
  }
}

selfCheck();

// ---------- 扫描规则 ----------
// 两类匹配面：
//   matchOn: "code" —— 剥离字符串字面量后匹配（识别真实代码行为，避免字符串内容误报）；
//   matchOn: "text" —— 仅剥离注释后匹配（识别导入语句、路径字符串等必须保留字面量的信号）。

const SENSITIVE_PATH = re(
  "\\.credentials|credentials\\.ya?ml|id_(?:rsa|ed25519|ecdsa)|known_hosts|\\.ssh[\\\\/]|\\.env(?:\\.[\\w.-]+)?|api[_-]?key|\\bsecret\\b|\\btoken\\b|\\bpassword\\b|\\bpasswd\\b|private[_-]?key|\\.aws[\\\\/]|\\.gnupg|\\bconfig_backup\\b|\\bAppData\\b|\\bkeychain\\b|\\bwallet\\b|\\bkeystore\\b|\\.kube[\\\\/]|\\bkubeconfig\\b",
  "i"
);
const PATHISH = re("[\\\\/]|~|credentials|\\bsecret\\b|\\btoken\\b|\\bpassword\\b|\\bpasswd\\b|api[_-]?key|id_(?:rsa|ed25519)|\\.env\\b", "i");
const SENSITIVE_VAR = re("api[_-]?key|secret|token|credential|password|passwd|private[_-]?key|\\bauth\\b", "i");
const URL_RE = re("(?:https?|wss?)://[^\\s'\"`<>)\\]}]+", "gi");
const TELEMETRY = re("telemetry|analytics|metrics|sentry|tracking|collect|beacon|stats|instrumentation", "i");
const DYNAMIC_CMD = re(
  "(?:(?:execSync|execFileSync|spawnSync)\\b|(?:^|[^\\w.])(?:exec|execFile|spawn|fork))\\s*\\((?:[^\\n]*?\\$\\{|[^\\n]*\\+[^\\n]*|\\s*[A-Za-z_$][\\w$]*\\s*(?:,|\\)))"
);

const RULES = [
  { matchOn: "code", type: "动态求值", severity: "critical", pattern: re("\\beval\\s*\\(|\\bnew\\s+Function\\s*\\(|(?:^|[^\\w$.])Function\\s*\\(|\\bvm\\.(?:runIn\\w*|compileFunction|Script)\\b") },
  { matchOn: "code", type: "patch 层 !!js", severity: "critical", pattern: re("!!js"), yamlOnly: true },
  { matchOn: "text", type: "开机自启", severity: "critical", pattern: re("auto[-_ ]?launch|auto[-_ ]?start\\b|\\bschtasks\\b|CurrentVersion" + "\\\\" + "Run|HKEY_" + "(?:CURRENT_USER|LOCAL_MACHINE)|Launch" + "Agents|Startup" + "Approved|login ?items?") },
  { matchOn: "code", type: "命令执行", severity: "high", pattern: re("\\bexecSync\\b|\\bexecFileSync\\b|\\bspawnSync\\b|(?:^|[^\\w.])(?:exec|execFile|spawn|fork)\\s*\\(") },
  { matchOn: "text", type: "命令执行", severity: "high", pattern: re("from\\s+['\"](?:node:)?child_process|require\\s*\\(\\s*['\"]child_process") },
  { matchOn: "code", type: "网络访问", severity: "high", pattern: re("\\bfetch\\s*\\(|\\baxios\\b|\\bWebSocket\\b|\\bnet\\.(?:connect|createConnection)|\\bhttp\\.(?:request|get)|\\bhttps\\.(?:request|get)|\\bdns\\.|\\bsocket\\.io\\b|\\bundici\\b|\\bgrpc\\b") },
  { matchOn: "text", type: "网络访问", severity: "high", pattern: re("from\\s+['\"](?:node:)?(?:http|https|net|dns|tls)['\"]") },
  { matchOn: "code", type: "文件写入", severity: "medium", pattern: re("\\bfs\\.(?:write\\w*|appendFile\\w*|append\\b|createWriteStream|unlink\\w*|rm\\w*|rename\\w*|mkdir\\w*|chmod\\w*|truncate\\w*|symlink\\w*|copyFile\\w*|watchFile\\w*|unwatchFile\\w*)|\\bwriteFileSync\\b|\\bwriteFile\\b|\\bappendFileSync\\b|\\bappendFile\\b|\\bcreateWriteStream\\b|\\bunlinkSync\\b|\\brmSync\\b|\\brenameSync\\b|\\bmkdirSync\\b|\\bchmodSync\\b|\\btruncateSync\\b|\\bcopyFileSync\\b|\\bsymlinkSync\\b|\\bwriteSync\\b") },
  { matchOn: "text", type: "文件写入", severity: "medium", pattern: re("from\\s+['\"]node:fs/promises['\"]|require\\s*\\(\\s*['\"]node:fs/promises['\"]") },
  { matchOn: "code", type: "文件读取", severity: "info", pattern: re("\\bfs\\.(?:read\\w*|open\\w*|stat\\w*|lstat\\w*|exists\\w*|access\\w*|createReadStream|readlink\\w*|realpath\\w*|opendir\\w*)|\\b(?:readFileSync|readFile|readdirSync|readdir|createReadStream|statSync|stat|lstatSync|lstat|existsSync|exists|accessSync|access|readlinkSync|realpathSync|openSync|readSync)\\b") },
  { matchOn: "text", type: "文件读取", severity: "info", pattern: re("from\\s+['\"](?:node:)?fs['\"]|require\\s*\\(\\s*['\"]fs['\"]") },
  { matchOn: "text", type: "profile 修改面", severity: "medium", pattern: re("cordis" + "\\" + ".patch" + "\\" + ".yml|dsh" + "\\" + ".profile" + "\\" + ".bundles|cordis" + "\\" + ".yml") },
  { matchOn: "code", type: "环境变量读取", severity: "info", pattern: re("process\\.env(?:\\.\\w+|\\s*\\[)") },
  { matchOn: "text", type: "环境变量读取", severity: "info", pattern: re("process\\.env\\s*\\[") }
];

const SKIP_DIRS = new Set(["node_modules", ".git", ".svn", ".hg", ".cache", ".tmp", ".mnemon", "coverage", "__pycache__"]);
const SCAN_EXTENSIONS = new Set([".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".json", ".yaml", ".yml", ".sh", ".ps1", ".psm1", ".bat", ".cmd", ".py"]);
const INSTALL_SCRIPT_KEYS = ["preinstall", "install", "postinstall", "prepare"];
const MAX_DEPTH = 8;
const MAX_FILES = 2000;
const MAX_LINES_PER_FILE = 20000;
const MAX_ITEMS_PER_BUCKET = 400;
const COMMENT_HASH = re("#[^\\n]*", "g");
const COMMENT_SLASH = re("(?<!:)//[^\\n]*|/\\*[\\s\\S]*?\\*/", "g");
const STRING_ONLY = re("'(?:[^'\\\\]|\\\\.)*'|\"(?:[^\"\\\\]|\\\\.)*\"|`(?:[^`\\\\]|\\\\.)*`", "g");

// ---------- 文件收集 ----------

function collectFiles(dir, out, depth) {
  if (depth > MAX_DEPTH || out.length >= MAX_FILES) return;
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    if (entry.isSymbolicLink()) continue; // 不跟随符号链接
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      collectFiles(path, out, depth + 1);
    } else if (entry.isFile()) {
      if (SCAN_EXTENSIONS.has(extname(entry.name).toLowerCase())) out.push(path);
    }
  }
}

// ---------- 报告组装 ----------

function makeState() {
  const state = {
    buckets: { hardVeto: [], riskItems: [], observations: [] },
    seen: new Set(),
    networkTargets: new Set(),
    sensitivePaths: new Set(),
    truncated: false,
    scanned: 0,
    pluginName: null,
    push(bucket, type, severity, evidence, dedupeKey) {
      if (this.seen.has(dedupeKey)) return;
      this.seen.add(dedupeKey);
      if (this.buckets[bucket].length >= MAX_ITEMS_PER_BUCKET) {
        this.truncated = true;
        return;
      }
      this.buckets[bucket].push({ type, severity, evidence });
    }
  };
  return state;
}

function isSensitiveLine(line, state) {
  if (!PATHISH.test(line)) return false;
  if (!SENSITIVE_PATH.test(line)) return false;
  const match = line.match(SENSITIVE_PATH);
  if (match) state.sensitivePaths.add(match[0]);
  return true;
}

function applyRule(rule, rawLine, codeLine, textLine, relFile, lineNo, state) {
  const line = rawLine.trim();
  switch (rule.type) {
    case "动态求值":
    case "开机自启":
    case "patch 层 !!js":
      state.push("hardVeto", rule.type, rule.severity, relFile + ":" + lineNo + "  " + line.slice(0, 140), relFile + "|" + lineNo + "|" + rule.type);
      return;
    case "命令执行": {
      state.push("riskItems", rule.type, rule.severity, relFile + ":" + lineNo + "  " + line.slice(0, 140), relFile + "|" + lineNo + "|" + rule.type);
      if (DYNAMIC_CMD.test(textLine)) {
        state.push("riskItems", "指令注入面", "medium", relFile + ":" + lineNo + "  " + line.slice(0, 140), relFile + "|" + lineNo + "|指令注入面");
      }
      return;
    }
    case "网络访问": {
      const urls = textLine.match(URL_RE) || [];
      for (const url of urls) state.networkTargets.add(url);
      const telemetry = TELEMETRY.test(textLine) || urls.some((url) => TELEMETRY.test(url));
      state.push("riskItems", telemetry ? "遥测导出" : "网络访问", "high", relFile + ":" + lineNo + "  " + line.slice(0, 140), relFile + "|" + lineNo + "|" + rule.type);
      return;
    }
    case "文件写入": {
      if (isSensitiveLine(textLine, state)) {
        state.push("hardVeto", "凭据落盘", "critical", relFile + ":" + lineNo + "  " + line.slice(0, 140), relFile + "|" + lineNo + "|凭据落盘");
      } else {
        state.push("riskItems", "文件写入", "medium", relFile + ":" + lineNo + "  " + line.slice(0, 140), relFile + "|" + lineNo + "|" + rule.type);
      }
      return;
    }
    case "文件读取": {
      if (isSensitiveLine(textLine, state)) {
        state.push("riskItems", "凭据读取", "high", relFile + ":" + lineNo + "  " + line.slice(0, 140), relFile + "|" + lineNo + "|凭据读取");
      } else {
        state.push("observations", "文件读取", "info", relFile + ":" + lineNo + "  " + line.slice(0, 140), relFile + "|" + lineNo + "|" + rule.type);
      }
      return;
    }
    case "profile 修改面":
      state.push("riskItems", rule.type, rule.severity, relFile + ":" + lineNo + "  " + line.slice(0, 140), relFile + "|" + lineNo + "|" + rule.type);
      return;
    case "环境变量读取": {
      const sensitive = SENSITIVE_VAR.test(textLine);
      state.push(sensitive ? "riskItems" : "observations", sensitive ? "凭据读取" : "环境变量读取", sensitive ? "high" : "info", relFile + ":" + lineNo + "  " + line.slice(0, 140), relFile + "|" + lineNo + "|环境变量读取");
      return;
    }
  }
}

function readPackageManifest(file, rootDir, state) {
  const relFile = relative(rootDir, file);
  try {
    const meta = JSON.parse(readFileSync(file, "utf8"));
    if (meta && typeof meta === "object" && typeof meta.name === "string" && state.pluginName === null) {
      state.pluginName = meta.name;
    }
    const scripts = meta && meta.scripts;
    if (scripts && typeof scripts === "object") {
      for (const key of INSTALL_SCRIPT_KEYS) {
        const command = scripts[key];
        if (typeof command === "string" && command.trim() !== "") {
          state.push("hardVeto", "安装期脚本", "critical", relFile + ": scripts." + key + " = " + command.slice(0, 120), relFile + "|" + key);
        }
      }
    }
  } catch (error) {
    state.push("observations", "manifest 解析失败", "info", relFile + ": " + String((error && error.message) || error).slice(0, 140), relFile + "|parse-error");
  }
}

function scanFile(file, rootDir, state) {
  let text;
  try {
    text = readFileSync(file, "utf8");
  } catch {
    return;
  }
  if (text.indexOf("\u0000") !== -1) return; // 二进制文件跳过
  state.scanned += 1;
  const relFile = relative(rootDir, file);
  const yamlish = /\.ya?ml$/i.test(file);
  const scriptish = /\.(py|sh|ps1|psm1|bat|cmd)$/i.test(file);
  const commentPattern = yamlish || scriptish ? COMMENT_HASH : COMMENT_SLASH;
  const lines = text.split(/\r?\n/);
  const limit = Math.min(lines.length, MAX_LINES_PER_FILE);
  if (lines.length > MAX_LINES_PER_FILE) state.truncated = true;
  for (let index = 0; index < limit; index += 1) {
    const rawLine = lines[index];
    if (rawLine.trim() === "") continue;
    const textLine = rawLine.replace(commentPattern, "");
    if (textLine.trim() === "") continue;
    const codeLine = textLine.replace(STRING_ONLY, "");
    for (const rule of RULES) {
      if (rule.yamlOnly && !yamlish) continue;
      const matchLine = rule.matchOn === "text" ? textLine : codeLine;
      if (!rule.pattern.test(matchLine)) continue;
      applyRule(rule, rawLine, codeLine, textLine, relFile, index + 1, state);
    }
  }
}

// ---------- 审计入口 ----------

export function auditPlugin(inputPath) {
  const report = {
    pluginName: null,
    scanTime: new Date().toISOString(),
    scannedDirectory: null,
    filesScanned: 0,
    findings: { hardVeto: [], riskItems: [], observations: [] },
    summary: { vetoCount: 0, riskCount: 0, observationCount: 0, riskLevel: "none" },
    networkTargets: [],
    sensitivePaths: [],
    truncated: false,
    writesPerformed: false
  };
  try {
    if (typeof inputPath !== "string" || inputPath.trim() === "") {
      throw new Error("audit_plugin 需要插件目录路径参数");
    }
    const dir = resolve(inputPath.trim());
    let targetStat;
    try {
      targetStat = statSync(dir);
    } catch {
      throw new Error("无法访问目录: " + dir);
    }
    if (!targetStat.isDirectory()) throw new Error("目标不是目录: " + dir);

    const state = makeState();
    const files = [];
    collectFiles(dir, files, 0);
    if (files.length >= MAX_FILES) state.truncated = true;

    for (const file of files) {
      if (basename(file) === "package.json") readPackageManifest(file, dir, state);
      scanFile(file, dir, state);
    }

    const byEvidence = (a, b) => (a.evidence < b.evidence ? -1 : a.evidence > b.evidence ? 1 : 0);
    report.pluginName = state.pluginName || basename(dir);
    report.scannedDirectory = dir;
    report.filesScanned = state.scanned;
    report.findings.hardVeto = state.buckets.hardVeto.sort(byEvidence);
    report.findings.riskItems = state.buckets.riskItems.sort(byEvidence);
    report.findings.observations = state.buckets.observations.sort(byEvidence);
    report.summary.vetoCount = report.findings.hardVeto.length;
    report.summary.riskCount = report.findings.riskItems.length;
    report.summary.observationCount = report.findings.observations.length;
    report.summary.riskLevel =
      report.summary.vetoCount > 0 ? "critical" : report.summary.riskCount > 0 ? "high" : report.summary.observationCount > 0 ? "low" : "none";
    report.networkTargets = Array.from(state.networkTargets).sort();
    report.sensitivePaths = Array.from(state.sensitivePaths).sort();
    report.truncated = state.truncated;
    return report;
  } catch (error) {
    return {
      ok: false,
      error: String((error && error.message) || error),
      scanTime: report.scanTime,
      writesPerformed: false
    };
  }
}

// ---------- 工具注册 ----------

const defineTool = (value) => value;
const textContent = (value) => [{ type: "text", text: typeof value === "string" ? value : JSON.stringify(value, null, 2) }];

export function apply(ctx) {
  ctx.tools.register(defineTool({
    name: "audit_plugin",
    description:
      "对指定插件目录做只读静态安全审计，输出权限画像报告：文件访问（含敏感路径标记）、子进程执行、网络访问（含硬编码 URL/域名提取与遥测识别）、环境变量读取（敏感变量名标记）、动态求值、安装期脚本、patch 层 !!js。纯静态扫描：不执行被扫描插件的任何代码，不写文件，不联网，不读环境变量。",
    parameters: {
      type: "object",
      properties: {
        path: { type: "string", description: "被扫描插件的目录路径（绝对路径，或相对工作区路径）" }
      },
      required: ["path"]
    },
    output: {
      schema: { type: "object", additionalProperties: true },
      render: (_args, value) => textContent(value)
    },
    execute: (args) => auditPlugin(args && args.path),
    presentCall: (args) => ({
      card: "generic",
      title: "Audit plugin permission profile",
      kind: "search",
      rawInput: args && args.path
    }),
    presentResult: () => ({
      card: "generic",
      title: "Permission profile report ready"
    })
  }));
}
