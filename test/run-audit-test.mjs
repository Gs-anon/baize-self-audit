// Local test runner for baize-self-audit.
// Runs the same module that will be loaded by the plugin host, including the
// load-time self-check, then audits the two fixtures and (optionally) a real
// installed plugin directory. Read-only: nothing is written anywhere.
//
// Optional real-target scan: set DSH_MNEMON_DIR (or AUDIT_TARGET_DIR) to an
// installed plugin directory to audit it as section 4; otherwise it is skipped.

import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { auditPlugin } from "../index.js";

const here = dirname(fileURLToPath(import.meta.url));
let failures = 0;

function check(label, condition, detail) {
  if (condition) {
    console.log("PASS  " + label);
  } else {
    failures += 1;
    console.log("FAIL  " + label + (detail ? "  => " + detail : ""));
  }
}

const types = (report, bucket) => (report.findings[bucket] || []).map((item) => item.type);

console.log("== 1. evil-plugin fixture ==");
const evil = auditPlugin(join(here, "audit-fixtures", "evil-plugin"));
console.log(JSON.stringify({ summary: evil.summary, writesPerformed: evil.writesPerformed, networkTargets: evil.networkTargets, sensitivePaths: evil.sensitivePaths }, null, 2));
check("riskLevel = critical", evil.summary.riskLevel === "critical", evil.summary.riskLevel);
check("writesPerformed = false", evil.writesPerformed === false);
check("hardVeto: 动态求值", types(evil, "hardVeto").includes("动态求值"));
check("hardVeto: 安装期脚本", types(evil, "hardVeto").includes("安装期脚本"));
check("hardVeto: patch 层 !!js", types(evil, "hardVeto").includes("patch 层 !!js"));
check("hardVeto: 凭据落盘", types(evil, "hardVeto").includes("凭据落盘"));
check("riskItems: 命令执行", types(evil, "riskItems").includes("命令执行"));
check("riskItems: 指令注入面", types(evil, "riskItems").includes("指令注入面"));
check("riskItems: 遥测导出", types(evil, "riskItems").includes("遥测导出"));
check("riskItems: 网络访问", types(evil, "riskItems").includes("网络访问"));
check("riskItems: 凭据读取", types(evil, "riskItems").includes("凭据读取"));
check("riskItems: 文件写入", types(evil, "riskItems").includes("文件写入"));
check("observations: 文件读取", types(evil, "observations").includes("文件读取"));
check("observations: 环境变量读取", types(evil, "observations").includes("环境变量读取"));
check("网络目标已提取", evil.networkTargets.some((u) => u.startsWith("https://telemetry.example.com")));

console.log("\n== 2. good-plugin fixture ==");
const good = auditPlugin(join(here, "audit-fixtures", "good-plugin"));
console.log(JSON.stringify({ summary: good.summary, findings: good.findings }, null, 2));
check("riskLevel = low", good.summary.riskLevel === "low", good.summary.riskLevel);
check("vetoCount = 0", good.summary.vetoCount === 0);
check("riskCount = 0", good.summary.riskCount === 0);
check("observations contain 文件读取", types(good, "observations").includes("文件读取"));
check("writesPerformed = false", good.writesPerformed === false);

console.log("\n== 3. self-audit of the auditor itself ==");
const self = auditPlugin(join(here, ".."));
const fixtureVeto = self.findings.hardVeto.filter((item) => /^test[\\/]/.test(item.evidence));
const ownVeto = self.findings.hardVeto.filter((item) => !/^test[\\/]/.test(item.evidence));
console.log(JSON.stringify({ summary: self.summary, fixtureVetoCount: fixtureVeto.length, ownVeto: ownVeto, riskTypes: [...new Set(types(self, "riskItems"))] }, null, 2));
// 说明：仓库根目录级自审会把 test/ 下的恶意夹具也计入（6 条硬否决，属预期）；
// 断言只看插件自身源码（test/ 之外）：应为零硬否决。真正的红线防线是加载期
// 自检 selfCheck()（本模块 import 时已执行且通过）。
check("self-audit: no hardVeto outside test fixtures", ownVeto.length === 0, JSON.stringify(ownVeto.map((item) => item.evidence)));
check("self-audit writesPerformed = false", self.writesPerformed === false);

console.log("\n== 4. real target (optional, via DSH_MNEMON_DIR / AUDIT_TARGET_DIR) ==");
const realTarget = process.env.DSH_MNEMON_DIR || process.env.AUDIT_TARGET_DIR;
if (realTarget && existsSync(realTarget)) {
  const mnemon = auditPlugin(realTarget);
  console.log(JSON.stringify({ pluginName: mnemon.pluginName, scannedDirectory: mnemon.scannedDirectory, filesScanned: mnemon.filesScanned, summary: mnemon.summary, writesPerformed: mnemon.writesPerformed, truncated: mnemon.truncated, networkTargets: mnemon.networkTargets.slice(0, 10), sensitivePaths: mnemon.sensitivePaths.slice(0, 10) }, null, 2));
  console.log("hardVeto types:", JSON.stringify(types(mnemon, "hardVeto")));
  console.log("riskItem types:", JSON.stringify([...new Set(types(mnemon, "riskItems"))]));
  check("filesScanned > 0", mnemon.filesScanned > 0, String(mnemon.filesScanned));
  check("writesPerformed = false", mnemon.writesPerformed === false);
} else {
  console.log("SKIP  (set DSH_MNEMON_DIR or AUDIT_TARGET_DIR to an installed plugin directory to enable)");
}

console.log("\n== 5. error path ==");
const missing = auditPlugin(join(here, "does-not-exist"));
check("missing dir returns ok:false", missing && missing.ok === false, JSON.stringify(missing));

console.log("\n" + (failures === 0 ? "ALL CHECKS PASSED" : failures + " CHECK(S) FAILED"));
process.exitCode = failures === 0 ? 0 : 1;
