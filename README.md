# baize-self-audit

白泽静态权限画像审计器 —— 只读扫描已安装的第三方 DSH 插件，输出权限画像报告。

## 用途

- 依据：《白泽构建宪法》第四章（权限与安全）、第五章 5.1（插件安装纪律：非安全市场插件须先审计）。
- 提供工具 `audit_plugin`，参数 `path` 为被扫描插件目录，返回结构化 JSON 权限画像。

## 权限与边界（最小必要权限）

| 边界 | 承诺 |
|:---|:---|
| 文件 | 仅读取（`readdirSync` / `readFileSync` / `statSync`），**零写入**，报告中 `writesPerformed` 恒为 `false` |
| 执行 | **不加载、不求值、不运行**被扫描目录中的任何代码；扫描是纯静态的 |
| 网络 | 无任何网络模块，完全离线 |
| 环境变量 | 不读取 `process.env` |
| 系统配置 | 不改注册表、启动项或任何系统配置 |
| 依赖 | 零第三方依赖，仅 Node.js 内置模块 `node:fs` / `node:path` / `node:url` |

**加载期自检**：插件加载时会扫描自身源码，若出现 `child_process`、`eval`、`new Function`、`vm`、`fetch`/`axios`/`net`/`http`、`process.env`、文件写入 API 等任何被禁止的引用，立即抛错拒绝加载。

## 报告结构

```json
{
  "pluginName": "被扫描插件名",
  "scanTime": "ISO 时间戳",
  "scannedDirectory": "扫描目录",
  "filesScanned": 12,
  "findings": {
    "hardVeto":    [{ "type": "动态求值 / 安装期脚本 / 开机自启 / 凭据落盘 / patch 层 !!js", "severity": "critical", "evidence": "文件:行号 代码片段" }],
    "riskItems":   [{ "type": "命令执行 / 指令注入面 / 网络访问 / 遥测导出 / 凭据读取 / 文件写入 / profile 修改面", "severity": "high | medium", "evidence": "..." }],
    "observations":[{ "type": "文件读取 / 环境变量读取 / 文件访问", "severity": "info", "evidence": "..." }]
  },
  "summary": { "vetoCount": 0, "riskCount": 0, "observationCount": 0, "riskLevel": "none | low | high | critical" },
  "networkTargets": [],
  "sensitivePaths": [],
  "truncated": false,
  "writesPerformed": false
}
```

风险分级：`hardVeto`（硬否决，出现即 critical）＞ `riskItems`（待确认能力，人工复核）＞ `observations`（仅供参考）。

## 使用

1. 安装后由 profile 的 patch 层挂载（`cordis.patch.yml` 中一条 `insert`，无 `!!js`）。
2. 调用工具：`audit_plugin`，`path` 填插件目录，例如 `C:\Users\<user>\.dsh\profiles\desktop\node_modules\dsh-mnemon`。
3. 审查返回的 JSON 报告，核对 `summary.riskLevel` 与各条 `evidence`。

## 测试

```bash
node test/run-audit-test.mjs
```

只读测试，不写任何文件：恶意夹具（应命中全部硬否决与风险项）、良性夹具（应零误报）、自审（应无硬否决）、错误路径。可选真实目标扫描：设置 `DSH_MNEMON_DIR` 或 `AUDIT_TARGET_DIR` 指向一个已安装插件目录。

## 回滚

在插件管理器中停用或移除 `baize-self-audit` 即可；它不写入任何状态，卸载无残留。
