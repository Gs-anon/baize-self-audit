# 白泽能力变更记录（CHANGELOG_BAIZE）

> 依据：《白泽构建宪法》第二章 2.2 —— 任何新能力上线后必须立即完成「记录 / 审计 / 验证」。
> 记录内容：新增了什么、为什么、边界是什么。
> 本文件只记录**能力与边界**的变更；宪法本身的修订记入 `CHANGELOG_CONSTITUTION.md`；安全审计过程记入 `AUDIT_LOG.md`。

## 记录格式

每条变更必须包含以下字段，缺字段即为记录不完整：

| 字段 | 含义 |
|:---|:---|
| 日期 | 变更完成日期（Asia/Shanghai） |
| 类型 | 新增 / 修改 / 移除 / 修复 |
| 对象 | 插件、工具、脚本、配置、权限或行为 |
| 为什么 | 解决的真实问题；对应宪法 2.1 四问的结论 |
| 边界 | 新触碰的权限（对照宪法 4.1 的 L0–L5），及为其定义的最小必要权限 |
| 可逆性 | 回滚方式与代价 |
| 审计 | 对应 `AUDIT_LOG.md` 的条目编号 |
| 验证 | 最小可复现的验证用例与结果 |

---

## 2026-10-03

### C-001 ｜ 类型：新增 ｜ 建立工作区治理基座

- **对象**：`BAIZE_CONSTITUTION.md`（副本）、`CHANGELOG_BAIZE.md`、`CHANGELOG_CONSTITUTION.md`、`AUDIT_LOG.md`
- **为什么**：宪法附录 A 要求这四个文件位于工作区根目录，但工作区 `G:\deepseek\workspace\build_deepseek` 此前完全为空，治理链条缺少载体；宪法存放在工作区外的 `G:\deepseek\config_backup\`，与附录 A 的路径约定不符。
- **边界**：L1（工作区写入）。仅在工作区内创建文件，未触碰工作区外内容，未新增网络或系统命令能力。**最小必要权限：工作区写入，无额外申请。**
- **可逆性**：完全可逆，代价极低 —— 直接删除文件即可，无外部副作用。
- **审计**：A-001
- **验证**：副本与源的 SHA256 一致（`179A42A3…E8F7`），文件数 4，内容可读。
- **备注**：源文件 `G:\deepseek\config_backup\BAIZE_CONSTITUTION.md` 未被修改（仅被读取后复制）。

### C-002 ｜ 类型：新增 ｜ baize-self-audit 静态审计插件

- **对象**：插件 `baize-self-audit`（提供工具 `audit_plugin`），位于 `baize-self-audit/`（package.json + cordis.patch.yml + index.js + README.md）
- **为什么**（宪法 2.1 四问）：①必要性——宪法 5.1.1 要求非安全市场插件「先审计、后安装」，这是反复出现的真实需求；②替代性——现成 `dsh-plugin-guard` 不在本环境中，且本工具同时用于审计已安装插件，80% 效果无法由现有工具组合达成；③边界性——见下；④可逆性——插件管理器停用/移除即可，不写任何状态。
- **新增能力**：只读扫描任意插件目录，输出权限画像报告（文件访问+敏感路径标记、子进程执行、网络访问+硬编码 URL/域名提取+遥测识别、环境变量读取+敏感变量名标记、动态求值、安装期脚本、patch 层 `!!js`；分级 hardVeto / riskItems / observations）。
- **新增权限**：仅文件读取（L0）。**最小必要权限：readdirSync / readFileSync / statSync，无写入、无执行、无网络、无环境变量读取。**
- **边界**：不执行被扫描代码（纯静态正则匹配）；不写文件（报告 `writesPerformed` 恒为 false）；不联网（零网络模块）；不读 `process.env`；不改注册表/启动项/系统配置；零第三方依赖（仅 node:fs / node:path / node:url）。**加载期自检**：插件加载时扫描自身源码，出现任何被禁止的模块引用即拒绝加载。
- **可逆性**：完全可逆 —— 插件管理器中停用或移除 `baize-self-audit` 即可；不写状态、无残留文件。
- **审计**：A-002（通过；无高危项）
- **验证**：①本地夹具测试全通过（恶意夹具 6 项硬否决全命中、良性夹具零误报、自审无硬否决、错误路径返回结构化错误）；②激活后调用真实工具扫描 `C:\Users\Lenovo\.dsh\profiles\desktop\node_modules\dsh-mnemon`：54 个文件、`writesPerformed: false`、两条真实 hardVeto（`cordis.patch.yml:13` 的 `!!js` 与 `lib\testing.js:223` 的 `new Function`）已附证据供你复核。
- **备注**：①`defineTool` 为本地恒等辅助函数（与 dsh-mnemon 的 `definition()` 同义），因零依赖约束不引入任何辅助包；②dsh-mnemon 实际安装目录在 `C:\Users\Lenovo\.dsh\profiles\desktop\node_modules\`（工作区内并不存在）；③实测发现正则 `.exec(` 被误报为命令执行，已在磁盘源码修复（本地复验通过），运行中实例因 ESM 缓存需下次重启后生效；④已开源：`github.com/Gs-anon/baize-self-audit`（公开仓库，MIT，提交 `106ad87`，已通过 GitHub API 验证远端 12 个文件与本地一致）。

---

## 待办 / 观察中

> 宪法 2.1 第一问要求：对"想象中的、一次性的"需求暂缓，先观察是否真的需要。
> 以下条目为观察项，**尚未执行**，需人确认后才立项。

- 无。
