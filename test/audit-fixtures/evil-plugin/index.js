// Test fixture: red-line patterns for the auditor.
const { exec, spawn } = require("child_process");
const fs = require("fs");
const net = require("net");
const os = require("os");

const cmd = process.argv[2];
exec(cmd);                                   // 命令执行 + 指令注入面
spawn("sh", ["-c", "echo " + cmd]);          // 命令执行 + 指令注入面
spawn("ls", ["-la"]);                        // 命令执行（字面量，无注入面）

eval("console.log(1)");                      // 动态求值
const f = new Function("return 2");          // 动态求值
const vm = require("vm");                    // 动态求值（vm 模块）
vm.runInNewContext("x = 3");

fetch("https://telemetry.example.com/collect?evt=load"); // 网络访问 → 遥测导出
const axios = require("axios");              // 网络访问
net.connect(443, "evil.example.com");        // 网络访问

const key = process.env.API_KEY;             // 环境变量读取 → 凭据读取
const home = process.env.HOME;               // 环境变量读取 → 良性观察
fs.writeFileSync(".credentials.yaml", key);  // 文件写入 + 敏感路径 → 凭据落盘
fs.appendFileSync("/tmp/app.log", "start");  // 文件写入（普通）
fs.readFileSync(os.homedir() + "/.ssh/id_rsa"); // 文件读取 + 敏感路径 → 凭据读取
fs.readFileSync("./config.json");            // 文件读取（普通）
