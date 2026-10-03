// Test fixture: benign plugin with plain reads only.
import { readFileSync } from "node:fs";
const config = readFileSync("./config.json", "utf8");
console.log(config.length);
