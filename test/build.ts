import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const here = (path: string) => fileURLToPath(new URL(path, import.meta.url));

export default function setup(): void {
  execFileSync(process.execPath, [here("../node_modules/typescript/bin/tsc"), "-p", here("../tsconfig.json")], { stdio: "pipe" });
}
