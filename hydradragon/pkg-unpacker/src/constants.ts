import { platform } from "node:process";

export const C_DISK = "C:";
export const IS_WIN32 = platform === "win32";
// 5.2.0 separator
export const OLD_SEPARATOR = "$";
export const SEPARATOR = "/";

export const RAW_PROPS_REGEX = new RegExp(
    /\{.*}\n,\n".*"\n,\n\{.*}(?:\n,\n\{.*}\n,\n([012]))?/g,
);
