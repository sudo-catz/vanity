import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { encodeDeployData } from "viem";
import type { Abi, AbiParameter } from "viem";

type CliArgs = Map<string, string>;

const args = parseArgs(process.argv.slice(2));

if (args.has("help") || args.has("h")) {
  printUsage();
  process.exit(0);
}

const saltInput = mustGet(args, "salt", "32-byte salt");
const constructorArgsRaw = args.get("constructor-args");
const parsedConstructorArgs = constructorArgsRaw ? parseConstructorArgs(constructorArgsRaw) : undefined;
const { bytecode, abi } = getBytecodeAndAbi(args, Boolean(parsedConstructorArgs));
const bytecodeWithArgs = parsedConstructorArgs
  ? appendConstructorArgs(bytecode, abi, parsedConstructorArgs)
  : bytecode;
const salt = normalizeSalt(saltInput);
const calldata = `0x${salt.slice(2)}${bytecodeWithArgs.slice(2)}`;
const outFile = args.get("out");

console.log("Salt (32 bytes):", salt);
console.log("Bytecode length :", (bytecodeWithArgs.length - 2) / 2, "bytes");
console.log("Calldata        :", calldata);

if (outFile) {
  const outputPath = path.resolve(process.cwd(), outFile);
  writeFileSync(outputPath, `${calldata}\n`);
  console.log("Calldata file   :", outputPath);
}

console.log("");
console.log("Example cast call:");
console.log(
  `cast send 0x4e59b44847b379578588920cA78FbF26c0B4956C --value 0 --data ${calldata} --rpc-url <rpc>`
);

function getBytecodeAndAbi(cliArgs: CliArgs, requireAbi: boolean): {
  bytecode: `0x${string}`;
  abi?: Abi;
} {
  const bytecodeHex = cliArgs.get("bytecode");
  if (bytecodeHex && !requireAbi) {
    return { bytecode: normalizeBytecode(bytecodeHex) };
  }

  const artifactPath =
    cliArgs.get("artifact") ??
    "artifacts/contracts/Create2Factory.sol/Create2Factory.json";
  const artifactFullPath = path.resolve(process.cwd(), artifactPath);
  const artifact = JSON.parse(readFileSync(artifactFullPath, "utf8"));
  const code: string | undefined = bytecodeHex ?? artifact.bytecode;
  const abi: Abi | undefined = artifact.abi;

  if (!code || code === "0x") {
    throw new Error(`Artifact at ${artifactFullPath} does not contain creation bytecode`);
  }

  if (requireAbi && !abi) {
    throw new Error(`Artifact at ${artifactFullPath} is missing ABI for constructor encoding`);
  }

  return { bytecode: normalizeBytecode(code), abi };
}

function normalizeSalt(value: string): `0x${string}` {
  const hex = strip0x(value);
  if (hex.length > 64) {
    throw new Error("Salt longer than 32 bytes");
  }
  return `0x${hex.padStart(64, "0")}`;
}

function normalizeBytecode(value: string): `0x${string}` {
  const hex = strip0x(value);
  if (hex.length === 0 || hex.length % 2 !== 0) {
    throw new Error("Bytecode must be non-empty full bytes");
  }
  return `0x${hex}`;
}

function parseConstructorArgs(raw: string): unknown[] {
  const trimmed = raw.trim();
  if (!trimmed) {
    return [];
  }
  if ((trimmed.startsWith("[") && trimmed.endsWith("]")) || trimmed.startsWith("{")) {
    const parsed = JSON.parse(trimmed);
    if (!Array.isArray(parsed)) {
      throw new Error("--constructor-args JSON must be an array");
    }
    return parsed;
  }
  return trimmed.split(",").map((part) => part.trim()).filter((part) => part.length > 0);
}

function appendConstructorArgs(
  bytecode: `0x${string}`,
  abi: Abi | undefined,
  rawArgs: unknown[]
): `0x${string}` {
  if (!abi) {
    throw new Error("ABI is required to encode constructor arguments");
  }
  const constructor = abi.find((item) => item.type === "constructor");
  const inputs = constructor?.inputs ?? [];
  if (inputs.length !== rawArgs.length) {
    throw new Error(
      `Constructor expects ${inputs.length} argument(s) but ${rawArgs.length} provided`
    );
  }
  const coercedArgs = inputs.map((input, index) =>
    coerceArg(rawArgs[index], input)
  );
  const encoded = encodeDeployData({
    abi,
    bytecode,
    args: coercedArgs as any[],
  });
  return encoded;
}

function coerceArg(value: unknown, param: AbiParameter): unknown {
  const type = param.type;

  if (type.endsWith("]")) {
    const arrayValue = ensureArray(value);
    const innerType = type.slice(0, type.lastIndexOf("["));
    return arrayValue.map((item) =>
      coerceArg(item, { ...param, type: innerType })
    );
  }

  if (type === "tuple") {
    if (!param.components) {
      throw new Error("Tuple parameter missing components");
    }
    const tupleValue = ensureArray(value);
    if (tupleValue.length !== param.components.length) {
      throw new Error("Tuple argument length mismatch");
    }
    return param.components.map((component, idx) =>
      coerceArg(tupleValue[idx], component)
    );
  }

  if (type.startsWith("uint") || type.startsWith("int")) {
    return coerceBigInt(value);
  }

  if (type === "bool") {
    if (typeof value === "boolean") {
      return value;
    }
    if (typeof value === "string") {
      const normalized = value.trim().toLowerCase();
      if (["true", "1"].includes(normalized)) return true;
      if (["false", "0"].includes(normalized)) return false;
    }
    throw new Error(`Cannot parse boolean argument: ${value}`);
  }

  if (type === "string") {
    if (typeof value === "string") {
      return value;
    }
    return JSON.stringify(value);
  }

  if (type === "address") {
    if (typeof value !== "string") {
      throw new Error("Address arguments must be strings");
    }
    return value;
  }

  if (type === "bytes") {
    if (typeof value !== "string") {
      throw new Error("Bytes arguments must be hex strings");
    }
    return value;
  }

  if (type.startsWith("bytes")) {
    if (typeof value !== "string") {
      throw new Error("Fixed-bytes arguments must be hex strings");
    }
    return value;
  }

  throw new Error(`Unsupported constructor parameter type: ${type}`);
}

function ensureArray(value: unknown): unknown[] {
  if (Array.isArray(value)) {
    return value;
  }
  if (typeof value === "string") {
    const parsed = JSON.parse(value);
    if (Array.isArray(parsed)) {
      return parsed;
    }
  }
  throw new Error("Expected array-like constructor argument");
}

function coerceBigInt(value: unknown): bigint {
  if (typeof value === "bigint") {
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isInteger(value)) {
      throw new Error("Integer arguments must be whole numbers");
    }
    return BigInt(value);
  }
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (!trimmed.length) {
      throw new Error("Empty integer argument");
    }
    return BigInt(trimmed);
  }
  throw new Error(`Cannot parse integer argument: ${value}`);
}

function strip0x(value: string): string {
  return value.startsWith("0x") ? value.slice(2) : value;
}

function parseArgs(argv: string[]): CliArgs {
  const result: CliArgs = new Map();
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith("--")) {
      continue;
    }
    const key = arg.slice(2);
    const next = argv[i + 1];
    if (next && !next.startsWith("--")) {
      result.set(key, next);
      i++;
    } else {
      result.set(key, "true");
    }
  }
  return result;
}

function mustGet(args: CliArgs, key: string, label: string): string {
  const value = args.get(key);
  if (!value) {
    throw new Error(`Missing --${key} (${label})`);
  }
  return value;
}

function printUsage() {
  console.log(`Usage: tsx scripts/build-create2-calldata.ts --salt <hex> [options]

Options:
  --artifact <path>   Hardhat artifact JSON (default Create2Factory)
  --bytecode <hex>    Provide the creation bytecode directly
  --constructor-args  JSON array or comma-separated constructor args
  --out <path>        Write calldata to a file
  --salt <hex>        32-byte salt (0x-prefixed or not)
  --help              Show this message
`);
}
