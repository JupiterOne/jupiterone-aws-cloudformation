#!/usr/bin/env npx tsx
/**
 * Regenerate every CloudFormation/Markdown/Terraform file under
 * `cloudformation/` from the upstream JupiterOne ingestion-sources
 * configuration (the public HTTP endpoint that exposes the S3-backed payload).
 *
 * Source (in priority order):
 *   1. `--input <path>` (or `INGESTION_SOURCES_FILE` env var) - local JSON file
 *   2. `--url <url>`    (or `INGESTION_SOURCES_URL`  env var) - HTTPS endpoint
 *
 * Modes:
 *   --check      Validate templates would not change. Exits non-zero on diff.
 *   --apply      Write changes to disk (default).
 */
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { resolve, relative, dirname } from 'node:path';
import { syncTemplates, type FileWrite } from './lib/sync';
import type { RawIngestionSourcesPayload } from './lib/source';

const REPO_ROOT = resolve(__dirname, '..');
const DEFAULT_DEFINITION_ID = '7a669809-6e55-45b9-bf23-aa27613118e9';
const DEFAULT_BASE_URL =
  'https://api.us.jupiterone.io/integrations-public/v1/ingestion-sources/definitions';

interface CliArgs {
  mode: 'apply' | 'check';
  inputPath?: string;
  url?: string;
  baseUrl: string;
  definitionId: string;
}

function parseArgs(argv: string[]): CliArgs {
  const args: CliArgs = {
    mode: 'apply',
    inputPath: process.env.INGESTION_SOURCES_FILE,
    url: process.env.INGESTION_SOURCES_URL,
    baseUrl: process.env.INGESTION_SOURCES_BASE_URL ?? DEFAULT_BASE_URL,
    definitionId:
      process.env.INGESTION_SOURCES_DEFINITION_ID ?? DEFAULT_DEFINITION_ID,
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--check') args.mode = 'check';
    else if (arg === '--apply') args.mode = 'apply';
    else if (arg === '--input') args.inputPath = argv[++i];
    else if (arg === '--url') args.url = argv[++i];
    else if (arg === '--base-url') args.baseUrl = argv[++i];
    else if (arg === '--definition-id') args.definitionId = argv[++i];
    else if (arg === '--help' || arg === '-h') {
      printHelp();
      process.exit(0);
    } else {
      console.error(`Unknown argument: ${arg}`);
      process.exit(2);
    }
  }
  return args;
}

function printHelp(): void {
  console.log(`Usage: tsx scripts/sync-permissions.ts [options]

Options:
  --check                Validate templates would not change; exits 1 on diff
  --apply                Write regenerated files to disk (default)
  --input <path>         Read source JSON from a local file
  --url <url>            Override the full source URL
  --base-url <url>       Override only the base URL (defaults to ${DEFAULT_BASE_URL})
  --definition-id <id>   Override the integration definition id (default: ${DEFAULT_DEFINITION_ID})

Environment overrides:
  INGESTION_SOURCES_FILE, INGESTION_SOURCES_URL,
  INGESTION_SOURCES_BASE_URL, INGESTION_SOURCES_DEFINITION_ID
`);
}

function resolveUrl(args: CliArgs): string {
  if (args.url) return args.url;
  return `${args.baseUrl.replace(/\/$/, '')}/${args.definitionId}`;
}

async function loadSource(args: CliArgs): Promise<RawIngestionSourcesPayload> {
  if (args.inputPath) {
    const raw = await readFile(args.inputPath, 'utf8');
    return JSON.parse(raw) as RawIngestionSourcesPayload;
  }
  const url = resolveUrl(args);
  console.log(`Fetching ${url}...`);
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`Fetch ${url} failed: ${res.status} ${res.statusText}`);
  }
  return (await res.json()) as RawIngestionSourcesPayload;
}

async function applyWrites(writes: FileWrite[]): Promise<number> {
  let changed = 0;
  for (const write of writes) {
    const existing = existsSync(write.path)
      ? await readFile(write.path, 'utf8')
      : null;
    if (existing === write.content) continue;
    await mkdir(dirname(write.path), { recursive: true });
    await writeFile(write.path, write.content, 'utf8');
    changed++;
    console.log(`updated ${relative(REPO_ROOT, write.path)}`);
  }
  return changed;
}

async function checkWrites(writes: FileWrite[]): Promise<number> {
  let drift = 0;
  for (const write of writes) {
    const existing = existsSync(write.path)
      ? await readFile(write.path, 'utf8')
      : null;
    if (existing === write.content) continue;
    drift++;
    console.error(`drift: ${relative(REPO_ROOT, write.path)}`);
  }
  return drift;
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const payload = await loadSource(args);
  const writes = await syncTemplates(payload, { repoRoot: REPO_ROOT });

  if (args.mode === 'check') {
    const drift = await checkWrites(writes);
    if (drift > 0) {
      console.error(
        `\n${drift} file(s) would change. Run \`pnpm sync:permissions\` and commit.`,
      );
      process.exit(1);
    }
    console.log(`All ${writes.length} files match the source.`);
    return;
  }

  const changed = await applyWrites(writes);
  if (changed === 0) {
    console.log(`No changes (${writes.length} files already up to date).`);
  } else {
    console.log(`\nWrote ${changed} file(s).`);
  }
}

main().catch((err: unknown) => {
  console.error(err);
  process.exit(1);
});
