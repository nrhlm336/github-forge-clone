// A GitHub-compatible git forge in one file: git smart HTTP (upload-pack protocol v2 + v0,
// receive-pack v0), the REST v3 surface, the GraphQL v4 subset gh and github-mcp-server speak,
// and an MCP endpoint (streamable HTTP, revision 2026-07-28 with a legacy initialize handshake).
//
// Everything lives in memory: one content-addressed git object store shared by every surface, so
// a commit made through the contents API is the same object a clone fetches, and an issue made
// over MCP is the same object REST reads. All server-made commits use a deterministic logical
// clock and the token owner's identity, so replaying the same request sequence reproduces the
// same object ids byte for byte. Node standard library only.

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { createHash } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';

// -------------------------------------------------------------------------------------------------
// small helpers
// -------------------------------------------------------------------------------------------------

const JSON_TYPE = 'application/json; charset=utf-8';
const ZERO_OID = '0'.repeat(40);
const PKT_MAX_PAYLOAD = 65520 - 4;

let requestSeq = 0;

function sha1Hex(data: Buffer): string {
  return createHash('sha1').update(data).digest('hex');
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function sendJson(res: ServerResponse, status: number, body: unknown, headers: Readonly<Record<string, string>> = {}): void {
  const text = `${JSON.stringify(body)}\n`;
  res.writeHead(status, {
    'content-type': JSON_TYPE,
    'content-length': Buffer.byteLength(text),
    'x-github-request-id': `FORGE-${(++requestSeq).toString(16).toUpperCase().padStart(6, '0')}`,
    ...headers,
  });
  res.end(text);
}

function sendRaw(res: ServerResponse, status: number, body: Buffer, contentType: string): void {
  res.writeHead(status, {
    'content-type': contentType,
    'content-length': body.length,
    'x-github-request-id': `FORGE-${(++requestSeq).toString(16).toUpperCase().padStart(6, '0')}`,
    'cache-control': 'no-cache',
  });
  res.end(body);
}

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

/** Parse a JSON request body; `undefined` when the body is empty, `INVALID_JSON` when malformed. */
const INVALID_JSON = Symbol('invalid-json');
function parseJsonBody(raw: Buffer): unknown {
  const text = raw.toString('utf8').trim();
  if (text === '') return undefined;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return INVALID_JSON;
  }
}

// -------------------------------------------------------------------------------------------------
// git object model
// -------------------------------------------------------------------------------------------------

type GitObjectType = 'commit' | 'tree' | 'blob' | 'tag';

interface GitObject {
  type: GitObjectType;
  data: Buffer;
}

const TYPE_CODE: Readonly<Record<GitObjectType, number>> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const CODE_TYPE: Readonly<Record<number, GitObjectType>> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

/** The one object store: oid -> object, shared by every repository and every surface. */
const objectStore = new Map<string, GitObject>();

function hashObject(type: GitObjectType, data: Buffer): string {
  const hash = createHash('sha1');
  hash.update(Buffer.from(`${type} ${data.length}\0`, 'utf8'));
  hash.update(data);
  return hash.digest('hex');
}

function storeObject(type: GitObjectType, data: Buffer): string {
  const oid = hashObject(type, data);
  if (!objectStore.has(oid)) objectStore.set(oid, { type, data });
  return oid;
}

function getObject(oid: string): GitObject | undefined {
  return objectStore.get(oid);
}

interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}

function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let offset = 0;
  while (offset < data.length) {
    const space = data.indexOf(0x20, offset);
    if (space < 0) break;
    const nul = data.indexOf(0x00, space + 1);
    if (nul < 0 || nul + 21 > data.length) break;
    entries.push({
      mode: data.subarray(offset, space).toString('ascii'),
      name: data.subarray(space + 1, nul).toString('utf8'),
      oid: data.subarray(nul + 1, nul + 21).toString('hex'),
    });
    offset = nul + 21;
  }
  return entries;
}

function compareTreeNames(a: TreeEntry, b: TreeEntry): number {
  const left = Buffer.from(a.mode === '40000' ? `${a.name}/` : a.name, 'utf8');
  const right = Buffer.from(b.mode === '40000' ? `${b.name}/` : b.name, 'utf8');
  return Buffer.compare(left, right);
}

function buildTree(entries: readonly TreeEntry[]): Buffer {
  const sorted = [...entries].sort(compareTreeNames);
  const parts: Buffer[] = [];
  for (const entry of sorted) {
    parts.push(Buffer.from(`${entry.mode} ${entry.name}\0`, 'utf8'));
    parts.push(Buffer.from(entry.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

function storeTree(entries: readonly TreeEntry[]): string {
  return storeObject('tree', buildTree(entries));
}

interface CommitView {
  tree: string;
  parents: string[];
  author: string;
  committer: string;
  message: string;
}

function parseCommit(data: Buffer): CommitView {
  const text = data.toString('utf8');
  const blank = text.indexOf('\n\n');
  const header = blank < 0 ? text : text.slice(0, blank);
  const view: CommitView = { tree: '', parents: [], author: '', committer: '', message: blank < 0 ? '' : text.slice(blank + 2) };
  for (const line of header.split('\n')) {
    const space = line.indexOf(' ');
    if (space < 0) continue;
    const key = line.slice(0, space);
    const value = line.slice(space + 1);
    if (key === 'tree') view.tree = value;
    else if (key === 'parent') view.parents.push(value);
    else if (key === 'author') view.author = value;
    else if (key === 'committer') view.committer = value;
  }
  return view;
}

interface TagView {
  object: string;
  type: string;
  tag: string;
}

function parseTag(data: Buffer): TagView {
  const text = data.toString('utf8');
  const view: TagView = { object: '', type: '', tag: '' };
  for (const line of text.split('\n')) {
    if (line === '') break;
    const space = line.indexOf(' ');
    if (space < 0) continue;
    const key = line.slice(0, space);
    if (key === 'object') view.object = line.slice(space + 1);
    else if (key === 'type') view.type = line.slice(space + 1);
    else if (key === 'tag') view.tag = line.slice(space + 1);
  }
  return view;
}

/** Peel an oid through annotated tags to the commit it names (or return it unchanged). */
function peelToCommit(oid: string): string {
  let current = oid;
  for (let hops = 0; hops < 16; hops += 1) {
    const object = getObject(current);
    if (object === undefined || object.type !== 'tag') return current;
    current = parseTag(object.data).object;
  }
  return current;
}

// -------------------------------------------------------------------------------------------------
// packfiles
// -------------------------------------------------------------------------------------------------

function packEntryHeader(type: GitObjectType, size: number): Buffer {
  const bytes: number[] = [];
  let byte = (TYPE_CODE[type] << 4) | (size & 0x0f);
  size = Math.floor(size / 16);
  while (size > 0) {
    bytes.push(byte | 0x80);
    byte = size & 0x7f;
    size = Math.floor(size / 128);
  }
  bytes.push(byte);
  return Buffer.from(bytes);
}

/** A version-2 pack of whole objects (no deltas), with a valid SHA-1 trailer. */
function writePack(oids: readonly string[]): Buffer {
  const parts: Buffer[] = [];
  const header = Buffer.alloc(12);
  header.write('PACK', 0, 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(oids.length, 8);
  parts.push(header);
  for (const oid of oids) {
    const object = getObject(oid);
    if (object === undefined) continue;
    parts.push(packEntryHeader(object.type, object.data.length));
    parts.push(deflateSync(object.data, { level: 6 }));
  }
  const body = Buffer.concat(parts);
  const trailer = createHash('sha1').update(body).digest();
  return Buffer.concat([body, trailer]);
}

function readPackVarint(buffer: Buffer, start: number): { size: number; next: number; first: number } {
  let byte = buffer[start] ?? 0;
  const first = byte;
  let size = byte & 0x0f;
  let shift = 4;
  let offset = start + 1;
  while (byte & 0x80) {
    byte = buffer[offset] ?? 0;
    offset += 1;
    size += (byte & 0x7f) * 2 ** shift;
    shift += 7;
  }
  return { size, next: offset, first };
}

function inflateAt(buffer: Buffer, offset: number): { data: Buffer; next: number } {
  const result = inflateSync(buffer.subarray(offset), { info: true }) as unknown as { buffer: Buffer; engine: { bytesWritten: number } };
  return { data: result.buffer, next: offset + result.engine.bytesWritten };
}

function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let offset = 0;
  const readSize = (): number => {
    let value = 0;
    let shift = 0;
    for (;;) {
      const byte = delta[offset] ?? 0;
      offset += 1;
      value += (byte & 0x7f) * 2 ** shift;
      shift += 7;
      if (!(byte & 0x80)) break;
    }
    return value;
  };
  readSize();
  const targetSize = readSize();
  const out = Buffer.alloc(targetSize);
  let written = 0;
  while (offset < delta.length) {
    const op = delta[offset] ?? 0;
    offset += 1;
    if (op & 0x80) {
      let copyOffset = 0;
      let copySize = 0;
      let shift = 0;
      for (let bit = 0; bit < 4; bit += 1) {
        if (op & (1 << bit)) {
          copyOffset += (delta[offset] ?? 0) * 2 ** shift;
          offset += 1;
        }
        shift += 8;
      }
      shift = 0;
      for (let bit = 4; bit < 7; bit += 1) {
        if (op & (1 << bit)) {
          copySize += (delta[offset] ?? 0) * 2 ** shift;
          offset += 1;
        }
        shift += 8;
      }
      if (copySize === 0) copySize = 0x10000;
      base.copy(out, written, copyOffset, copyOffset + copySize);
      written += copySize;
    } else if (op !== 0) {
      const literal = op & 0x7f;
      delta.copy(out, written, offset, offset + literal);
      offset += literal;
      written += literal;
    } else {
      throw new Error('delta opcode 0');
    }
  }
  return out;
}

/** Ingest a received pack into the store, resolving OFS/REF deltas (including thin-pack bases). */
function ingestPack(pack: Buffer): void {
  if (pack.length < 12 + 20) throw new Error('pack too short');
  if (pack.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('not a pack');
  const count = pack.readUInt32BE(8);
  let offset = 12;
  const pending: Array<{ type: GitObjectType; data: Buffer }> = [];
  const byOffset = new Map<number, string>();
  interface DeltaJob { kind: 'ofs' | 'ref'; base: string; delta: Buffer }
  const deltas: DeltaJob[] = [];
  for (let index = 0; index < count; index += 1) {
    const entryOffset = offset;
    const { next, first } = readPackVarint(pack, offset);
    offset = next;
    const code = (first >> 4) & 0x7;
    if (code === 6) {
      // OFS_DELTA
      let byte = pack[offset] ?? 0;
      offset += 1;
      let baseOffset = byte & 0x7f;
      while (byte & 0x80) {
        byte = pack[offset] ?? 0;
        offset += 1;
        baseOffset = (baseOffset + 1) * 128 + (byte & 0x7f);
      }
      const inflated = inflateAt(pack, offset);
      offset = inflated.next;
      deltas.push({ kind: 'ofs', base: String(entryOffset - baseOffset), delta: inflated.data });
    } else if (code === 7) {
      // REF_DELTA
      const baseOid = pack.subarray(offset, offset + 20).toString('hex');
      offset += 20;
      const inflated = inflateAt(pack, offset);
      offset = inflated.next;
      deltas.push({ kind: 'ref', base: baseOid, delta: inflated.data });
    } else {
      const type = CODE_TYPE[code];
      if (type === undefined) throw new Error(`bad pack object type ${code}`);
      const inflated = inflateAt(pack, offset);
      offset = inflated.next;
      const oid = storeObject(type, inflated.data);
      byOffset.set(entryOffset, oid);
      pending.push({ type, data: inflated.data });
    }
  }
  void pending;
  // Resolve deltas iteratively: a delta's base may itself be a delta resolved in an earlier pass.
  const offsetOid = new Map<number, string>(byOffset);
  let jobs = deltas.map((job) => ({ ...job, baseOid: job.kind === 'ofs' ? offsetOid.get(Number(job.base)) : job.base }));
  let guard = 0;
  while (jobs.length > 0 && guard < 64) {
    guard += 1;
    const remaining: typeof jobs = [];
    for (const job of jobs) {
      const base = job.baseOid !== undefined ? getObject(job.baseOid) : undefined;
      if (base === undefined) {
        remaining.push(job);
        continue;
      }
      const data = applyDelta(base.data, job.delta);
      storeObject(base.type, data);
    }
    if (remaining.length === jobs.length) break; // unresolvable bases: leave them out
    jobs = remaining;
  }
}

// -------------------------------------------------------------------------------------------------
// reachability, shallow math, ancestry
// -------------------------------------------------------------------------------------------------

/** Every object reachable from `roots` (commits walk to trees and parents, tags to their target). */
function collectReachable(roots: Iterable<string>, stopAt?: ReadonlySet<string>): Set<string> {
  const seen = new Set<string>();
  const queue: string[] = [...roots];
  while (queue.length > 0) {
    const oid = queue.pop() as string;
    if (seen.has(oid)) continue;
    const object = getObject(oid);
    if (object === undefined) continue;
    seen.add(oid);
    if (object.type === 'commit') {
      const commit = parseCommit(object.data);
      queue.push(commit.tree);
      if (stopAt === undefined || !stopAt.has(oid)) {
        for (const parent of commit.parents) queue.push(parent);
      }
    } else if (object.type === 'tag') {
      queue.push(parseTag(object.data).object);
    } else if (object.type === 'tree') {
      for (const entry of parseTree(object.data)) {
        if (entry.mode !== '160000') queue.push(entry.oid);
      }
    }
  }
  return seen;
}

/** Commit ancestry distances (BFS levels) from `tips`, following parents (stops past `maxLevel`). */
function commitLevels(tips: readonly string[], maxLevel = Number.POSITIVE_INFINITY): Map<string, number> {
  const levels = new Map<string, number>();
  let frontier: string[] = [];
  for (const tip of tips) {
    const commit = peelToCommit(tip);
    if (!levels.has(commit)) {
      levels.set(commit, 0);
      frontier.push(commit);
    }
  }
  let level = 0;
  while (frontier.length > 0 && level < maxLevel) {
    level += 1;
    const next: string[] = [];
    for (const oid of frontier) {
      const object = getObject(oid);
      if (object === undefined || object.type !== 'commit') continue;
      for (const parent of parseCommit(object.data).parents) {
        if (!levels.has(parent)) {
          levels.set(parent, level);
          next.push(parent);
        }
      }
    }
    frontier = next;
  }
  return levels;
}

/** True when `ancestor` is reachable from `descendant` through commit parents. */
function isAncestor(ancestor: string, descendant: string): boolean {
  if (ancestor === descendant) return true;
  const seen = new Set<string>();
  const queue = [descendant];
  while (queue.length > 0) {
    const oid = queue.pop() as string;
    if (oid === ancestor) return true;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const object = getObject(oid);
    if (object !== undefined && object.type === 'commit') queue.push(...parseCommit(object.data).parents);
  }
  return false;
}

/** A best common ancestor of two commits, or null when their histories are disjoint. */
function mergeBaseOf(a: string, b: string): string | null {
  const ancestorsOfA = new Set<string>();
  const queue = [a];
  while (queue.length > 0) {
    const oid = queue.pop() as string;
    if (ancestorsOfA.has(oid)) continue;
    ancestorsOfA.add(oid);
    const object = getObject(oid);
    if (object !== undefined && object.type === 'commit') queue.push(...parseCommit(object.data).parents);
  }
  const seen = new Set<string>();
  const walk = [b];
  while (walk.length > 0) {
    const oid = walk.shift() as string;
    if (seen.has(oid)) continue;
    seen.add(oid);
    if (ancestorsOfA.has(oid)) return oid;
    const object = getObject(oid);
    if (object !== undefined && object.type === 'commit') walk.push(...parseCommit(object.data).parents);
  }
  return null;
}

// -------------------------------------------------------------------------------------------------
// flat trees: path <-> blob maps for merges, diffs and the contents API
// -------------------------------------------------------------------------------------------------

interface FlatEntry {
  mode: string;
  oid: string;
}

/** Flatten a tree (by oid) into a map of `path -> {mode, oid}` for files (submodules skipped). */
function flattenTree(treeOid: string, prefix = '', out = new Map<string, FlatEntry>()): Map<string, FlatEntry> {
  const object = getObject(treeOid);
  if (object === undefined || object.type !== 'tree') return out;
  for (const entry of parseTree(object.data)) {
    const path = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
    if (entry.mode === '40000') flattenTree(entry.oid, path, out);
    else if (entry.mode !== '160000') out.set(path, { mode: entry.mode, oid: entry.oid });
  }
  return out;
}

/** Rebuild nested tree objects from a flat path map; returns the root tree oid. */
function unflattenTree(flat: ReadonlyMap<string, FlatEntry>): string {
  interface DirNode {
    files: Map<string, FlatEntry>;
    dirs: Map<string, DirNode>;
  }
  const root: DirNode = { files: new Map(), dirs: new Map() };
  for (const [path, entry] of flat) {
    const parts = path.split('/');
    let node = root;
    for (let index = 0; index < parts.length - 1; index += 1) {
      const part = parts[index] as string;
      let child = node.dirs.get(part);
      if (child === undefined) {
        child = { files: new Map(), dirs: new Map() };
        node.dirs.set(part, child);
      }
      node = child;
    }
    node.files.set(parts[parts.length - 1] as string, entry);
  }
  const build = (node: DirNode): string => {
    const entries: TreeEntry[] = [];
    for (const [name, entry] of node.files) entries.push({ mode: entry.mode, name, oid: entry.oid });
    for (const [name, child] of node.dirs) entries.push({ mode: '40000', name, oid: build(child) });
    return storeTree(entries);
  };
  return build(root);
}

/** Read one path out of a commit's tree: the entry, or undefined. */
function treeEntryAt(commitOid: string | null, path: string): FlatEntry | undefined {
  if (commitOid === null) return undefined;
  const object = getObject(commitOid);
  if (object === undefined || object.type !== 'commit') return undefined;
  return flattenTree(parseCommit(object.data).tree).get(path);
}

/** The directory listing of one path inside a tree oid. */
function listTreeAt(treeOid: string, path: string): TreeEntry[] | null {
  if (path === '') {
    const object = getObject(treeOid);
    return object !== undefined && object.type === 'tree' ? parseTree(object.data) : null;
  }
  const parts = path.split('/');
  let current = treeOid;
  for (const part of parts) {
    const object = getObject(current);
    if (object === undefined || object.type !== 'tree') return null;
    const entry = parseTree(object.data).find((candidate) => candidate.name === part);
    if (entry === undefined || entry.mode !== '40000') return null;
    current = entry.oid;
  }
  const object = getObject(current);
  return object !== undefined && object.type === 'tree' ? parseTree(object.data) : null;
}

interface FileChange {
  path: string;
  status: 'added' | 'removed' | 'modified';
  additions: number;
  deletions: number;
}

function lineCount(oid: string): number {
  const object = getObject(oid);
  if (object === undefined) return 0;
  const text = object.data.toString('utf8');
  if (text === '') return 0;
  return text.split('\n').length;
}

/** The file-level diff between two flat trees (base -> head), with line counts. */
function diffFlat(base: ReadonlyMap<string, FlatEntry>, head: ReadonlyMap<string, FlatEntry>): FileChange[] {
  const changes: FileChange[] = [];
  const paths = new Set<string>([...base.keys(), ...head.keys()]);
  for (const path of [...paths].sort()) {
    const before = base.get(path);
    const after = head.get(path);
    if (before !== undefined && after === undefined) {
      changes.push({ path, status: 'removed', additions: 0, deletions: lineCount(before.oid) });
    } else if (before === undefined && after !== undefined) {
      changes.push({ path, status: 'added', additions: lineCount(after.oid), deletions: 0 });
    } else if (before !== undefined && after !== undefined && before.oid !== after.oid) {
      changes.push({ path, status: 'modified', additions: lineCount(after.oid), deletions: lineCount(before.oid) });
    }
  }
  return changes;
}

// -------------------------------------------------------------------------------------------------
// forge state
// -------------------------------------------------------------------------------------------------

interface ForgeUser {
  login: string;
  id: number;
  name: string;
  email: string;
}

/** The token owner: the suite's sealed viewer identity. */
const VIEWER: ForgeUser = { login: 'adaiversen', id: 1000, name: 'ada iversen', email: 'adaiversen@example.invalid' };

/** The token the env hands the entry; when unset (local runs) any bearer token is accepted. */
const EXPECTED_TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';

function tokenAccepted(req: IncomingMessage): boolean {
  const header = req.headers.authorization ?? '';
  const match = /^Bearer\s+(.+)$/i.exec(header);
  if (match === null) return false;
  if (EXPECTED_TOKEN === '') return true;
  return match[1] === EXPECTED_TOKEN;
}

interface IssueComment {
  id: number;
  body: string;
  author: string;
}

interface ForgeIssue {
  kind: 'issue';
  number: number;
  id: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: string[];
  comments: IssueComment[];
  seq: number;
}

interface ForgePull {
  kind: 'pull';
  number: number;
  id: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  merged: boolean;
  mergedAt: string | null;
  mergeCommitSha: string | null;
  headRef: string;
  baseRef: string;
  seq: number;
}

interface ForgeLabel {
  id: number;
  name: string;
  color: string;
  description: string;
}

interface ForgeRepo {
  id: number;
  owner: string;
  name: string;
  description: string;
  isPrivate: boolean;
  defaultBranch: string;
  refs: Map<string, string>;
  issues: Map<number, ForgeIssue>;
  pulls: Map<number, ForgePull>;
  labels: Map<string, ForgeLabel>;
  nextNumber: number;
  seq: number;
}

const repos = new Map<string, ForgeRepo>();
let nextRepoId = 5000;
let nextIssueId = 100000;
let nextLabelId = 200000;
let nextCommentId = 300000;
let globalSeq = 0;

/** Deterministic logical clock: a fixed epoch plus a per-commit tick (never the wall clock). */
const CLOCK_EPOCH_SEC = 1700000000;
let clockTick = 0;
function nextTimestampSec(): number {
  clockTick += 1;
  return CLOCK_EPOCH_SEC + clockTick;
}
function isoOf(sec: number): string {
  return new Date(sec * 1000).toISOString();
}
function nowIso(): string {
  return isoOf(CLOCK_EPOCH_SEC + clockTick);
}

function repoKey(owner: string, name: string): string {
  return `${owner}/${name}`;
}

function findRepo(owner: string, name: string): ForgeRepo | undefined {
  return repos.get(repoKey(owner, name));
}

function createRepo(owner: string, name: string, description: string, isPrivate: boolean): ForgeRepo | null {
  const key = repoKey(owner, name);
  if (repos.has(key)) return null;
  const repo: ForgeRepo = {
    id: nextRepoId,
    owner,
    name,
    description,
    isPrivate,
    defaultBranch: 'main',
    refs: new Map(),
    issues: new Map(),
    pulls: new Map(),
    labels: new Map(),
    nextNumber: 1,
    seq: ++globalSeq,
  };
  nextRepoId += 1;
  repos.set(key, repo);
  return repo;
}

function headRefOf(repo: ForgeRepo): string {
  return `refs/heads/${repo.defaultBranch}`;
}

function branchTip(repo: ForgeRepo, branch: string): string | null {
  return repo.refs.get(`refs/heads/${branch}`) ?? null;
}

/** The commit a ref name (branch, tag or full ref) resolves to, peeled through tags. */
function refTipCommit(repo: ForgeRepo, ref: string): string | null {
  const full = ref.startsWith('refs/') ? ref : `refs/heads/${ref}`;
  const oid = repo.refs.get(full);
  if (oid === undefined) return null;
  return peelToCommit(oid);
}

/** Make a commit on a branch from a flat tree, authored by the viewer at the logical clock. */
function commitOnBranch(repo: ForgeRepo, branch: string, flat: ReadonlyMap<string, FlatEntry>, message: string): string {
  const treeOid = unflattenTree(flat);
  const parent = branchTip(repo, branch);
  const timestamp = nextTimestampSec();
  const identity = `${VIEWER.name} <${VIEWER.email}> ${timestamp} +0000`;
  const lines = [`tree ${treeOid}`];
  if (parent !== null) lines.push(`parent ${parent}`);
  lines.push(`author ${identity}`, `committer ${identity}`, '', message);
  const commitOid = storeObject('commit', Buffer.from(lines.join('\n'), 'utf8'));
  repo.refs.set(`refs/heads/${branch}`, commitOid);
  return commitOid;
}

/** The flat tree at a branch tip (empty for an unborn branch). */
function flatAtBranch(repo: ForgeRepo, branch: string): Map<string, FlatEntry> {
  const tip = branchTip(repo, branch);
  if (tip === null) return new Map();
  const object = getObject(tip);
  if (object === undefined || object.type !== 'commit') return new Map();
  return flattenTree(parseCommit(object.data).tree);
}

function createIssue(repo: ForgeRepo, title: string, body: string, labels: string[]): ForgeIssue {
  const issue: ForgeIssue = {
    kind: 'issue',
    number: repo.nextNumber,
    id: nextIssueId,
    title,
    body,
    state: 'open',
    labels: [...labels],
    comments: [],
    seq: ++globalSeq,
  };
  repo.nextNumber += 1;
  nextIssueId += 1;
  repo.issues.set(issue.number, issue);
  return issue;
}

function createPull(repo: ForgeRepo, title: string, body: string, headRef: string, baseRef: string): ForgePull | null {
  if (branchTip(repo, headRef) === null || branchTip(repo, baseRef) === null) return null;
  for (const pull of repo.pulls.values()) {
    if (pull.state === 'open' && pull.headRef === headRef && pull.baseRef === baseRef) return null; // already exists
  }
  const pull: ForgePull = {
    kind: 'pull',
    number: repo.nextNumber,
    id: nextIssueId,
    title,
    body,
    state: 'open',
    merged: false,
    mergedAt: null,
    mergeCommitSha: null,
    headRef,
    baseRef,
    seq: ++globalSeq,
  };
  repo.nextNumber += 1;
  nextIssueId += 1;
  repo.pulls.set(pull.number, pull);
  return pull;
}

/** Whether merging head into base conflicts: a path both sides changed away from the merge base, differently. */
function pullConflict(repo: ForgeRepo, pull: ForgePull): boolean {
  const baseTip = branchTip(repo, pull.baseRef);
  const headTip = branchTip(repo, pull.headRef);
  if (baseTip === null || headTip === null) return true;
  const base = mergeBaseOf(baseTip, headTip);
  if (base === null) return true;
  const baseFlat = flattenTree(parseCommit(getObject(base)?.data ?? Buffer.alloc(0)).tree);
  const baseChanges = new Map(diffFlat(baseFlat, flatAtBranch(repo, pull.baseRef)).map((change) => [change.path, change]));
  for (const change of diffFlat(baseFlat, flatAtBranch(repo, pull.headRef))) {
    const other = baseChanges.get(change.path);
    if (other === undefined) continue;
    const headEntry = flatAtBranch(repo, pull.headRef).get(change.path);
    const baseEntry = flatAtBranch(repo, pull.baseRef).get(change.path);
    if ((headEntry?.oid ?? null) !== (baseEntry?.oid ?? null)) return true;
  }
  return false;
}

type MergeOutcome = { ok: true; sha: string } | { ok: false; reason: 'conflict' | 'not-open' | 'missing' };

/** Merge a pull request into its base branch (merge, squash or rebase), GitHub semantics. */
function mergePull(repo: ForgeRepo, pull: ForgePull, method: string): MergeOutcome {
  if (pull.state !== 'open') return { ok: false, reason: 'not-open' };
  const baseTip = branchTip(repo, pull.baseRef);
  const headTip = branchTip(repo, pull.headRef);
  if (baseTip === null || headTip === null) return { ok: false, reason: 'missing' };
  if (pullConflict(repo, pull)) return { ok: false, reason: 'conflict' };
  const mergeBase = mergeBaseOf(baseTip, headTip) ?? baseTip;
  const baseFlat = flattenTree(parseCommit((getObject(mergeBase) as GitObject).data).tree);
  const headFlat = flatAtBranch(repo, pull.headRef);
  const baseCurrent = flatAtBranch(repo, pull.baseRef);
  // Merged tree: the head's changes relative to the merge base, laid over the current base tree.
  const merged = new Map(baseCurrent);
  for (const change of diffFlat(baseFlat, headFlat)) {
    const entry = headFlat.get(change.path);
    if (entry === undefined) merged.delete(change.path);
    else merged.set(change.path, entry);
  }
  let sha: string;
  if (method === 'rebase') {
    // Replay the head's own commits (oldest first) onto the base tip, then point the head at the result.
    const levels = commitLevels([headTip]);
    const own: string[] = [];
    for (const [oid] of [...levels.entries()].sort((a, b) => b[1] - a[1])) {
      if (oid === mergeBase) break;
      if (!isAncestor(oid, mergeBase)) own.push(oid);
    }
    own.reverse();
    let currentFlat = new Map(baseCurrent);
    let parent = baseTip;
    sha = baseTip;
    for (const commitOid of own) {
      const commitObject = getObject(commitOid) as GitObject;
      const commit = parseCommit(commitObject.data);
      const parentTree = commit.parents.length > 0 ? flattenTree(parseCommit((getObject(commit.parents[0] as string) as GitObject).data).tree) : new Map<string, FlatEntry>();
      const commitTree = flattenTree(commit.tree);
      for (const change of diffFlat(parentTree, commitTree)) {
        const entry = commitTree.get(change.path);
        if (entry === undefined) currentFlat.delete(change.path);
        else currentFlat.set(change.path, entry);
      }
      const treeOid = unflattenTree(currentFlat);
      const timestamp = nextTimestampSec();
      const lines = [`tree ${treeOid}`, `parent ${parent}`, `author ${commit.author}`, `committer ${VIEWER.name} <${VIEWER.email}> ${timestamp} +0000`, '', commit.message];
      sha = storeObject('commit', Buffer.from(lines.join('\n'), 'utf8'));
      parent = sha;
    }
    repo.refs.set(`refs/heads/${pull.baseRef}`, sha);
    repo.refs.set(`refs/heads/${pull.headRef}`, sha);
  } else if (method === 'squash') {
    sha = commitOnBranch(repo, pull.baseRef, merged, `${pull.title} (#${pull.number})`);
  } else {
    const treeOid = unflattenTree(merged);
    const timestamp = nextTimestampSec();
    const identity = `${VIEWER.name} <${VIEWER.email}> ${timestamp} +0000`;
    const lines = [
      `tree ${treeOid}`,
      `parent ${baseTip}`,
      `parent ${headTip}`,
      `author ${identity}`,
      `committer ${identity}`,
      '',
      `Merge pull request #${pull.number} from ${pull.headRef}`,
    ];
    sha = storeObject('commit', Buffer.from(lines.join('\n'), 'utf8'));
    repo.refs.set(`refs/heads/${pull.baseRef}`, sha);
  }
  pull.state = 'closed';
  pull.merged = true;
  pull.mergedAt = isoOf(nextTimestampSec());
  pull.mergeCommitSha = sha;
  return { ok: true, sha };
}

// -------------------------------------------------------------------------------------------------
// JSON views (REST shapes; extra properties are allowed by the suite)
// -------------------------------------------------------------------------------------------------

function userJson(user: ForgeUser): Record<string, unknown> {
  return { login: user.login, id: user.id, name: user.name, email: user.email, type: 'User' };
}

function repoJson(repo: ForgeRepo): Record<string, unknown> {
  return {
    id: repo.id,
    name: repo.name,
    full_name: `${repo.owner}/${repo.name}`,
    owner: userJson(VIEWER),
    private: repo.isPrivate,
    description: repo.description,
    default_branch: repo.defaultBranch,
    html_url: `https://forge.invalid/${repo.owner}/${repo.name}`,
    created_at: nowIso(),
    updated_at: nowIso(),
    has_issues: true,
    open_issues_count: [...repo.issues.values()].filter((issue) => issue.state === 'open').length,
  };
}

function labelJson(label: ForgeLabel): Record<string, unknown> {
  return { id: label.id, name: label.name, color: label.color, description: label.description };
}

function issueJson(repo: ForgeRepo, issue: ForgeIssue): Record<string, unknown> {
  return {
    id: issue.id,
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labels: issue.labels.map((name) => {
      const label = repo.labels.get(name);
      return label !== undefined ? labelJson(label) : { name };
    }),
    comments: issue.comments.length,
    user: userJson(VIEWER),
    created_at: nowIso(),
    updated_at: nowIso(),
    html_url: `https://forge.invalid/${repo.owner}/${repo.name}/issues/${issue.number}`,
  };
}

function commentJson(comment: IssueComment): Record<string, unknown> {
  return { id: comment.id, body: comment.body, user: userJson(VIEWER), created_at: nowIso(), updated_at: nowIso() };
}

function pullJson(repo: ForgeRepo, pull: ForgePull): Record<string, unknown> {
  const headTip = branchTip(repo, pull.headRef);
  const baseTip = branchTip(repo, pull.baseRef);
  return {
    id: pull.id,
    number: pull.number,
    title: pull.title,
    body: pull.body,
    state: pull.state,
    merged: pull.merged,
    merged_at: pull.mergedAt,
    merge_commit_sha: pull.mergeCommitSha,
    head: { ref: pull.headRef, sha: headTip, label: `${repo.owner}:${pull.headRef}` },
    base: { ref: pull.baseRef, sha: baseTip, label: `${repo.owner}:${pull.baseRef}` },
    user: userJson(VIEWER),
    created_at: nowIso(),
    updated_at: nowIso(),
    html_url: `https://forge.invalid/${repo.owner}/${repo.name}/pull/${pull.number}`,
  };
}

// -------------------------------------------------------------------------------------------------
// pkt-line codec
// -------------------------------------------------------------------------------------------------

function pktLine(payload: string | Buffer): Buffer {
  const data = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const header = Buffer.from((data.length + 4).toString(16).padStart(4, '0'), 'ascii');
  return Buffer.concat([header, data]);
}
const PKT_FLUSH = Buffer.from('0000', 'ascii');
const PKT_DELIM = Buffer.from('0001', 'ascii');

type PktItem = Buffer | string | 'flush' | 'delim';
function pktJoin(items: readonly PktItem[]): Buffer {
  return Buffer.concat(
    items.map((item) => {
      if (item === 'flush') return PKT_FLUSH;
      if (item === 'delim') return PKT_DELIM;
      if (Buffer.isBuffer(item)) return item; // already framed by pktLine()
      return pktLine(item);
    }),
  );
}

/** Decode a complete pkt-line stream; returns the data payloads and the offset of the first flush. */
function decodePktStream(body: Buffer): { lines: Buffer[]; rest: Buffer } | null {
  const lines: Buffer[] = [];
  let offset = 0;
  while (offset + 4 <= body.length) {
    const header = body.subarray(offset, offset + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(header)) return null;
    const length = Number.parseInt(header, 16);
    if (length === 0) return { lines, rest: body.subarray(offset + 4) };
    if (length === 1 || length === 2) {
      offset += 4;
      continue;
    }
    if (length < 4 || offset + length > body.length) return null;
    lines.push(body.subarray(offset + 4, offset + length));
    offset += length;
  }
  return { lines, rest: body.subarray(offset) };
}

/** Split a v2 command request into its argument lines (after the delim). */
function v2Arguments(lines: readonly Buffer[]): string[] {
  return lines.map((line) => line.toString('utf8').replace(/\n$/, ''));
}

// -------------------------------------------------------------------------------------------------
// git smart HTTP
// -------------------------------------------------------------------------------------------------

const UPLOAD_CAPS_V0 = 'side-band-64k ofs-delta symref=HEAD:refs/heads/main agent=makefun-forge/1.0';
const RECEIVE_CAPS = 'report-status side-band-64k delete-refs ofs-delta agent=makefun-forge/1.0';

/** The ref lines of a v0 advertisement: HEAD first (with capabilities on it), then refs sorted. */
function v0Advertisement(repo: ForgeRepo, service: string): Buffer {
  const caps = service === 'git-receive-pack' ? RECEIVE_CAPS : UPLOAD_CAPS_V0;
  const items: PktItem[] = [pktLine(`# service=${service}\n`), 'flush'];
  const headTarget = headRefOf(repo);
  const headOid = repo.refs.get(headTarget);
  const lines: string[] = [];
  if (headOid !== undefined) lines.push(`${headOid} HEAD\0${caps}\n`);
  else lines.push(`${ZERO_OID} capabilities^{}\0${caps}\n`);
  const names = [...repo.refs.keys()].sort();
  for (const name of names) {
    const oid = repo.refs.get(name) as string;
    lines.push(`${oid} ${name}\n`);
    const object = getObject(oid);
    if (object !== undefined && object.type === 'tag') lines.push(`${peelToCommit(oid)} ${name}^{}\n`);
  }
  if (headOid === undefined && names.length > 0) {
    // An unborn HEAD alongside other refs: HEAD still names its target on its own line.
    lines.splice(1, 0, `${ZERO_OID} HEAD\0\n`);
  }
  for (const line of lines) items.push(pktLine(line));
  items.push('flush');
  return pktJoin(items);
}

function v2Advertisement(): Buffer {
  return pktJoin([
    pktLine('# service=git-upload-pack\n'),
    'flush',
    pktLine('version 2\n'),
    pktLine('agent=makefun-forge/1.0\n'),
    pktLine('ls-refs=unborn\n'),
    pktLine('fetch=shallow\n'),
    pktLine('object-format=sha1\n'),
    'flush',
  ]);
}

/** One ls-refs answer line for a ref, honouring peel/symrefs/unborn arguments. */
function lsRefLine(repo: ForgeRepo, name: string, oid: string, args: ReadonlySet<string>): string | null {
  const parts: string[] = [];
  if (name === 'HEAD') {
    const target = headRefOf(repo);
    if (oid === ZERO_OID) {
      if (!args.has('unborn')) return null;
      parts.push(`unborn HEAD`);
      if (args.has('symrefs')) parts.push(`symref-target:${target}`);
      return `${parts.join(' ')}\n`;
    }
    parts.push(`${oid} HEAD`);
    if (args.has('symrefs')) parts.push(`symref-target:${target}`);
    return `${parts.join(' ')}\n`;
  }
  parts.push(`${oid} ${name}`);
  const object = getObject(oid);
  if (object !== undefined && object.type === 'tag' && args.has('peel')) parts.push(`peeled:${peelToCommit(oid)}`);
  return `${parts.join(' ')}\n`;
}

function handleLsRefs(repo: ForgeRepo, lines: readonly Buffer[], res: ServerResponse): void {
  const args = v2Arguments(lines);
  const argSet = new Set<string>();
  const prefixes: string[] = [];
  for (const arg of args.slice(1)) {
    if (arg.startsWith('ref-prefix ')) prefixes.push(arg.slice('ref-prefix '.length));
    else argSet.add(arg);
  }
  const items: PktItem[] = [];
  const headOid = repo.refs.get(headRefOf(repo)) ?? ZERO_OID;
  const headLine = lsRefLine(repo, 'HEAD', headOid, argSet);
  const wanted = (name: string): boolean => prefixes.length === 0 || prefixes.some((prefix) => name.startsWith(prefix));
  if (headLine !== null && wanted('HEAD')) items.push(pktLine(headLine));
  for (const name of [...repo.refs.keys()].sort()) {
    if (!wanted(name)) continue;
    const line = lsRefLine(repo, name, repo.refs.get(name) as string, argSet);
    if (line !== null) items.push(pktLine(line));
  }
  items.push('flush');
  sendRaw(res, 200, pktJoin(items), 'application/x-git-upload-pack-result');
}

interface FetchPlan {
  objects: string[];
  shallow: string[];
  unshallow: string[];
  ready: boolean;
  commonHave: string | null;
}

/** Decide what a fetch sends: the objects the client lacks, honouring haves, shallow and deepen. */
function planFetch(wants: readonly string[], haves: readonly string[], shallowIn: readonly string[], deepen: number | null): FetchPlan {
  const haveStop = new Set(shallowIn);
  const haveSet = collectReachable(haves, haveStop);
  // What the client already holds through its shallow boundary commits counts as had, too.
  for (const boundary of shallowIn) haveSet.add(boundary);
  const wantCommits = wants.map((want) => peelToCommit(want));
  if (deepen !== null) {
    const levels = commitLevels(wantCommits, deepen - 1);
    // `deepen N` is a total depth measured from the wants (git's semantics, and the suite's:
    // a depth-1 clone holds the tip alone; deepen 2 on it delivers exactly one more generation).
    const maxLevel = deepen - 1;
    const included = new Set<string>();
    const newBoundary: string[] = [];
    for (const [commit, level] of levels) {
      if (level > maxLevel) continue;
      const object = getObject(commit) as GitObject;
      const parsed = parseCommit(object.data);
      included.add(commit);
      collectTreeObjects(parsed.tree, included);
      if (level === maxLevel && parsed.parents.length > 0) newBoundary.push(commit);
    }
    // Tag objects pointing at included commits travel too.
    for (const want of wants) {
      const object = getObject(want);
      if (object !== undefined && object.type === 'tag') included.add(want);
    }
    // haveSet already holds every commit at or above the client's boundary (and its trees and
    // blobs), so one filter serves both the fresh-shallow and the deepen case.
    const send = [...included].filter((oid) => !haveSet.has(oid));
    const unshallow: string[] = [];
    for (const boundary of shallowIn) {
      const commit = peelToCommit(boundary);
      const level = levels.get(commit);
      if (level !== undefined && level <= maxLevel) {
        const object = getObject(commit);
        if (object !== undefined && object.type === 'commit') {
          const parents = parseCommit(object.data).parents;
          const covered = parents.every((parent) => (levels.get(parent) ?? Infinity) <= maxLevel);
          if (covered) unshallow.push(commit);
        }
      }
    }
    return { objects: send, shallow: newBoundary.filter((oid) => !unshallow.includes(oid)), unshallow, ready: false, commonHave: null };
  }
  const wantSet = collectReachable(wants);
  const missing = [...wantSet].filter((oid) => !haveSet.has(oid));
  const commonHave = haves.find((have) => getObject(have) !== undefined) ?? null;
  return { objects: missing, shallow: [], unshallow: [], ready: missing.length === 0, commonHave };
}

function collectTreeObjects(treeOid: string, into: Set<string>): void {
  const object = getObject(treeOid);
  if (object === undefined || object.type !== 'tree') return;
  into.add(treeOid);
  for (const entry of parseTree(object.data)) {
    if (entry.mode === '40000') collectTreeObjects(entry.oid, into);
    else if (entry.mode !== '160000') into.add(entry.oid);
  }
}

/** Wrap a pack in sideband band-1 packets. */
function sidebandPackets(pack: Buffer): Buffer[] {
  const packets: Buffer[] = [];
  for (let offset = 0; offset < pack.length; offset += PKT_MAX_PAYLOAD - 1) {
    const chunk = pack.subarray(offset, Math.min(pack.length, offset + PKT_MAX_PAYLOAD - 1));
    packets.push(pktLine(Buffer.concat([Buffer.from([1]), chunk])));
  }
  if (packets.length === 0) packets.push(pktLine(Buffer.from([1])));
  return packets;
}

function handleFetchV2(lines: readonly Buffer[], res: ServerResponse): void {
  const args = v2Arguments(lines);
  const wants: string[] = [];
  const haves: string[] = [];
  const shallowIn: string[] = [];
  let deepen: number | null = null;
  for (const arg of args.slice(1)) {
    if (arg.startsWith('want ')) wants.push(arg.slice(5).trim());
    else if (arg.startsWith('have ')) haves.push(arg.slice(5).trim());
    else if (arg.startsWith('shallow ')) shallowIn.push(arg.slice(8).trim());
    else if (arg.startsWith('deepen ')) deepen = Number.parseInt(arg.slice(7).trim(), 10);
  }
  const plan = planFetch(wants, haves, shallowIn, deepen);
  const items: PktItem[] = [pktLine('acknowledgments\n')];
  if (plan.ready) {
    items.push(pktLine('ready\n'), 'flush');
    sendRaw(res, 200, pktJoin(items), 'application/x-git-upload-pack-result');
    return;
  }
  items.push(pktLine(plan.commonHave !== null ? `ACK ${plan.commonHave}\n` : 'NAK\n'), 'delim');
  if (deepen !== null) {
    items.push(pktLine('shallow-info\n'));
    for (const oid of plan.shallow) items.push(pktLine(`shallow ${oid}\n`));
    for (const oid of plan.unshallow) items.push(pktLine(`unshallow ${oid}\n`));
    items.push('delim');
  }
  items.push(pktLine('packfile\n'));
  const pack = writePack(plan.objects);
  for (const packet of sidebandPackets(pack)) items.push(packet);
  items.push('flush');
  sendRaw(res, 200, pktJoin(items), 'application/x-git-upload-pack-result');
}

function handleFetchV0(lines: readonly Buffer[], res: ServerResponse): void {
  const wants: string[] = [];
  const haves: string[] = [];
  const shallowIn: string[] = [];
  let deepen: number | null = null;
  for (const line of lines) {
    const text = line.toString('utf8').replace(/\n$/, '');
    if (text.startsWith('want ')) wants.push(text.slice(5, 45));
    else if (text.startsWith('have ')) haves.push(text.slice(5, 45));
    else if (text.startsWith('shallow ')) shallowIn.push(text.slice(8, 48));
    else if (text.startsWith('deepen ')) deepen = Number.parseInt(text.slice(7), 10);
  }
  const plan = planFetch(wants, haves, shallowIn, deepen);
  const items: PktItem[] = [];
  if (plan.ready) {
    items.push(pktLine('NAK\n'), 'flush');
    sendRaw(res, 200, pktJoin(items), 'application/x-git-upload-pack-result');
    return;
  }
  items.push(pktLine(plan.commonHave !== null ? `ACK ${plan.commonHave}\n` : 'NAK\n'));
  for (const oid of plan.shallow) items.push(pktLine(`shallow ${oid}\n`));
  for (const oid of plan.unshallow) items.push(pktLine(`unshallow ${oid}\n`));
  const pack = writePack(plan.objects);
  for (const packet of sidebandPackets(pack)) items.push(packet);
  items.push('flush');
  sendRaw(res, 200, pktJoin(items), 'application/x-git-upload-pack-result');
}

interface PushCommandLine {
  oldOid: string;
  newOid: string;
  ref: string;
}

function handleReceivePack(repo: ForgeRepo, body: Buffer, res: ServerResponse): void {
  const decoded = decodePktStream(body);
  if (decoded === null || decoded.lines.length === 0) {
    sendJson(res, 400, { message: 'malformed receive-pack request' });
    return;
  }
  const commands: PushCommandLine[] = [];
  let capabilities = '';
  decoded.lines.forEach((raw, index) => {
    let text = raw.toString('utf8').replace(/\n$/, '');
    if (index === 0) {
      const nul = text.indexOf('\0');
      if (nul >= 0) {
        capabilities = text.slice(nul + 1);
        text = text.slice(0, nul);
      }
    }
    const parts = text.split(' ');
    if (parts.length >= 3) commands.push({ oldOid: parts[0] as string, newOid: parts[1] as string, ref: parts.slice(2).join(' ') });
  });
  const wantsReport = capabilities.split(' ').includes('report-status');
  const wantsSideband = capabilities.split(' ').includes('side-band-64k');
  let unpackOk = true;
  let unpackDetail = 'ok';
  const pack = decoded.rest;
  const hasUpdate = commands.some((command) => command.newOid !== ZERO_OID);
  if (hasUpdate && pack.length > 0) {
    try {
      ingestPack(pack);
    } catch {
      unpackOk = false;
      unpackDetail = 'index-pack failed';
    }
  } else if (hasUpdate && pack.length === 0) {
    unpackOk = false;
    unpackDetail = 'no pack received';
  }
  const reportLines: string[] = [`unpack ${unpackDetail}\n`];
  for (const command of commands) {
    if (!unpackOk) {
      reportLines.push(`ng ${command.ref} unpacker error\n`);
      continue;
    }
    const current = repo.refs.get(command.ref) ?? ZERO_OID;
    if (command.newOid === ZERO_OID) {
      // delete
      if (current === ZERO_OID) {
        reportLines.push(`ng ${command.ref} reference does not exist\n`);
      } else {
        repo.refs.delete(command.ref);
        reportLines.push(`ok ${command.ref}\n`);
      }
      continue;
    }
    const newObject = getObject(command.newOid);
    if (newObject === undefined) {
      reportLines.push(`ng ${command.ref} unknown object\n`);
      continue;
    }
    if (command.oldOid !== current && command.oldOid !== ZERO_OID && current !== ZERO_OID) {
      reportLines.push(`ng ${command.ref} reference is not up to date\n`);
      continue;
    }
    if (command.ref.startsWith('refs/heads/') && current !== ZERO_OID) {
      const newCommit = peelToCommit(command.newOid);
      if (!isAncestor(current, newCommit)) {
        reportLines.push(`ng ${command.ref} non-fast-forward\n`);
        continue;
      }
    }
    repo.refs.set(command.ref, command.newOid);
    reportLines.push(`ok ${command.ref}\n`);
  }
  if (!wantsReport) {
    sendRaw(res, 200, Buffer.alloc(0), 'application/x-git-receive-pack-result');
    return;
  }
  const reportStream = pktJoin(reportLines.map((line) => pktLine(line)));
  if (wantsSideband) {
    const packets: Buffer[] = [];
    for (let offset = 0; offset < reportStream.length; offset += PKT_MAX_PAYLOAD - 1) {
      const chunk = reportStream.subarray(offset, Math.min(reportStream.length, offset + PKT_MAX_PAYLOAD - 1));
      packets.push(pktLine(Buffer.concat([Buffer.from([1]), chunk])));
    }
    packets.push(PKT_FLUSH);
    sendRaw(res, 200, Buffer.concat(packets), 'application/x-git-receive-pack-result');
    return;
  }
  sendRaw(res, 200, Buffer.concat([reportStream, PKT_FLUSH]), 'application/x-git-receive-pack-result');
}

function handleUploadPack(repo: ForgeRepo, body: Buffer, res: ServerResponse): void {
  const decoded = decodePktStream(body);
  if (decoded === null || decoded.lines.length === 0) {
    sendJson(res, 400, { message: 'malformed upload-pack request' });
    return;
  }
  const first = decoded.lines[0]?.toString('utf8') ?? '';
  if (first.startsWith('command=ls-refs')) {
    handleLsRefs(repo, decoded.lines, res);
    return;
  }
  if (first.startsWith('command=fetch')) {
    handleFetchV2(decoded.lines, res);
    return;
  }
  handleFetchV0(decoded.lines, res);
}

// -------------------------------------------------------------------------------------------------
// REST v3
// -------------------------------------------------------------------------------------------------

function apiError(res: ServerResponse, status: number, message: string): void {
  sendJson(res, status, { message });
}

function sendNoContent(res: ServerResponse): void {
  res.writeHead(204, { 'x-github-request-id': `FORGE-${(++requestSeq).toString(16).toUpperCase().padStart(6, '0')}` });
  res.end();
}

interface RestContext {
  req: IncomingMessage;
  res: ServerResponse;
  segments: string[];
  query: URLSearchParams;
  body: unknown;
}

function paginationLinks(ctx: RestContext, total: number, perPage: number, page: number): string | null {
  const host = ctx.req.headers.host ?? 'entry';
  const base = `http://${host}/api/v3/user/repos`;
  const lastPage = Math.max(1, Math.ceil(total / perPage));
  const links: string[] = [];
  if (page < lastPage) {
    links.push(`<${base}?per_page=${perPage}&page=${page + 1}>; rel="next"`);
    links.push(`<${base}?per_page=${perPage}&page=${lastPage}>; rel="last"`);
  }
  if (page > 1) {
    links.push(`<${base}?per_page=${perPage}&page=${page - 1}>; rel="prev"`);
    links.push(`<${base}?per_page=${perPage}&page=1>; rel="first"`);
  }
  return links.length > 0 ? links.join(', ') : null;
}

function restCreateRepo(ctx: RestContext): void {
  const { res, body } = ctx;
  if (!isRecord(body) || typeof body.name !== 'string' || body.name === '') {
    apiError(res, 422, 'name is required');
    return;
  }
  const name = body.name;
  if (!/^[A-Za-z0-9._-]+$/.test(name)) {
    apiError(res, 422, 'name is invalid');
    return;
  }
  const existing = findRepo(VIEWER.login, name);
  if (existing !== undefined) {
    apiError(res, 422, 'name already exists on this account');
    return;
  }
  const repo = createRepo(VIEWER.login, name, typeof body.description === 'string' ? body.description : '', body.private !== false);
  if (repo === null) {
    apiError(res, 422, 'name already exists on this account');
    return;
  }
  if (body.auto_init === true) {
    const flat = new Map<string, FlatEntry>();
    commitOnBranch(repo, repo.defaultBranch, flat, 'Initial commit');
  }
  sendJson(res, 201, repoJson(repo));
}

function restListUserRepos(ctx: RestContext): void {
  const { res, query } = ctx;
  const perPage = Math.min(100, Math.max(1, Number.parseInt(query.get('per_page') ?? '30', 10) || 30));
  const page = Math.max(1, Number.parseInt(query.get('page') ?? '1', 10) || 1);
  const mine = [...repos.values()].filter((repo) => repo.owner === VIEWER.login).sort((a, b) => a.seq - b.seq);
  const slice = mine.slice((page - 1) * perPage, page * perPage);
  const headers: Record<string, string> = {};
  const link = paginationLinks(ctx, mine.length, perPage, page);
  if (link !== null) headers.link = link;
  sendJson(res, 200, slice.map(repoJson), headers);
}

function restRepoRoutes(ctx: RestContext, repo: ForgeRepo): void {
  const { req, res, segments, query, body } = ctx;
  const method = req.method ?? 'GET';
  const rest = segments.slice(2); // after repos/{owner}
  const sub = rest[1] ?? '';

  if (rest.length === 1) {
    if (method === 'GET') {
      sendJson(res, 200, repoJson(repo));
      return;
    }
    if (method === 'PATCH') {
      if (repo.owner !== VIEWER.login) {
        apiError(res, 404, 'Not Found');
        return;
      }
      if (isRecord(body)) {
        if (typeof body.description === 'string') repo.description = body.description;
        if (typeof body.private === 'boolean') repo.isPrivate = body.private;
        if (typeof body.default_branch === 'string' && branchTip(repo, body.default_branch) !== null) repo.defaultBranch = body.default_branch;
      }
      sendJson(res, 200, repoJson(repo));
      return;
    }
    if (method === 'DELETE') {
      if (repo.owner !== VIEWER.login) {
        apiError(res, 404, 'Not Found');
        return;
      }
      repos.delete(repoKey(repo.owner, repo.name));
      sendNoContent(res);
      return;
    }
    apiError(res, 404, 'Not Found');
    return;
  }

  if (sub === 'branches') {
    if (rest.length === 2 && method === 'GET') {
      const branches = [...repo.refs.entries()]
        .filter(([name]) => name.startsWith('refs/heads/'))
        .map(([name, oid]) => ({ name: name.slice('refs/heads/'.length), commit: { sha: oid }, protected: false }));
      sendJson(res, 200, branches);
      return;
    }
    if (rest.length === 3 && method === 'GET') {
      const branch = decodeURIComponent(rest[2] as string);
      const tip = branchTip(repo, branch);
      if (tip === null) {
        apiError(res, 404, 'Branch not found');
        return;
      }
      sendJson(res, 200, { name: branch, commit: { sha: tip } });
      return;
    }
    apiError(res, 404, 'Not Found');
    return;
  }

  if (sub === 'git' && rest[2] === 'refs') {
    if (method === 'POST' && rest.length === 3) {
      if (!isRecord(body) || typeof body.ref !== 'string' || typeof body.sha !== 'string') {
        apiError(res, 422, 'ref and sha are required');
        return;
      }
      if (!body.ref.startsWith('refs/')) {
        apiError(res, 422, 'ref must start with refs/');
        return;
      }
      if (getObject(body.sha) === undefined) {
        apiError(res, 422, 'sha does not name an object');
        return;
      }
      if (repo.refs.has(body.ref)) {
        apiError(res, 422, 'Reference already exists');
        return;
      }
      repo.refs.set(body.ref, body.sha);
      sendJson(res, 201, { ref: body.ref, object: { sha: body.sha, type: getObject(body.sha)?.type ?? 'commit' } });
      return;
    }
    if (method === 'GET') {
      const refName = rest.slice(3).join('/');
      if (refName === '') {
        const all = [...repo.refs.entries()].map(([name, oid]) => ({ ref: name, object: { sha: oid, type: getObject(oid)?.type ?? 'commit' } }));
        sendJson(res, 200, all);
        return;
      }
      const oid = repo.refs.get(`refs/${refName}`);
      if (oid === undefined) {
        apiError(res, 404, 'Reference not found');
        return;
      }
      sendJson(res, 200, { ref: `refs/${refName}`, object: { sha: oid, type: getObject(oid)?.type ?? 'commit' } });
      return;
    }
    apiError(res, 404, 'Not Found');
    return;
  }

  if (sub === 'commits' && rest.length === 2 && method === 'GET') {
    const shaParam = query.get('sha');
    let start: string | null = null;
    if (shaParam !== null && shaParam !== '') {
      start = refTipCommit(repo, shaParam) ?? (getObject(shaParam)?.type === 'commit' ? shaParam : null);
    } else {
      start = branchTip(repo, repo.defaultBranch);
    }
    if (start === null) {
      sendJson(res, 200, []);
      return;
    }
    const levels = commitLevels([start]);
    const ordered = [...levels.entries()].sort((a, b) => a[1] - b[1]).map(([oid]) => oid);
    const items = ordered.map((oid) => {
      const commit = parseCommit((getObject(oid) as GitObject).data);
      const authorMatch = /^(.*) <(.*)> (\d+) /.exec(commit.author);
      return {
        sha: oid,
        commit: {
          message: commit.message,
          tree: { sha: commit.tree },
          author: { name: authorMatch?.[1] ?? '', email: authorMatch?.[2] ?? '', date: isoOf(Number(authorMatch?.[3] ?? CLOCK_EPOCH_SEC)) },
          committer: { name: authorMatch?.[1] ?? '', email: authorMatch?.[2] ?? '' },
        },
        parents: commit.parents.map((parent) => ({ sha: parent })),
      };
    });
    sendJson(res, 200, items);
    return;
  }

  if (sub === 'contents') {
    restContents(ctx, repo, rest.slice(2).join('/'));
    return;
  }

  if (sub === 'labels') {
    restLabels(ctx, repo, rest);
    return;
  }

  if (sub === 'issues') {
    restIssues(ctx, repo, rest);
    return;
  }

  if (sub === 'pulls') {
    restPulls(ctx, repo, rest);
    return;
  }

  apiError(res, 404, 'Not Found');
}

function restContents(ctx: RestContext, repo: ForgeRepo, rawPath: string): void {
  const { req, res, query, body } = ctx;
  const method = req.method ?? 'GET';
  const path = rawPath.split('/').map((segment) => decodeURIComponent(segment)).join('/').replace(/^\/+|\/+$/g, '');

  if (method === 'GET') {
    const ref = query.get('ref') ?? repo.defaultBranch;
    const tip = refTipCommit(repo, ref);
    if (tip === null) {
      apiError(res, 404, 'Not Found');
      return;
    }
    const treeOid = parseCommit((getObject(tip) as GitObject).data).tree;
    if (path === '') {
      const entries = listTreeAt(treeOid, '');
      if (entries === null) {
        apiError(res, 404, 'Not Found');
        return;
      }
      sendJson(res, 200, entries.map((entry) => contentsEntryJson(repo, entry, '')));
      return;
    }
    const flat = flattenTree(treeOid);
    const file = flat.get(path);
    if (file !== undefined) {
      const object = getObject(file.oid) as GitObject;
      sendJson(res, 200, {
        type: 'file',
        name: path.split('/').pop(),
        path,
        sha: file.oid,
        size: object.data.length,
        encoding: 'base64',
        content: object.data.toString('base64'),
      });
      return;
    }
    const dirEntries = listTreeAt(treeOid, path);
    if (dirEntries !== null) {
      sendJson(res, 200, dirEntries.map((entry) => contentsEntryJson(repo, entry, path)));
      return;
    }
    apiError(res, 404, 'Not Found');
    return;
  }

  if (method === 'PUT' || method === 'DELETE') {
    if (!isRecord(body) || typeof body.message !== 'string') {
      apiError(res, 422, 'message is required');
      return;
    }
    const branch = typeof body.branch === 'string' && body.branch !== '' ? body.branch : repo.defaultBranch;
    if (branchTip(repo, branch) === null && !repo.refs.has(`refs/heads/${branch}`)) {
      // A contents write names the branch it creates when it does not exist yet (from the default tip).
      const baseTip = branchTip(repo, repo.defaultBranch);
      if (baseTip !== null) repo.refs.set(`refs/heads/${branch}`, baseTip);
    }
    const flat = flatAtBranch(repo, branch);
    const existing = flat.get(path);
    if (method === 'PUT') {
      if (typeof body.content !== 'string') {
        apiError(res, 422, 'content is required');
        return;
      }
      const data = Buffer.from(body.content.replace(/\s+/g, ''), 'base64');
      if (existing !== undefined && typeof body.sha === 'string' && body.sha !== existing.oid) {
        apiError(res, 409, 'sha does not match the current blob');
        return;
      }
      if (existing === undefined && typeof body.sha === 'string' && body.sha !== '') {
        apiError(res, 422, 'sha was supplied for a file that does not exist');
        return;
      }
      const blobOid = storeObject('blob', data);
      flat.set(path, { mode: '100644', oid: blobOid });
      const commitOid = commitOnBranch(repo, branch, flat, body.message);
      sendJson(res, existing !== undefined ? 200 : 201, {
        content: { name: path.split('/').pop(), path, sha: blobOid, size: data.length, type: 'file', encoding: 'base64' },
        commit: { sha: commitOid, message: body.message },
      });
      return;
    }
    // DELETE
    if (existing === undefined) {
      apiError(res, 404, 'Not Found');
      return;
    }
    if (typeof body.sha === 'string' && body.sha !== existing.oid) {
      apiError(res, 409, 'sha does not match the current blob');
      return;
    }
    flat.delete(path);
    const commitOid = commitOnBranch(repo, branch, flat, body.message);
    sendJson(res, 200, { content: null, commit: { sha: commitOid, message: body.message } });
    return;
  }

  apiError(res, 404, 'Not Found');
}

function contentsEntryJson(repo: ForgeRepo, entry: TreeEntry, prefix: string): Record<string, unknown> {
  const object = getObject(entry.oid);
  return {
    type: entry.mode === '40000' ? 'dir' : 'file',
    name: entry.name,
    path: prefix === '' ? entry.name : `${prefix}/${entry.name}`,
    sha: entry.oid,
    size: entry.mode === '40000' ? 0 : (object?.data.length ?? 0),
    _repo: undefined,
    download_url: null,
  };
}

function restLabels(ctx: RestContext, repo: ForgeRepo, rest: string[]): void {
  const { req, res, body } = ctx;
  const method = req.method ?? 'GET';
  if (rest.length === 2 && method === 'GET') {
    sendJson(res, 200, [...repo.labels.values()].map(labelJson));
    return;
  }
  if (rest.length === 2 && method === 'POST') {
    if (!isRecord(body) || typeof body.name !== 'string' || body.name === '') {
      apiError(res, 422, 'name is required');
      return;
    }
    if (repo.labels.has(body.name)) {
      apiError(res, 422, 'name already exists');
      return;
    }
    const label: ForgeLabel = {
      id: nextLabelId,
      name: body.name,
      color: typeof body.color === 'string' ? body.color : 'ededed',
      description: typeof body.description === 'string' ? body.description : '',
    };
    nextLabelId += 1;
    repo.labels.set(label.name, label);
    sendJson(res, 201, labelJson(label));
    return;
  }
  apiError(res, 404, 'Not Found');
}

function labelNamesOf(repo: ForgeRepo, value: unknown): string[] | null {
  if (!Array.isArray(value)) return [];
  const names: string[] = [];
  for (const entry of value) {
    const name = typeof entry === 'string' ? entry : isRecord(entry) && typeof entry.name === 'string' ? entry.name : null;
    if (name === null) continue;
    if (!repo.labels.has(name)) return null;
    names.push(name);
  }
  return names;
}

function restIssues(ctx: RestContext, repo: ForgeRepo, rest: string[]): void {
  const { req, res, query, body } = ctx;
  const method = req.method ?? 'GET';

  if (rest.length === 2 && method === 'GET') {
    const state = query.get('state') ?? 'open';
    const direction = query.get('direction') ?? 'desc';
    let list = [...repo.issues.values()];
    if (state === 'open' || state === 'closed') list = list.filter((issue) => issue.state === state);
    list.sort((a, b) => (direction === 'asc' ? a.seq - b.seq : b.seq - a.seq));
    sendJson(res, 200, list.map((issue) => issueJson(repo, issue)));
    return;
  }

  if (rest.length === 2 && method === 'POST') {
    if (!isRecord(body) || typeof body.title !== 'string' || body.title === '') {
      apiError(res, 422, 'title is required');
      return;
    }
    const labels = labelNamesOf(repo, body.labels);
    if (labels === null) {
      apiError(res, 422, 'Validation Failed: one or more labels do not exist');
      return;
    }
    const issue = createIssue(repo, body.title, typeof body.body === 'string' ? body.body : '', labels);
    sendJson(res, 201, issueJson(repo, issue));
    return;
  }

  const number = Number.parseInt(rest[2] ?? '', 10);
  const issue = Number.isInteger(number) ? repo.issues.get(number) : undefined;

  if (rest.length === 3 && method === 'GET') {
    if (issue === undefined) {
      apiError(res, 404, 'Not Found');
      return;
    }
    sendJson(res, 200, issueJson(repo, issue));
    return;
  }

  if (rest.length === 3 && method === 'PATCH') {
    if (issue === undefined) {
      apiError(res, 404, 'Not Found');
      return;
    }
    if (isRecord(body)) {
      if (body.state === 'closed' || body.state === 'open') issue.state = body.state;
      if (typeof body.title === 'string') issue.title = body.title;
      if (typeof body.body === 'string') issue.body = body.body;
      if (body.labels !== undefined) {
        const labels = labelNamesOf(repo, body.labels);
        if (labels === null) {
          apiError(res, 422, 'Validation Failed: one or more labels do not exist');
          return;
        }
        issue.labels = labels;
      }
    }
    sendJson(res, 200, issueJson(repo, issue));
    return;
  }

  if (rest.length === 4 && rest[3] === 'comments') {
    if (issue === undefined) {
      apiError(res, 404, 'Not Found');
      return;
    }
    if (method === 'GET') {
      sendJson(res, 200, issue.comments.map(commentJson));
      return;
    }
    if (method === 'POST') {
      if (!isRecord(body) || typeof body.body !== 'string' || body.body === '') {
        apiError(res, 422, 'body is required');
        return;
      }
      const comment: IssueComment = { id: nextCommentId, body: body.body, author: VIEWER.login };
      nextCommentId += 1;
      issue.comments.push(comment);
      sendJson(res, 201, commentJson(comment));
      return;
    }
  }

  apiError(res, 404, 'Not Found');
}

function stripOwnerPrefix(ref: string): string {
  const colon = ref.indexOf(':');
  return colon >= 0 ? ref.slice(colon + 1) : ref;
}

function restPulls(ctx: RestContext, repo: ForgeRepo, rest: string[]): void {
  const { req, res, query, body } = ctx;
  const method = req.method ?? 'GET';

  if (rest.length === 2 && method === 'GET') {
    const state = query.get('state') ?? 'open';
    let list = [...repo.pulls.values()];
    if (state === 'open' || state === 'closed') list = list.filter((pull) => pull.state === state);
    list.sort((a, b) => a.number - b.number);
    sendJson(res, 200, list.map((pull) => pullJson(repo, pull)));
    return;
  }

  if (rest.length === 2 && method === 'POST') {
    if (!isRecord(body) || typeof body.title !== 'string' || typeof body.head !== 'string' || typeof body.base !== 'string') {
      apiError(res, 422, 'title, head and base are required');
      return;
    }
    const head = stripOwnerPrefix(body.head);
    const base = stripOwnerPrefix(body.base);
    if (branchTip(repo, head) === null || branchTip(repo, base) === null) {
      apiError(res, 422, 'Validation Failed: head or base branch does not exist');
      return;
    }
    const pull = createPull(repo, body.title, typeof body.body === 'string' ? body.body : '', head, base);
    if (pull === null) {
      apiError(res, 422, 'Validation Failed: a pull request already exists for this head and base');
      return;
    }
    sendJson(res, 201, pullJson(repo, pull));
    return;
  }

  const number = Number.parseInt(rest[2] ?? '', 10);
  const pull = Number.isInteger(number) ? repo.pulls.get(number) : undefined;

  if (rest.length === 3 && method === 'GET') {
    if (pull === undefined) {
      apiError(res, 404, 'Not Found');
      return;
    }
    sendJson(res, 200, pullJson(repo, pull));
    return;
  }

  if (rest.length === 4 && rest[3] === 'files' && method === 'GET') {
    if (pull === undefined) {
      apiError(res, 404, 'Not Found');
      return;
    }
    const baseTip = branchTip(repo, pull.baseRef);
    const headTip = branchTip(repo, pull.headRef);
    if (baseTip === null || headTip === null) {
      sendJson(res, 200, []);
      return;
    }
    const base = mergeBaseOf(baseTip, headTip) ?? baseTip;
    const baseFlat = flattenTree(parseCommit((getObject(base) as GitObject).data).tree);
    const headFlat = flattenTree(parseCommit((getObject(headTip) as GitObject).data).tree);
    const files = diffFlat(baseFlat, headFlat).map((change) => ({
      filename: change.path,
      status: change.status,
      additions: change.additions,
      deletions: change.deletions,
      changes: change.additions + change.deletions,
    }));
    sendJson(res, 200, files);
    return;
  }

  if (rest.length === 4 && rest[3] === 'merge' && method === 'PUT') {
    if (pull === undefined) {
      apiError(res, 404, 'Not Found');
      return;
    }
    const methodWanted = isRecord(body) && typeof body.merge_method === 'string' ? body.merge_method : 'merge';
    const outcome = mergePull(repo, pull, methodWanted);
    if (!outcome.ok) {
      if (outcome.reason === 'conflict') apiError(res, 405, 'Pull Request is not mergeable');
      else if (outcome.reason === 'not-open') apiError(res, 405, 'Pull Request is not open');
      else apiError(res, 404, 'Not Found');
      return;
    }
    sendJson(res, 200, { sha: outcome.sha, merged: true, message: 'Pull Request successfully merged' });
    return;
  }

  apiError(res, 404, 'Not Found');
}

/** The /api/v3 router. Every route needs the trial token; errors are JSON with a message. */
function handleRest(ctx: RestContext): void {
  const { req, res, segments } = ctx;
  const method = req.method ?? 'GET';
  if (!tokenAccepted(req)) {
    apiError(res, 401, 'Requires authentication');
    return;
  }
  if (segments.length === 0) {
    if (method === 'GET') {
      sendJson(
        res,
        200,
        {
          current_user_url: '/api/v3/user',
          repository_url: '/api/v3/repos/{owner}/{repo}',
          issue_search_url: '/api/v3/search/issues',
        },
        { 'x-oauth-scopes': 'repo, user, admin:org' },
      );
      return;
    }
    apiError(res, 404, 'Not Found');
    return;
  }
  if (segments[0] === 'meta' && segments.length === 1 && method === 'GET') {
    sendJson(res, 200, { installed_version: 'makefun-forge 1.0.0', hooks: [] });
    return;
  }
  if (segments[0] === 'user' && segments.length === 1 && method === 'GET') {
    sendJson(res, 200, userJson(VIEWER));
    return;
  }
  if (segments[0] === 'user' && segments[1] === 'repos') {
    if (method === 'POST' && segments.length === 2) {
      restCreateRepo(ctx);
      return;
    }
    if (method === 'GET' && segments.length === 2) {
      restListUserRepos(ctx);
      return;
    }
    apiError(res, 404, 'Not Found');
    return;
  }
  if (segments[0] === 'repos' && segments.length >= 3) {
    const owner = decodeURIComponent(segments[1] as string);
    const name = decodeURIComponent(segments[2] as string);
    const repo = findRepo(owner, name);
    if (repo === undefined) {
      apiError(res, 404, 'Not Found');
      return;
    }
    // Rewrite segments so repo routes see [repos, owner, name, ...rest].
    restRepoRoutes(ctx, repo);
    return;
  }
  apiError(res, 404, 'Not Found');
}

// -------------------------------------------------------------------------------------------------
// GraphQL v4 subset
// -------------------------------------------------------------------------------------------------

type GqlValue =
  | { kind: 'var'; name: string }
  | { kind: 'scalar'; value: string | number | boolean | null }
  | { kind: 'enum'; value: string }
  | { kind: 'list'; items: GqlValue[] }
  | { kind: 'object'; fields: Map<string, GqlValue> };

interface GqlField {
  alias: string | null;
  name: string;
  args: Map<string, GqlValue>;
  selection: GqlSelection[] | null;
}

type GqlSelection =
  | { kind: 'field'; field: GqlField }
  | { kind: 'spread'; name: string }
  | { kind: 'inline'; typeCondition: string | null; selection: GqlSelection[] };

interface GqlOperation {
  operation: 'query' | 'mutation';
  name: string | null;
  selection: GqlSelection[];
}

interface GqlDocument {
  operations: GqlOperation[];
  fragments: Map<string, { typeCondition: string | null; selection: GqlSelection[] }>;
}

function tokenizeGraphql(source: string): Array<{ kind: string; value: string }> {
  const tokens: Array<{ kind: string; value: string }> = [];
  let index = 0;
  while (index < source.length) {
    const char = source[index] as string;
    if (char === '#') {
      while (index < source.length && source[index] !== '\n') index += 1;
      continue;
    }
    if (/[\s,]/.test(char)) {
      index += 1;
      continue;
    }
    if (source.startsWith('...', index)) {
      tokens.push({ kind: 'spread', value: '...' });
      index += 3;
      continue;
    }
    if ('{}()[]:!=$@|&'.includes(char)) {
      tokens.push({ kind: 'punct', value: char });
      index += 1;
      continue;
    }
    if (char === '"') {
      if (source.startsWith('"""', index)) {
        const end = source.indexOf('"""', index + 3);
        tokens.push({ kind: 'string', value: source.slice(index + 3, end < 0 ? source.length : end) });
        index = end < 0 ? source.length : end + 3;
        continue;
      }
      let value = '';
      index += 1;
      while (index < source.length && source[index] !== '"') {
        if (source[index] === '\\') {
          const escaped = source[index + 1] ?? '';
          value += escaped === 'n' ? '\n' : escaped === 't' ? '\t' : escaped === 'r' ? '\r' : escaped;
          index += 2;
        } else {
          value += source[index];
          index += 1;
        }
      }
      index += 1;
      tokens.push({ kind: 'string', value });
      continue;
    }
    if (/[0-9-]/.test(char)) {
      let end = index;
      while (end < source.length && /[0-9.eE+-]/.test(source[end] as string)) end += 1;
      tokens.push({ kind: 'number', value: source.slice(index, end) });
      index = end;
      continue;
    }
    if (/[_A-Za-z]/.test(char)) {
      let end = index;
      while (end < source.length && /[_0-9A-Za-z]/.test(source[end] as string)) end += 1;
      tokens.push({ kind: 'name', value: source.slice(index, end) });
      index = end;
      continue;
    }
    index += 1;
  }
  return tokens;
}

function parseGraphql(source: string): GqlDocument {
  const tokens = tokenizeGraphql(source);
  let pos = 0;
  const peek = (): { kind: string; value: string } | undefined => tokens[pos];
  const next = (): { kind: string; value: string } => {
    const token = tokens[pos] as { kind: string; value: string };
    pos += 1;
    return token;
  };
  const expectPunct = (value: string): void => {
    const token = next();
    if (token.value !== value) throw new Error(`expected ${value}, got ${token.value}`);
  };

  function parseValue(): GqlValue {
    const token = next();
    if (token.kind === 'punct' && token.value === '$') {
      const name = next();
      return { kind: 'var', name: name.value };
    }
    if (token.kind === 'string') return { kind: 'scalar', value: token.value };
    if (token.kind === 'number') return { kind: 'scalar', value: Number(token.value) };
    if (token.kind === 'punct' && token.value === '[') {
      const items: GqlValue[] = [];
      while (peek()?.value !== ']') items.push(parseValue());
      next();
      return { kind: 'list', items };
    }
    if (token.kind === 'punct' && token.value === '{') {
      const fields = new Map<string, GqlValue>();
      while (peek()?.value !== '}') {
        const key = next();
        expectPunct(':');
        fields.set(key.value, parseValue());
      }
      next();
      return { kind: 'object', fields };
    }
    if (token.kind === 'name') {
      if (token.value === 'true') return { kind: 'scalar', value: true };
      if (token.value === 'false') return { kind: 'scalar', value: false };
      if (token.value === 'null') return { kind: 'scalar', value: null };
      return { kind: 'enum', value: token.value };
    }
    throw new Error(`unexpected value token ${token.value}`);
  }

  function skipBalanced(open: string, close: string): void {
    let depth = 0;
    for (;;) {
      const token = next();
      if (token === undefined) return;
      if (token.value === open) depth += 1;
      if (token.value === close) {
        depth -= 1;
        if (depth === 0) return;
      }
    }
  }

  function parseSelectionSet(): GqlSelection[] {
    expectPunct('{');
    const selections: GqlSelection[] = [];
    while (peek()?.value !== '}') {
      const token = peek();
      if (token === undefined) break;
      if (token.kind === 'spread') {
        next();
        const nameToken = next();
        if (nameToken.value === 'on') {
          const typeToken = next();
          selections.push({ kind: 'inline', typeCondition: typeToken.value, selection: parseSelectionSet() });
        } else {
          selections.push({ kind: 'spread', name: nameToken.value });
        }
        continue;
      }
      // a field
      let nameToken = next();
      let alias: string | null = null;
      if (peek()?.value === ':') {
        next();
        alias = nameToken.value;
        nameToken = next();
      }
      const args = new Map<string, GqlValue>();
      if (peek()?.value === '(') {
        skipBalancedArgs(args);
      }
      // directives: skip `@name` and an optional argument list
      while (peek()?.value === '@') {
        next();
        next();
        if (peek()?.value === '(') skipBalanced('(', ')');
      }
      let selection: GqlSelection[] | null = null;
      if (peek()?.value === '{') selection = parseSelectionSet();
      selections.push({ kind: 'field', field: { alias, name: nameToken.value, args, selection } });
    }
    next(); // }
    return selections;
  }

  function skipBalancedArgs(args: Map<string, GqlValue>): void {
    expectPunct('(');
    while (peek()?.value !== ')') {
      const key = next();
      expectPunct(':');
      args.set(key.value, parseValue());
    }
    next();
  }

  const operations: GqlOperation[] = [];
  const fragments = new Map<string, { typeCondition: string | null; selection: GqlSelection[] }>();
  while (pos < tokens.length) {
    const token = peek();
    if (token === undefined) break;
    if (token.value === '{') {
      operations.push({ operation: 'query', name: null, selection: parseSelectionSet() });
      continue;
    }
    if (token.kind === 'name' && (token.value === 'query' || token.value === 'mutation' || token.value === 'subscription')) {
      next();
      let name: string | null = null;
      if (peek()?.kind === 'name') name = next().value;
      if (peek()?.value === '(') skipBalanced('(', ')'); // variable definitions
      while (peek()?.value === '@') {
        next();
        next();
        if (peek()?.value === '(') skipBalanced('(', ')');
      }
      operations.push({ operation: token.value === 'mutation' ? 'mutation' : 'query', name, selection: parseSelectionSet() });
      continue;
    }
    if (token.kind === 'name' && token.value === 'fragment') {
      next();
      const nameToken = next();
      next(); // on
      const typeToken = next();
      fragments.set(nameToken.value, { typeCondition: typeToken.value, selection: parseSelectionSet() });
      continue;
    }
    next();
  }
  return { operations, fragments };
}

function resolveValue(value: GqlValue, variables: Readonly<Record<string, unknown>>): unknown {
  switch (value.kind) {
    case 'var':
      return variables[value.name] ?? null;
    case 'scalar':
      return value.value;
    case 'enum':
      return value.value;
    case 'list':
      return value.items.map((item) => resolveValue(item, variables));
    case 'object': {
      const out: Record<string, unknown> = {};
      for (const [key, entry] of value.fields) out[key] = resolveValue(entry, variables);
      return out;
    }
  }
}

function argsOf(field: GqlField, variables: Readonly<Record<string, unknown>>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of field.args) out[key] = resolveValue(value, variables);
  return out;
}

// ---- global ids ---------------------------------------------------------------------------------

function globalId(type: string, key: string): string {
  return Buffer.from(`${type}:${key}`, 'utf8').toString('base64');
}

function decodeGlobalId(id: string): { type: string; key: string } | null {
  try {
    const text = Buffer.from(id, 'base64').toString('utf8');
    const colon = text.indexOf(':');
    if (colon < 0) return null;
    return { type: text.slice(0, colon), key: text.slice(colon + 1) };
  } catch {
    return null;
  }
}

function repoByDbId(dbId: number): ForgeRepo | undefined {
  for (const repo of repos.values()) if (repo.id === dbId) return repo;
  return undefined;
}

// ---- typed GraphQL values ------------------------------------------------------------------------

class GqlObj {
  readonly typename: string;
  readonly data: Record<string, unknown>;
  constructor(typename: string, data: Record<string, unknown>) {
    this.typename = typename;
    this.data = data;
  }
}

const SCHEMA_FIELDS: Readonly<Record<string, readonly string[]>> = {
  Query: ['viewer', 'repository', 'node', 'nodes', '__type', '__schema', 'search', 'user', 'organization'],
  Mutation: ['createIssue', 'closeIssue', 'createPullRequest', 'mergePullRequest', 'addComment', 'updateIssue', 'reopenIssue'],
  User: ['login', 'id', 'name', 'email', 'url'],
  Repository: [
    'id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission',
    'hasIssuesEnabled', 'hasProjectsEnabled', 'isPrivate', 'description', 'issue', 'issues',
    'pullRequest', 'pullRequests', 'labels', 'url', 'createdAt', 'updatedAt',
  ],
  Ref: ['name', 'target'],
  Issue: ['id', 'number', 'title', 'state', 'body', 'author', 'labels', 'comments', 'createdAt', 'updatedAt', 'url', 'repository'],
  PullRequest: [
    'id', 'number', 'title', 'body', 'state', 'merged', 'mergedAt', 'mergeable', 'headRefName',
    'baseRefName', 'headRef', 'baseRef', 'files', 'author', 'createdAt', 'updatedAt', 'url', 'repository',
  ],
  PullRequestChangedFile: ['path', 'additions', 'deletions', 'changeType'],
  IssueConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  PullRequestConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  PullRequestChangedFileConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  PageInfo: ['hasNextPage', 'hasPreviousPage', 'startCursor', 'endCursor'],
  CreateIssuePayload: ['issue', 'clientMutationId'],
  CloseIssuePayload: ['issue', 'clientMutationId'],
  CreatePullRequestPayload: ['pullRequest', 'clientMutationId'],
  MergePullRequestPayload: ['pullRequest', 'clientMutationId'],
  AddCommentPayload: ['commentEdge', 'clientMutationId', 'subject'],
  CommentEdge: ['node', 'cursor'],
  IssueComment: ['id', 'body', 'author', 'createdAt', 'url'],
  __Type: ['name', 'kind', 'description', 'fields', 'enumValues', 'possibleTypes', 'inputFields', 'ofType'],
  __Field: ['name', 'description', 'type', 'args', 'isDeprecated'],
  __EnumValue: ['name', 'description', 'isDeprecated'],
  __Schema: ['queryType', 'mutationType', 'types', 'directives'],
  Label: ['id', 'name', 'color', 'description'],
  LabelConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
};

const ENUM_TYPES: Readonly<Record<string, readonly string[]>> = {
  SearchType: ['ISSUE', 'PULL_REQUEST', 'REPOSITORY', 'USER', 'DISCUSSION', 'COMMIT', 'CODE'],
  IssueState: ['OPEN', 'CLOSED'],
  PullRequestState: ['OPEN', 'CLOSED', 'MERGED'],
  MergeableState: ['MERGEABLE', 'CONFLICTING', 'UNKNOWN'],
  PullRequestMergeMethod: ['MERGE', 'SQUASH', 'REBASE'],
  RepositoryPermission: ['ADMIN', 'MAINTAIN', 'WRITE', 'TRIAGE', 'READ'],
  IssueOrderField: ['CREATED_AT', 'UPDATED_AT', 'COMMENTS'],
  OrderDirection: ['ASC', 'DESC'],
};

function typeInfo(name: string): GqlObj | null {
  if (ENUM_TYPES[name] !== undefined) {
    return new GqlObj('__Type', {
      name,
      kind: 'ENUM',
      fields: null,
      enumValues: (ENUM_TYPES[name] as readonly string[]).map((value) => new GqlObj('__EnumValue', { name: value })),
    });
  }
  const fields = SCHEMA_FIELDS[name];
  if (fields === undefined) return null;
  return new GqlObj('__Type', {
    name,
    kind: 'OBJECT',
    fields: fields.map((fieldName) => new GqlObj('__Field', { name: fieldName })),
    enumValues: null,
  });
}

function cursorOf(index: number): string {
  return Buffer.from(`cursor:${index}`, 'utf8').toString('base64');
}

function indexOfCursor(cursor: unknown): number {
  if (typeof cursor !== 'string' || cursor === '') return 0;
  try {
    const text = Buffer.from(cursor, 'base64').toString('utf8');
    const match = /^cursor:(\d+)$/.exec(text);
    return match !== null ? Number.parseInt(match[1] as string, 10) : 0;
  } catch {
    return 0;
  }
}

interface ConnectionResult {
  nodes: unknown[];
  pageInfo: GqlObj;
  totalCount: number;
}

function paginate(items: unknown[], args: Record<string, unknown>): ConnectionResult {
  const first = typeof args.first === 'number' && Number.isFinite(args.first) ? Math.max(0, Math.trunc(args.first)) : items.length;
  const start = args.after !== undefined && args.after !== null ? indexOfCursor(args.after) : 0;
  const nodes = items.slice(start, start + first);
  const endIndex = start + nodes.length;
  return {
    nodes,
    pageInfo: new GqlObj('PageInfo', {
      hasNextPage: endIndex < items.length,
      hasPreviousPage: start > 0,
      startCursor: nodes.length > 0 ? cursorOf(start) : null,
      endCursor: nodes.length > 0 ? cursorOf(endIndex) : null,
    }),
    totalCount: items.length,
  };
}

function repoGql(repo: ForgeRepo): GqlObj {
  return new GqlObj('Repository', { repo });
}

function issueGql(repo: ForgeRepo, issue: ForgeIssue): GqlObj {
  return new GqlObj('Issue', {
    id: globalId('Issue', `${repo.id}:${issue.number}`),
    number: issue.number,
    title: issue.title,
    state: issue.state === 'open' ? 'OPEN' : 'CLOSED',
    body: issue.body,
    repoRef: repo,
    issueRef: issue,
  });
}

function pullGql(repo: ForgeRepo, pull: ForgePull): GqlObj {
  return new GqlObj('PullRequest', {
    id: globalId('PullRequest', `${repo.id}:${pull.number}`),
    number: pull.number,
    title: pull.title,
    body: pull.body,
    state: pull.merged ? 'MERGED' : pull.state === 'open' ? 'OPEN' : 'CLOSED',
    merged: pull.merged,
    mergedAt: pull.mergedAt,
    headRefName: pull.headRef,
    baseRefName: pull.baseRef,
    mergeable: pull.state === 'open' ? (pullConflict(repo, pull) ? 'CONFLICTING' : 'MERGEABLE') : 'UNKNOWN',
    repoRef: repo,
    pullRef: pull,
  });
}

function resolveRepoField(repo: ForgeRepo, field: GqlField, variables: Readonly<Record<string, unknown>>): unknown {
  const args = argsOf(field, variables);
  switch (field.name) {
    case 'id':
      return globalId('Repository', String(repo.id));
    case 'databaseId':
      return repo.id;
    case 'name':
      return repo.name;
    case 'nameWithOwner':
      return `${repo.owner}/${repo.name}`;
    case 'owner':
      return new GqlObj('User', { login: repo.owner, id: globalId('User', String(VIEWER.id)), name: VIEWER.name });
    case 'defaultBranchRef': {
      if (repo.refs.size === 0) return null;
      return new GqlObj('Ref', { name: repo.defaultBranch });
    }
    case 'viewerPermission':
      return 'ADMIN';
    case 'hasIssuesEnabled':
    case 'hasProjectsEnabled':
      return true;
    case 'isPrivate':
      return repo.isPrivate;
    case 'description':
      return repo.description;
    case 'issue': {
      const number = typeof args.number === 'number' ? args.number : -1;
      const issue = repo.issues.get(number);
      return issue === undefined ? null : issueGql(repo, issue);
    }
    case 'issues': {
      let list = [...repo.issues.values()];
      const states = Array.isArray(args.states) ? (args.states as unknown[]).map((state) => String(state)) : null;
      if (states !== null) list = list.filter((issue) => states.includes(issue.state === 'open' ? 'OPEN' : 'CLOSED'));
      const orderBy = isRecord(args.orderBy) ? args.orderBy : null;
      const direction = orderBy !== null && typeof orderBy.direction === 'string' ? orderBy.direction : 'DESC';
      list.sort((a, b) => (direction === 'ASC' ? a.number - b.number : b.number - a.number));
      const page = paginate(list.map((issue) => issueGql(repo, issue)), args);
      return new GqlObj('IssueConnection', page as unknown as Record<string, unknown>);
    }
    case 'pullRequest': {
      const number = typeof args.number === 'number' ? args.number : -1;
      const pull = repo.pulls.get(number);
      return pull === undefined ? null : pullGql(repo, pull);
    }
    case 'pullRequests': {
      let list = [...repo.pulls.values()];
      const states = Array.isArray(args.states) ? (args.states as unknown[]).map((state) => String(state)) : null;
      if (states !== null) {
        list = list.filter((pull) => states.includes(pull.merged ? 'MERGED' : pull.state === 'open' ? 'OPEN' : 'CLOSED'));
      }
      list.sort((a, b) => b.number - a.number);
      const page = paginate(list.map((pull) => pullGql(repo, pull)), args);
      return new GqlObj('PullRequestConnection', page as unknown as Record<string, unknown>);
    }
    default:
      return null;
  }
}

function resolvePullField(repo: ForgeRepo, pull: ForgePull, field: GqlField, variables: Readonly<Record<string, unknown>>): unknown {
  if (field.name === 'files') {
    const args = argsOf(field, variables);
    const baseTip = branchTip(repo, pull.baseRef);
    const headTip = branchTip(repo, pull.headRef);
    let nodes: GqlObj[] = [];
    if (baseTip !== null && headTip !== null) {
      const base = mergeBaseOf(baseTip, headTip) ?? baseTip;
      const baseFlat = flattenTree(parseCommit((getObject(base) as GitObject).data).tree);
      const headFlat = flattenTree(parseCommit((getObject(headTip) as GitObject).data).tree);
      nodes = diffFlat(baseFlat, headFlat).map(
        (change) => new GqlObj('PullRequestChangedFile', { path: change.path, additions: change.additions, deletions: change.deletions }),
      );
    }
    const page = paginate(nodes, args);
    return new GqlObj('PullRequestChangedFileConnection', page as unknown as Record<string, unknown>);
  }
  return null;
}

function repoFromGlobalId(id: unknown): ForgeRepo | null {
  if (typeof id !== 'string') return null;
  const decoded = decodeGlobalId(id);
  if (decoded === null) return null;
  if (decoded.type === 'Repository') return repoByDbId(Number(decoded.key)) ?? null;
  return null;
}

function issueFromGlobalId(id: unknown): { repo: ForgeRepo; issue: ForgeIssue } | null {
  if (typeof id !== 'string') return null;
  const decoded = decodeGlobalId(id);
  if (decoded === null || decoded.type !== 'Issue') return null;
  const [repoId, number] = decoded.key.split(':').map((part) => Number(part));
  const repo = repoId !== undefined ? repoByDbId(repoId) : undefined;
  if (repo === undefined || number === undefined) return null;
  const issue = repo.issues.get(number);
  return issue === undefined ? null : { repo, issue };
}

function pullFromGlobalId(id: unknown): { repo: ForgeRepo; pull: ForgePull } | null {
  if (typeof id !== 'string') return null;
  const decoded = decodeGlobalId(id);
  if (decoded === null || decoded.type !== 'PullRequest') return null;
  const [repoId, number] = decoded.key.split(':').map((part) => Number(part));
  const repo = repoId !== undefined ? repoByDbId(repoId) : undefined;
  if (repo === undefined || number === undefined) return null;
  const pull = repo.pulls.get(number);
  return pull === undefined ? null : { repo, pull };
}

function nodeByGlobalId(id: unknown): GqlObj | null {
  if (typeof id !== 'string') return null;
  const decoded = decodeGlobalId(id);
  if (decoded === null) return null;
  if (decoded.type === 'Repository') {
    const repo = repoByDbId(Number(decoded.key));
    return repo === undefined ? null : repoGql(repo);
  }
  if (decoded.type === 'Issue') {
    const found = issueFromGlobalId(id);
    return found === null ? null : issueGql(found.repo, found.issue);
  }
  if (decoded.type === 'PullRequest') {
    const found = pullFromGlobalId(id);
    return found === null ? null : pullGql(found.repo, found.pull);
  }
  if (decoded.type === 'User') return new GqlObj('User', { login: VIEWER.login, id, name: VIEWER.name });
  return null;
}

interface GqlExecContext {
  doc: GqlDocument;
  variables: Readonly<Record<string, unknown>>;
  errors: Array<{ message: string }>;
}

function resolveField(obj: GqlObj, field: GqlField, ctx: GqlExecContext): unknown {
  if (field.name === '__typename') return obj.typename;
  const known = SCHEMA_FIELDS[obj.typename];
  if (known !== undefined && !known.includes(field.name)) {
    ctx.errors.push({ message: `Field '${field.name}' doesn't exist on type '${obj.typename}'` });
    return null;
  }
  const args = argsOf(field, ctx.variables);
  if (obj.typename === 'Query') {
    switch (field.name) {
      case 'viewer':
        return new GqlObj('User', { login: VIEWER.login, id: globalId('User', String(VIEWER.id)), name: VIEWER.name });
      case 'repository': {
        const repo = typeof args.owner === 'string' && typeof args.name === 'string' ? findRepo(args.owner, args.name) : undefined;
        return repo === undefined ? null : repoGql(repo);
      }
      case 'node':
        return nodeByGlobalId(args.id);
      case '__type':
        return typeof args.name === 'string' ? typeInfo(args.name) : null;
      case '__schema':
        return new GqlObj('__Schema', { queryType: typeInfo('Query'), mutationType: typeInfo('Mutation') });
      case 'user':
        return args.login === VIEWER.login ? new GqlObj('User', { login: VIEWER.login, id: globalId('User', String(VIEWER.id)), name: VIEWER.name }) : null;
      default:
        return null;
    }
  }
  if (obj.typename === 'Mutation') {
    const input = isRecord(args.input) ? args.input : {};
    switch (field.name) {
      case 'createIssue': {
        const repo = repoFromGlobalId(input.repositoryId);
        if (repo === null || typeof input.title !== 'string') {
          ctx.errors.push({ message: 'createIssue: repository not found or title missing' });
          return null;
        }
        const issue = createIssue(repo, input.title, typeof input.body === 'string' ? input.body : '', []);
        return new GqlObj('CreateIssuePayload', { issue: issueGql(repo, issue) });
      }
      case 'closeIssue': {
        const found = issueFromGlobalId(input.issueId);
        if (found === null) {
          ctx.errors.push({ message: 'closeIssue: issue not found' });
          return null;
        }
        found.issue.state = 'closed';
        return new GqlObj('CloseIssuePayload', { issue: issueGql(found.repo, found.issue) });
      }
      case 'createPullRequest': {
        const repo = repoFromGlobalId(input.repositoryId);
        if (repo === null || typeof input.baseRefName !== 'string' || typeof input.headRefName !== 'string') {
          ctx.errors.push({ message: 'createPullRequest: repository or refs missing' });
          return null;
        }
        const head = stripOwnerPrefix(input.headRefName);
        const base = stripOwnerPrefix(input.baseRefName);
        let pull = createPull(repo, typeof input.title === 'string' ? input.title : '', typeof input.body === 'string' ? input.body : '', head, base);
        if (pull === null) {
          pull = [...repo.pulls.values()].find((candidate) => candidate.headRef === head && candidate.baseRef === base) ?? null;
        }
        if (pull === null) {
          ctx.errors.push({ message: 'createPullRequest: branches do not exist' });
          return null;
        }
        return new GqlObj('CreatePullRequestPayload', { pullRequest: pullGql(repo, pull) });
      }
      case 'mergePullRequest': {
        const found = pullFromGlobalId(input.pullRequestId);
        if (found === null) {
          ctx.errors.push({ message: 'mergePullRequest: pull request not found' });
          return null;
        }
        const method = typeof input.mergeMethod === 'string' ? input.mergeMethod.toLowerCase() : 'merge';
        const outcome = mergePull(found.repo, found.pull, method);
        if (!outcome.ok) ctx.errors.push({ message: `mergePullRequest: ${outcome.reason}` });
        return new GqlObj('MergePullRequestPayload', { pullRequest: pullGql(found.repo, found.pull) });
      }
      case 'addComment': {
        const found = issueFromGlobalId(input.subjectId);
        if (found === null || typeof input.body !== 'string') {
          ctx.errors.push({ message: 'addComment: subject not found or body missing' });
          return null;
        }
        const comment: IssueComment = { id: nextCommentId, body: input.body, author: VIEWER.login };
        nextCommentId += 1;
        found.issue.comments.push(comment);
        const node = new GqlObj('IssueComment', {
          id: globalId('IssueComment', `${found.repo.id}:${found.issue.number}:${comment.id}`),
          body: comment.body,
        });
        return new GqlObj('AddCommentPayload', { commentEdge: new GqlObj('CommentEdge', { node, cursor: cursorOf(0) }) });
      }
      default:
        return null;
    }
  }
  if (obj.typename === 'Repository') {
    const repo = obj.data.repo as ForgeRepo;
    return resolveRepoField(repo, field, ctx.variables);
  }
  if (obj.typename === 'PullRequest' && field.name === 'files') {
    return resolvePullField(obj.data.repoRef as ForgeRepo, obj.data.pullRef as ForgePull, field, ctx.variables);
  }
  return field.name in obj.data ? obj.data[field.name] : null;
}

function completeValue(value: unknown, selection: GqlSelection[] | null, ctx: GqlExecContext): unknown {
  if (value === null || value === undefined) return null;
  if (Array.isArray(value)) return value.map((entry) => completeValue(entry, selection, ctx));
  if (value instanceof GqlObj) {
    if (selection === null) return value.data;
    return executeSelectionSet(value, selection, ctx);
  }
  return value;
}

function executeSelectionSet(obj: GqlObj, selections: readonly GqlSelection[], ctx: GqlExecContext): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const selection of selections) {
    if (selection.kind === 'field') {
      const key = selection.field.alias ?? selection.field.name;
      out[key] = completeValue(resolveField(obj, selection.field, ctx), selection.field.selection, ctx);
    } else if (selection.kind === 'spread') {
      const fragment = ctx.doc.fragments.get(selection.name);
      if (fragment !== undefined && (fragment.typeCondition === null || fragment.typeCondition === obj.typename || fragment.typeCondition === 'Node')) {
        Object.assign(out, executeSelectionSet(obj, fragment.selection, ctx));
      }
    } else if (selection.kind === 'inline') {
      if (selection.typeCondition === null || selection.typeCondition === obj.typename || selection.typeCondition === 'Node') {
        Object.assign(out, executeSelectionSet(obj, selection.selection, ctx));
      }
    }
  }
  return out;
}

function executeGraphqlOperation(document: GqlDocument, operationName: string | null, variables: Readonly<Record<string, unknown>>): Record<string, unknown> {
  const errors: Array<{ message: string }> = [];
  let operation: GqlOperation | undefined;
  if (operationName !== null) operation = document.operations.find((candidate) => candidate.name === operationName);
  if (operation === undefined) operation = document.operations[0];
  if (operation === undefined) return { data: null, errors: [{ message: 'no operation in document' }] };
  const root = new GqlObj(operation.operation === 'mutation' ? 'Mutation' : 'Query', {});
  const ctx: GqlExecContext = { doc: document, variables, errors };
  const data = executeSelectionSet(root, operation.selection, ctx);
  const envelope: Record<string, unknown> = { data };
  if (errors.length > 0) envelope.errors = errors;
  return envelope;
}

function handleGraphql(req: IncomingMessage, res: ServerResponse, raw: Buffer): void {
  if (!tokenAccepted(req)) {
    apiError(res, 401, 'Requires authentication');
    return;
  }
  const body = parseJsonBody(raw);
  if (body === INVALID_JSON || body === undefined) {
    sendJson(res, 200, { data: null, errors: [{ message: 'request body is not valid JSON' }] });
    return;
  }
  const runOne = (entry: unknown): Record<string, unknown> => {
    if (!isRecord(entry) || typeof entry.query !== 'string') return { data: null, errors: [{ message: 'query is required' }] };
    let document: GqlDocument;
    try {
      document = parseGraphql(entry.query);
    } catch (err) {
      return { data: null, errors: [{ message: err instanceof Error ? err.message : 'parse error' }] };
    }
    const variables = isRecord(entry.variables) ? entry.variables : {};
    const operationName = typeof entry.operationName === 'string' ? entry.operationName : null;
    return executeGraphqlOperation(document, operationName, variables);
  };
  if (Array.isArray(body)) {
    sendJson(res, 200, body.map(runOne));
    return;
  }
  sendJson(res, 200, runOne(body));
}

// -------------------------------------------------------------------------------------------------
// MCP endpoint (streamable HTTP)
// -------------------------------------------------------------------------------------------------

const MCP_SERVER_INFO = { name: 'makefun-forge', version: '1.0.0' };
const MCP_SUPPORTED_VERSIONS = ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];

interface McpToolDef {
  name: string;
  description: string;
  properties: Record<string, Record<string, unknown>>;
  required: string[];
}

const MCP_TOOLS: readonly McpToolDef[] = [
  {
    name: 'create_repo',
    description: 'Create a new repository for the authenticated user.',
    properties: {
      name: { type: 'string', description: 'The repository name.' },
      description: { type: 'string', description: 'A short description of the repository.' },
      private: { type: 'boolean', description: 'Whether the repository is private.' },
    },
    required: ['name'],
  },
  {
    name: 'get_repo',
    description: 'Get a repository by owner and name.',
    properties: {
      owner: { type: 'string', description: 'The repository owner login.' },
      repo: { type: 'string', description: 'The repository name.' },
      full_name: { type: 'string', description: 'The full name, owner/repo.' },
    },
    required: ['owner', 'repo'],
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    properties: {
      owner: { type: 'string', description: 'The repository owner login.' },
      repo: { type: 'string', description: 'The repository name.' },
      title: { type: 'string', description: 'The issue title.' },
      body: { type: 'string', description: 'The issue body.' },
      labels: { type: 'array', items: { type: 'string' }, description: 'Label names to apply.' },
    },
    required: ['owner', 'repo', 'title'],
  },
  {
    name: 'list_issues',
    description: 'List the issues of a repository.',
    properties: {
      owner: { type: 'string', description: 'The repository owner login.' },
      repo: { type: 'string', description: 'The repository name.' },
      state: { type: 'string', description: 'open, closed or all.' },
    },
    required: ['owner', 'repo'],
  },
  {
    name: 'get_issue',
    description: 'Get one issue by number.',
    properties: {
      owner: { type: 'string', description: 'The repository owner login.' },
      repo: { type: 'string', description: 'The repository name.' },
      issue_number: { type: 'number', description: 'The issue number.' },
    },
    required: ['owner', 'repo', 'issue_number'],
  },
  {
    name: 'create_pull_request',
    description: 'Create a pull request from a head branch into a base branch.',
    properties: {
      owner: { type: 'string', description: 'The repository owner login.' },
      repo: { type: 'string', description: 'The repository name.' },
      title: { type: 'string', description: 'The pull request title.' },
      body: { type: 'string', description: 'The pull request body.' },
      head: { type: 'string', description: 'The head branch name.' },
      base: { type: 'string', description: 'The base branch name.' },
    },
    required: ['owner', 'repo', 'title', 'head', 'base'],
  },
  {
    name: 'list_pull_requests',
    description: 'List the pull requests of a repository.',
    properties: {
      owner: { type: 'string', description: 'The repository owner login.' },
      repo: { type: 'string', description: 'The repository name.' },
      state: { type: 'string', description: 'open, closed or all.' },
    },
    required: ['owner', 'repo'],
  },
  {
    name: 'merge_pull_request',
    description: 'Merge a pull request by number.',
    properties: {
      owner: { type: 'string', description: 'The repository owner login.' },
      repo: { type: 'string', description: 'The repository name.' },
      pull_number: { type: 'number', description: 'The pull request number.' },
    },
    required: ['owner', 'repo', 'pull_number'],
  },
];

function mcpToolsList(): unknown {
  return {
    tools: MCP_TOOLS.map((tool) => ({
      name: tool.name,
      description: tool.description,
      inputSchema: { type: 'object', properties: tool.properties, required: tool.required },
    })),
  };
}

function toolResult(value: unknown): Record<string, unknown> {
  return { content: [{ type: 'text', text: JSON.stringify(value) }], structuredContent: value, isError: false };
}

function toolError(message: string): Record<string, unknown> {
  return { content: [{ type: 'text', text: message }], isError: true };
}

function repoForTool(args: Record<string, unknown>): ForgeRepo | null {
  let owner = typeof args.owner === 'string' ? args.owner : '';
  let repo = typeof args.repo === 'string' ? args.repo : '';
  if ((owner === '' || repo === '') && typeof args.full_name === 'string' && args.full_name.includes('/')) {
    const [namedOwner, namedRepo] = args.full_name.split('/', 2);
    if (owner === '') owner = namedOwner as string;
    if (repo === '') repo = namedRepo as string;
  }
  if (owner === '' || repo === '') return null;
  return findRepo(owner, repo) ?? null;
}

function runMcpTool(name: string, args: Record<string, unknown>): Record<string, unknown> {
  switch (name) {
    case 'create_repo': {
      const repoName = String(args.name ?? '');
      const existing = findRepo(VIEWER.login, repoName);
      if (existing !== undefined) return toolResult(repoJson(existing));
      const repo = createRepo(VIEWER.login, repoName, typeof args.description === 'string' ? args.description : '', args.private !== false);
      return repo === null ? toolError('repository already exists') : toolResult(repoJson(repo));
    }
    case 'get_repo': {
      const repo = repoForTool(args);
      return repo === null ? toolError('repository not found') : toolResult(repoJson(repo));
    }
    case 'create_issue': {
      const repo = repoForTool(args);
      if (repo === null) return toolError('repository not found');
      const labels = labelNamesOf(repo, args.labels) ?? [];
      const issue = createIssue(repo, String(args.title ?? ''), typeof args.body === 'string' ? args.body : '', labels);
      return toolResult(issueJson(repo, issue));
    }
    case 'list_issues': {
      const repo = repoForTool(args);
      if (repo === null) return toolError('repository not found');
      const state = typeof args.state === 'string' ? args.state : 'open';
      let list = [...repo.issues.values()];
      if (state === 'open' || state === 'closed') list = list.filter((issue) => issue.state === state);
      list.sort((a, b) => a.number - b.number);
      return toolResult(list.map((issue) => issueJson(repo, issue)));
    }
    case 'get_issue': {
      const repo = repoForTool(args);
      if (repo === null) return toolError('repository not found');
      const issue = repo.issues.get(typeof args.issue_number === 'number' ? args.issue_number : -1);
      return issue === undefined ? toolError('issue not found') : toolResult(issueJson(repo, issue));
    }
    case 'create_pull_request': {
      const repo = repoForTool(args);
      if (repo === null) return toolError('repository not found');
      const head = stripOwnerPrefix(String(args.head ?? ''));
      const base = stripOwnerPrefix(String(args.base ?? ''));
      const pull = createPull(repo, String(args.title ?? ''), typeof args.body === 'string' ? args.body : '', head, base);
      if (pull === null) {
        const existing = [...repo.pulls.values()].find((candidate) => candidate.headRef === head && candidate.baseRef === base && candidate.state === 'open');
        return existing !== undefined ? toolResult(pullJson(repo, existing)) : toolError('could not create the pull request (branches missing or it already exists)');
      }
      return toolResult(pullJson(repo, pull));
    }
    case 'list_pull_requests': {
      const repo = repoForTool(args);
      if (repo === null) return toolError('repository not found');
      const state = typeof args.state === 'string' ? args.state : 'open';
      let list = [...repo.pulls.values()];
      if (state === 'open' || state === 'closed') list = list.filter((pull) => pull.state === state);
      list.sort((a, b) => a.number - b.number);
      return toolResult(list.map((pull) => pullJson(repo, pull)));
    }
    case 'merge_pull_request': {
      const repo = repoForTool(args);
      if (repo === null) return toolError('repository not found');
      const pull = repo.pulls.get(typeof args.pull_number === 'number' ? args.pull_number : -1);
      if (pull === undefined) return toolError('pull request not found');
      const outcome = mergePull(repo, pull, 'merge');
      if (!outcome.ok) return toolError(`could not merge: ${outcome.reason}`);
      return toolResult(pullJson(repo, pull));
    }
    default:
      return toolError(`unknown tool ${name}`);
  }
}

function handleMcp(req: IncomingMessage, res: ServerResponse, raw: Buffer): void {
  if (req.method === 'DELETE') {
    sendJson(res, 200, {});
    return;
  }
  if (!tokenAccepted(req)) {
    apiError(res, 401, 'Requires authentication');
    return;
  }
  const body = parseJsonBody(raw);
  if (body === INVALID_JSON || body === undefined || !isRecord(body)) {
    sendJson(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
    return;
  }
  const id = 'id' in body ? body.id : undefined;
  const method = typeof body.method === 'string' ? body.method : '';
  const params = isRecord(body.params) ? body.params : {};
  const reply = (result: unknown): void => sendJson(res, 200, { jsonrpc: '2.0', id: id ?? null, result });
  const replyError = (code: number, message: string): void => sendJson(res, 200, { jsonrpc: '2.0', id: id ?? null, error: { code, message } });

  if (id === undefined) {
    // A notification: accepted, no body owed.
    res.writeHead(202, { 'x-github-request-id': `FORGE-${(++requestSeq).toString(16).toUpperCase().padStart(6, '0')}` });
    res.end();
    return;
  }
  switch (method) {
    case 'server/discover':
      reply({
        resultType: 'complete',
        supportedVersions: MCP_SUPPORTED_VERSIONS,
        capabilities: { tools: {} },
        serverInfo: MCP_SERVER_INFO,
      });
      return;
    case 'initialize': {
      const offered = typeof params.protocolVersion === 'string' ? params.protocolVersion : '';
      const chosen = MCP_SUPPORTED_VERSIONS.includes(offered) ? offered : '2025-11-25';
      res.setHeader('mcp-session-id', 'forge-session');
      reply({ protocolVersion: chosen, capabilities: { tools: {} }, serverInfo: MCP_SERVER_INFO });
      return;
    }
    case 'ping':
      reply({});
      return;
    case 'tools/list':
      reply(mcpToolsList());
      return;
    case 'tools/call': {
      const toolName = typeof params.name === 'string' ? params.name : '';
      const tool = MCP_TOOLS.find((candidate) => candidate.name === toolName);
      if (tool === undefined) {
        replyError(-32602, `unknown tool: ${toolName}`);
        return;
      }
      const args = isRecord(params.arguments) ? params.arguments : {};
      const missing = tool.required.filter((key) => args[key] === undefined || args[key] === null || args[key] === '');
      if (missing.length > 0) {
        replyError(-32602, `missing required argument(s): ${missing.join(', ')}`);
        return;
      }
      reply(runMcpTool(toolName, args));
      return;
    }
    default:
      replyError(-32601, `method not found: ${method}`);
  }
}

// -------------------------------------------------------------------------------------------------
// the server
// -------------------------------------------------------------------------------------------------

export function createApp(): Server {
  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    void (async (): Promise<void> => {
      try {
        const url = new URL(req.url ?? '/', 'http://entry');
        const path = url.pathname;
        const method = req.method ?? 'GET';

        if (method === 'GET' && path === '/healthz') {
          sendJson(res, 200, { ok: true });
          return;
        }

        const needsBody = method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE';
        const raw = needsBody ? await readBody(req) : Buffer.alloc(0);

        if (path === '/api/graphql') {
          if (method !== 'POST') {
            apiError(res, 404, 'Not Found');
            return;
          }
          handleGraphql(req, res, raw);
          return;
        }

        if (path === '/mcp') {
          if (method === 'POST' || method === 'DELETE') {
            handleMcp(req, res, raw);
            return;
          }
          apiError(res, 405, 'Method Not Allowed');
          return;
        }

        if (path === '/api/v3' || path.startsWith('/api/v3/')) {
          const segments = path
            .slice('/api/v3'.length)
            .split('/')
            .filter((segment) => segment !== '');
          let body: unknown;
          if (needsBody && raw.length > 0) {
            body = parseJsonBody(raw);
            if (body === INVALID_JSON) {
              apiError(res, 400, 'Invalid JSON');
              return;
            }
          }
          handleRest({ req, res, segments, query: url.searchParams, body });
          return;
        }

        const gitMatch = /^\/([^/]+)\/([^/]+)\.git(\/.*)?$/.exec(path);
        if (gitMatch !== null) {
          const owner = decodeURIComponent(gitMatch[1] as string);
          const name = decodeURIComponent(gitMatch[2] as string);
          const suffix = gitMatch[3] ?? '';
          const repo = findRepo(owner, name);
          if (repo === undefined) {
            apiError(res, 404, 'Not Found');
            return;
          }
          if (!tokenAccepted(req)) {
            apiError(res, 401, 'Requires authentication');
            return;
          }
          if (method === 'GET' && suffix === '/info/refs') {
            const service = url.searchParams.get('service') ?? '';
            if (service === 'git-upload-pack') {
              const protocol = req.headers['git-protocol'] ?? '';
              if (protocol.includes('version=2')) sendRaw(res, 200, v2Advertisement(), 'application/x-git-upload-pack-advertisement');
              else sendRaw(res, 200, v0Advertisement(repo, service), 'application/x-git-upload-pack-advertisement');
              return;
            }
            if (service === 'git-receive-pack') {
              sendRaw(res, 200, v0Advertisement(repo, service), 'application/x-git-receive-pack-advertisement');
              return;
            }
            apiError(res, 400, 'unknown service');
            return;
          }
          if (method === 'POST' && suffix === '/git-upload-pack') {
            handleUploadPack(repo, raw, res);
            return;
          }
          if (method === 'POST' && suffix === '/git-receive-pack') {
            handleReceivePack(repo, raw, res);
            return;
          }
          apiError(res, 404, 'Not Found');
          return;
        }

        apiError(res, 404, 'Not Found');
      } catch (err) {
        if (!res.headersSent) apiError(res, 500, err instanceof Error ? err.message : 'internal error');
        else res.end();
      }
    })();
  });
  // Keep-alive latency matters to the read workload: Nagle + delayed ACK would tax every request.
  server.on('connection', (socket) => socket.setNoDelay(true));
  return server;
}
