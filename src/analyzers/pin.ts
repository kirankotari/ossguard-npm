/**
 * Pin GitHub Actions to commit SHAs for supply-chain safety.
 */

import * as fs from "node:fs";
import * as path from "node:path";

export interface PinAction {
  file: string;
  lineNumber: number;
  original: string;
  owner: string;
  repo: string;
  ref: string;
  resolvedSha: string;
  pinned: string;
  alreadyPinned: boolean;
  error: string;
}

export interface PinReport {
  actions: PinAction[];
  pinnedCount: number;
  alreadyPinnedCount: number;
  failedCount: number;
  totalRefs: number;
}

const USES_RE = /^(\s*-?\s*uses:\s*)([a-zA-Z0-9\-_.]+\/[a-zA-Z0-9\-_.]+(?:\/[a-zA-Z0-9\-_.]+)?)@(\S+)/gm;
const SHA_RE = /^[0-9a-f]{40}$/;

export function scanActions(projectPath: string): PinReport {
  const wfDir = path.join(path.resolve(projectPath), ".github", "workflows");
  if (!fs.existsSync(wfDir)) return { actions: [], pinnedCount: 0, alreadyPinnedCount: 0, failedCount: 0, totalRefs: 0 };

  const actions: PinAction[] = [];
  let already = 0, total = 0;

  for (const file of fs.readdirSync(wfDir).sort()) {
    if (!file.endsWith(".yml") && !file.endsWith(".yaml")) continue;
    const content = fs.readFileSync(path.join(wfDir, file), "utf-8");
    let match: RegExpExecArray | null;
    const re = new RegExp(USES_RE.source, "gm");
    while ((match = re.exec(content)) !== null) {
      const actionRef = match[2];
      const ref = match[3];
      total++;
      const parts = actionRef.split("/");
      const isPinned = SHA_RE.test(ref);
      if (isPinned) already++;
      const lineNum = content.slice(0, match.index).split("\n").length;
      actions.push({ file, lineNumber: lineNum, original: `${actionRef}@${ref}`, owner: parts[0], repo: parts[1] || "", ref, resolvedSha: "", pinned: "", alreadyPinned: isPinned, error: "" });
    }
  }

  return { actions, pinnedCount: 0, alreadyPinnedCount: already, failedCount: 0, totalRefs: total };
}

export async function pinActions(projectPath: string, dryRun = false): Promise<PinReport> {
  const resolved = path.resolve(projectPath);
  const report = scanActions(resolved);
  if (!report.actions.length) return report;

  const toResolve = report.actions.filter((a) => !a.alreadyPinned);
  await resolveShas(toResolve);

  let pinned = 0;
  if (!dryRun) {
    const byFile: Record<string, PinAction[]> = {};
    for (const a of report.actions) { if (!a.alreadyPinned && a.resolvedSha) { (byFile[a.file] ??= []).push(a); } }
    const wfDir = path.join(resolved, ".github", "workflows");
    for (const [file, fileActions] of Object.entries(byFile)) {
      let content = fs.readFileSync(path.join(wfDir, file), "utf-8");
      for (const a of fileActions) {
        const old = `${a.owner}/${a.repo}@${a.ref}`;
        const replacement = `${a.owner}/${a.repo}@${a.resolvedSha}  # ${a.ref}`;
        content = content.replace(old, replacement);
        a.pinned = `${a.owner}/${a.repo}@${a.resolvedSha}`;
        pinned++;
      }
      fs.writeFileSync(path.join(wfDir, file), content);
    }
  } else {
    for (const a of toResolve) {
      if (a.resolvedSha) { a.pinned = `${a.owner}/${a.repo}@${a.resolvedSha}`; pinned++; }
    }
  }

  report.pinnedCount = pinned;
  report.failedCount = toResolve.filter((a) => !a.resolvedSha).length;
  return report;
}

async function resolveShas(actions: PinAction[]): Promise<void> {
  const seen = new Map<string, string>();
  for (const action of actions) {
    const key = `${action.owner}/${action.repo}@${action.ref}`;
    if (seen.has(key)) { action.resolvedSha = seen.get(key)!; continue; }
    const sha = await resolveSingle(action.owner, action.repo, action.ref);
    action.resolvedSha = sha;
    seen.set(key, sha);
    if (!sha) action.error = "Could not resolve SHA";
  }
}

async function resolveSingle(owner: string, repo: string, ref: string): Promise<string> {
  for (const refType of ["tags", "heads"]) {
    try {
      const url = `https://api.github.com/repos/${owner}/${repo}/git/ref/${refType}/${ref}`;
      const resp = await fetch(url, { headers: { Accept: "application/vnd.github.v3+json" }, signal: AbortSignal.timeout(10000) });
      if (resp.ok) {
        const data = await resp.json() as { object?: { sha?: string; type?: string } };
        let sha = data.object?.sha ?? "";
        if (data.object?.type === "tag" && sha) {
          const tagResp = await fetch(`https://api.github.com/repos/${owner}/${repo}/git/tags/${sha}`, { headers: { Accept: "application/vnd.github.v3+json" }, signal: AbortSignal.timeout(10000) });
          if (tagResp.ok) { const tagData = await tagResp.json() as { object?: { sha?: string } }; sha = tagData.object?.sha ?? sha; }
        }
        return sha;
      }
    } catch { continue; }
  }
  return "";
}
