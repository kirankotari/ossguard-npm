/**
 * Cross-project security comparison — compare security posture of two projects.
 */

import { runAudit, type AuditReport } from "./audit.js";

export interface CompareMetric {
  name: string;
  projectAValue: string;
  projectBValue: string;
  winner: string;
}

export interface CompareReport {
  projectAName: string;
  projectBName: string;
  projectAGrade: string;
  projectBGrade: string;
  metrics: CompareMetric[];
  winner: string;
  auditA: AuditReport | null;
  auditB: AuditReport | null;
}

export async function compareProjects(pathA: string, pathB: string): Promise<CompareReport> {
  const auditA = await runAudit(pathA);
  const auditB = await runAudit(pathB);

  const nameA = auditA.projectInfo?.repoName ?? pathA.split("/").pop() ?? "A";
  const nameB = auditB.projectInfo?.repoName ?? pathB.split("/").pop() ?? "B";

  const metrics: CompareMetric[] = [];

  metrics.push(compareGrades("Overall Grade", auditA.overallGrade, auditB.overallGrade));
  metrics.push(compareNumeric("Config Score", auditA.configScore, auditA.configTotal, auditB.configScore, auditB.configTotal, true));

  if (auditA.depHealth || auditB.depHealth) {
    const aScore = auditA.depHealth?.aggregateScore ?? 0;
    const bScore = auditB.depHealth?.aggregateScore ?? 0;
    metrics.push({ name: "Dep Health Score", projectAValue: `${aScore}/10`, projectBValue: `${bScore}/10`, winner: aScore > bScore ? "a" : bScore > aScore ? "b" : "tie" });

    const aVulns = auditA.depHealth?.totalVulns ?? 0;
    const bVulns = auditB.depHealth?.totalVulns ?? 0;
    metrics.push({ name: "Total Vulnerabilities", projectAValue: String(aVulns), projectBValue: String(bVulns), winner: aVulns < bVulns ? "a" : bVulns < aVulns ? "b" : "tie" });

    const aCrit = auditA.depHealth?.criticalVulns ?? 0;
    const bCrit = auditB.depHealth?.criticalVulns ?? 0;
    metrics.push({ name: "Critical Vulns", projectAValue: String(aCrit), projectBValue: String(bCrit), winner: aCrit < bCrit ? "a" : bCrit < aCrit ? "b" : "tie" });

    metrics.push({ name: "Total Dependencies", projectAValue: String(auditA.depHealth?.totalDeps ?? 0), projectBValue: String(auditB.depHealth?.totalDeps ?? 0), winner: "" });
  }

  if (auditA.reachability || auditB.reachability) {
    const aRv = auditA.reachability?.reachableVulns ?? 0;
    const bRv = auditB.reachability?.reachableVulns ?? 0;
    metrics.push({ name: "Reachable Vulns", projectAValue: String(aRv), projectBValue: String(bRv), winner: aRv < bRv ? "a" : bRv < aRv ? "b" : "tie" });
  }

  const af = auditA.findings.length, bf = auditB.findings.length;
  metrics.push({ name: "Findings", projectAValue: String(af), projectBValue: String(bf), winner: af < bf ? "a" : bf < af ? "b" : "tie" });

  const aWins = metrics.filter((m) => m.winner === "a").length;
  const bWins = metrics.filter((m) => m.winner === "b").length;

  return { projectAName: nameA, projectBName: nameB, projectAGrade: auditA.overallGrade, projectBGrade: auditB.overallGrade, metrics, winner: aWins > bWins ? "a" : bWins > aWins ? "b" : "tie", auditA, auditB };
}

function compareGrades(name: string, gradeA: string, gradeB: string): CompareMetric {
  const vals: Record<string, number> = { A: 4, B: 3, C: 2, D: 1, F: 0 };
  const va = vals[gradeA] ?? 0, vb = vals[gradeB] ?? 0;
  return { name, projectAValue: gradeA, projectBValue: gradeB, winner: va > vb ? "a" : vb > va ? "b" : "tie" };
}

function compareNumeric(name: string, aVal: number, aTotal: number, bVal: number, bTotal: number, higherBetter: boolean): CompareMetric {
  const aP = aTotal ? (aVal / aTotal) * 100 : 0;
  const bP = bTotal ? (bVal / bTotal) * 100 : 0;
  const winner = higherBetter ? (aP > bP ? "a" : bP > aP ? "b" : "tie") : (aP < bP ? "a" : bP < aP ? "b" : "tie");
  return { name, projectAValue: `${aVal}/${aTotal} (${Math.round(aP)}%)`, projectBValue: `${bVal}/${bTotal} (${Math.round(bP)}%)`, winner };
}
