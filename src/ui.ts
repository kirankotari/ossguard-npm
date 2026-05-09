/**
 * Terminal UI helpers — replaces Python's rich library.
 * Uses chalk for colors, cli-table3 for tables, ora for spinners.
 */

import chalk from "chalk";
import Table from "cli-table3";

export const BANNER = `
   ___  ____ ____   ____                     _
  / _ \\/ ___/ ___| / ___|_   _  __ _ _ __ __| |
 | | | \\___ \\___ \\| |  _| | | |/ _\` | '__/ _\` |
 | |_| |___) |__) | |_| | |_| | (_| | | | (_| |
  \\___/|____/____/ \\____|\\__,_|\\__,_|_|  \\__,_|
`;

export function printBanner(subtitle: string, version: string): void {
  console.log(chalk.blue.bold(`╭─ OSSGuard — ${subtitle} ─ v${version} ─╮`));
  console.log(chalk.blue(BANNER));
  console.log(chalk.blue.bold("╰" + "─".repeat(40) + "╯"));
}

export function printPanel(content: string, title?: string): void {
  const border = "─".repeat(60);
  if (title) {
    console.log(chalk.bold(`┌─ ${title} ${"─".repeat(Math.max(0, 56 - title.length))}┐`));
  } else {
    console.log(`┌${border}┐`);
  }
  console.log(`│ ${content.padEnd(58)} │`);
  console.log(`└${border}┘`);
}

export function printError(msg: string): void {
  console.error(chalk.red("Error:"), msg);
}

export function printSuccess(msg: string): void {
  console.log(chalk.green("✓"), msg);
}

export function printWarning(msg: string): void {
  console.log(chalk.yellow("!"), msg);
}

export function printInfo(msg: string): void {
  console.log(chalk.cyan(">"), msg);
}

export function boolIcon(value: boolean): string {
  return value ? chalk.green("Yes") : chalk.red("No");
}

export function statusIcon(value: boolean): string {
  return value ? chalk.green("Configured") : chalk.yellow("Missing");
}

export function riskColor(level: string): string {
  const colors: Record<string, (s: string) => string> = {
    CRITICAL: chalk.red.bold,
    HIGH: chalk.red,
    MEDIUM: chalk.yellow,
    LOW: chalk.cyan,
    OK: chalk.green,
  };
  const fn = colors[level] ?? ((s: string) => s);
  return fn(level);
}

export function scoreColor(score: number): (s: string) => string {
  if (score >= 8) return chalk.green;
  if (score >= 5) return chalk.yellow;
  return chalk.red;
}

export function pctColor(pct: number): (s: string) => string {
  if (pct === 100) return chalk.green;
  if (pct >= 50) return chalk.yellow;
  return chalk.red;
}

export function createTable(headers: string[], options?: { title?: string }): Table.Table {
  const table = new Table({
    head: headers.map((h) => chalk.cyan(h)),
    style: { head: [], border: [] },
  });
  if (options?.title) {
    console.log(chalk.bold(`\n${options.title}`));
  }
  return table;
}

export function printTable(table: Table.Table): void {
  console.log(table.toString());
}

export async function withSpinner<T>(message: string, fn: () => Promise<T>): Promise<T> {
  const { default: ora } = await import("ora");
  const spinner = ora(chalk.green(message)).start();
  try {
    const result = await fn();
    spinner.succeed();
    return result;
  } catch (err) {
    spinner.fail();
    throw err;
  }
}

export { chalk };
