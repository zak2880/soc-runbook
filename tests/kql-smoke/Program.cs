// soc-runbook — KQL syntax validation harness
//
// Parses every .kql file under kql/ and reports any syntax-level diagnostics
// emitted by Microsoft.Azure.Kusto.Language. Does NOT run semantic analysis —
// unknown tables, columns, and analyst-supplied placeholder values
// (HOSTNAME, USERNAME, PASTE_HASH_HERE) are expected and intentionally
// filtered out. This tool validates grammar only.
//
// Also scans every .md file in the repo for ```kql fenced code blocks and
// syntax-checks each one the same way — .md files are the canonical home
// for documented queries, so their embedded KQL needs the same guardrail
// as standalone .kql files.
//
// See docs/kql-validation.md for details.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Kusto.Language;
using Kusto.Language.Editor;

namespace SocRunbook;

internal static class Program
{
    private static readonly string[] ExcludedDirSegments =
    {
        "/scratchpad/",
        "/bin/",
        "/obj/",
        "/.git/",
        "/node_modules/"
    };

    private static int Main(string[] args)
    {
        string repoRoot = args.Length > 0
            ? Path.GetFullPath(args[0])
            : FindRepoRoot();

        if (!Directory.Exists(repoRoot))
        {
            Console.Error.WriteLine($"Repo root does not exist: {repoRoot}");
            return 2;
        }

        var kqlFiles = Directory
            .EnumerateFiles(repoRoot, "*.kql", SearchOption.AllDirectories)
            .Where(IsIncluded)
            .OrderBy(f => f, StringComparer.Ordinal)
            .ToList();

        var mdFiles = Directory
            .EnumerateFiles(repoRoot, "*.md", SearchOption.AllDirectories)
            .Where(IsIncluded)
            .OrderBy(f => f, StringComparer.Ordinal)
            .ToList();

        if (kqlFiles.Count == 0 && mdFiles.Count == 0)
        {
            Console.Error.WriteLine($"No .kql or .md files found under {repoRoot}");
            return 2;
        }

        Console.WriteLine($"soc-runbook — KQL syntax check");
        Console.WriteLine($"Root : {repoRoot}");
        Console.WriteLine($"Files: {kqlFiles.Count} .kql, {mdFiles.Count} .md (scratchpad/ excluded)");
        Console.WriteLine(new string('-', 72));

        int kqlPassCount = 0;
        int kqlFailCount = 0;

        foreach (var file in kqlFiles)
        {
            string relPath = Path.GetRelativePath(repoRoot, file).Replace('\\', '/');
            string text;
            try
            {
                text = File.ReadAllText(file);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"FAIL  {relPath}");
                Console.WriteLine($"      read error: {ex.Message}");
                kqlFailCount++;
                continue;
            }

            var errors = GetSyntaxErrors(text);
            if (errors.Count == 0)
            {
                Console.WriteLine($"PASS  {relPath}");
                kqlPassCount++;
            }
            else
            {
                Console.WriteLine($"FAIL  {relPath}");
                foreach (var d in errors)
                {
                    var (line, col) = LineColumnFromOffset(text, d.Start);
                    Console.WriteLine($"      line {line}, col {col}: {d.Message}");
                }
                kqlFailCount++;
            }
        }

        int mdPassCount = 0;
        int mdFailCount = 0;

        foreach (var file in mdFiles)
        {
            string relPath = Path.GetRelativePath(repoRoot, file).Replace('\\', '/');
            string mdText;
            try
            {
                mdText = File.ReadAllText(file);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"FAIL  {relPath} (block 1)");
                Console.WriteLine($"      read error: {ex.Message}");
                mdFailCount++;
                continue;
            }

            var blocks = ExtractKqlBlocks(mdText);
            foreach (var block in blocks)
            {
                string label = $"{relPath} (block {block.BlockIndex}, line {block.StartLine})";
                var errors = GetSyntaxErrors(block.Code);
                if (errors.Count == 0)
                {
                    Console.WriteLine($"PASS  {label}");
                    mdPassCount++;
                }
                else
                {
                    Console.WriteLine($"FAIL  {label}");
                    foreach (var d in errors)
                    {
                        var (relLine, col) = LineColumnFromOffset(block.Code, d.Start);
                        int absLine = block.StartLine + relLine - 1;
                        Console.WriteLine($"      line {absLine}, col {col}: {d.Message}");
                    }
                    mdFailCount++;
                }
            }
        }

        Console.WriteLine(new string('-', 72));
        Console.WriteLine($"KQL files: {kqlFiles.Count}   Pass: {kqlPassCount}   Fail: {kqlFailCount}   |   MD blocks: {mdPassCount + mdFailCount}   Pass: {mdPassCount}   Fail: {mdFailCount}");
        return (kqlFailCount == 0 && mdFailCount == 0) ? 0 : 1;
    }

    private static List<(int BlockIndex, int StartLine, string Code)> ExtractKqlBlocks(string text)
    {
        var blocks = new List<(int, int, string)>();
        var lines = text.Replace("\r\n", "\n").Split('\n');
        int blockIndex = 0;
        int i = 0;

        while (i < lines.Length)
        {
            if (lines[i].Trim() == "```kql")
            {
                blockIndex++;
                int startLine = i + 2; // 1-based line number of the first line of code inside the fence
                var sb = new StringBuilder();
                int j = i + 1;
                while (j < lines.Length && lines[j].Trim() != "```")
                {
                    sb.Append(lines[j]);
                    sb.Append('\n');
                    j++;
                }
                blocks.Add((blockIndex, startLine, sb.ToString()));
                i = j + 1;
            }
            else
            {
                i++;
            }
        }

        return blocks;
    }

    private static List<Diagnostic> GetSyntaxErrors(string text)
    {
        var code = KustoCode.Parse(text);
        var diags = code.GetSyntaxDiagnostics();

        return diags
            .Where(d => d.Severity == DiagnosticSeverity.Error)
            .Where(d => !IsSemanticNoise(d.Message))
            .ToList();
    }

    private static bool IsSemanticNoise(string message)
    {
        if (string.IsNullOrEmpty(message)) return false;
        string m = message.ToLowerInvariant();

        return m.Contains("could not be resolved")
            || m.Contains("not declared")
            || m.Contains("does not exist")
            || (m.Contains("unknown") && (m.Contains("name") || m.Contains("table") || m.Contains("column") || m.Contains("function")))
            || m.StartsWith("the name ")
            || m.Contains("not found in scope");
    }

    private static (int line, int col) LineColumnFromOffset(string text, int offset)
    {
        if (offset < 0) offset = 0;
        if (offset > text.Length) offset = text.Length;
        int line = 1, col = 1;
        for (int i = 0; i < offset; i++)
        {
            if (text[i] == '\n') { line++; col = 1; }
            else if (text[i] != '\r') { col++; }
        }
        return (line, col);
    }

    private static bool IsIncluded(string path)
    {
        string normalised = "/" + path.Replace('\\', '/').TrimStart('/');
        foreach (var seg in ExcludedDirSegments)
        {
            if (normalised.Contains(seg)) return false;
        }
        return true;
    }

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "repo-contract.md")))
                return dir.FullName;
            dir = dir.Parent;
        }
        return Directory.GetCurrentDirectory();
    }
}
