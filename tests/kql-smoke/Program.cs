// soc-runbook — KQL syntax validation harness
//
// Parses every .kql file under kql/ and reports any syntax-level diagnostics
// emitted by Microsoft.Azure.Kusto.Language. Does NOT run semantic analysis —
// unknown tables, columns, and analyst-supplied placeholder values
// (HOSTNAME, USERNAME, PASTE_HASH_HERE) are expected and intentionally
// filtered out. This tool validates grammar only.
//
// See docs/kql-validation.md for details.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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

        var files = Directory
            .EnumerateFiles(repoRoot, "*.kql", SearchOption.AllDirectories)
            .Where(IsIncluded)
            .OrderBy(f => f, StringComparer.Ordinal)
            .ToList();

        if (files.Count == 0)
        {
            Console.Error.WriteLine($"No .kql files found under {repoRoot}");
            return 2;
        }

        Console.WriteLine($"soc-runbook — KQL syntax check");
        Console.WriteLine($"Root : {repoRoot}");
        Console.WriteLine($"Files: {files.Count} (scratchpad/ excluded)");
        Console.WriteLine(new string('-', 72));

        int passCount = 0;
        int failCount = 0;

        foreach (var file in files)
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
                failCount++;
                continue;
            }

            var errors = GetSyntaxErrors(text);
            if (errors.Count == 0)
            {
                Console.WriteLine($"PASS  {relPath}");
                passCount++;
            }
            else
            {
                Console.WriteLine($"FAIL  {relPath}");
                foreach (var d in errors)
                {
                    var (line, col) = LineColumnFromOffset(text, d.Start);
                    Console.WriteLine($"      line {line}, col {col}: {d.Message}");
                }
                failCount++;
            }
        }

        Console.WriteLine(new string('-', 72));
        Console.WriteLine($"Total: {files.Count}   Pass: {passCount}   Fail: {failCount}");
        return failCount == 0 ? 0 : 1;
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
