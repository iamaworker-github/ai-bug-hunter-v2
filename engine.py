#!/usr/bin/env python3
"""
engine.py — Standalone AI Bug Hunter CLI
Works WITHOUT Claude Code or any AI subscription.

Providers (auto-detected, first available wins):
  FREE:  zen      — OpenCode Zen free models, set ZEN_API_KEY (https://opencode.ai/zen)
  FREE:  ollama   — local model, zero cost
                    install: curl -fsSL https://ollama.ai/install.sh | sh
                    then:    ollama pull qwen2.5:14b
         groq     — cloud free tier (fast), set GROQ_API_KEY
                    get key: https://console.groq.com
         deepseek — very cheap cloud,       set DEEPSEEK_API_KEY
                    get key: https://platform.deepseek.com
  PAID:  claude   — set ANTHROPIC_API_KEY
         openai   — set OPENAI_API_KEY
         grok     — set XAI_API_KEY

Usage:
  ./engine.py setup                        one-time config wizard
  ./engine.py recon  <target>              recon + AI surface analysis
  ./engine.py hunt   <target>              full hunt pipeline
  ./engine.py validate "<finding>"         7-Question Gate on a finding
  ./engine.py report [--findings-dir DIR]  write submission-ready report
  ./engine.py chain  [--findings-dir DIR]  build A->B->C exploit chain
  ./engine.py triage "<finding>"           fast triage (pass/kill/downgrade)
  ./engine.py chat                         interactive Q&A shell
  ./engine.py models                       list available models
  ./engine.py status                       show hunt status
  ./engine.py providers                    show all providers + API key status
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path

# ── Paths ──────────────────────────────────────────────────────────────────────
HERE     = Path(__file__).resolve().parent  # resolve symlink first so /usr/local/bin/ai-bug-hunter -> repo dir
AGENTS   = HERE / "agents"
TOOLS    = HERE / "tools"
RECON    = HERE / "recon"
FINDINGS = HERE / "findings"
REPORTS  = HERE / "reports"
CONFIG   = Path.home() / ".ai-bug-hunter" / "config.json"

# ── Colors ─────────────────────────────────────────────────────────────────────
GREEN  = "\033[0;32m"
CYAN   = "\033[0;36m"
YELLOW = "\033[1;33m"
RED    = "\033[0;31m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
NC     = "\033[0m"


def ok(msg):   print(f"{GREEN}{BOLD}[+]{NC} {msg}")
def info(msg): print(f"{CYAN}{BOLD}[*]{NC} {msg}")
def warn(msg): print(f"{YELLOW}{BOLD}[!]{NC} {msg}")
def err(msg):  print(f"{RED}{BOLD}[-]{NC} {msg}")


def header(title: str):
    width = max(len(title) + 4, 60)
    print(f"\n{BOLD}{'═' * width}{NC}")
    print(f"{BOLD}  {title}{NC}")
    print(f"{BOLD}{'═' * width}{NC}\n")


def load_config() -> dict:
    if CONFIG.exists():
        try:
            return json.loads(CONFIG.read_text())
        except Exception:
            pass
    return {}


def save_config(cfg: dict):
    CONFIG.parent.mkdir(parents=True, exist_ok=True)
    CONFIG.write_text(json.dumps(cfg, indent=2))


COMMAND_ALIASES = {
    "setup": {"setup", "init"},
    "providers": {"providers", "p"},
    "models": {"models", "m"},
    "status": {"status", "s"},
    "chat": {"chat", "ask"},
    "recon": {"recon", "r"},
    "hunt": {"hunt", "h"},
    "validate": {"validate", "v"},
    "triage": {"triage", "t"},
    "report": {"report", "rep"},
    "chain": {"chain", "c"},
    "autopilot": {"autopilot", "auto", "ap"},
    "pickup": {"pickup", "resume"},
    "surface": {"surface", "surf"},
    "remember": {"remember", "mem", "learn"},
    "memory-gc": {"memory-gc", "mgc"},
    "scope": {"scope", "sc"},
    "scope-aggregate": {"scope-aggregate", "sa"},
    "intel": {"intel", "i"},
    "takeover": {"takeover", "to"},
    "cloud-recon": {"cloud-recon", "cr"},
    "secrets-hunt": {"secrets-hunt", "sh"},
    "secrets-leak": {"secrets-leak", "sl"},
    "param-discover": {"param-discover", "pd"},
    "bypass-403": {"bypass-403", "b403", "bypass"},
    "scan-cves": {"scan-cves", "cves"},
    "arsenal": {"arsenal", "tools"},
    "web3-audit": {"web3-audit", "web3"},
    "token-scan": {"token-scan", "tscan"},
    "wordlist-gen": {"wordlist-gen", "wgen"},
    "spray": {"spray", "sp"},
    "breach-check": {"breach-check", "breach"},
    "osint-employees": {"osint-employees", "osint"},
}


def _print_quick_help():
    print(textwrap.dedent("""
    AI Bug Hunter v2 — 30+ commands

    SETUP:
      setup / init          One-time config wizard
      providers / p         Show providers + API key status
      models / m            List available models
      status / s            Show pipeline status

    CORE:
      recon <target> / r    Full recon + AI analysis
      hunt <target> / h     Full hunt pipeline
      validate / v          7-Question Gate
      triage / t            Fast triage
      report / rep          Submission-ready report
      chain / c             Build exploit chains
      chat / ask            Interactive AI shell

    AUTOPILOT:
      autopilot <t> / ap    Autonomous hunt loop
      pickup <t> / resume   Resume previous hunt
      surface <t> / surf    Ranked attack surface
      remember / mem        Save to memory
      memory-gc / mgc       Clean memory files

    RECON:
      intel <t> / i         CVEs + disclosed reports
      scope <a> / sc        Verify asset scope
      scope-aggregate / sa  Pull in-scope assets
      takeover <t> / to     Subdomain takeover scan
      cloud-recon <t> / cr  S3/Azure/GCP discovery
      secrets-hunt <t> / sh Leaked creds in JS/git
      secrets-leak <t> / sl BACK-ME-UP secrets scan
      param-discover / pd   Hidden HTTP params
      bypass-403 / b403     403/401 bypass
      scan-cves / cves      Nuclei CVE sweep
      arsenal / tools       List installed tools

    WEB3:
      web3-audit / web3     Smart contract audit
      token-scan / tscan    Rug-pull analysis

    EXTRA:
      wordlist-gen / wgen   Custom wordlists
      spray / sp            Password spraying
      breach-check / breach Breach data check
      osint-employees/osint Employee OSINT
    """).strip())


def _normalize_cli_argv(argv: list[str]) -> list[str]:
    if not argv:
        return argv
    if argv[0] in {"help", "-help"}:
        return ["--help", *argv[1:]]
    return ["--help" if item == "-help" else item for item in argv]


def load_agent_prompt(agent_name: str) -> str:
    """Read agents/<name>.md, strip YAML frontmatter, return body as system prompt."""
    md = AGENTS / f"{agent_name}.md"
    if not md.exists():
        return ""
    text = md.read_text()
    if text.startswith("---"):
        end = text.find("---", 3)
        if end != -1:
            text = text[end + 3:].lstrip()
    return text.strip()


def _import_brain():
    """Import Brain and LLMClient from brain.py."""
    sys.path.insert(0, str(HERE))
    try:
        from brain import Brain, LLMClient  # noqa: PLC0415
        return Brain, LLMClient
    except ImportError as e:
        err(f"Could not import brain.py: {e}")
        sys.exit(1)


def _get_client(provider: str | None = None):
    """Return an LLMClient, applying saved config if no env override."""
    _, LLMClient = _import_brain()
    cfg = load_config()
    if not provider and not os.environ.get("BRAIN_PROVIDER"):
        provider = cfg.get("provider")
    if provider:
        os.environ["BRAIN_PROVIDER"] = provider
    return LLMClient(provider)


def _get_brain(provider: str | None = None):
    """Return a Brain instance."""
    Brain, _ = _import_brain()
    cfg = load_config()
    if not provider and not os.environ.get("BRAIN_PROVIDER"):
        provider = cfg.get("provider")
    if provider:
        os.environ["BRAIN_PROVIDER"] = provider
    return Brain()


def _run_shell(cmd: str, cwd: str | None = None, timeout: int = 3600) -> tuple[bool, str]:
    """Run a shell command with live output, return (success, combined_output)."""
    try:
        proc = subprocess.Popen(
            cmd, shell=True, cwd=cwd or str(HERE),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        lines = []
        for line in proc.stdout:
            print(line, end="", flush=True)
            lines.append(line)
        proc.wait(timeout=timeout)
        return proc.returncode == 0, "".join(lines)
    except subprocess.TimeoutExpired:
        proc.kill()
        return False, "timed out"
    except Exception as e:
        return False, str(e)


# ── Commands ───────────────────────────────────────────────────────────────────

def cmd_setup(args):
    """Interactive setup wizard."""
    header("AI Bug Hunter Setup")

    providers = {
        "1": ("zen",      "OpenCode Zen (FREE models)  — needs ZEN_API_KEY (opencode.ai/zen)"),
        "2": ("ollama",   "Ollama  (local, FREE)       — needs ollama running locally"),
        "3": ("groq",     "Groq    (cloud, FREE tier)  — needs GROQ_API_KEY"),
        "4": ("deepseek", "DeepSeek (cloud, very cheap)— needs DEEPSEEK_API_KEY"),
        "5": ("claude",   "Claude  (paid)              — needs ANTHROPIC_API_KEY"),
        "6": ("openai",   "OpenAI  (paid)              — needs OPENAI_API_KEY"),
        "7": ("grok",     "Grok/xAI (paid)             — needs XAI_API_KEY"),
    }

    print("Choose your AI backend:\n")
    for k, (_, desc) in providers.items():
        print(f"  {k}) {desc}")
    print()

    choice = input("Enter number [1]: ").strip() or "1"
    provider = providers.get(choice, ("ollama", ""))[0]

    cfg = load_config()
    cfg["provider"] = provider

    env_map = {
        "zen":      "ZEN_API_KEY",
        "groq":     "GROQ_API_KEY",
        "deepseek": "DEEPSEEK_API_KEY",
        "claude":   "ANTHROPIC_API_KEY",
        "openai":   "OPENAI_API_KEY",
        "grok":     "XAI_API_KEY",
    }

    if provider in env_map:
        env_var = env_map[provider]
        existing = os.environ.get(env_var, "")
        print(f"\nEnter {env_var} (blank = keep existing): ", end="")
        api_key = input().strip()
        if api_key:
            cfg[env_var] = api_key
            os.environ[env_var] = api_key
        elif existing:
            info(f"Using existing {env_var} from environment")
        else:
            warn(f"No {env_var} set — provider may not work")

    save_config(cfg)
    ok(f"Config saved to {CONFIG}")

    # Test connection
    info("Testing connection...")
    _, LLMClient = _import_brain()
    if provider in env_map and cfg.get(env_map[provider]):
        os.environ[env_map[provider]] = cfg[env_map[provider]]

    client = LLMClient(provider)
    if client.available:
        ok(f"Connected: {client.description}")
        reply = client.chat(None, "You are a helpful assistant.",
                            "Reply with exactly: READY", max_tokens=10)
        ok(f"Model responded: {reply.strip()}" if reply else "Connected (no reply — pull a model if using Ollama)")
    else:
        err(f"Provider '{provider}' not available")
        if provider == "ollama":
            print(f"\n  {YELLOW}Install Ollama:{NC}")
            print("    curl -fsSL https://ollama.ai/install.sh | sh")
            print("    ollama pull qwen2.5:14b")
        elif provider in env_map:
            print(f"\n  {YELLOW}Set API key:{NC}  export {env_map[provider]}=your_key_here")


def cmd_providers(args):
    """Show all providers and API key status."""
    _, LLMClient = _import_brain()
    cfg = load_config()
    saved = cfg.get("provider", "")

    env_map = {
        "zen":      "ZEN_API_KEY",
        "ollama":   None,
        "groq":     "GROQ_API_KEY",
        "deepseek": "DEEPSEEK_API_KEY",
        "claude":   "ANTHROPIC_API_KEY",
        "openai":   "OPENAI_API_KEY",
        "grok":     "XAI_API_KEY",
    }
    tier = {
        "zen": "FREE (cloud)",    "ollama": "FREE (local)", "groq": "FREE tier",
        "deepseek": "cheap",      "claude": "paid",
        "openai": "paid",         "grok": "paid",
    }

    print(f"\n  {'PROVIDER':<12} {'TIER':<16} {'STATUS':<20} {'NOTE'}")
    print(f"  {'─'*12} {'─'*16} {'─'*20} {'─'*30}")

    for prov, env_var in env_map.items():
        if env_var:
            key_set = bool(os.environ.get(env_var) or cfg.get(env_var))
            status  = f"{GREEN}key set{NC}" if key_set else f"{RED}no key{NC}"
            note    = env_var if not key_set else ""
        else:
            try:
                import urllib.request
                urllib.request.urlopen("http://localhost:11434", timeout=1)
                status = f"{GREEN}running{NC}"
                note   = ""
            except Exception:
                status = f"{YELLOW}not running{NC}"
                note   = "ollama serve"

        marker = f" {BOLD}<- active{NC}" if prov == saved else ""
        print(f"  {BOLD}{prov:<12}{NC} {tier[prov]:<16} {status:<30} {DIM}{note}{NC}{marker}")

    print(f"\n  Config: {CONFIG}")
    print(f"  Change: ./engine.py setup\n")


def cmd_models(args):
    """List available models for the active provider."""
    cfg = load_config()
    provider = getattr(args, "provider", None) or cfg.get("provider")
    client = _get_client(provider)
    if not client.available:
        err(f"Provider '{client.provider}' not available. Run: ./engine.py setup")
        return
    models = client.list_models()
    info(f"Provider: {client.description}")
    if models:
        for m in models:
            print(f"  {GREEN}•{NC} {m}")
    else:
        warn("No models found")
        if client.provider == "ollama":
            print("  Pull a model: ollama pull qwen2.5:14b")


def cmd_recon(args):
    """Run recon pipeline then AI surface analysis."""
    target = args.target
    header(f"Recon: {target}")

    script = TOOLS / "recon_engine.sh"
    if script.exists():
        info("Running recon pipeline...")
        success, _ = _run_shell(f'bash "{script}" "{target}"')
        if not success:
            warn("Recon had issues — continuing with AI analysis")
    else:
        warn("recon_engine.sh not found — skipping to AI analysis")

    recon_dir = RECON / target
    info("Running AI surface analysis...")
    brain = _get_brain()
    result = brain.analyze_recon(str(recon_dir) if recon_dir.exists() else target)
    if result:
        print(f"\n{result}")
    else:
        warn("AI analysis returned no output — check provider with: ./engine.py providers")


def cmd_hunt(args):
    """Full hunt pipeline: recon + vuln scan + AI analysis."""
    target = args.target
    header(f"Hunt: {target}")

    # Run recon
    script = TOOLS / "recon_engine.sh"
    if script.exists():
        info("Phase 1: Recon...")
        _run_shell(f'bash "{script}" "{target}"')

    # Run vuln scan
    vuln_script = TOOLS / "vuln_scanner.sh"
    recon_dir = RECON / target
    if vuln_script.exists() and recon_dir.exists():
        info("Phase 2: Vuln scan...")
        _run_shell(f'bash "{vuln_script}" "{recon_dir}"')

    # AI analysis
    info("Phase 3: AI analysis...")
    brain = _get_brain()
    findings_dir = FINDINGS / target
    if findings_dir.exists():
        brain.interpret_scan(str(findings_dir))
    elif recon_dir.exists():
        brain.analyze_recon(str(recon_dir))
    else:
        warn(f"No data for {target} — run recon first")


def cmd_validate(args):
    """Run 7-Question Gate on a finding description."""
    finding = getattr(args, "finding", "") or ""
    if not finding:
        finding = _read_stdin_or_prompt("Paste your finding description (Ctrl+D when done):\n")

    header("7-Question Gate")
    info(f"Finding: {finding[:120]}{'...' if len(finding) > 120 else ''}")

    brain = _get_brain()
    decision, explanation = brain.triage_finding(finding)

    print(f"\n{BOLD}{'─'*60}{NC}")
    if decision.startswith("PASS"):
        color = GREEN
    elif "DOWNGRADE" in decision or "CHAIN" in decision:
        color = YELLOW
    else:
        color = RED
    print(f"{color}{BOLD}DECISION: {decision}{NC}")
    if explanation:
        print(f"\n{explanation}")
    print(f"{BOLD}{'─'*60}{NC}\n")


def cmd_triage(args):
    """Alias for validate."""
    cmd_validate(args)


def cmd_report(args):
    """Generate a submission-ready bug report."""
    findings_dir = getattr(args, "findings_dir", "") or ""
    if not findings_dir:
        targets = sorted(FINDINGS.glob("*/")) if FINDINGS.exists() else []
        if targets:
            findings_dir = str(targets[-1])
            info(f"Using findings dir: {findings_dir}")
        else:
            err("No findings dir found. Use: ./engine.py report --findings-dir findings/<target>")
            sys.exit(1)

    header("Report Writer")
    brain = _get_brain()

    recon_dir = ""
    target_name = Path(findings_dir).name
    candidate = RECON / target_name
    if candidate.exists():
        recon_dir = str(candidate)

    result = brain.write_report(findings_dir, recon_dir)
    if result:
        print(f"\n{result}")
        ok("Report written.")
    else:
        warn("No report output — ensure findings directory has data")


def cmd_chain(args):
    """Build A->B->C exploit chain."""
    findings_dir = getattr(args, "findings_dir", "") or ""
    finding = getattr(args, "finding", "") or ""

    if not findings_dir:
        targets = sorted(FINDINGS.glob("*/")) if FINDINGS.exists() else []
        if targets:
            findings_dir = str(targets[-1])

    header("Chain Builder")

    if findings_dir and Path(findings_dir).exists():
        brain = _get_brain()
        result = brain.build_chains(findings_dir)
        if result:
            print(f"\n{result}")
            return

    # Fallback: agent-prompt mode with finding description
    if not finding:
        finding = _read_stdin_or_prompt("Describe the bug to chain from:\n")

    system = load_agent_prompt("chain-builder")
    client = _get_client()
    if not client.available:
        err("No AI provider available. Run: ./engine.py setup")
        sys.exit(1)
    sys.path.insert(0, str(HERE))
    from brain import BRAIN_SYSTEM  # noqa: PLC0415
    result = client.chat(None, system or BRAIN_SYSTEM,
                         f"Build an exploit chain starting from this bug:\n\n{finding}")
    if result:
        print(f"\n{result}")


def cmd_chat(args):
    """Interactive Q&A shell."""
    header("AI Bug Hunter Chat")
    client = _get_client()
    if not client.available:
        err("No AI provider available. Run: ./engine.py setup")
        sys.exit(1)

    sys.path.insert(0, str(HERE))
    from brain import BRAIN_SYSTEM  # noqa: PLC0415

    ok(f"Connected: {client.description}")
    print(f"{DIM}Type 'exit' or Ctrl+C to quit{NC}\n")

    history: list[dict] = []
    while True:
        try:
            user_input = input(f"{CYAN}{BOLD}you>{NC} ").strip()
        except (KeyboardInterrupt, EOFError):
            print()
            break

        if user_input.lower() in ("exit", "quit", "q"):
            break
        if not user_input:
            continue

        ctx_parts = []
        for turn in history[-4:]:
            ctx_parts.append(f"[you] {turn['user']}")
            ctx_parts.append(f"[assistant] {turn['assistant']}")
        prompt = ("\n".join(ctx_parts) + "\n\n" if ctx_parts else "") + f"[you] {user_input}"

        reply = client.chat(None, BRAIN_SYSTEM, prompt, max_tokens=2000)
        if reply:
            print(f"\n{reply}\n")
            history.append({"user": user_input, "assistant": reply})
        else:
            warn("No response — check provider with: ./engine.py providers")


def cmd_status(args):
    """Show pipeline status."""
    header("Hunt Status")

    recon_targets = sorted(RECON.glob("*/")) if RECON.exists() else []
    print(f"  {BOLD}Recon completed:{NC} {len(recon_targets)} target(s)")
    for t in recon_targets[:5]:
        subs = t / "subdomains" / "all.txt"
        live = t / "live" / "urls.txt"
        n_subs = sum(1 for _ in subs.open()) if subs.exists() else 0
        n_live = sum(1 for _ in live.open()) if live.exists() else 0
        print(f"    {GREEN}•{NC} {t.name}: {n_subs} subdomains, {n_live} live hosts")

    finding_targets = sorted(FINDINGS.glob("*/")) if FINDINGS.exists() else []
    print(f"\n  {BOLD}Findings:{NC} {len(finding_targets)} target(s)")
    for t in finding_targets[:5]:
        summary = t / "summary.txt"
        if summary.exists():
            m = re.search(r"TOTAL FINDINGS:\s*(\d+)", summary.read_text())
            count = m.group(1) if m else "?"
            print(f"    {GREEN}•{NC} {t.name}: {count} findings")

    report_targets = sorted(REPORTS.glob("*/")) if REPORTS.exists() else []
    print(f"\n  {BOLD}Reports:{NC} {len(report_targets)} target(s)")
    for t in report_targets[:5]:
        print(f"    {GREEN}•{NC} {t.name}: {len(list(t.glob('*.md')))} report(s)")

    print(f"\n  {BOLD}Provider:{NC} ", end="")
    client = _get_client()
    if client.available:
        print(f"{GREEN}{client.description}{NC}")
    else:
        print(f"{RED}not configured{NC} — run: ./engine.py setup")
    print()


def cmd_autopilot(args):
    """Full autonomous hunt loop."""
    target = args.target
    mode = getattr(args, "mode", "full") or "full"
    header(f"Autopilot: {target} [{mode}]")

    brain = _get_brain()
    if mode in ("quick", "fast"):
        info("Quick mode — recon + AI analysis only")
        cmd_recon(args)
    else:
        info("Full autopilot — recon, vuln scan, AI analysis")
        cmd_hunt(args)

    brain_cmd = f"python3 brain.py --phase autopilot --target {target} --findings-dir {FINDINGS / target}"
    success, out = _run_shell(brain_cmd)
    if not success:
        warn("Autopilot brain phase had issues")


def cmd_pickup(args):
    """Resume previous hunt."""
    target = args.target
    findings_dir = FINDINGS / target
    recon_dir = RECON / target
    if not findings_dir.exists() and not recon_dir.exists():
        err(f"No previous hunt data found for {target}")
        return
    header(f"Resume: {target}")
    info(f"Findings: {findings_dir.exists()}")
    info(f"Recon:    {recon_dir.exists()}")
    info("Continuing hunt pipeline...")
    cmd_hunt(args)


def cmd_surface(args):
    """Ranked attack surface."""
    target = args.target
    header(f"Attack Surface: {target}")
    adapter = TOOLS / "recon_adapter.py"
    recon_dir = RECON / target
    if not recon_dir.exists():
        info("No recon data — running recon first")
        _run_shell(f'bash "{TOOLS / "recon_engine.sh"}" "{target}"')
    if adapter.exists():
        _run_shell(f'python3 "{adapter}" --recon-dir "{recon_dir}"')
    else:
        brain = _get_brain()
        result = brain.analyze_recon(str(recon_dir) if recon_dir.exists() else target)
        if result:
            print(f"\n{result}")


def cmd_remember(args):
    """Save to cross-session memory."""
    details = getattr(args, "details", "") or ""
    if not details:
        details = _read_stdin_or_prompt("What to remember?\n")
    if not details:
        warn("Nothing to remember")
        return
    header("Memory")
    mem_dir = HERE / "memory"
    if mem_dir.exists():
        sys.path.insert(0, str(HERE))
        try:
            from memory.rotation import append_memory  # noqa: PLC0415
            append_memory(details)
            ok("Saved to memory")
        except ImportError:
            pass
    # Fallback: append to memory file
    mem_file = HERE / "memory.txt"
    with mem_file.open("a") as f:
        f.write(f"{details}\n")
    ok(f"Saved to {mem_file}")


def cmd_memory_gc(args):
    """Rotate/clean memory files."""
    header("Memory GC")
    mem_dir = HERE / "memory"
    if mem_dir.exists():
        sys.path.insert(0, str(HERE))
        try:
            from memory.rotation import rotate  # noqa: PLC0415
            rotate()
            ok("Memory rotated")
            return
        except ImportError:
            pass
    mem_file = HERE / "memory.txt"
    if mem_file.exists():
        lines = mem_file.read_text().splitlines()
        keep = 100
        if len(lines) > keep:
            mem_file.write_text("\n".join(lines[-keep:]) + "\n")
            ok(f"Trimmed memory to {keep} entries")


def cmd_scope(args):
    """Verify scope for an asset."""
    asset = args.asset
    header(f"Scope Check: {asset}")
    checker = TOOLS / "scope_checker.py"
    if checker.exists():
        _run_shell(f'python3 "{checker}" "{asset}"')
    else:
        info(f"Manual check: verify {asset} is in scope for your program")


def cmd_scope_aggregate(args):
    """Pull all in-scope assets from program."""
    program = args.program
    header(f"Scope Aggregate: {program}")
    agg = TOOLS / "scope_aggregator.sh"
    if agg.exists():
        _run_shell(f'bash "{agg}" "{program}"')
    else:
        warn("scope_aggregator.sh not found")
        info(f"Manual: visit {program}'s HackerOne/Bugcrowd page for scope")


def cmd_intel(args):
    """Fetch CVEs + disclosed reports for target."""
    target = args.target
    header(f"Intel: {target}")

    engine = TOOLS / "intel_engine.py"
    if engine.exists():
        tech = getattr(args, "tech", "") or ""
        tech_flag = f"--tech \"{tech}\"" if tech else ""
        _run_shell(f'python3 "{engine}" --target "{target}" {tech_flag}')
    else:
        info(f"Gathering intel for {target}...")
        brain = _get_brain()
        result = brain.chat(None, "You are a bug bounty intel analyst.",
                            f"Research CVEs and disclosed reports for {target}", max_tokens=2000)
        if result:
            print(f"\n{result}")


def cmd_takeover(args):
    """Subdomain takeover scan."""
    target = args.target
    header(f"Takeover Scan: {target}")
    scanner = TOOLS / "takeover_scanner.sh"
    recon_dir = RECON / target
    if not recon_dir.exists():
        info("No recon data — running recon first")
        _run_shell(f'bash "{TOOLS / "recon_engine.sh"}" "{target}"')
    if scanner.exists() and recon_dir.exists():
        _run_shell(f'bash "{scanner}" --recon "{recon_dir}"')
    else:
        warn("takeover_scanner.sh not found or no recon data")


def cmd_cloud_recon(args):
    """Cloud asset discovery (S3/Azure/GCP)."""
    target = args.target
    header(f"Cloud Recon: {target}")
    script = TOOLS / "cloud_recon.sh"
    if script.exists():
        _run_shell(f'bash "{script}" "{target}"')
    else:
        info("Checking common cloud buckets...")
        brain = _get_brain()
        result = brain.chat(None, "You are a cloud recon specialist.",
                            f"List common S3/Azure/GCP bucket naming patterns for {target}",
                            max_tokens=1000)
        if result:
            print(f"\n{result}")


def cmd_secrets_hunt(args):
    """Search for leaked credentials in JS, git, etc."""
    target = args.target
    header(f"Secrets Hunt: {target}")
    script = TOOLS / "secrets_hunter.sh"
    if script.exists():
        _run_shell(f'bash "{script}" "{target}"')
    else:
        info("Checking for exposed secrets...")
        gitleaks_cmd = f"gitleaks detect --source {HERE} --no-git -v 2>/dev/null || true"
        _run_shell(gitleaks_cmd)


def cmd_secrets_leak(args):
    """BACK-ME-UP: multi-collector secrets leak detection."""
    target = args.target
    header(f"BACK-ME-UP: {target}")
    script = TOOLS / "backmeup.sh"
    if script.exists():
        _run_shell(f'bash "{script}" -d "{target}"')
    else:
        err("backmeup.sh not found. BACK-ME-UP requires the tools/ directory.")


def cmd_param_discover(args):
    """Discover hidden HTTP parameters."""
    url = args.url
    header(f"Param Discover: {url}")
    script = TOOLS / "param_discovery.sh"
    if script.exists():
        _run_shell(f'bash "{script}" "{url}"')
    else:
        info("Running AI-assisted param discovery...")
        brain = _get_brain()
        result = brain.chat(None, "You are a web security tester.",
                            f"Suggest hidden/undocumented HTTP parameters to test for: {url}",
                            max_tokens=1000)
        if result:
            print(f"\n{result}")


def cmd_bypass_403(args):
    """403/401 bypass techniques."""
    url = args.url
    header(f"403 Bypass: {url}")
    script = TOOLS / "bypass_403.sh"
    if script.exists():
        _run_shell(f'bash "{script}" "{url}"')
    else:
        info("Generating 403 bypass payloads...")
        brain = _get_brain()
        result = brain.chat(None, "You are a web security tester.",
                            f"Generate 403/401 bypass techniques for: {url}. Include headers, methods, path traversal.",
                            max_tokens=1500)
        if result:
            print(f"\n{result}")


def cmd_scan_cves(args):
    """Nuclei CVE sweep."""
    target = args.target
    header(f"CVE Scan: {target}")
    script = TOOLS / "cve_scan.sh"
    if script.exists():
        _run_shell(f'bash "{script}" "{target}"')
    else:
        info("Running nuclei CVE scan...")
        _run_shell(f"nuclei -target {target} -tags cve -severity critical,high -o {FINDINGS / target / 'cves.txt'} 2>/dev/null || true")


def cmd_arsenal(args):
    """List installed tools."""
    header("Arsenal — Installed Tools")
    tools_list = [
        "subfinder", "httpx", "nuclei", "dnsx", "naabu", "katana",
        "ffuf", "gau", "waybackurls", "gospider", "hakrawler",
        "gitleaks", "trufflehog", "dalfox", "amass", "s3scanner",
        "subjack", "gf", "byp4xx", "cariddi", "gauplus",
        "interactsh-client", "puredns", "gobuster", "aquatone",
        "nmap", "sqlmap", "rg", "sisakulint", "dalfox",
    ]
    installed = []
    missing = []
    for t in tools_list:
        if subprocess.run(["which", t], capture_output=True).returncode == 0:
            installed.append(t)
        else:
            missing.append(t)

    print(f"\n  {BOLD}INSTALLED ({len(installed)}):{NC}")
    for t in sorted(installed):
        print(f"    {GREEN}✓{NC} {t}")
    if missing:
        print(f"\n  {DIM}MISSING ({len(missing)}):{NC}")
        for t in sorted(missing):
            print(f"    {DIM}·{NC} {t}")
    print()


def cmd_web3_audit(args):
    """Smart contract audit."""
    contract = args.contract
    header(f"Web3 Audit: {contract}")
    if contract.startswith("0x") or contract.endswith(".sol"):
        info("Running AI smart contract audit...")
        brain = _get_brain()
        result = brain.chat(None, "You are a senior Web3 security auditor with 10+ years Solidity experience.",
                            f"Audit this smart contract for all vulnerability classes:\n\n{contract}",
                            max_tokens=4000)
        if result:
            print(f"\n{result}")
    else:
        web3_dir = HERE / "web3"
        if web3_dir.exists():
            info(f"Web3 audit methodology available in {web3_dir}")
        brain = _get_brain()
        result = brain.chat(None, "You are a Web3 security auditor.",
                            f"Audit this contract address or source: {contract}", max_tokens=4000)
        if result:
            print(f"\n{result}")


def cmd_token_scan(args):
    """Meme coin / token rug-pull analysis."""
    contract = args.contract
    header(f"Token Scan: {contract}")
    brain = _get_brain()
    result = brain.chat(None, "You are a crypto token security analyst specialized in detecting rug pulls.",
                        f"Analyze this token/contract for rug pull signals:\n\n{contract}",
                        max_tokens=3000)
    if result:
        print(f"\n{result}")


def cmd_wordlist_gen(args):
    """Generate custom wordlists."""
    header("Wordlist Generator")
    script = TOOLS / "wordlist_engine.sh"
    if script.exists():
        extra = getattr(args, "args", []) or []
        _run_shell(f'bash "{script}" {" ".join(extra)}')
    else:
        info("Generating common wordlist patterns...")
        brain = _get_brain()
        result = brain.chat(None, "You are a wordlist generation expert for web security testing.",
                            "Generate a comprehensive wordlist of common API endpoints, admin paths, and parameter names.",
                            max_tokens=2000)
        if result:
            print(f"\n{result}")


def cmd_spray(args):
    """Password spraying orchestration."""
    header("Spray Orchestrator")
    script = TOOLS / "spray_orchestrator.sh"
    if script.exists():
        extra = getattr(args, "args", []) or []
        _run_shell(f'bash "{script}" {" ".join(extra)}')
    else:
        warn("spray_orchestrator.sh not found")
        info("Password spraying requires: spray_orchestrator.sh + cred tools")


def cmd_breach_check(args):
    """Check for breached credentials."""
    target = getattr(args, "target", "") or ""
    if not target:
        target = _read_stdin_or_prompt("Enter email or domain to check:\n")
    if not target:
        err("No target specified")
        return
    header(f"Breach Check: {target}")
    checker = TOOLS / "breach_checker.py"
    if checker.exists():
        _run_shell(f'python3 "{checker}" "{target}"')
    else:
        info(f"Checking breach data for {target}...")
        brain = _get_brain()
        result = brain.chat(None, "You are a security researcher.",
                            f"Research known data breaches and credential leaks for: {target}",
                            max_tokens=1500)
        if result:
            print(f"\n{result}")


def cmd_osint_employees(args):
    """Employee/email OSINT gathering."""
    target = args.target
    header(f"OSINT Employees: {target}")
    script = TOOLS / "osint_employees.sh"
    if script.exists():
        _run_shell(f'bash "{script}" "{target}"')
    else:
        info(f"Gathering employee intel for {target}...")
        brain = _get_brain()
        result = brain.chat(None, "You are an OSINT specialist.",
                            f"Find employee names, email patterns, and organizational structure for {target}",
                            max_tokens=2000)
        if result:
            print(f"\n{result}")


# ── Utility ────────────────────────────────────────────────────────────────────

def _read_stdin_or_prompt(prompt_text: str) -> str:
    if not sys.stdin.isatty():
        return sys.stdin.read().strip()
    print(prompt_text, end="", flush=True)
    lines = []
    try:
        while True:
            lines.append(input())
    except EOFError:
        pass
    return "\n".join(lines).strip()


def _print_banner():
    G1  = "\033[1;32m"   # bright green
    G2  = "\033[0;32m"   # normal green
    G3  = "\033[2;32m"   # dim green
    W   = "\033[1;37m"   # white bold
    LINES = [
        ("  ██████╗ ██╗   ██╗ ██████╗ ",                         G1),
        ("  ██╔══██╗██║   ██║██╔════╝ ",                         G2),
        ("  ██████╔╝██║   ██║██║  ███╗",                         G1),
        ("  ██╔══██╗██║   ██║██║   ██║",                         G2),
        ("  ██████╔╝╚██████╔╝╚██████╔╝",                         G1),
        ("  ╚═════╝  ╚═════╝  ╚═════╝ ",                         G3),
        ("  ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ ", G1),
        ("  ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗", G2),
        ("  ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝", G1),
        ("  ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗", G2),
        ("  ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║",  G1),
        ("  ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝", G3),
    ]
    print()
    for line, color in LINES:
        print(f"{color}{line}{NC}")
    print()
    print(f"  {G3}by {W}ai-bug-hunter-v2{NC}  {G3}·{NC}  {G2}ai-bug-hunter.local{NC}  {G3}·{NC}  {G1}v2 exclusive{NC}")
    print(f"  {G3}github.com/{G2}iamaworker-github{G3}/ai-bug-hunter-v2{NC}")
    print(f"  {G3}free · 33 vuln classes · BACK-ME-UP · Zen API{NC}")
    print()


# ── CLI entry point ────────────────────────────────────────────────────────────

def main():
    argv = _normalize_cli_argv(sys.argv[1:])
    parser = argparse.ArgumentParser(
        prog="engine.py",
        description="Standalone AI Bug Hunter Engine — works without Claude Code",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        Free setup (zero subscription):
          curl -fsSL https://ollama.ai/install.sh | sh
          ollama pull qwen2.5:14b
          ./engine.py setup
          ./engine.py recon target.com

        Free cloud (Groq — very fast):
          export GROQ_API_KEY=gsk_...
          ./engine.py recon target.com

        Switch providers anytime:
          ./engine.py setup
        """),
    )
    parser.add_argument("--provider", "-p",
                        help="Force provider: ollama / groq / deepseek / claude / openai / grok / zen")
    parser.add_argument("--no-banner", action="store_true", help="Suppress banner")

    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    sub.add_parser("setup",     aliases=["init"], help="One-time config wizard")
    sub.add_parser("providers", aliases=["p"], help="Show all providers + API key status")
    sub.add_parser("models",    aliases=["m"], help="List available models for active provider")
    sub.add_parser("status",    aliases=["s"], help="Show hunt pipeline status")
    sub.add_parser("chat",      aliases=["ask"], help="Interactive AI shell")

    p_recon = sub.add_parser("recon", aliases=["r"], help="Recon + AI surface analysis")
    p_recon.add_argument("target", help="Target domain or IP")

    p_hunt = sub.add_parser("hunt", aliases=["h"], help="Full hunt pipeline")
    p_hunt.add_argument("target", help="Target domain or IP")
    p_hunt.add_argument("--quick", action="store_true", help="Quick mode (fewer checks)")

    p_val = sub.add_parser("validate", aliases=["v"], help="7-Question Gate on a finding")
    p_val.add_argument("finding", nargs="?", default="", help="Finding description (or pipe via stdin)")

    p_triage = sub.add_parser("triage", aliases=["t"], help="Fast triage (alias for validate)")
    p_triage.add_argument("finding", nargs="?", default="", help="Finding description")

    p_rep = sub.add_parser("report", aliases=["rep"], help="Write submission-ready bug report")
    p_rep.add_argument("--findings-dir", default="", help="Path to findings/<target> directory")

    p_chain = sub.add_parser("chain", aliases=["c"], help="Build A->B->C exploit chain")
    p_chain.add_argument("--findings-dir", default="", help="Path to findings/<target> directory")
    p_chain.add_argument("finding", nargs="?", default="", help="Bug A description (or pipe via stdin)")

    p_auto = sub.add_parser("autopilot", aliases=["auto", "ap"], help="Full autonomous hunt loop")
    p_auto.add_argument("target", help="Target domain or IP")
    p_auto.add_argument("mode", nargs="?", default="full", help="Mode: full|quick")

    p_pickup = sub.add_parser("pickup", aliases=["resume"], help="Resume previous hunt")
    p_pickup.add_argument("target", help="Target domain or IP to resume")

    p_surf = sub.add_parser("surface", aliases=["surf"], help="Ranked attack surface analysis")
    p_surf.add_argument("target", help="Target domain or IP")

    p_mem = sub.add_parser("remember", aliases=["mem", "learn"], help="Save to cross-session memory")
    p_mem.add_argument("details", nargs="?", default="", help="Details to remember")

    sub.add_parser("memory-gc", aliases=["mgc"], help="Rotate/clean memory files")

    p_scope = sub.add_parser("scope", aliases=["sc"], help="Verify asset scope")
    p_scope.add_argument("asset", help="Domain or URL to scope-check")

    p_sa = sub.add_parser("scope-aggregate", aliases=["sa"], help="Pull in-scope assets from program")
    p_sa.add_argument("program", help="Program URL or slug")

    p_intel = sub.add_parser("intel", aliases=["i"], help="CVEs + disclosed reports for target")
    p_intel.add_argument("target", help="Target domain or IP")
    p_intel.add_argument("--tech", default="", help="Comma-separated technologies (e.g. nextjs,graphql)")

    p_to = sub.add_parser("takeover", aliases=["to"], help="Subdomain takeover scan")
    p_to.add_argument("target", help="Target domain or IP")

    p_cr = sub.add_parser("cloud-recon", aliases=["cr"], help="Cloud asset discovery (S3/Azure/GCP)")
    p_cr.add_argument("target", help="Target domain or IP")

    p_sh = sub.add_parser("secrets-hunt", aliases=["sh"], help="Search leaked creds in JS/git/repos")
    p_sh.add_argument("target", help="Target domain or IP")

    p_sl = sub.add_parser("secrets-leak", aliases=["sl"], help="BACK-ME-UP multi-collector secrets scan")
    p_sl.add_argument("target", help="Target domain or IP")

    p_pd = sub.add_parser("param-discover", aliases=["pd"], help="Discover hidden HTTP parameters")
    p_pd.add_argument("url", help="Full URL to probe for parameters")

    p_bp = sub.add_parser("bypass-403", aliases=["b403", "bypass"], help="403/401 bypass techniques")
    p_bp.add_argument("url", help="URL with 403/401 response")

    p_cv = sub.add_parser("scan-cves", aliases=["cves"], help="Nuclei CVE sweep (critical/high)")
    p_cv.add_argument("target", help="Target domain or IP")

    sub.add_parser("arsenal", aliases=["tools"], help="List installed security tools")

    p_wa = sub.add_parser("web3-audit", aliases=["web3"], help="Smart contract security audit")
    p_wa.add_argument("contract", help="Contract address or .sol source path")

    p_ts = sub.add_parser("token-scan", aliases=["tscan"], help="Meme coin / token rug-pull analysis")
    p_ts.add_argument("contract", help="Token contract address")

    p_wg = sub.add_parser("wordlist-gen", aliases=["wgen"], help="Generate custom wordlists")
    p_wg.add_argument("args", nargs=argparse.REMAINDER, help="Args passed to wordlist_engine.sh")

    p_sp = sub.add_parser("spray", aliases=["sp"], help="Password spraying orchestration")
    p_sp.add_argument("args", nargs=argparse.REMAINDER, help="Args passed to spray_orchestrator.sh")

    p_bc = sub.add_parser("breach-check", aliases=["breach"], help="Check for breached credentials")
    p_bc.add_argument("target", nargs="?", default="", help="Email or domain to check")

    p_oe = sub.add_parser("osint-employees", aliases=["osint"], help="Employee/email OSINT gathering")
    p_oe.add_argument("target", help="Target domain")

    args = parser.parse_args(argv)

    # Apply provider override
    if getattr(args, "provider", None):
        os.environ["BRAIN_PROVIDER"] = args.provider

    # Load saved API keys into environment before any LLM call
    cfg = load_config()
    for env_var in ("ZEN_API_KEY", "GROQ_API_KEY", "DEEPSEEK_API_KEY", "ANTHROPIC_API_KEY",
                    "OPENAI_API_KEY", "XAI_API_KEY"):
        if not os.environ.get(env_var) and cfg.get(env_var):
            os.environ[env_var] = cfg[env_var]

    quiet_cmds = {"status", "providers", "models", None}
    if not getattr(args, "no_banner", False) and args.command not in quiet_cmds:
        _print_banner()

    dispatch = {
        "setup":          cmd_setup,
        "providers":      cmd_providers,
        "models":         cmd_models,
        "recon":          cmd_recon,
        "hunt":           cmd_hunt,
        "validate":       cmd_validate,
        "triage":         cmd_triage,
        "report":         cmd_report,
        "chain":          cmd_chain,
        "chat":           cmd_chat,
        "status":         cmd_status,
        "autopilot":      cmd_autopilot,
        "pickup":         cmd_pickup,
        "surface":        cmd_surface,
        "remember":       cmd_remember,
        "memory-gc":      cmd_memory_gc,
        "scope":          cmd_scope,
        "scope-aggregate": cmd_scope_aggregate,
        "intel":          cmd_intel,
        "takeover":       cmd_takeover,
        "cloud-recon":    cmd_cloud_recon,
        "secrets-hunt":   cmd_secrets_hunt,
        "secrets-leak":   cmd_secrets_leak,
        "param-discover": cmd_param_discover,
        "bypass-403":     cmd_bypass_403,
        "scan-cves":      cmd_scan_cves,
        "arsenal":        cmd_arsenal,
        "web3-audit":     cmd_web3_audit,
        "token-scan":     cmd_token_scan,
        "wordlist-gen":   cmd_wordlist_gen,
        "spray":          cmd_spray,
        "breach-check":   cmd_breach_check,
        "osint-employees": cmd_osint_employees,
    }

    if not args.command:
        parser.print_help()
        print()
        _print_quick_help()
        return

    fn = dispatch.get(args.command)
    if fn:
        fn(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
