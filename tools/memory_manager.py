#!/usr/bin/env python3
"""
Memory System - Persist findings, techniques, and patterns across sessions
Uses JSONL files with rotation at 10MB
"""
import json, os, time
from pathlib import Path

MEMORY_DIR = Path(__file__).parent.parent / "memory"

class Memory:
    def __init__(self):
        MEMORY_DIR.mkdir(parents=True, exist_ok=True)
        self.journal_file = MEMORY_DIR / "journal.jsonl"
        self.patterns_file = MEMORY_DIR / "patterns.jsonl"
        self.audit_file = MEMORY_DIR / "audit.jsonl"
        self.max_size = 10 * 1024 * 1024  # 10MB
    
    def _rotate(self, filepath):
        if filepath.exists() and filepath.stat().st_size > self.max_size:
            backup = filepath.with_suffix(f".{int(time.time())}.jsonl.bak")
            filepath.rename(backup)
            print(f"[memory] Rotated {filepath.name} -> {backup.name}")
    
    def log_journal(self, entry_type, target, data):
        """Log a journal entry"""
        self._rotate(self.journal_file)
        entry = {
            "type": entry_type,
            "target": target,
            "data": data,
            "timestamp": time.time()
        }
        with open(self.journal_file, "a") as f:
            f.write(json.dumps(entry) + "\n")
    
    def log_pattern(self, target, vuln_type, technique, success=True):
        """Log a successful attack pattern"""
        self._rotate(self.patterns_file)
        entry = {
            "target": target,
            "vuln_type": vuln_type,
            "technique": technique,
            "success": success,
            "timestamp": time.time()
        }
        with open(self.patterns_file, "a") as f:
            f.write(json.dumps(entry) + "\n")
    
    def log_audit(self, target, summary):
        """Log audit/finding summary"""
        self._rotate(self.audit_file)
        entry = {
            "target": target,
            "summary": summary,
            "timestamp": time.time()
        }
        with open(self.audit_file, "a") as f:
            f.write(json.dumps(entry) + "\n")
    
    def get_patterns_for_target(self, target):
        """Get learned patterns for a target"""
        if not self.patterns_file.exists():
            return []
        patterns = []
        with open(self.patterns_file) as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    if entry["target"] == target:
                        patterns.append(entry)
                except:
                    pass
        return patterns

if __name__ == "__main__":
    mem = Memory()
    import sys
    if len(sys.argv) > 1:
        mem.log_journal("cli", sys.argv[1], {"action": "manual_log"})
        print(f"[+] Logged entry for {sys.argv[1]}")
    else:
        print(f"Memory stats:")
        for f in [mem.journal_file, mem.patterns_file, mem.audit_file]:
            if f.exists():
                lines = len(f.read_text().splitlines())
                size = f.stat().st_size
                print(f"  {f.name}: {lines} entries, {size/1024:.1f}KB")
