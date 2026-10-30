#!/usr/bin/env python3
"""Fail on high-confidence credential patterns and accidentally included runtime state.
This is a small release guard, not a complete secret scanner or security audit.
"""
from pathlib import Path
import re,subprocess,sys
ROOT=Path(__file__).resolve().parent.parent
skip={'node_modules','artifacts','__pycache__','.git'}
patterns=[re.compile(rb'github_pat_[A-Za-z0-9_]{30,}'),re.compile(rb'gh[pousr]_[A-Za-z0-9]{30,}'),re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),re.compile(rb'AKIA[0-9A-Z]{16}'),re.compile(rb'https://[^\s\"\']*chainstack[^\s\"\']*/[a-fA-F0-9]{24,}')]
files=[p for p in ROOT.rglob('*') if p.is_file() or p.is_symlink()]
errors=[];count=0
for p in files:
 rel=p.relative_to(ROOT)
 if any(part in skip for part in rel.parts) or p.suffix=='.pyc':continue
 count+=1
 private=(p.name.startswith('.env') and p.name!='.env.example') or '.sqlite' in p.name or p.name=='node.json' or (p.name.startswith('wallet-monitor-') and p.suffix=='.json') or p.suffix=='.log'
 if private or p.is_symlink():errors.append(str(rel));continue
 if p.stat().st_size>2*1024*1024:errors.append(str(rel));continue
 if any(pattern.search(p.read_bytes()) for pattern in patterns):errors.append(str(rel))
if errors:
 print('Source guard blocked files (values withheld):',', '.join(errors),file=sys.stderr);raise SystemExit(1)
print(f'Source guard passed for {count} files; heuristic checks do not prove absence of secrets.')
