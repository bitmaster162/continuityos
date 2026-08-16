from __future__ import annotations

import argparse
import json
from pathlib import Path

from .store.sqlite import SQLiteEvidenceStore


def _store(path: str) -> SQLiteEvidenceStore:
    return SQLiteEvidenceStore(Path(path).expanduser())


def main(argv=None) -> int:
    p=argparse.ArgumentParser(prog="sct")
    p.add_argument("--db",default=str(Path.home()/".sct"/"evidence.db"))
    sub=p.add_subparsers(dest="cmd",required=True)
    sub.add_parser("init")
    sub.add_parser("doctor")
    sub.add_parser("verify")
    args=p.parse_args(argv)
    store=_store(args.db)
    try:
        if args.cmd=="init": result={"ok":True,"db":str(store.path),"head":store.head().__dict__}
        elif args.cmd=="doctor": result={"ok":True,"capabilities":sorted(store.capabilities()),"verify":store.verify().__dict__}
        else: result=store.verify().__dict__
        print(json.dumps(result,ensure_ascii=False,sort_keys=True))
        return 0 if result.get("ok",True) else 2
    finally: store.close()

if __name__=="__main__": raise SystemExit(main())
