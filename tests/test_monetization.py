"""Offline tests for the monetization-map builder (cos moneymap)."""
import os, tempfile
os.environ["CONTINUITYOS_SILENCE_EMBED_WARN"] = "1"
from continuityos.monetization import extract_signals, build_map, build, render_map_md, scan_paths

SAMPLE = """
# My offers
Inner Circle — $997/mo, private channel
Consulting 1-on-1: $299/ч
Course bundle $497 one-time
GPT-S:CORE SDK license $4,999
Enterprise retainer $9,970/year
Target: $350K/мес by M12
"""

def test_extract_prices_and_cadence():
    sig = extract_signals(SAMPLE)
    amts = sorted({s["price_usd"] for s in sig})
    assert 997 in amts and 299 in amts and 497 in amts and 4999 in amts and 9970 in amts
    assert 350000 in amts                      # $350K parsed as 350000
    cad = {round(s["price_usd"]): s["cadence"] for s in sig}
    assert cad[997] == "monthly" and cad[299] == "hourly" and cad[9970] == "annual" and cad[497] == "one-time"
    print("PASS extract_prices_and_cadence")

def test_build_map_buckets_tiers():
    m = build_map(extract_signals(SAMPLE))
    assert any(o["price_usd"] == 997 for o in m["tiers"]["Recurring (monthly)"])
    assert any(o["price_usd"] == 299 for o in m["tiers"]["Services (hourly)"])
    assert any(o["price_usd"] == 4999 for o in m["tiers"]["One-time / products"])
    assert any(o["price_usd"] == 350000 for o in m["tiers"]["Recurring (monthly)"])  # /мес
    # $9,970/year -> annual tier; a $5000+ one-time would be enterprise
    assert any(o["price_usd"] == 9970 for o in m["tiers"]["Recurring (annual)"])
    print("PASS build_map_buckets_tiers")

def test_build_from_dir_and_render():
    d = tempfile.mkdtemp()
    open(os.path.join(d, "plan.md"), "w", encoding="utf-8").write(SAMPLE)
    open(os.path.join(d, "notes.txt"), "w", encoding="utf-8").write("Delist EWS $99/mo premium")
    m = build(paths=[d])
    assert m["files_scanned"] == 2 and m["count"] >= 6
    md = render_map_md(m)
    assert "Monetization map" in md and "$997/monthly" in md and "Delist EWS" in md
    print("PASS build_from_dir_and_render")

def test_dedupe_and_empty():
    m = build_map(extract_signals("Inner Circle $997/mo\nInner Circle $997/mo"))
    assert m["count"] == 1                      # identical lines deduped
    empty = render_map_md(build_map([]))
    assert "No priced offers" in empty
    print("PASS dedupe_and_empty")

def test_scan_skips_binaryish_and_missing():
    d = tempfile.mkdtemp()
    open(os.path.join(d, "a.md"), "w", encoding="utf-8").write("$50/mo")
    sc = scan_paths([d, "/nonexistent/path"])
    assert sc["files"] == 1
    print("PASS scan_skips_binaryish_and_missing")

def run():
    for n in sorted(x for x in globals() if x.startswith("test_")):
        globals()[n]()
    print("ALL_MONETIZATION_TESTS_PASS")

if __name__ == "__main__":
    run()
