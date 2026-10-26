"""Whether a retrained model may replace the shipped one: its report against
the shipped model's (models/url-model.json). The two were measured on
different data, so the limits leave room for that; a model that fails any
of them is not proposed. The same limits hold against the hand-checked
model's report (baseline.json), so small losses cannot add up from month to
month.

- No benign source has more than 0.2% of its never-seen pages at High.
- The AUC is at most 0.005 lower.
- The share of never-seen Phishing.Database pages at High is at most 3
  points lower.
- Scoring stays within §16's budget: p50 under 5 µs on the training machine,
  or, when the shipped model was measured on the same machine ("champion"),
  at most a quarter slower than it (CI's machines are slower than the one
  the budget was set on, and slower for the shipped model too).

When the new report also measured the shipped model on the same test sites
("champion", rift-train --champion), the two are compared like for like,
with tighter limits: the AUC at most 0.002 lower, the never-seen
Phishing.Database pages at High at most 1 point lower, and no benign source
more than 0.05 points higher at High.

The data is checked too: a source whose test sites fell below half of the
shipped report's (a feed that failed or shrank) refuses the model, which
would otherwise learn from a lopsided month.

usage: python3 -I gate.py <shipped.json> <new.json> [<baseline.json>]   (prints a summary; exit 1 if refused)
"""
import json, sys

old, new = (json.load(open(path)) for path in sys.argv[1:3])
references = [("shipped", old)] + [("baseline", json.load(open(path))) for path in sys.argv[3:4]]


def high(report, source):
    for row in report["test"]:
        if row["source"] == source and row["view"] == "address":
            return row["high_rate"]
    return None


problems = []
for row in new["test"]:
    if row["label"] == "benign" and row["view"] == "address" and row["high_rate"] > 0.002:
        problems.append(f"{row['source']}: {row['high_rate']:.2%} of ordinary pages at High")
auc_new, caught_new = new["auc_trained_sources_address_view"], high(new, "phishdb")
for name, ref in references:
    auc_ref, caught_ref = ref["auc_trained_sources_address_view"], high(ref, "phishdb")
    if auc_new < auc_ref - 0.005:
        problems.append(f"AUC {auc_new:.4f}, against the {name} {auc_ref:.4f}")
    if caught_new is None or (caught_ref is not None and caught_new < caught_ref - 0.03):
        problems.append(f"never-seen Phishing.Database pages at High: {caught_new}, against the {name} {caught_ref:.2%}")
auc_old = old["auc_trained_sources_address_view"]
p50 = new["scoring_microseconds_on_this_machine"]["p50"]
champion_p50 = new.get("champion", {}).get("scoring_microseconds_on_this_machine", {}).get("p50")
if champion_p50 is not None:
    if p50 > champion_p50 * 1.25:
        problems.append(f"scoring p50 {p50} µs, against the shipped model's {champion_p50} µs on this machine")
elif p50 >= 5:
    problems.append(f"scoring p50 {p50} µs")

champion = new.get("champion")
if champion:
    auc_champion = champion["auc_trained_sources_address_view"]
    if auc_new < auc_champion - 0.002:
        problems.append(f"AUC {auc_new:.4f}, against the shipped model's {auc_champion:.4f} on the same sites")
    caught_champion = high(champion, "phishdb")
    if caught_champion is not None and (caught_new is None or caught_new < caught_champion - 0.01):
        problems.append(f"never-seen Phishing.Database pages at High: {caught_new}, against the shipped model's {caught_champion:.2%} on the same sites")
    for row in new["test"]:
        if row["label"] == "benign" and row["view"] == "address":
            before = high(champion, row["source"])
            if before is not None and row["high_rate"] > before + 0.0005:
                problems.append(f"{row['source']}: {row['high_rate']:.2%} of ordinary pages at High, against the shipped model's {before:.2%} on the same sites")


def sizes(report):
    return {row["source"]: row["n"] for row in report["test"] if row["view"] == "address"}


for source, n in sizes(old).items():
    now = sizes(new).get(source)
    if now is not None and now < n / 2:
        problems.append(f"{source}: {now} test sites, against {n} last time (a feed failed or shrank)")

print(f"AUC {auc_old:.4f} -> {auc_new:.4f}" + (f" (shipped model on the same sites: {champion['auc_trained_sources_address_view']:.4f})" if champion else ""))
for source in [r["source"] for r in new["test"] if r["view"] == "address"]:
    before, after = high(old, source), high(new, source)
    print(f"  {source:<18} High {'-' if before is None else f'{before:.2%}':>7} -> {after:.2%}")
print(f"model {new['model']['sha256']} ({new['model']['bytes']} bytes)")
if problems:
    print("refused:\n  " + "\n  ".join(problems))
    sys.exit(1)
print("passes the gate")
