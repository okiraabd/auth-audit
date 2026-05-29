import json, sys
sys.path.insert(0,'src')
data = json.loads(open('output/results.json').read())
print('=== SUMMARY ===')
print(f'Total: {data["total"]}')
for v, c in data['summary'].items():
    print(f'  {v}: {c}')
print()
print('=== PER-DOMAIN ===')
for r in data['results']:
    t3 = r.get('tier3_output') or {}
    t2 = r.get('tier2_output') or {}
    t1 = r.get('tier1_output') or {}
    t3_verb = t3.get('verdict','skipped') if t3 else 'skipped'
    t3_conf = t3.get('confidence','-') if t3 else '-'
    print(f"  {r['domain']:<35} {r['final_verdict']:<20} {r['confidence']:>3}%  T{r['tier_reached']}  review={r['needs_manual_review']}")
    print(f"    T1 verdict={t1.get('rule_verdict','?')} score={t1.get('rule_score','?')} triggered={t1.get('triggered_rules','?')}")
    print(f"    T2 verdict={t2.get('verdict','N/A')} conf={t2.get('confidence','N/A')} hermes_needed={t2.get('needs_browser_escalation','N/A')}")
    print(f"    T3 verdict={t3_verb} conf={t3_conf}")
    print(f"    reasoning: {r['reasoning'][:120]}...")
    print()
