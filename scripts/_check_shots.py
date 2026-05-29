import json

data = json.loads(open('output/run3/results.json').read())

print('=== SCREENSHOT CHECK ===')
for r in data['results']:
    t3 = r.get('tier3_output') or {}
    shots = t3.get('screenshots', [])
    if shots:
        print(f"\n{r['domain']} (T{r['tier_reached']}):")
        for s in shots:
            prefix = 'S3 ✅' if str(s).startswith('http') else 'LOCAL ⚠️'
            print(f'  [{prefix}] {s}')
    elif r['tier_reached'] == 3:
        print(f"\n{r['domain']} (T3): ⚠️  no screenshots returned")

print()
print('=== VERDICTS ===')
for r in data['results']:
    print(f"  {r['domain']:<35} {r['final_verdict']:<12} {r['confidence']}%  T{r['tier_reached']}")
