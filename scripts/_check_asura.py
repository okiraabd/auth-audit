import json
data = json.loads(open('output/results.json', encoding='utf-8').read())
for r in data['results']:
    if r['domain'] == 'asura-s3.stellardata.ai':
        print(f"Verdict: {r['final_verdict']}")
        print(f"Reasoning: {r['reasoning']}")
        t3 = r.get('tier3_output') or {}
        print(f"T3 Verdict: {t3.get('verdict')}")
        print(f"T3 Reasoning: {t3.get('reasoning')}")
        print(f"T3 Evidence: {t3.get('visual_evidence')}")
        print(f"Screenshots: {len(t3.get('screenshots', []))}")
