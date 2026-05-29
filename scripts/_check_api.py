import json
data = json.loads(open('output/results.json', encoding='utf-8').read())
for r in data['results']:
    if 'api-agent' in r['domain']:
        print(f"Domain: {r['domain']}")
        for p, i in r['probe_summary'].items():
            print(f"  {p}: {i.get('status')} {i.get('error')}")
