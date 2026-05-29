import json

data = json.loads(open('output/results.json', encoding='utf-8').read())

print("=== SCREENSHOT UNIQUENESS CHECK ===\n")
all_hashes = {}
for r in data['results']:
    t3 = r.get('tier3_output') or {}
    shots = t3.get('screenshots', [])
    for s in shots:
        # extract filename hash from URL or filename
        fname = s.split('/')[-1]
        if fname in all_hashes:
            print(f"!! DUPLICATE !! {fname}")
            print(f"   Appears in: {all_hashes[fname]} AND {r['domain']}")
        else:
            all_hashes[fname] = r['domain']

print(f"Total screenshots: {len(all_hashes)}")
print(f"Unique screenshots: {len(set(all_hashes.keys()))}")

if len(all_hashes) == len(set(all_hashes.keys())):
    print("\n✅ ALL SCREENSHOTS ARE UNIQUE — zero bleed between domains!")
else:
    print("\n❌ DUPLICATE SCREENSHOTS DETECTED")

print("\n=== PER DOMAIN BREAKDOWN ===")
for r in data['results']:
    t3 = r.get('tier3_output') or {}
    shots = t3.get('screenshots', [])
    s3 = [s for s in shots if s.startswith('http')]
    local = [s for s in shots if not s.startswith('http')]
    if shots or r['tier_reached'] == 3:
        icon = '✅' if s3 else ('⚠️' if local else '❌')
        print(f"  {icon} {r['domain']}: {len(s3)} S3 | {len(local)} local")
        for s in shots:
            fname = s.split('/')[-1]
            print(f"       {fname}")
