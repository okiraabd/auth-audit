import json, sys

data = json.loads(open('output/results.json', encoding='utf-8').read())

print("=" * 70)
print(f"  COMPREHENSIVE AUTH AUDIT EVALUATION — {len(data['results'])} domains")
print("=" * 70)

for r in data['results']:
    d = r['domain']
    v = r['final_verdict']
    conf = r['confidence']
    tier = r['tier_reached']
    svc = r['service_type']
    reasoning = r['reasoning']
    probe_count = len(r.get('probe_summary', {}))
    t3 = r.get('tier3_output') or {}
    t2 = r.get('tier2_output') or {}
    shots = t3.get('screenshots', [])
    s3_shots = [s for s in shots if s.startswith('http')]
    local_shots = [s for s in shots if not s.startswith('http')]

    emoji_map = {
        'PROTECTED': '🔒', 'OPEN': '🔓', 'PARTIAL': '⚠️', 
        'OPEN_API': '🔓', 'OPEN_DOCS': '📄', 'UNKNOWN': '❓', 
        'UNREACHABLE': '💀', 'GRAPHQL_OPEN': '⚠️', 'GRAPHQL_CRITICAL': '🚨',
        'OPEN_API_CRITICAL': '🚨'
    }
    em = emoji_map.get(v, '❓')

    print(f"\n{'─'*70}")
    print(f"  {em} {d}")
    print(f"     Verdict     : {v}  ({conf}% confidence)")
    print(f"     Service     : {svc}  |  Tier: T{tier}  |  Paths probed: {probe_count}")
    
    # Count discovery discovered paths
    discovery_paths = [p for p, i in r.get('probe_summary', {}).items() if i.get('category') == 'discovery_discovered']
    if discovery_paths:
        print(f"     Active Discovery      : {len(discovery_paths)} new path(s) discovered → {', '.join(discovery_paths[:3])}")
    
    # Screenshot status
    if s3_shots:
        print(f"     Screenshots : ✅ {len(s3_shots)} saved to S3")
        for s in s3_shots:
            print(f"                   {s}")
    elif local_shots:
        print(f"     Screenshots : ⚠️  {len(local_shots)} local only (S3 upload failed)")
    elif tier == 3:
        print(f"     Screenshots : ⚠️  T3 ran but no screenshots")
    
    # Reasoning
    print(f"     Reasoning   : {reasoning[:220]}...")
    
    # Visual evidence
    ev = t3.get('visual_evidence') or t2.get('browser_escalation_reason', '')
    if ev:
        print(f"     Evidence    : {ev[:180]}")

print(f"\n{'='*70}")
print("\nSCREENSHOT HEALTH:")
all_domains_t3 = [r for r in data['results'] if r['tier_reached'] == 3]
all_screenshots_ok = all(
    any(s.startswith('http') for s in (r.get('tier3_output') or {}).get('screenshots', []))
    for r in all_domains_t3
)
print(f"  Domains that reached T3  : {len(all_domains_t3)}")
print(f"  All screenshots on S3    : {'✅ YES' if all_screenshots_ok else '❌ NO — some failed'}")
for r in all_domains_t3:
    shots = (r.get('tier3_output') or {}).get('screenshots', [])
    s3 = [s for s in shots if s.startswith('http')]
    local = [s for s in shots if not s.startswith('http')]
    status = '✅' if s3 else '❌'
    print(f"    {status} {r['domain']}: {len(s3)} S3, {len(local)} local")
