"""Free Resources Hunter collector. Standard library only.
Safe by design: public sources only, no accounts, no spending, never sets VERIFIED."""
import json, urllib.request, urllib.parse, datetime, os, re
UA = {"User-Agent": "free-resources-hunter/1.0 (public-data check)"}
now = datetime.datetime.now(datetime.timezone.utc)
today = now.strftime("%Y-%m-%d")

def get(url, headers=None, timeout=15):
    req = urllib.request.Request(url, headers={**UA, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read()

data = json.load(open("data.json"))
items = data["items"]

# 1) Reachability + public domain registration date (RDAP) for each site
for d in items:
    host = urllib.parse.urlparse(d["site"]).hostname or ""
    try:
        status, _ = get(d["site"])
        d["siteStatus"] = status
    except Exception as e:
        d["siteStatus"] = "error: " + str(e)[:60]
    d["siteChecked"] = today
    parts = host.split(".")
    root = ".".join(parts[-2:]) if len(parts) >= 2 else host
    try:
        _, body = get("https://rdap.org/domain/" + root)
        for ev in json.loads(body).get("events", []):
            if ev.get("eventAction") == "registration":
                d["domainRegistered"] = ev["eventDate"][:10]
    except Exception:
        d.setdefault("domainRegistered", None)
    if d.get("domainRegistered"):
        age = (now.date() - datetime.date.fromisoformat(d["domainRegistered"])).days
        d["fl"] = [f for f in d["fl"] if not f.startswith("Domain registered")]
        if age < 180:
            d["fl"].append(f"Domain registered only {age} days ago (recent domains deserve extra care; not proof of a problem).")

# 2) New public GitHub repos as UNCONFIRMED candidates (real creation dates)
since = (now - datetime.timedelta(days=7)).strftime("%Y-%m-%d")
q = urllib.parse.quote(f"free llm api created:>{since}")
hdr = {"Accept": "application/vnd.github+json"}
if os.environ.get("GITHUB_TOKEN"):
    hdr["Authorization"] = "Bearer " + os.environ["GITHUB_TOKEN"]
try:
    _, body = get(f"https://api.github.com/search/repositories?q={q}&sort=created&order=desc&per_page=10", hdr)
    known = {d["site"] for d in items}
    for r in json.loads(body).get("items", []):
        if r["html_url"] in known:
            continue
        items.append({"id": len(items), "n": r["full_name"], "site": r["html_url"], "cat": "llm",
            "kind": "Candidate: GitHub repo (may be a list, not a provider)", "models": "not checked",
            "quota": "not checked", "reset": "not checked", "req": "not checked", "fmt": "not checked",
            "st": "UNCONFIRMED", "ev": [["GitHub repo", r["html_url"]]],
            "fl": ["Auto-discovered; contents not reviewed. Repo may promote shared keys or scams: do not paste credentials anywhere."],
            "src": today, "added": today, "repoCreated": r["created_at"][:10]})
except Exception as e:
    data["githubError"] = str(e)[:80]

data["updated"] = now.strftime("%Y-%m-%dT%H:%M:%SZ")
json.dump(data, open("data.json", "w"), indent=1)
print("items:", len(items))
