#!/usr/bin/env bash
# Sets up the eval workspace: the demo app as a git repo, the engagement, the earlier review,
# and a copy of the roster that is fetched, vetted and approved by "eval-fixture" with the real tools.
# Needs network access to github.com (fetching the pinned generals).
set -eu
here="$(dirname "$0")"
skill="$here/../.."
cp -R "$here/files/." .
mkdir -p tasknest && cp "$skill/assets/tasknest.py" tasknest/ && (cd tasknest && git init -q && git add . && git -c user.email=t@t -c user.name=t commit -qm init)
sed -i "s#__PWD__#$PWD#g" .great-general/engagement.yaml
cp "$skill/generals.lock.json" generals.lock.json
python3 "$skill/scripts/generals.py" fetch --lock generals.lock.json --cache "$PWD/.gg-cache" >/dev/null
for id in $(python3 -c "import json;print(' '.join(g['id'] for g in json.load(open('generals.lock.json'))['generals'] if g.get('repo')))"); do
  python3 "$skill/scripts/generals.py" vet --lock generals.lock.json --cache "$PWD/.gg-cache" --id "$id" >/dev/null || true
  commit=$(python3 -c "import json,sys;print([g['commit'] for g in json.load(open('generals.lock.json'))['generals'] if g['id']==sys.argv[1]][0])" "$id")
  python3 "$skill/scripts/generals.py" approve --lock generals.lock.json --cache "$PWD/.gg-cache" --id "$id" --commit "$commit" --by eval-fixture --note "eval setup" >/dev/null
done
