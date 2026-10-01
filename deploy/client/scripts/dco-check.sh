#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# DCO check (CONTRACT §0a, plan 12 Q1): every non-merge commit in BASE..HEAD
# carries `Signed-off-by:` with its author's e-mail (https://developercertificate.org).
#   dco-check.sh [--dry-run] [BASE [HEAD]]     (default origin/main..HEAD)
# --dry-run reports without failing.
set -Eeuo pipefail
dry_run=0
if [[ ${1:-} == --dry-run ]]; then dry_run=1; shift; fi
base=${1:-origin/main} head=${2:-HEAD}

bad=0 n=0
while IFS=$'\x1f' read -r -d $'\x1e' sha email signoffs; do
	sha=${sha//$'\n'/}
	[[ -n $sha ]] || continue
	n=$((n + 1))
	email=${email,,}
	if [[ ${signoffs,,} == *"<$email>"* ]]; then
		printf 'ok   %s\n' "${sha:0:12}"
	else
		printf 'FAIL %s: no "Signed-off-by: … <%s>" (git commit -s)\n' "${sha:0:12}" "$email"
		bad=$((bad + 1))
	fi
done < <(git log --no-merges --format='%H%x1f%ae%x1f%(trailers:key=Signed-off-by,valueonly,separator=%x2C)%x1e' "$base..$head")

echo "$n commit(s), $bad without DCO sign-off"
((dry_run)) && exit 0
((bad == 0))
