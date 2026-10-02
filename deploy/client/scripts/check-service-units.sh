#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Checks the client service units (CONTRACT §15.2 "bounded worst case").
#
#   check-service-units.sh [--dry-run] [--live MOOCHY_BIN MOOCHY_HOME]
#
# Always: systemd-analyze verify of both units, exposure score of the system
# unit (must stay <= 2.0), the launchd plist parses.
# --live: runs `moochy up --foreground` under the real user unit (a runtime
# copy in $XDG_RUNTIME_DIR/systemd/user, binary and home substituted, the
# keystore passphrase from $MOOCHY_PASSPHRASE passed as a credential) and
# requires the self-lockdown report and the ready line. Needs a logged-in home.
set -Eeuo pipefail
here=$(cd "$(dirname "$0")/../service" && pwd)
dry_run=0 bin="" home=""
while (($#)); do
	case $1 in
	--dry-run) dry_run=1 ;;
	--live) bin=${2:?}; home=${3:?}; shift 2 ;;
	*) sed -n '3,/^set /s/^# \{0,1\}//p' "$0" >&2; exit 2 ;;
	esac
	shift
done
if ((dry_run)); then
	echo "[dry-run] systemd-analyze verify $here/moochy.{user,system}.service" >&2
	echo "[dry-run] systemd-analyze security --offline=yes moochy.system.service (<= 2.0)" >&2
	echo "[dry-run] plistlib parse $here/dev.moochy.agent.plist" >&2
	[[ -n $bin ]] && echo "[dry-run] systemctl --user start <runtime copy of moochy.user.service> with $bin, $home" >&2
	exit 0
fi

for u in moochy.user.service moochy.system.service; do
	out=$(systemd-analyze verify --man=no "$here/$u" 2>&1 | grep -v 'is not executable' || true)
	[[ -z $out ]] || { echo "FAIL verify $u: $out" >&2; exit 1; }
done
score=$(systemd-analyze security --offline=yes "$here/moochy.system.service" | sed -n 's/.*exposure level for .*: \([0-9.]*\) .*/\1/p')
awk -v s="$score" 'BEGIN { exit !(s <= 2.0) }' || { echo "FAIL system unit exposure $score > 2.0" >&2; exit 1; }
python3 -c 'import plistlib,sys; d=plistlib.load(open(sys.argv[1],"rb")); assert d["Umask"]==0o077 and d["HardResourceLimits"]["Core"]==0' "$here/dev.moochy.agent.plist"
echo "ok   units verify, system exposure $score, plist parses"
[[ -n $bin ]] || exit 0

: "${MOOCHY_PASSPHRASE:?set MOOCHY_PASSPHRASE for the live check}"
name=moochy-unitcheck-$$
dir=${XDG_RUNTIME_DIR:?}/systemd/user
work=$(mktemp -d "${TMPDIR:-/tmp}/moochy-unitcheck.XXXXXX")
cleanup() {
	systemctl --user stop "$name" 2>/dev/null || true
	rm -f "$dir/$name.service"
	systemctl --user daemon-reload || true
	rm -rf "$work"
}
trap cleanup EXIT
printf '%s' "$MOOCHY_PASSPHRASE" >"$work/pass" && chmod 0600 "$work/pass"
mkdir -p "$dir"
sed -e "s#%h/.local/bin/moochy#$bin#" \
	-e "s#^\[Service\]#[Service]\nEnvironment=MOOCHY_HOME=$home ${MOOCHY_INSECURE_DEV:+MOOCHY_INSECURE_DEV=1}\nLoadCredential=moochy-passphrase:$work/pass#" \
	-e "s#^Restart=on-failure#Restart=no#" \
	"$here/moochy.user.service" >"$dir/$name.service"
systemctl --user daemon-reload
since=$(date '+%F %T')
systemctl --user start "$name"
for _ in $(seq 60); do
	log=$(journalctl --user -u "$name" --since "$since" --no-pager -o cat)
	[[ $log == *'"event":"ready"'* || $log == *'"event":"error"'* ]] && break
	sleep 0.5
done
[[ $log == *'"locked":true'* && $log == *'"seccomp":true'* ]] || { echo "FAIL no lockdown report under the user unit: ${log:0:400}" >&2; exit 1; }
[[ $log == *'"event":"ready"'* ]] || { echo "FAIL not ready under the user unit: ${log:0:400}" >&2; exit 1; }
pid=$(systemctl --user show -p MainPID --value "$name")
if ! grep -q '^NoNewPrivs:[[:space:]]*1' "/proc/$pid/status" || ! grep -q '^Seccomp:[[:space:]]*2' "/proc/$pid/status"; then
	echo "FAIL unit seccomp/no_new_privs not applied" >&2
	exit 1
fi
echo "ok   moochy up under the user unit: locked down, ready, NoNewPrivs=1, Seccomp=2 (unit filter + self-lockdown)"
