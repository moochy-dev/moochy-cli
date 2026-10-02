#!/usr/bin/env bash
# macOS Seatbelt checks for moochy-sandbox (CONTRACT §15): `moochy run` (mirrors the Linux
# e93/e94/e97 tests), the donor self-lockdown and the validator child. Needs a real Mac.
# Usage: tests/macos-check.sh [path/to/moochy-sandbox-test]   (cargo build -p moochy-sandbox --bin moochy-sandbox-test)
set -u
B=${1:-$(cd "$(dirname "$0")/../../.." && pwd)/target/debug/moochy-sandbox-test}; BD=$(dirname "$B"); J=$(mktemp -d); trap 'rm -rf "$J"' EXIT
mkdir -p $J/wt $J/outside; (cd $J/wt && git init -q && echo hi > app.txt && echo "API_KEY=topsecret" > .env && echo "ignored.txt" > .gitignore && echo ign > ignored.txt && echo "-----BEGIN KEY-----" > id_ed25519 && git add app.txt .gitignore && git -c commit.gpgsign=false -c user.email=t@t -c user.name=t commit -qm init); echo outsidesecret > $J/outside/secret.txt
python3 -m http.server --bind 127.0.0.1 18787 >/dev/null 2>&1 & GW=$!
python3 -c "import socket,os,time; p='$J/gw.sock'; s=socket.socket(socket.AF_UNIX); s.bind(p); s.listen(); time.sleep(600)" & GS=$!
for i in $(seq 1 50); do curl -s -o /dev/null http://127.0.0.1:18787/ && [ -S $J/gw.sock ] && break; perl -e 'select(undef,undef,undef,0.1)'; done
pass=0; fail=0
R() { exp=$1; shift; out=$("$B" run $J/wt --ro $BD --gw $J/gw.sock --gw-port 18787 --env ANTHROPIC_BASE_URL=http://127.0.0.1:18787 -- "$@" 2>&1); rc=$?; if [ $rc -eq 125 ] || echo "$out" | grep -q "sandbox-exec:"; then v=SETUP; elif [ "$exp" = ok ]; then [ $rc -eq 0 ] && v=PASS || v=FAIL; else [ $rc -ne 0 ] && v=PASS || v=FAIL; fi; [ $v = PASS ] && pass=$((pass+1)) || fail=$((fail+1)); printf "%-5s %-4s rc=%-3s %-50s | %s\n" $v $exp $rc "$(echo "$*" | sed "s|$J|J|g; s|$BD/||g; s|$HOME|~|g" | cut -c1-50)" "$(echo $out | sed "s|$J|J|g; s|$HOME|~|g" | cut -c1-90)"; }
R ok   $B write $J/wt/new.txt
R ok   $B read $J/wt/app.txt
R deny $B read $J/wt/.env
R deny $B read $J/wt/ignored.txt
R deny $B read $J/wt/id_ed25519
R deny $B read $J/outside/secret.txt
R deny $B write $J/outside/x.txt
SHARED=/tmp/moochy-check-$$.txt; echo shared > $SHARED
R deny $B read $SHARED
R deny $B write /tmp/moochy-check-$$-w.txt
R deny $B read $HOME/.zshrc
R deny $B read $HOME/.ssh/known_hosts
R deny $B hardlink $J/wt/.env $J/wt/link
R deny $B symlink $J/outside/secret.txt $J/wt/sl
R ok   $B connect 127.0.0.1:18787
R deny $B connect 1.1.1.1:443
R deny $B connect 127.0.0.1:8080
R ok   $B env ANTHROPIC_BASE_URL
R deny $B env ANTHROPIC_API_KEY
R deny $B env SSH_AUTH_SOCK
R ok   /bin/sh -c "echo inside-shell > /dev/null && echo ok"
R ok   /bin/sh -c "cd $J/wt && git status --short >/dev/null && echo git-ok"
R deny /bin/kill -0 $GW
R deny /usr/bin/security find-generic-password -s moochy-nonexistent-xyz
R deny /bin/sh -c "curl -s -m 3 https://example.com"
R deny /bin/sh -c "cat ~/.zshrc"
R deny /usr/bin/osascript -e "tell application \"System Events\" to get name of every process"
R deny /usr/bin/pbpaste
# --allow-host (CONNECT proxy on an ephemeral loopback port; only that port is reachable).
RA() { exp=$1; shift; out=$("$B" run $J/wt --ro $BD --allow-host example.com -- "$@" 2>&1); rc=$?; if [ $rc -eq 125 ] || echo "$out" | grep -q "sandbox-exec:"; then v=SETUP; elif [ "$exp" = ok ]; then [ $rc -eq 0 ] && v=PASS || v=FAIL; else [ $rc -ne 0 ] && v=PASS || v=FAIL; fi; [ $v = PASS ] && pass=$((pass+1)) || fail=$((fail+1)); printf "%-5s %-4s rc=%-3s %-50s | %s\n" $v $exp $rc "allow-host: $(echo "$*" | sed "s|$BD/||g" | cut -c1-38)" "$(echo $out | cut -c1-90)"; }
RA ok   $B env HTTPS_PROXY
RA ok   /bin/sh -c "$B proxy env example.com:443 | grep -q ' 200 '"
RA deny /bin/sh -c "$B proxy env example.org:443 | grep -q ' 200 '"
RA deny /bin/sh -c "$B proxy env example.com:22 | grep -q ' 200 '"
RA deny /bin/sh -c "curl -sS -m 5 --noproxy '*' -o /dev/null https://example.com"
RA deny $B connect 1.1.1.1:443
out=$("$B" run $J/wt --ro $BD --allow-host '*.example.com' -- /usr/bin/true 2>&1); if echo "$out" | grep -q "not an exact DNS host name"; then pass=$((pass+1)); echo "PASS  allow-host wildcard refused"; else fail=$((fail+1)); echo "FAIL  allow-host wildcard: $out"; fi
kill $GW $GS 2>/dev/null; wait 2>/dev/null; rm -f $SHARED /tmp/moochy-check-$$-w.txt
# Terminal injection (TIOCSTI) under a real pty: the control run outside must succeed (so the
# check is meaningful), the same call inside `moochy run` must be refused (A192).
ctl=$(script -q /dev/null "$B" tiocsti < /dev/null | tr -d '\r')
ins=$(script -q /dev/null "$B" run $J/wt --ro $BD -- "$B" tiocsti < /dev/null | tr -d '\r')
if echo "$ctl" | grep -q "tiocsti-ok" && echo "$ins" | grep -q "tiocsti-fail"; then pass=$((pass+1)); echo "PASS  tiocsti denied inside (control injects outside)"; else fail=$((fail+1)); echo "FAIL  tiocsti control=[$ctl] inside=[$ins]"; fi
# Donor lockdown (§15.2) and validator child: exec, files and ports closed; DNS + 443 open.
mkdir -p $J/state; echo canary > $J/canary.txt
d=$("$B" donor $J/state 8443 $J/canary.txt 18788)
for want in exec-sh-denied exec-env-denied exec-copied-binary-denied canary-read-fail state-write-ok connect9-fail "dns-ok https-connect-ok" gw-bind-ok bind-other-fail; do
  if echo "$d" | grep -q "$want"; then pass=$((pass+1)); echo "PASS  donor $want"; else fail=$((fail+1)); echo "FAIL  donor $want"; fi
done
echo "$d" | grep -q "(BAD)" && { fail=$((fail+1)); echo "FAIL  donor: $(echo "$d" | grep "(BAD)")"; }
for m in echo open socket exec; do
  if "$B" validator $m >/dev/null; then pass=$((pass+1)); echo "PASS  validator $m"; else fail=$((fail+1)); echo "FAIL  validator $m"; fi
done
echo "macOS sandbox checks: $pass pass, $fail fail"; [ -e $J/outside/x.txt ] && { echo "LEAK: wrote outside"; fail=$((fail+1)); }
[ $fail -eq 0 ]
