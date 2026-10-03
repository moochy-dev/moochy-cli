#!/usr/bin/env bash
# Local smoke test of the node doors in offline (stub executor) mode, no relay needed.
# Usage: MOOCHY_BIN=path/to/moochy cli/crates/node/tests/smoke.sh   (exit 0 = all PASS)
set -u
B=${MOOCHY_BIN:-$(cd "$(dirname "$0")/../../.." && pwd)/target/release/moochy}
T=$(mktemp -d "${TMPDIR:-/tmp}/moochy-smoke.XXXX")
H=$T/home
export MOOCHY_PASSPHRASE=smoke-pass MOOCHY_INSECURE_DEV=1
fail=0
ok() { echo "PASS $1"; }
ko() { echo "FAIL $1: $2"; fail=1; }
REPO=$T/repo; mkdir -p $REPO/src && git -C $REPO init -q && git -C $REPO remote add origin git@github.com:acme/widget.git
echo 'fn main() { println!("hi"); }' > $REPO/src/main.rs; echo "secret" > $REPO/.env
cd $REPO
READY=$($B --home $H up --offline)
echo "$READY" | grep -q '"event":"ready"' && ok "up ready" || { ko "up" "$READY"; exit 1; }
[ -f $H/state/node.json ] && ok "node.json" || ko "node.json" missing
[ "$(stat -c %a $H/state/node.sock)" = 600 ] && ok "socket 0600" || ko socket-mode "$(stat -c %a $H/state/node.sock)"
URL=$(python3 -c "import json,sys;print(json.load(open('$H/state/node.json'))['gateway_url'])")
PID=$(python3 -c "import json,sys;print(json.load(open('$H/state/node.json'))['pid'])")
ss -ltnp 2>/dev/null | grep "pid=$PID," | grep -v "127.0.0.1" && ko "loopback" "non-loopback listener" || ok "loopback-only listener"
S0=$(date +%s%N); $B --home $H status --json >/dev/null; S1=$(date +%s%N)
echo "status took $(( (S1-S0)/1000000 )) ms"
ENV=$($B --home $H env --json)
TOK=$(echo "$ENV" | python3 -c "import json,sys;print(json.load(sys.stdin)['token'])")
echo "$ENV" | python3 -c "import json,sys;d=json.load(sys.stdin);assert set(d)=={'anthropic_base_url','openai_base_url','token'}" && ok "env --json keys" || ko env "$ENV"
HP=${URL#http://}
c() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
[ "$(c -H "x-api-key: $TOK" $URL/v1/models)" = 200 ] && ok "models 200" || ko models x
[ "$(c -H "x-api-key: bad" $URL/v1/models)" = 401 ] && ok "wrong token 401" || ko wrongtoken x
[ "$(c $URL/v1/models)" = 401 ] && ok "no token 401" || ko notoken x
[ "$(c -H "Host: evil.example:${HP#*:}" -H "x-api-key: $TOK" $URL/v1/models)" = 403 ] && ok "bad Host 403" || ko host x
[ "$(c -H "Origin: http://evil.example" -H "x-api-key: $TOK" $URL/v1/models)" = 403 ] && ok "cross Origin 403" || ko origin x
curl -s -i -X OPTIONS -H "Origin: http://evil.example" -H "Access-Control-Request-Method: POST" $URL/v1/messages | grep -qi "access-control" && ko cors "CORS header present" || ok "no CORS headers"
BODY='{"model":"moochy/stub","max_tokens":64,"messages":[{"role":"user","content":"hi"}]}'
R=$(curl -s -H "x-api-key: $TOK" -H "anthropic-version: 2023-06-01" -d "$BODY" $URL/v1/messages)
echo "$R" | grep -q '"stub response' && ok "messages non-stream" || ko messages "$R"
R=$(curl -s -N -H "authorization: Bearer $TOK" -d "${BODY%\}},\"stream\":true}" $URL/v1/messages)
echo "$R" | grep -q 'event: message_stop' && ok "messages stream" || ko stream "$R"
R=$(curl -s -H "authorization: Bearer $TOK" -d '{"model":"moochy/stub","messages":[{"role":"user","content":"hi"}],"stream":true}' $URL/v1/chat/completions)
echo "$R" | grep -q 'data: \[DONE\]' && ok "chat completions stream (max_tokens injected)" || ko chat "$R"
R=$(curl -s -H "x-api-key: $TOK" -d '{"model":"moochy/stub","messages":[{"role":"user","content":"hello world"}]}' $URL/v1/messages/count_tokens)
echo "$R" | grep -q '"input_tokens"' && ok "count_tokens local" || ko count "$R"
R=$(curl -s -H "x-api-key: $TOK" -d '{"model":"nope","max_tokens":5,"messages":[]}' $URL/v1/messages)
echo "$R" | grep -q 'not_found_error' && ok "model_not_in_pool 404" || ko notinpool "$R"
R=$(curl -s -H "x-api-key: $TOK" -d '{"model":"a","model":"b","max_tokens":5}' $URL/v1/messages)
echo "$R" | grep -q 'duplicate' && ok "duplicate key refused" || ko dup "$R"
# MCP over HTTP
M() { curl -s -H "authorization: Bearer $TOK" -H 'accept: application/json, text/event-stream' -d "$1" $URL/mcp; }
[ "$(c -d '{"jsonrpc":"2.0","id":1,"method":"ping"}' $URL/mcp)" = 401 ] && ok "mcp no bearer 401" || ko mcp401 x
[ "$(c -H 'authorization: Bearer nope' -d '{"jsonrpc":"2.0","id":1,"method":"ping"}' $URL/mcp)" = 401 ] && ok "mcp bad bearer 401" || ko mcp401b x
R=$(M '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}')
echo "$R" | grep -q '"protocolVersion":"2025-06-18"' && ok "mcp http initialize" || ko init "$R"
R=$(M '{"jsonrpc":"2.0","id":2,"method":"tools/list"}')
echo "$R" | python3 -c "import json,sys;t=json.load(sys.stdin)['result']['tools'];assert [x['name'] for x in t]==['moochy_delegate','moochy_pool_status'];assert t[0]['inputSchema']['properties']['model']['enum']==['moochy/stub']" && ok "mcp tools/list (2 tools, model enum)" || ko list "$R"
R=$(M '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"moochy_delegate","arguments":{"prompt":"summarize","file_contents":[{"path":"src/main.rs","text":"fn main() {}"}]}}}')
echo "$R" | grep -q 'untrusted-content' && echo "$R" | grep -q 'stub response' && ok "mcp http delegate (file_contents, untrusted wrap)" || ko delegate "$R"
R=$(M '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"moochy_delegate","arguments":{"prompt":"x","files":[".env"]}}}')
echo "$R" | grep -q '"isError":true' && ok "mcp files deny .env" || ko denyenv "$R"
R=$(M '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"_meta":{"progressToken":"p1"},"name":"moochy_delegate","arguments":{"prompt":"x"}}}')
echo "$R" | grep -q '^event: message' && echo "$R" | grep -q 'stub response' && ok "mcp http SSE response" || ko sse "$R"
[ "$(c -X GET -H "authorization: Bearer $TOK" $URL/mcp)" = 405 ] && ok "mcp GET 405" || ko get405 x
# MCP over stdio (shim → LocalControl.McpPipe)
R=$( { printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}' '{"jsonrpc":"2.0","method":"notifications/initialized"}' '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"moochy_delegate","arguments":{"prompt":"hi","files":["src/main.rs"]}}}'; sleep 1; } | timeout 10 $B --home $H mcp )
echo "$R" | grep -q '"id":3' && echo "$R" | grep -q 'untrusted-content' && echo "$R" | grep -q 'moochy_pool_status' && ok "mcp stdio initialize/list/delegate" || ko stdio "$R"
$B --home $H pause | grep -q '"paused":true' && ok pause || ko pause x
$B --home $H journal | grep -q '"role":"gateway"' && ok journal || ko journal x
sleep 1
RSS=$(awk '/VmRSS/{print $2}' /proc/$PID/status); echo "idle RSS ${RSS} kB"
# CONTRACT §19.6: --org is always provider-qualified and never mixed with --repo (slug confusion).
O=$($B --home $H donate --org acme/widget --cap 5 --yes 2>&1); [ $? = 2 ] && echo "$O" | grep -q 'github/ORG' && ok "donate --org owner/name refused" || ko donate-org "$O"
O=$($B --home $H decisions --org github/acme --repo acme/widget 2>&1); [ $? = 2 ] && ok "--org with --repo refused" || ko org-repo "$O"
O=$($B --home $H donate --org github/acme --cap 5 --yes 2>&1); echo "$O" | grep -q 'organisation github/acme' && ok "donate --org reaches the link" || ko donate-org-ok "$O"
$B --home $H down >/dev/null && sleep 0.5
kill -0 $PID 2>/dev/null && ko down "still running" || ok "down"
[ -e $H/state/node.json ] && ko cleanup node.json || ok "node.json removed"
rm -rf $T
exit $fail
