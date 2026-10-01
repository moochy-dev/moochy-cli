//! `moochy connect <client>`: ready-made configuration for known clients, matching
//! `docs/guides/integrations.md`. Prints only: tokens appear as `$MOOCHY_TOKEN` / `{env:…}`
//! references or the client's own secret prompt, never inline (06 §13 token placement).

pub const CLIENTS: &[&str] = &[
    "claude-code",
    "opencode",
    "cursor",
    "cline",
    "continue",
    "zed",
    "goose",
    "windsurf",
    "vscode",
    "claude-desktop",
    "aider",
    "generic-mcp",
    "generic-openai",
    "generic-anthropic",
];

/// `url` = gateway base URL (`http://127.0.0.1:PORT`), `main`/`small` = pool models.
pub fn snippet(client: &str, url: &str, repo: &str, main: &str, small: &str) -> Option<String> {
    let token = format!("export MOOCHY_TOKEN=\"$(moochy env --repo {repo} --json | jq -r .token)\"\n");
    let mcp_json = format!(r#"{{"mcpServers": {{"moochy": {{"command": "moochy", "args": ["mcp", "--repo", "{repo}"]}}}}}}"#);
    let s = match client {
        "claude-code" => format!(
            "# MCP (user scope):\nclaude mcp add --scope user moochy -- moochy mcp --repo {repo}\nexport MCP_TOOL_TIMEOUT=300000\n\n\
             # API door (donated compute as the model):\n{token}export ANTHROPIC_BASE_URL={url}\nexport ANTHROPIC_AUTH_TOKEN=\"$MOOCHY_TOKEN\"\n\
             export ANTHROPIC_MODEL={main}\nexport ANTHROPIC_DEFAULT_HAIKU_MODEL={small}\nclaude\n"
        ),
        "opencode" => format!(
            "# ~/.config/opencode/opencode.json\n{token}{{\n  \"$schema\": \"https://opencode.ai/config.json\",\n  \"mcp\": {{\"moochy\": {{\"type\": \"local\", \"command\": [\"moochy\", \"mcp\", \"--repo\", \"{repo}\"], \"enabled\": true}}}},\n  \
             \"provider\": {{\"moochy\": {{\"npm\": \"@ai-sdk/openai-compatible\", \"name\": \"Moochy\",\n    \"options\": {{\"baseURL\": \"{url}/v1\", \"apiKey\": \"{{env:MOOCHY_TOKEN}}\"}},\n    \
             \"models\": {{\"{main}\": {{}}, \"{small}\": {{}}}}}}}},\n  \"model\": \"moochy/{main}\",\n  \"small_model\": \"moochy/{small}\"\n}}\n"
        ),
        "cursor" => format!("# ~/.cursor/mcp.json (Cursor's API path cannot reach 127.0.0.1: use MCP)\n{mcp_json}\n"),
        "windsurf" => format!("# ~/.codeium/windsurf/mcp_config.json\n{mcp_json}\n"),
        "claude-desktop" => format!("# claude_desktop_config.json\n{mcp_json}\n"),
        "cline" => format!(
            "# cline_mcp_settings.json\n{{\"mcpServers\": {{\"moochy\": {{\"command\": \"moochy\", \"args\": [\"mcp\", \"--repo\", \"{repo}\"], \"timeout\": 300}}}}}}\n\
             # API: provider \"OpenAI Compatible\", Base URL {url}/v1, API key = the token from `moochy env`, Model ID {main}\n"
        ),
        "continue" => format!(
            "# ~/.continue/config.yaml (store the token as the Continue secret MOOCHY_TOKEN)\nname: moochy\nversion: 0.0.1\nschema: v1\nmodels:\n  - name: {main} (Moochy)\n    provider: openai\n    \
             model: {main}\n    apiBase: {url}/v1\n    apiKey: ${{{{ secrets.MOOCHY_TOKEN }}}}\n    roles: [chat, edit, apply]\nmcpServers:\n  - name: moochy\n    command: moochy\n    args: [mcp, --repo, {repo}]\n"
        ),
        "zed" => format!(
            "// settings.json (enter the token as the provider API key in the Agent panel)\n{{\n  \"context_servers\": {{\"moochy\": {{\"command\": \"moochy\", \"args\": [\"mcp\", \"--repo\", \"{repo}\"]}}}},\n  \
             \"language_models\": {{\"openai_compatible\": {{\"Moochy\": {{\"api_url\": \"{url}/v1\", \"available_models\": [{{\"name\": \"{main}\", \"display_name\": \"{main} (Moochy)\", \"max_tokens\": 200000}}]}}}}}}\n}}\n"
        ),
        "goose" => format!(
            "# ~/.config/goose/config.yaml\nextensions:\n  moochy:\n    name: moochy\n    type: stdio\n    cmd: moochy\n    args: [mcp, --repo, {repo}]\n    enabled: true\n    timeout: 300\n\n\
             # API door:\n{token}export GOOSE_PROVIDER=anthropic\nexport ANTHROPIC_HOST={url}\nexport ANTHROPIC_API_KEY=\"$MOOCHY_TOKEN\"\nexport GOOSE_MODEL={main}\n"
        ),
        "vscode" => format!(
            "// MCP: Open User Configuration (mcp.json); VS Code prompts for the token once\n{{\n  \"inputs\": [{{\"type\": \"promptString\", \"id\": \"moochy-token\", \"description\": \"Moochy token (moochy env --json)\", \"password\": true}}],\n  \
             \"servers\": {{\n    \"moochy\": {{\"type\": \"stdio\", \"command\": \"moochy\", \"args\": [\"mcp\", \"--repo\", \"{repo}\"]}},\n    \
             \"moochy-http\": {{\"type\": \"http\", \"url\": \"{url}/mcp\", \"headers\": {{\"Authorization\": \"Bearer ${{input:moochy-token}}\"}}}}\n  }}\n}}\n"
        ),
        "aider" => format!("{token}export OPENAI_API_BASE={url}/v1\nexport OPENAI_API_KEY=\"$MOOCHY_TOKEN\"\naider --model openai/{main}\n"),
        "generic-mcp" => format!("# stdio\ncommand: moochy mcp --repo {repo}\n# Streamable HTTP\n{token}url: {url}/mcp\nheader: Authorization: Bearer $MOOCHY_TOKEN\n"),
        "generic-openai" => format!("{token}base_url: {url}/v1\napi_key: $MOOCHY_TOKEN\nmodel: {main}\n"),
        "generic-anthropic" => format!("{token}base_url: {url}\napi_key: $MOOCHY_TOKEN   (x-api-key or Authorization: Bearer)\nmodel: {main}\n"),
        _ => return None,
    };
    Some(format!("{s}\n# Models are the ones donated to this project (Claude, GPT, DeepSeek, Grok and others): `moochy status` lists them.\n# Keep command approval on in your agent when it uses donated tokens.\n"))
}

#[cfg(test)]
mod tests {
    #[test]
    fn every_client_has_a_snippet_without_inline_tokens() {
        for c in super::CLIENTS {
            let s = super::snippet(c, "http://127.0.0.1:4100", "acme/widget", "anthropic/claude-sonnet-5", "deepseek/deepseek-chat").unwrap();
            assert!(!s.contains("mooch_local_"), "{c}");
            assert!(s.contains("acme/widget") || s.contains("127.0.0.1:4100"), "{c}");
        }
        assert!(super::snippet("nope", "", "", "", "").is_none());
    }
}

/// JSON paths and the values to set there.
pub type Plan = Vec<(Vec<&'static str>, serde_json::Value)>;

/// `--write` support: the user-scoped JSON config file of a client and the values to merge in
/// (`(json path, value)`). Never a token: stdio shim entries, or env references.
pub fn write_plan(client: &str, home: &std::path::Path, repo: &str, url: &str, main: &str, small: &str) -> Option<(std::path::PathBuf, Plan)> {
    use serde_json::json;
    let xdg = std::env::var_os("XDG_CONFIG_HOME").map_or_else(|| home.join(".config"), std::path::PathBuf::from);
    let stdio = json!({"command": "moochy", "args": ["mcp", "--repo", repo]});
    Some(match client {
        "claude-code" => (home.join(".claude.json"), vec![(vec!["mcpServers", "moochy"], json!({"type": "stdio", "command": "moochy", "args": ["mcp", "--repo", repo]}))]),
        "cursor" => (home.join(".cursor/mcp.json"), vec![(vec!["mcpServers", "moochy"], stdio)]),
        "windsurf" => (home.join(".codeium/windsurf/mcp_config.json"), vec![(vec!["mcpServers", "moochy"], stdio)]),
        "claude-desktop" => (xdg.join("Claude/claude_desktop_config.json"), vec![(vec!["mcpServers", "moochy"], stdio)]),
        // Cline keeps its settings inside the editor profile: pass --config.
        "cline" => (home.join("cline_mcp_settings.json"), vec![(vec!["mcpServers", "moochy"], json!({"command": "moochy", "args": ["mcp", "--repo", repo], "timeout": 300}))]),
        "vscode" => (xdg.join("Code/User/mcp.json"), vec![(vec!["servers", "moochy"], json!({"type": "stdio", "command": "moochy", "args": ["mcp", "--repo", repo]}))]),
        "zed" => (xdg.join("zed/settings.json"), vec![(vec!["context_servers", "moochy"], stdio)]),
        "opencode" => (
            xdg.join("opencode/opencode.json"),
            vec![
                (vec!["mcp", "moochy"], json!({"type": "local", "command": ["moochy", "mcp", "--repo", repo], "enabled": true})),
                (
                    vec!["provider", "moochy"],
                    json!({"npm": "@ai-sdk/openai-compatible", "name": "Moochy", "options": {"baseURL": format!("{url}/v1"), "apiKey": "{env:MOOCHY_TOKEN}"},
                        "models": {main: {}, small: {}}}),
                ),
                (vec!["model"], json!(format!("moochy/{main}"))),
                (vec!["small_model"], json!(format!("moochy/{small}"))),
            ],
        ),
        _ => return None,
    })
}

/// Merge `(path, value)` pairs into a JSON object, creating intermediate objects.
pub fn merge(root: &mut serde_json::Value, plan: &Plan) -> bool {
    for (path, v) in plan {
        let mut cur = &mut *root;
        let Some((last, parents)) = path.split_last() else { continue };
        for k in parents {
            let Some(obj) = cur.as_object_mut() else { return false };
            cur = obj.entry((*k).to_owned()).or_insert_with(|| serde_json::json!({}));
        }
        let Some(obj) = cur.as_object_mut() else { return false };
        obj.insert((*last).to_owned(), v.clone());
    }
    true
}

/// Line diff preview: lines only in `old` as `-`, lines only in `new` as `+`.
pub fn diff(old: &str, new: &str) -> String {
    let (o, n): (Vec<&str>, Vec<&str>) = (old.lines().collect(), new.lines().collect());
    let mut out = String::new();
    for l in o.iter().filter(|l| !n.contains(l)) {
        out.push_str("- ");
        out.push_str(l);
        out.push('\n');
    }
    for l in n.iter().filter(|l| !o.contains(l)) {
        out.push_str("+ ");
        out.push_str(l);
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod write_tests {
    #[test]
    fn merge_and_diff() {
        let mut v = serde_json::json!({"theme": "dark"});
        let (_, plan) = super::write_plan("cursor", std::path::Path::new("/h"), "acme/w", "http://127.0.0.1:1", "m", "s").unwrap();
        assert!(super::merge(&mut v, &plan));
        assert_eq!(v["mcpServers"]["moochy"]["args"][2], "acme/w");
        assert_eq!(v["theme"], "dark");
        let d = super::diff("{\n  \"theme\": \"dark\"\n}", &serde_json::to_string_pretty(&v).unwrap());
        assert!(d.contains("+ ") && !d.contains("- \"theme\""));
        assert!(super::write_plan("aider", std::path::Path::new("/h"), "a/b", "", "", "").is_none());
    }
}
