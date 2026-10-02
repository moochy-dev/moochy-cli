//! `moochy connect <client>`: ready-made configuration for known clients, matching
//! `docs/guides/integrations.md`. Prints only: tokens appear as `$MOOCHY_TOKEN` / `{env:…}`
//! references or the client's own secret prompt, never inline (06 §13 token placement).
//!
//! The agents of CONTRACT §18 (`GUIDE_CLIENTS`) print their section of the guide itself
//! (embedded at build time): its prose as comments and its code blocks byte for byte, with the
//! guide's placeholders filled in (`http://127.0.0.1:PORT`, `owner/repo`,
//! `anthropic/claude-sonnet-5`); `MOOCHY_TOKEN` stays an environment reference.

/// The integrations guide (open source, like this crate).
const GUIDE: &str = include_str!("../../../../docs/guides/integrations.md");

/// Agents whose preset is their section of the guide (CONTRACT §18.1).
pub const GUIDE_CLIENTS: &[&str] = &["codex", "copilot-cli", "gemini-cli", "amp", "antigravity", "openclaw", "droid", "kilo-code", "kiro-cli", "hermes", "roo-code", "trae"];

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
    "codex",
    "copilot-cli",
    "gemini-cli",
    "amp",
    "antigravity",
    "openclaw",
    "droid",
    "kilo-code",
    "kiro-cli",
    "hermes",
    "roo-code",
    "trae",
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
        c if GUIDE_CLIENTS.contains(&c) => format!(
            "{}\n# The token: moochy env --repo {repo} --json prints it; export it as MOOCHY_TOKEN (sent as Authorization: Bearer or x-api-key), never write it into a file tracked by git.\n",
            guide_snippet(c, url, repo, main)?
        ),
        _ => return None,
    };
    Some(format!("{s}\n# Models are the ones donated to this project (Claude, GPT, DeepSeek, Grok and others): `moochy status` lists them.\n# Keep command approval on in your agent when it uses donated tokens.\n"))
}

/// The guide's section for `id`: from its `### ` heading to the next heading.
fn section(id: &str) -> Option<&'static str> {
    let at = GUIDE.find(&format!("\n`moochy connect {id}`"))?;
    let start = GUIDE.get(..at)?.rfind("\n### ")?.checked_add(1)?;
    let rest = GUIDE.get(at.checked_add(1)?..)?;
    let len = [rest.find("\n### "), rest.find("\n## ")].into_iter().flatten().min().unwrap_or(rest.len());
    GUIDE.get(start..at.checked_add(1)?.checked_add(len)?)
}

/// Agents whose API door this version serves although their guide section still says "not yet"
/// (Codex: `POST /v1/responses`, CONTRACT §18.6; the guide is updated by mo-docs): no MCP-only line.
const API_DOOR_SERVED: &[&str] = &["codex"];

/// The guide section of a §18 agent as a preset: prose as `# ` comments, code blocks verbatim
/// (placeholders filled), and a plain line when the agent reaches donated tokens through MCP only.
fn guide_snippet(id: &str, url: &str, repo: &str, main: &str) -> Option<String> {
    let fill = |l: &str| l.replace("http://127.0.0.1:PORT", url).replace("owner/repo", repo).replace("anthropic/claude-sonnet-5", main);
    let mut out = String::new();
    let mut block: Option<String> = None;
    for l in section(id)?.lines() {
        if let Some(b) = block.as_mut() {
            if l.starts_with("```") {
                out.push_str(b);
                block = None;
            } else {
                b.push_str(&fill(l));
                b.push('\n');
            }
            continue;
        }
        if l.starts_with("```") {
            block = Some(String::new());
        } else if let Some(row) = l.strip_prefix("| API") {
            // The "Tool" cell of the API row says when the agent is MCP only.
            let tool = row.split('|').nth(2).unwrap_or_default().trim().replace("**", "");
            if (tool.contains("MCP only") || tool.contains("not yet")) && !API_DOOR_SERVED.contains(&id) {
                out.push_str("# API: ");
                out.push_str(&tool);
                out.push_str(". This agent uses donated tokens through MCP (moochy_delegate).\n");
            }
        } else if l.starts_with('|') {
        } else if l.trim().is_empty() {
            if !out.ends_with("\n\n") && !out.is_empty() {
                out.push('\n');
            }
        } else {
            out.push_str("# ");
            // Comments are plain text: no markdown emphasis; code spans in single quotes.
            out.push_str(&fill(l.trim_start_matches("### ")).replace("**", "").replace('`', "'"));
            out.push('\n');
        }
    }
    (block.is_none() && !out.is_empty()).then_some(out)
}

#[cfg(test)]
mod tests {
    /// The guide's code blocks of `id`'s section, placeholders filled (what the preset must
    /// contain byte for byte).
    fn guide_blocks(id: &str, url: &str, repo: &str, main: &str) -> Vec<String> {
        let sec = super::section(id).unwrap();
        sec.split("```")
            .skip(1)
            .step_by(2)
            .map(|b| b.split_once('\n').unwrap().1.replace("http://127.0.0.1:PORT", url).replace("owner/repo", repo).replace("anthropic/claude-sonnet-5", main))
            .collect()
    }

    #[test]
    fn guide_presets_are_the_guide() {
        let (url, repo, main) = ("http://127.0.0.1:4100", "gitlab/acme/tools/widget", "deepseek/deepseek-chat");
        // Every id in the guide's agents table has a preset, and every guide preset has a section.
        let table = super::GUIDE.split_once("| Agent | `moochy connect` |").unwrap().1.split("\n\n").next().unwrap();
        for id in table.lines().filter_map(|l| l.split('|').nth(2)).filter_map(|c| c.trim().strip_prefix('`')?.strip_suffix('`')) {
            assert!(super::CLIENTS.contains(&id), "guide lists `moochy connect {id}`");
        }
        for id in super::GUIDE_CLIENTS {
            let s = super::snippet(id, url, repo, main, main).unwrap();
            let blocks = guide_blocks(id, url, repo, main);
            assert!(!blocks.is_empty(), "{id}");
            for b in &blocks {
                assert!(s.contains(b.as_str()), "{id}: guide block missing or changed:\n{b}\n--- preset:\n{s}");
            }
            assert!(!s.contains("PORT") && !s.contains("owner/repo") && !s.contains("mooch_local_"), "{id}: {s}");
            assert!(s.contains("moochy mcp") || s.contains(r#""mcp", "--repo""#), "{id}: an MCP door");
        }
        // MCP-only agents say so; Codex has both doors (its Responses provider, §18.6).
        for id in ["gemini-cli", "amp", "antigravity", "kiro-cli"] {
            assert!(super::snippet(id, url, repo, main, main).unwrap().contains("# API: "), "{id}");
        }
        let codex = super::snippet("codex", url, repo, main, main).unwrap();
        assert!(codex.contains("wire_api = \"responses\"\n") && codex.contains(&format!("base_url = \"{url}/v1\"")) && !codex.contains("# API: not yet"), "{codex}");
        assert!(super::snippet("droid", url, repo, main, main).unwrap().lines().all(|l| !l.starts_with("# API: ")));
    }

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
    let vscode_user = if cfg!(target_os = "macos") { home.join("Library/Application Support/Code/User") } else { xdg.join("Code/User") };
    let stdio = json!({"command": "moochy", "args": ["mcp", "--repo", repo]});
    let servers = |file: std::path::PathBuf, entry: serde_json::Value| (file, vec![(vec!["mcpServers", "moochy"], entry)]);
    Some(match client {
        "claude-code" => (home.join(".claude.json"), vec![(vec!["mcpServers", "moochy"], json!({"type": "stdio", "command": "moochy", "args": ["mcp", "--repo", repo]}))]),
        "cursor" => (home.join(".cursor/mcp.json"), vec![(vec!["mcpServers", "moochy"], stdio)]),
        "windsurf" => (home.join(".codeium/windsurf/mcp_config.json"), vec![(vec!["mcpServers", "moochy"], stdio)]),
        "claude-desktop" => (xdg.join("Claude/claude_desktop_config.json"), vec![(vec!["mcpServers", "moochy"], stdio)]),
        // Cline keeps its settings inside the editor profile: pass --config.
        "cline" => (home.join("cline_mcp_settings.json"), vec![(vec!["mcpServers", "moochy"], json!({"command": "moochy", "args": ["mcp", "--repo", repo], "timeout": 300}))]),
        "vscode" => (vscode_user.join("mcp.json"), vec![(vec!["servers", "moochy"], json!({"type": "stdio", "command": "moochy", "args": ["mcp", "--repo", repo]}))]),
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
        // CONTRACT §18: the MCP stdio entry of each agent's own config file (guide paths). TOML and
        // YAML files are edited in place (`toml_edit`, `yaml_edit`), JSON merged.
        "codex" => (home.join(".codex/config.toml"), vec![(vec!["mcp_servers", "moochy"], stdio)]),
        "copilot-cli" => servers(home.join(".copilot/mcp-config.json"), json!({"type": "local", "command": "moochy", "args": ["mcp", "--repo", repo], "tools": ["*"]})),
        "gemini-cli" => servers(home.join(".gemini/settings.json"), stdio),
        "amp" => (xdg.join("amp/settings.json"), vec![(vec!["amp.mcpServers", "moochy"], stdio)]),
        "antigravity" => servers(home.join(".gemini/config/mcp_config.json"), stdio),
        // JSON5 in general: a file that is plain JSON is merged, anything else is refused.
        "openclaw" => (home.join(".openclaw/openclaw.json"), vec![(vec!["mcp", "servers", "moochy"], stdio)]),
        "droid" => servers(home.join(".factory/mcp.json"), json!({"type": "stdio", "command": "moochy", "args": ["mcp", "--repo", repo]})),
        "kilo-code" => (xdg.join("kilo/kilo.json"), vec![(vec!["mcp", "moochy"], json!({"type": "local", "command": ["moochy", "mcp", "--repo", repo]}))]),
        "kiro-cli" => servers(home.join(".kiro/settings/mcp.json"), stdio),
        "hermes" => (home.join(".hermes/config.yaml"), vec![(vec!["mcp_servers", "moochy"], stdio)]),
        "roo-code" => servers(vscode_user.join("globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json"), stdio),
        // Trae reads MCP servers from the project (stdio only: no token in it).
        "trae" => servers(std::path::PathBuf::from(".trae/mcp.json"), stdio),
        _ => return None,
    })
}

/// A plan entry as `key = value` / `key: value` lines (scalars and string arrays in JSON
/// notation, which TOML basic strings and YAML flow style both read).
fn flat_entries(v: &serde_json::Value) -> Result<Vec<(String, String)>, String> {
    let obj = v.as_object().ok_or("not a table")?;
    obj.iter()
        .map(|(k, v)| {
            let ok_key = !k.is_empty() && k.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-');
            let ok_val = !v.is_object() && v.as_array().is_none_or(|a| a.iter().all(|x| !x.is_object() && !x.is_array()));
            if ok_key && ok_val { Ok((k.clone(), v.to_string().replace(",\"", ", \""))) } else { Err(format!("cannot write `{k}` here")) }
        })
        .collect()
}

/// Codex `config.toml`: replace the `[a.b]` table of each entry (up to the next table header), or
/// append it; everything else stays byte for byte.
pub fn toml_edit(old: &str, plan: &Plan) -> Result<String, String> {
    let mut lines: Vec<String> = old.lines().map(str::to_owned).collect();
    for (path, v) in plan {
        if path.iter().any(|k| !k.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')) {
            return Err("unsupported key".into());
        }
        let header = format!("[{}]", path.join("."));
        let mut table = vec![header.clone()];
        table.extend(flat_entries(v)?.into_iter().map(|(k, v)| format!("{k} = {v}")));
        if let Some(at) = lines.iter().position(|l| l.trim() == header) {
            let end = lines.iter().skip(at.saturating_add(1)).position(|l| l.trim_start().starts_with('[')).map_or(lines.len(), |n| at.saturating_add(1).saturating_add(n));
            let blank = lines.get(..end).and_then(|s| s.last()).is_some_and(|l| l.trim().is_empty()) && end > at.saturating_add(1);
            if blank {
                table.push(String::new());
            }
            lines.splice(at..end, table);
        } else {
            if lines.last().is_some_and(|l| !l.trim().is_empty()) {
                lines.push(String::new());
            }
            lines.extend(table);
        }
    }
    Ok(lines.join("\n") + if lines.is_empty() { "" } else { "\n" })
}

/// Hermes `config.yaml` (block style): the entry under its top-level key, replaced or inserted;
/// a top-level key written in flow style (`mcp_servers: {…}`) is refused (edit by hand).
pub fn yaml_edit(old: &str, plan: &Plan) -> Result<String, String> {
    let indent = |l: &str| l.len().saturating_sub(l.trim_start().len());
    let mut lines: Vec<String> = old.lines().map(str::to_owned).collect();
    for (path, v) in plan {
        let [top, child] = path.as_slice() else { return Err("unsupported path".into()) };
        let entries = flat_entries(v)?;
        let block = |ci: usize| -> Vec<String> {
            let mut b = vec![format!("{}{child}:", " ".repeat(ci))];
            b.extend(entries.iter().map(|(k, v)| format!("{}{k}: {v}", " ".repeat(ci.saturating_add(2)))));
            b
        };
        let top_line = format!("{top}:");
        let Some(at) = lines.iter().position(|l| l.trim_end() == top_line) else {
            if lines.iter().any(|l| l.starts_with(&top_line)) {
                return Err(format!("`{top}` is written in flow style: edit it by hand"));
            }
            lines.push(top_line);
            lines.extend(block(2));
            continue;
        };
        let body_end = lines.iter().skip(at.saturating_add(1)).position(|l| !l.trim().is_empty() && indent(l) == 0).map_or(lines.len(), |n| at.saturating_add(1).saturating_add(n));
        let body = lines.get(at.saturating_add(1)..body_end).unwrap_or_default();
        let ci = body.iter().find(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#')).map_or(2, |l| indent(l));
        match body.iter().position(|l| indent(l) == ci && l.trim_end().trim_start() == format!("{child}:")) {
            Some(rel) => {
                let start = at.saturating_add(1).saturating_add(rel);
                let end = lines.iter().take(body_end).skip(start.saturating_add(1)).position(|l| !l.trim().is_empty() && indent(l) <= ci).map_or(body_end, |n| start.saturating_add(1).saturating_add(n));
                lines.splice(start..end, block(ci));
            }
            None => {
                lines.splice(at.saturating_add(1)..at.saturating_add(1), block(ci));
            }
        }
    }
    Ok(lines.join("\n") + if lines.is_empty() { "" } else { "\n" })
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
        for c in super::GUIDE_CLIENTS {
            assert!(super::write_plan(c, std::path::Path::new("/h"), "a/b", "", "", "").is_some(), "{c}");
        }
    }

    #[test]
    fn toml_and_yaml_edits_keep_everything_else() {
        let (_, plan) = super::write_plan("codex", std::path::Path::new("/h"), "acme/w", "", "", "").unwrap();
        let old = "model = \"o3\"\n\n[mcp_servers.other]\ncommand = \"x\"\n";
        let new = super::toml_edit(old, &plan).unwrap();
        assert_eq!(new, "model = \"o3\"\n\n[mcp_servers.other]\ncommand = \"x\"\n\n[mcp_servers.moochy]\nargs = [\"mcp\", \"--repo\", \"acme/w\"]\ncommand = \"moochy\"\n");
        assert_eq!(super::toml_edit(&new, &plan).unwrap(), new, "idempotent");
        let stale = new.replace("acme/w", "old/repo") + "\n[profiles.x]\nmodel = \"y\"\n";
        let fixed = super::toml_edit(&stale, &plan).unwrap();
        assert!(fixed.contains("acme/w") && !fixed.contains("old/repo") && fixed.ends_with("[profiles.x]\nmodel = \"y\"\n"), "{fixed}");
        let (_, plan) = super::write_plan("hermes", std::path::Path::new("/h"), "acme/w", "", "", "").unwrap();
        let old = "model:\n  default: x\nmcp_servers:\n  github:\n    command: gh\n    args: [mcp]\n# end\n";
        let new = super::yaml_edit(old, &plan).unwrap();
        assert_eq!(new, "model:\n  default: x\nmcp_servers:\n  moochy:\n    args: [\"mcp\", \"--repo\", \"acme/w\"]\n    command: \"moochy\"\n  github:\n    command: gh\n    args: [mcp]\n# end\n");
        assert_eq!(super::yaml_edit(&new, &plan).unwrap(), new, "idempotent");
        assert_eq!(super::yaml_edit("", &plan).unwrap(), "mcp_servers:\n  moochy:\n    args: [\"mcp\", \"--repo\", \"acme/w\"]\n    command: \"moochy\"\n");
        assert!(super::yaml_edit("mcp_servers: {}\n", &plan).is_err(), "flow style is left to the human");
    }
}
