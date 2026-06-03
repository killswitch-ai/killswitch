import React, { useState, useEffect } from "react";
import { Helmet } from "react-helmet-async";
import { Link } from "wouter";
import { Terminal, ChevronRight, Hash } from "lucide-react";
import { Navbar } from "@/components/layout/Navbar";
import { Footer } from "@/components/layout/Footer";
import { CodeBlock } from "@/components/ui/CodeBlock";

const SECTIONS = [
  { id: "installation", label: "Installation" },
  { id: "quickstart", label: "Quick Start" },
  { id: "modes", label: "Control Modes" },
  { id: "context-manager", label: "Context Manager" },
  { id: "decorator", label: "Decorator" },
  { id: "guarded-clients", label: "Guarded Clients" },
  { id: "detection", label: "Detection Layers" },
  { id: "wizard", label: "Config Wizard" },
  { id: "cli", label: "CLI Reference" },
  { id: "config-file", label: "Configuration File" },
  { id: "exceptions", label: "Exceptions" },
];

function SectionAnchor({ id }: { id: string }) {
  return <div id={id} className="scroll-mt-24" />;
}

function SectionHeading({ id, children }: { id: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center gap-2 group">
      <h2 id={id} className="text-2xl font-bold tracking-tight scroll-mt-24">{children}</h2>
      <a href={`#${id}`} className="opacity-0 group-hover:opacity-40 hover:!opacity-100 transition-opacity text-primary">
        <Hash className="h-4 w-4" />
      </a>
    </div>
  );
}

function SubHeading({ id, children }: { id: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center gap-2 group mt-10 mb-4">
      <h3 id={id} className="text-lg font-semibold scroll-mt-24">{children}</h3>
      <a href={`#${id}`} className="opacity-0 group-hover:opacity-40 hover:!opacity-100 transition-opacity text-primary">
        <Hash className="h-3 w-3" />
      </a>
    </div>
  );
}

function Callout({ type = "info", children }: { type?: "info" | "warning" | "tip"; children: React.ReactNode }) {
  const styles = {
    info: "border-primary/40 bg-primary/5 text-primary",
    warning: "border-yellow-500/40 bg-yellow-500/5 text-yellow-400",
    tip: "border-green-500/40 bg-green-500/5 text-green-400",
  };
  const labels = { info: "Note", warning: "Warning", tip: "Tip" };
  return (
    <div className={`border-l-2 px-4 py-3 rounded-r-lg my-4 ${styles[type]}`}>
      <span className="text-xs font-bold uppercase tracking-wider mr-2">{labels[type]}</span>
      <span className="text-sm text-muted-foreground">{children}</span>
    </div>
  );
}

function PropRow({ name, type, default: def, children }: { name: string; type: string; default?: string; children: React.ReactNode }) {
  return (
    <tr className="border-b border-white/5">
      <td className="py-3 pr-4 font-mono text-sm text-primary">{name}</td>
      <td className="py-3 pr-4 font-mono text-xs text-muted-foreground">{type}</td>
      <td className="py-3 pr-4 font-mono text-xs text-muted-foreground">{def ?? "—"}</td>
      <td className="py-3 text-sm text-muted-foreground">{children}</td>
    </tr>
  );
}

export default function Docs() {
  const [activeSection, setActiveSection] = useState("installation");

  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting) {
            setActiveSection(entry.target.id);
          }
        }
      },
      { rootMargin: "-20% 0% -70% 0%", threshold: 0 }
    );
    SECTIONS.forEach(({ id }) => {
      const el = document.getElementById(id);
      if (el) observer.observe(el);
    });
    return () => observer.disconnect();
  }, []);

  return (
    <div className="min-h-screen flex flex-col dark bg-background">
      <Helmet>
        <title>Documentation — killswitch-ai</title>
        <meta name="description" content="Full API reference and configuration guide for killswitch-ai, the local LLM egress control library for Python." />
        <link rel="canonical" href="https://killswitch-ai.com/docs" />
        <meta property="og:url" content="https://killswitch-ai.com/docs" />
        <meta property="og:title" content="Documentation — killswitch-ai" />
        <meta property="og:type" content="website" />
      </Helmet>

      <Navbar />

      <div className="flex-1 container mx-auto px-4 md:px-6 py-12">
        <div className="flex gap-12">
          {/* Sidebar */}
          <aside className="hidden lg:block w-56 shrink-0">
            <div className="sticky top-24 space-y-1">
              <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-4 px-3">On this page</p>
              {SECTIONS.map(({ id, label }) => (
                <a
                  key={id}
                  href={`#${id}`}
                  data-testid={`link-sidebar-${id}`}
                  className={`block px-3 py-1.5 text-sm rounded-md transition-colors ${
                    activeSection === id
                      ? "text-primary bg-primary/10 font-medium"
                      : "text-muted-foreground hover:text-foreground hover:bg-white/5"
                  }`}
                >
                  {label}
                </a>
              ))}
            </div>
          </aside>

          {/* Content */}
          <main className="flex-1 min-w-0 space-y-16 max-w-3xl">
            {/* Page header */}
            <div className="space-y-3 pb-8 border-b border-white/10">
              <div className="flex items-center gap-2 text-sm text-muted-foreground">
                <Link href="/" className="hover:text-foreground transition-colors">Home</Link>
                <ChevronRight className="h-3 w-3" />
                <span className="text-foreground">Documentation</span>
              </div>
              <h1 className="text-4xl font-bold tracking-tight">Documentation</h1>
              <p className="text-muted-foreground text-lg">
                Full reference for installing, configuring, and integrating killswitch-ai into your Python LLM workflows.
              </p>
            </div>

            {/* ── Installation ── */}
            <section>
              <SectionAnchor id="installation" />
              <SectionHeading id="installation">Installation</SectionHeading>
              <p className="mt-4 text-muted-foreground leading-relaxed">
                killswitch-ai requires Python 3.9 or later. Install from PyPI:
              </p>
              <CodeBlock language="bash" className="mt-4" code={`pip install killswitch-ai`} />
              <p className="mt-4 text-muted-foreground leading-relaxed">
                No cloud account, API key, or external service is required. All scanning runs in your local Python process.
              </p>
              <Callout type="tip">
                Pin to a specific version in production: <code className="font-mono text-xs">pip install killswitch-ai==0.1.0</code>
              </Callout>
            </section>

            {/* ── Quick Start ── */}
            <section>
              <SectionAnchor id="quickstart" />
              <SectionHeading id="quickstart">Quick Start</SectionHeading>
              <p className="mt-4 mb-2 text-muted-foreground">
                The fastest way to protect your OpenAI calls is <code className="font-mono text-sm text-primary">install()</code>, which patches the SDK globally:
              </p>
              <CodeBlock language="python" className="mt-4" code={`import killswitch_ai
killswitch_ai.install()  # patches openai + anthropic globally

from openai import OpenAI
client = OpenAI()

# All completions are now scanned — no other code changes needed
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Hello!"}]
)`} />
              <p className="mt-6 text-muted-foreground">
                Or use the context manager for block-scoped protection:
              </p>
              <CodeBlock language="python" className="mt-4" code={`from killswitch_ai import killswitch
import openai

with killswitch(mode="kill"):
    # Raises KillswitchBlocked if secrets detected
    response = openai.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt}]
    )`} />
            </section>

            {/* ── Modes ── */}
            <section>
              <SectionAnchor id="modes" />
              <SectionHeading id="modes">Control Modes</SectionHeading>
              <p className="mt-4 text-muted-foreground leading-relaxed">
                Every killswitch-ai entry point accepts a <code className="font-mono text-sm text-primary">mode</code> parameter that controls what happens when sensitive content is detected.
              </p>
              <div className="mt-6 overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-white/10 text-left">
                      <th className="pb-3 pr-4 font-semibold text-foreground">Mode</th>
                      <th className="pb-3 pr-4 font-semibold text-foreground">Behaviour</th>
                      <th className="pb-3 font-semibold text-foreground">Best for</th>
                    </tr>
                  </thead>
                  <tbody className="text-muted-foreground">
                    <tr className="border-b border-white/5">
                      <td className="py-3 pr-4 font-mono text-red-400">"kill"</td>
                      <td className="py-3 pr-4">Raises <code className="font-mono text-xs">KillswitchBlocked</code>. Request never sent.</td>
                      <td className="py-3">CI, production servers</td>
                    </tr>
                    <tr className="border-b border-white/5">
                      <td className="py-3 pr-4 font-mono text-yellow-400">"pause"</td>
                      <td className="py-3 pr-4">Stops and prompts the terminal. Developer chooses block / redact / allow.</td>
                      <td className="py-3">Local development</td>
                    </tr>
                    <tr className="border-b border-white/5">
                      <td className="py-3 pr-4 font-mono text-blue-400">"redact"</td>
                      <td className="py-3 pr-4">Replaces sensitive value with <code className="font-mono text-xs">[REDACTED]</code> and sends the sanitized request.</td>
                      <td className="py-3">Automated pipelines</td>
                    </tr>
                    <tr>
                      <td className="py-3 pr-4 font-mono text-muted-foreground">"report_only"</td>
                      <td className="py-3 pr-4">Logs the finding and allows the request through unchanged.</td>
                      <td className="py-3">Auditing / trial runs</td>
                    </tr>
                  </tbody>
                </table>
              </div>
              <Callout type="info">
                Per-finding-type overrides in <code className="font-mono text-xs">killswitch.yml</code> take precedence over the global mode. See the Configuration File section.
              </Callout>
            </section>

            {/* ── Context Manager ── */}
            <section>
              <SectionAnchor id="context-manager" />
              <SectionHeading id="context-manager">Context Manager</SectionHeading>
              <p className="mt-4 text-muted-foreground leading-relaxed">
                The <code className="font-mono text-sm text-primary">killswitch</code> context manager patches OpenAI and Anthropic for the duration of its block, then restores the originals.
              </p>
              <CodeBlock language="python" className="mt-4" code={`from killswitch_ai import killswitch

with killswitch(mode="redact"):
    response = openai.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": user_input}]
    )`} />

              <SubHeading id="context-manager-params">Parameters</SubHeading>
              <table className="w-full text-sm mt-2">
                <thead>
                  <tr className="border-b border-white/10 text-left">
                    <th className="pb-3 pr-4 font-semibold text-foreground">Name</th>
                    <th className="pb-3 pr-4 font-semibold text-foreground">Type</th>
                    <th className="pb-3 pr-4 font-semibold text-foreground">Default</th>
                    <th className="pb-3 font-semibold text-foreground">Description</th>
                  </tr>
                </thead>
                <tbody>
                  <PropRow name="mode" type='str' default='"pause"'>
                    One of <code className="font-mono text-xs">"kill"</code>, <code className="font-mono text-xs">"pause"</code>, <code className="font-mono text-xs">"redact"</code>, <code className="font-mono text-xs">"report_only"</code>.
                  </PropRow>
                  <PropRow name="config" type="Config | None" default="None">
                    Optional <code className="font-mono text-xs">Config</code> object. When omitted, the config is loaded from the nearest <code className="font-mono text-xs">killswitch.yml</code>.
                  </PropRow>
                </tbody>
              </table>
            </section>

            {/* ── Decorator ── */}
            <section>
              <SectionAnchor id="decorator" />
              <SectionHeading id="decorator">Decorator</SectionHeading>
              <p className="mt-4 text-muted-foreground leading-relaxed">
                Wrap any function that calls an LLM. The decorator applies the same scanning as the context manager to every invocation of the function.
              </p>
              <CodeBlock language="python" className="mt-4" code={`from killswitch_ai import killswitch
from openai import OpenAI

client = OpenAI()

@killswitch(mode="kill")
def summarize(text: str) -> str:
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": f"Summarize: {text}"}]
    )
    return response.choices[0].message.content`} />
              <Callout type="warning">
                The decorator wraps the entire function body. If the function makes multiple LLM calls, all of them are scanned.
              </Callout>
            </section>

            {/* ── Guarded Clients ── */}
            <section>
              <SectionAnchor id="guarded-clients" />
              <SectionHeading id="guarded-clients">Guarded Clients</SectionHeading>
              <p className="mt-4 text-muted-foreground leading-relaxed">
                For explicit wrapping without monkey-patching, use the provider-specific guarded client classes.
              </p>

              <SubHeading id="guarded-openai">GuardedOpenAI</SubHeading>
              <CodeBlock language="python" code={`from openai import OpenAI
from killswitch_ai.openai import GuardedOpenAI

client = GuardedOpenAI(OpenAI())

# chat completions
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": prompt}]
)

# responses API
response = client.responses.create(
    model="gpt-4o",
    input=prompt
)`} />

              <SubHeading id="guarded-anthropic">GuardedAnthropic</SubHeading>
              <CodeBlock language="python" code={`from anthropic import Anthropic
from killswitch_ai.anthropic import GuardedAnthropic

client = GuardedAnthropic(Anthropic())

message = client.messages.create(
    model="claude-opus-4-5",
    max_tokens=1024,
    messages=[{"role": "user", "content": prompt}]
)`} />

              <SubHeading id="install-helper">Global install()</SubHeading>
              <p className="text-muted-foreground">
                <code className="font-mono text-sm text-primary">killswitch_ai.install()</code> monkey-patches both <code className="font-mono text-sm">openai</code> and <code className="font-mono text-sm">anthropic</code> modules so all existing client instances are automatically protected.
              </p>
              <CodeBlock language="python" className="mt-4" code={`import killswitch_ai

# Call once at application startup — before any client is created
killswitch_ai.install()

# Optionally uninstall (restores original SDKs)
killswitch_ai.uninstall()`} />
            </section>

            {/* ── Detection Layers ── */}
            <section>
              <SectionAnchor id="detection" />
              <SectionHeading id="detection">Detection Layers</SectionHeading>
              <p className="mt-4 mb-6 text-muted-foreground leading-relaxed">
                Every outbound payload passes through five independent detection layers before the HTTP request is made.
              </p>

              <div className="space-y-6">
                {[
                  {
                    num: "01",
                    title: "Prohibited Terms",
                    finding: "prohibited_term",
                    desc: "Keyword blocklist matched against all string values in the payload. Default terms include CONFIDENTIAL, DO_NOT_SEND_TO_AI, BEGIN RSA PRIVATE KEY, and common secret variable names. Extend with custom terms in killswitch.yml.",
                  },
                  {
                    num: "02",
                    title: "Regex Pattern Matching",
                    finding: "secret_pattern",
                    desc: "A curated set of regular expressions for well-known secret formats: OpenAI keys (sk-...), Anthropic keys (sk-ant-...), AWS access/secret keys, GitHub tokens, Stripe keys, JWT tokens, database URLs, and more.",
                  },
                  {
                    num: "03",
                    title: "Shannon Entropy Scanning",
                    finding: "high_entropy_string",
                    desc: "Calculates the Shannon entropy of every sufficiently long string (≥ 24 chars by default). High-entropy strings (≥ 4.2 bits/char by default) are likely random tokens or keys even if they don't match a known pattern.",
                  },
                  {
                    num: "04",
                    title: "Sensitive File Path Detection",
                    finding: "sensitive_file_path",
                    desc: "Detects references to well-known sensitive file paths embedded in text: .env, .pem, .key, id_rsa, credentials.json, ~/.aws/credentials, and similar.",
                  },
                  {
                    num: "05",
                    title: "Recursive Payload Scanning",
                    finding: "varies",
                    desc: "All four layers above are applied recursively to nested structures — dicts, lists, JSON strings embedded in strings. No secrets hide in deeply nested RAG context or tool-call arguments.",
                  },
                ].map(({ num, title, finding, desc }) => (
                  <div key={num} className="flex gap-5">
                    <div className="shrink-0 w-8 h-8 rounded-full bg-primary/10 border border-primary/30 flex items-center justify-center">
                      <span className="text-xs font-mono text-primary">{num}</span>
                    </div>
                    <div>
                      <div className="flex items-center gap-3 mb-1">
                        <h3 className="font-semibold text-foreground">{title}</h3>
                        <code className="text-xs font-mono text-muted-foreground bg-white/5 px-2 py-0.5 rounded">{finding}</code>
                      </div>
                      <p className="text-muted-foreground text-sm leading-relaxed">{desc}</p>
                    </div>
                  </div>
                ))}
              </div>
            </section>

            {/* ── Wizard ── */}
            <section>
              <SectionAnchor id="wizard" />
              <SectionHeading id="wizard">Config Wizard</SectionHeading>
              <p className="mt-4 text-muted-foreground leading-relaxed">
                The interactive setup wizard generates a <code className="font-mono text-sm text-primary">killswitch.yml</code> configuration file in the current directory.
              </p>
              <CodeBlock language="bash" className="mt-4" code={`killswitch wizard`} />
              <p className="mt-4 text-muted-foreground">The wizard walks you through four steps:</p>
              <ol className="mt-4 space-y-3 text-muted-foreground text-sm list-none">
                {[
                  ["Step 1 — Mode", "Choose the default action: pause, kill, redact, or report_only."],
                  ["Step 2 — Data categories", "Toggle which categories of data are protected (API keys, .env files, private keys, passwords, database URLs, cloud credentials, JWT tokens, high-entropy strings)."],
                  ["Step 3 — Email reports", "Opt in to receive weekly anonymous usage summaries by email. Only counts — no prompt text, no secret values."],
                  ["Step 4 — Save", "Generates killswitch.yml in the current directory."],
                ].map(([title, desc]) => (
                  <li key={title as string} className="flex gap-3">
                    <span className="text-primary shrink-0">›</span>
                    <span><span className="font-semibold text-foreground">{title}:</span> {desc}</span>
                  </li>
                ))}
              </ol>
            </section>

            {/* ── CLI ── */}
            <section>
              <SectionAnchor id="cli" />
              <SectionHeading id="cli">CLI Reference</SectionHeading>
              <p className="mt-4 mb-6 text-muted-foreground">All commands are available as <code className="font-mono text-sm">killswitch &lt;subcommand&gt;</code>.</p>

              <div className="space-y-8">
                {[
                  {
                    cmd: "killswitch wizard",
                    desc: "Run the interactive setup wizard. Generates killswitch.yml.",
                  },
                  {
                    cmd: "killswitch scan <text|file>",
                    desc: "Scan a string or file for sensitive content and print findings. Useful for testing your policy before deployment.",
                    example: `# Scan a string
killswitch scan "sk-abc123..."

# Scan a file
killswitch scan ./prompt_template.txt`,
                  },
                  {
                    cmd: "killswitch menu",
                    desc: "Open the interactive TUI menu. Browse recent sessions, view findings, and inspect event logs.",
                  },
                  {
                    cmd: "killswitch email --off",
                    desc: "Disable email reports. Edits the nearest killswitch.yml.",
                  },
                ].map(({ cmd, desc, example }) => (
                  <div key={cmd}>
                    <CodeBlock language="bash" code={cmd} />
                    <p className="mt-2 text-sm text-muted-foreground">{desc}</p>
                    {example && <CodeBlock language="bash" className="mt-3" code={example} />}
                  </div>
                ))}
              </div>
            </section>

            {/* ── Config File ── */}
            <section>
              <SectionAnchor id="config-file" />
              <SectionHeading id="config-file">Configuration File</SectionHeading>
              <p className="mt-4 text-muted-foreground leading-relaxed">
                killswitch-ai searches for <code className="font-mono text-sm text-primary">killswitch.yml</code> in the current directory, then <code className="font-mono text-sm">.killswitch/config.yml</code>, then <code className="font-mono text-sm">~/.killswitch/config.yml</code>.
              </p>
              <CodeBlock language="yaml" className="mt-4" code={`# killswitch.yml

mode:
  default_action: pause  # kill | pause | redact | report_only

detection:
  prohibited_terms:
    - CONFIDENTIAL
    - DO_NOT_SEND_TO_AI
    - MY_INTERNAL_SECRET
  entropy_detection:
    enabled: true
    min_length: 24       # ignore strings shorter than this
    threshold: 4.2       # Shannon bits/char threshold

# Per-finding-type overrides (take precedence over default_action)
actions:
  openai_key: kill
  anthropic_key: kill
  aws_access_key: kill
  aws_secret_key: kill
  github_token: kill
  stripe_key: kill
  private_key: kill
  database_url: pause
  jwt_token: pause
  sensitive_file_path: pause
  high_entropy_string: report_only
  generic_password: report_only

logging:
  enabled: true
  log_dir: .killswitch   # relative to CWD
  store_raw_payloads: false
  store_secret_values: false

email:
  enabled: false
  address: ""
  frequency: weekly

meta:
  install_id: <auto-generated uuid>
  project_id: <hash of cwd>`} />
            </section>

            {/* ── Exceptions ── */}
            <section>
              <SectionAnchor id="exceptions" />
              <SectionHeading id="exceptions">Exceptions</SectionHeading>
              <p className="mt-4 mb-6 text-muted-foreground">
                All exceptions are importable from <code className="font-mono text-sm text-primary">killswitch_ai.exceptions</code>.
              </p>

              <SubHeading id="killswitch-blocked">KillswitchBlocked</SubHeading>
              <p className="text-muted-foreground text-sm leading-relaxed">
                Raised in <code className="font-mono text-xs">kill</code> mode (and in <code className="font-mono text-xs">pause</code> mode if the user chooses to block). Inherits from <code className="font-mono text-xs">RuntimeError</code>.
              </p>
              <CodeBlock language="python" className="mt-4" code={`from killswitch_ai import killswitch
from killswitch_ai.exceptions import KillswitchBlocked

try:
    with killswitch(mode="kill"):
        response = client.chat.completions.create(...)
except KillswitchBlocked as e:
    print(f"Blocked — finding: {e.finding_id}")
    print(f"Event:   {e.event_id}")`} />

              <SubHeading id="killswitch-config-error">KillswitchConfigError</SubHeading>
              <p className="text-muted-foreground text-sm leading-relaxed">
                Raised when <code className="font-mono text-xs">killswitch.yml</code> exists but cannot be parsed. Inherits from <code className="font-mono text-xs">ValueError</code>.
              </p>
            </section>

            {/* Bottom nav */}
            <div className="pt-8 border-t border-white/10 flex justify-between text-sm">
              <Link href="/features" className="text-muted-foreground hover:text-primary transition-colors inline-flex items-center gap-1">
                ← Features
              </Link>
              <Link href="/quickstart" className="text-muted-foreground hover:text-primary transition-colors inline-flex items-center gap-1">
                Quickstart →
              </Link>
            </div>
          </main>
        </div>
      </div>

      <Footer />
    </div>
  );
}
