import React from "react";
import { Helmet } from "react-helmet-async";
import { Shield, Lock, Globe, Server, FileWarning, ShieldCheck, XCircle, Mail } from "lucide-react";
import { Navbar } from "@/components/layout/Navbar";
import { Footer } from "@/components/layout/Footer";

export default function WhyKillswitch() {
  return (
    <div className="min-h-screen flex flex-col dark">
      <Helmet>
        <title>Why LLM Egress Control Matters — killswitch-ai</title>
        <meta name="description" content="Learn about LLM egress control, prompt injection risks, and why local-first, zero-trust AI safety is critical for enterprise development." />
        <link rel="canonical" href="https://killswitch-ai.com/why-killswitch" />
        <meta property="og:url" content="https://killswitch-ai.com/why-killswitch" />
        <meta property="og:title" content="Why LLM Egress Control Matters — killswitch-ai" />
        <meta property="og:type" content="website" />
      </Helmet>
      
      <Navbar />
      
      <main className="flex-1">
        <div className="container mx-auto px-4 md:px-6 py-20 max-w-4xl">
          <div className="mb-16 text-center">
            <h1 className="font-display text-5xl md:text-7xl font-bold uppercase tracking-tight mb-6">Why LLM Egress Control Matters.</h1>
            <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
              AI safety isn't just about what models generate. It's about what you inadvertently send them.
            </p>
          </div>

          <div className="prose prose-invert prose-lg max-w-none">
            <div className="p-6 bg-red-950/20 border border-red-900/50 rounded-xl mb-12">
              <h3 className="text-red-400 font-semibold flex items-center gap-2 mt-0 mb-4">
                <FileWarning className="h-5 w-5" /> The Core Problem
              </h3>
              <p className="text-foreground/90 m-0">
                Developers are building agents that pull from internal databases, read local files, and scrape external websites. These raw contexts are immediately shoved into LLM prompts. Without an egress firewall, a single prompt injection attack or a careless developer logging string can leak AWS keys, customer PII, or proprietary source code to a third-party API.
              </p>
            </div>

            <h2>The Rise of RAG and the Expanding Attack Surface</h2>
            <p>
              Retrieval-Augmented Generation (RAG) is powerful because it gives LLMs context. But context is messy. When your pipeline blindly retrieves documents and appends them to a prompt, you lose control over the exact string being transmitted across the internet. 
            </p>
            <p>
              If an internal document contains passwords, or if a user-supplied file contains malicious instructions designed to extract system variables, your application will obediently package those secrets into a JSON payload and HTTP POST them to OpenAI or Anthropic.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 my-12 not-prose">
              <div className="p-6 border border-white/10 rounded-xl bg-card">
                <Lock className="h-8 w-8 text-primary mb-4" />
                <h3 className="text-xl font-bold mb-2">Zero-Trust Architecture</h3>
                <p className="text-muted-foreground">Assume all data leaving your application boundary is compromised until verified. killswitch-ai enforces this boundary locally.</p>
              </div>
              <div className="p-6 border border-white/10 rounded-xl bg-card">
                <Server className="h-8 w-8 text-primary mb-4" />
                <h3 className="text-xl font-bold mb-2">Local-First Verification</h3>
                <p className="text-muted-foreground">Cloud-based DLP proxies add latency and require you to trust another vendor. killswitch-ai runs in-memory within your Python process.</p>
              </div>
            </div>

            <h2>Real-World Consequences</h2>
            <p>
              When secrets hit an external provider's API, the damage is already done. Even if the provider promises not to train on API data, the data has traversed networks, hit their load balancers, and resides in their ephemeral memory and compliance logs.
            </p>
            <ul>
              <li><strong>Compliance Violations:</strong> Sending PHI/PII to non-BAA covered endpoints violates HIPAA and GDPR.</li>
              <li><strong>Credential Compromise:</strong> Leaked AWS keys or database passwords require immediate, costly rotation.</li>
              <li><strong>Intellectual Property Loss:</strong> Sending unreleased product codenames or financial projections.</li>
            </ul>

            <hr className="border-white/10 my-12" />

            <h2>Where killswitch-ai Fits</h2>
            <p>
              <strong>killswitch-ai is the seatbelt.</strong> It doesn't replace secure coding practices. It doesn't replace identity and access management. It sits precisely at the chokepoint between your Python application and the network request.
            </p>
            <p>
              By operating as a lightweight, pip-installable library rather than a heavy enterprise proxy, it allows individual developers to secure their own code on day one, while giving platform teams the ability to enforce organization-wide policies via a shared <code>.killswitch.yaml</code>.
            </p>
            
            <hr className="border-white/10 my-12" />

            <h2>Privacy First — What Stays on Your Machine</h2>
            <p>
              killswitch-ai is designed around a simple principle: <strong>your prompts are yours</strong>. The library never phones home, never uploads payloads for analysis, and never requires an internet connection for its core protection.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 my-8 not-prose">
              <div className="p-6 border border-green-900/50 rounded-xl bg-green-950/10">
                <div className="flex items-center gap-2 mb-4">
                  <ShieldCheck className="h-6 w-6 text-green-400" />
                  <h3 className="text-lg font-bold text-green-400 m-0">What runs locally</h3>
                </div>
                <ul className="space-y-2 text-sm text-muted-foreground">
                  {[
                    "All scanning and detection logic",
                    "Your .killswitch.yaml policy file",
                    "Incident logs (stored in .killswitch/ in your project)",
                    "Redaction and blocking decisions",
                    "The local report browser (killswitch menu)",
                  ].map((item) => (
                    <li key={item} className="flex items-start gap-2">
                      <span className="text-green-400 mt-0.5">✓</span> {item}
                    </li>
                  ))}
                </ul>
              </div>

              <div className="p-6 border border-red-900/50 rounded-xl bg-red-950/10">
                <div className="flex items-center gap-2 mb-4">
                  <XCircle className="h-6 w-6 text-red-400" />
                  <h3 className="text-lg font-bold text-red-400 m-0">What never leaves your machine</h3>
                </div>
                <ul className="space-y-2 text-sm text-muted-foreground">
                  {[
                    "Your prompts or message content",
                    "The actual secret values that triggered a block",
                    "API keys or credentials",
                    "Source code or file contents",
                    "File system paths",
                  ].map((item) => (
                    <li key={item} className="flex items-start gap-2">
                      <span className="text-red-400 mt-0.5">✗</span> {item}
                    </li>
                  ))}
                </ul>
              </div>
            </div>

            <div className="p-6 bg-white/5 border border-white/10 rounded-xl my-8 not-prose">
              <div className="flex items-start gap-4">
                <Mail className="h-6 w-6 text-primary shrink-0 mt-1" />
                <div>
                  <h3 className="text-lg font-bold mb-2">Optional email reports — opt-in only</h3>
                  <p className="text-muted-foreground text-sm leading-relaxed mb-4">
                    During <code className="text-primary">killswitch wizard</code> setup you can opt in to a weekly summary email. This is entirely optional and off by default. If you opt in, here is the complete list of what is sent:
                  </p>
                  <ul className="space-y-1 text-sm text-muted-foreground mb-4">
                    {[
                      "A hashed, anonymous install ID (not tied to your identity or machine)",
                      "A hashed project ID (a hash of your project directory name — not the path)",
                      "Aggregate counts: total calls intercepted, total blocks, total redactions",
                      "The detection layer that fired (e.g., \"regex\", \"entropy\") — never the value that matched",
                      "Your configured mode (kill / redact / pause / report_only)",
                    ].map((item) => (
                      <li key={item} className="flex items-start gap-2">
                        <span className="text-primary mt-0.5">·</span> {item}
                      </li>
                    ))}
                  </ul>
                  <p className="text-muted-foreground text-sm">
                    You can opt out at any time by running <code className="text-primary">killswitch wizard</code> again and selecting "No" at the email prompt, or by setting <code className="text-primary">telemetry_enabled: false</code> in your <code className="text-primary">.killswitch.yaml</code>.
                  </p>
                </div>
              </div>
            </div>

            <div className="mt-12 p-8 bg-primary/10 border border-primary/20 rounded-xl text-center not-prose">
              <Globe className="h-12 w-12 text-primary mx-auto mb-4" />
              <h3 className="text-2xl font-bold text-foreground mb-4">Secure your egress traffic today.</h3>
              <p className="text-muted-foreground mb-6">Open-source, local-first, and highly configurable.</p>
              <a href="/quickstart" className="inline-flex items-center justify-center rounded-md text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50 bg-primary text-primary-foreground hover:bg-primary/90 h-10 px-8 py-2">
                Get Started
              </a>
            </div>
          </div>
        </div>
      </main>
      
      <Footer />
    </div>
  );
}
