import React from "react";
import { Helmet } from "react-helmet-async";
import { Shield, ShieldAlert, ShieldBan, ShieldCheck, Terminal, Code2, Database, GitMerge, FileWarning } from "lucide-react";
import { Navbar } from "@/components/layout/Navbar";
import { Footer } from "@/components/layout/Footer";
import { CodeBlock } from "@/components/ui/CodeBlock";

export default function Features() {
  return (
    <div className="min-h-screen flex flex-col dark">
      <Helmet>
        <title>Features — killswitch-ai</title>
        <meta name="description" content="Explore the 5 detection layers and 4 control modes of killswitch-ai. Deep-dive into how it intercepts and protects LLM API payloads." />
        <link rel="canonical" href="https://killswitch-ai.com/features" />
        <meta property="og:url" content="https://killswitch-ai.com/features" />
        <meta property="og:title" content="Features — killswitch-ai" />
        <meta property="og:type" content="website" />
      </Helmet>
      
      <Navbar />
      
      <main className="flex-1">
        <div className="container mx-auto px-4 md:px-6 py-20">
          <div className="max-w-3xl mb-16">
            <h1 className="font-display text-5xl md:text-7xl font-bold uppercase tracking-tight mb-6">Defense in Depth.</h1>
            <p className="text-xl text-muted-foreground">
              killswitch-ai isn't a simple regex filter. It's a comprehensive scanning pipeline that deeply inspects payloads across 5 detection layers and enforces policy through 4 execution modes.
            </p>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-12">
            {/* Detection Layers */}
            <div className="lg:col-span-7 space-y-12">
              <div>
                <h2 className="text-2xl font-semibold mb-8 flex items-center gap-3">
                  <Database className="text-primary h-6 w-6" /> 
                  5 Detection Layers
                </h2>
                
                <div className="space-y-8">
                  <FeatureCard 
                    icon={<FileWarning className="text-destructive h-5 w-5" />}
                    title="1. Prohibited Terms (Blocklist)"
                    description="Fast, exact-match scanning for company-specific prohibited keywords, project codenames, or competitor references that should never leave your network."
                  />
                  <FeatureCard 
                    icon={<Code2 className="text-primary h-5 w-5" />}
                    title="2. Regex Patterns"
                    description="Detect structured sensitive data like SSNs, credit cards, JWTs, AWS keys, and standard API token formats."
                  />
                  <FeatureCard 
                    icon={<ShieldAlert className="text-yellow-500 h-5 w-5" />}
                    title="3. Shannon Entropy Scanning"
                    description="The catch-all for unknown secrets. Calculates character entropy to detect highly random strings typical of cryptographic keys and passwords, even if they don't match known regex patterns."
                  />
                  <FeatureCard 
                    icon={<Terminal className="text-primary h-5 w-5" />}
                    title="4. Sensitive File Path Detection"
                    description="Prevents accidental uploads of local file paths (e.g., /etc/shadow, ~/.aws/credentials) that might have been accidentally included in RAG context."
                  />
                  <FeatureCard 
                    icon={<GitMerge className="text-primary h-5 w-5" />}
                    title="5. Recursive Structured Payload Scanning"
                    description="Deeply traverses nested dictionaries, lists, and JSON payloads. If a secret is buried 5 levels deep in a tool-calling argument, killswitch-ai finds it."
                  />
                </div>
              </div>
            </div>

            {/* Control Modes */}
            <div className="lg:col-span-5 space-y-12">
              <div className="bg-card border border-border rounded-xl p-8 sticky top-24">
                <h2 className="text-2xl font-semibold mb-8 flex items-center gap-3">
                  <Shield className="text-primary h-6 w-6" /> 
                  4 Control Modes
                </h2>
                
                <div className="space-y-6">
                  <div className="p-4 rounded-lg bg-red-950/20 border border-red-900/50">
                    <h3 className="font-mono font-bold text-red-400 mb-2 flex items-center gap-2">
                      <ShieldBan className="h-4 w-4" /> mode="kill"
                    </h3>
                    <p className="text-sm text-muted-foreground mb-3">Hard block. Instantly raises a <code className="text-red-400">KillswitchBlocked</code> exception and halts execution.</p>
                  </div>
                  
                  <div className="p-4 rounded-lg bg-yellow-950/20 border border-yellow-900/50">
                    <h3 className="font-mono font-bold text-yellow-400 mb-2 flex items-center gap-2">
                      <ShieldAlert className="h-4 w-4" /> mode="pause"
                    </h3>
                    <p className="text-sm text-muted-foreground">Stops execution and prompts the developer in the terminal (y/n) to review the payload before sending.</p>
                  </div>

                  <div className="p-4 rounded-lg bg-primary/10 border border-primary/30">
                    <h3 className="font-mono font-bold text-primary mb-2 flex items-center gap-2">
                      <ShieldCheck className="h-4 w-4" /> mode="redact"
                    </h3>
                    <p className="text-sm text-muted-foreground">Silently replaces sensitive values with <code className="text-primary">[REDACTED]</code> and allows the API call to proceed safely.</p>
                  </div>

                  <div className="p-4 rounded-lg bg-white/5 border border-white/10">
                    <h3 className="font-mono font-bold text-foreground mb-2 flex items-center gap-2">
                      <FileWarning className="h-4 w-4" /> mode="report_only"
                    </h3>
                    <p className="text-sm text-muted-foreground">Logs the incident for auditing purposes but does not block or modify the payload.</p>
                  </div>
                </div>
              </div>
            </div>
          </div>
          
          <div className="mt-24 max-w-4xl mx-auto">
            <h2 className="font-display text-4xl font-bold uppercase tracking-tight mb-8">Implementation Patterns</h2>
            
            <div className="space-y-8">
              <div>
                <h3 className="text-xl font-semibold mb-4">Context Manager</h3>
                <p className="text-muted-foreground mb-4">The cleanest way to wrap specific API calls without modifying the underlying client.</p>
                <CodeBlock 
                  language="python"
                  code={`from killswitch_ai import killswitch
import openai

# Protects any outbound LLM calls made within this block
with killswitch(mode="kill"):
    response = openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": f"Analyze this user data: {user_data}"}]
    )`}
                />
              </div>

              <div>
                <h3 className="text-xl font-semibold mb-4">Decorator</h3>
                <p className="text-muted-foreground mb-4">Ideal for securing internal wrapper functions or specialized LLM agents.</p>
                <CodeBlock 
                  language="python"
                  code={`from killswitch_ai import killswitch
import anthropic

@killswitch(mode="redact")
def generate_summary(text_block):
    client = anthropic.Anthropic()
    return client.messages.create(
        model="claude-3-opus-20240229",
        max_tokens=1000,
        messages=[{"role": "user", "content": text_block}]
    )`}
                />
              </div>
            </div>
          </div>
        </div>
      </main>
      
      <Footer />
    </div>
  );
}

function FeatureCard({ icon, title, description }: { icon: React.ReactNode, title: string, description: string }) {
  return (
    <div className="flex gap-4 items-start">
      <div className="mt-1 p-2 bg-white/5 rounded border border-white/10 shrink-0">
        {icon}
      </div>
      <div>
        <h3 className="text-lg font-semibold text-foreground mb-2">{title}</h3>
        <p className="text-muted-foreground leading-relaxed">{description}</p>
      </div>
    </div>
  );
}
