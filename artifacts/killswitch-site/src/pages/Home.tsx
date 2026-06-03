import React from "react";
import { Helmet } from "react-helmet-async";
import { Terminal, Shield, ArrowRight, ShieldBan, ShieldAlert, ShieldCheck, Github } from "lucide-react";
import { Link } from "wouter";
import { Button } from "@/components/ui/button";
import { Navbar } from "@/components/layout/Navbar";
import { Footer } from "@/components/layout/Footer";
import { CodeBlock } from "@/components/ui/CodeBlock";

export default function Home() {
  return (
    <div className="min-h-screen flex flex-col dark bg-background selection:bg-primary/30">
      <Helmet>
        <title>killswitch-ai | LLM Egress Control & Security</title>
        <meta name="description" content="The seatbelt for AI-powered dev teams. Intercept, block, or redact sensitive data before it reaches external LLM APIs." />
      </Helmet>
      
      <Navbar />
      
      <main className="flex-1">
        {/* Hero Section */}
        <section className="relative pt-24 pb-32 lg:pt-36 lg:pb-40 overflow-hidden">
          <div className="absolute inset-0 z-0">
            <img 
              src="/hero-bg.png" 
              alt="Secure data flow background" 
              className="w-full h-full object-cover opacity-20"
            />
            <div className="absolute inset-0 bg-gradient-to-b from-background via-background/90 to-background"></div>
          </div>
          
          <div className="container mx-auto px-4 md:px-6 relative z-10">
            <div className="max-w-4xl mx-auto text-center space-y-8 animate-in fade-in slide-in-from-bottom-8 duration-1000">
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-white/5 border border-white/10 text-sm font-medium text-muted-foreground mb-4">
                <Shield className="h-4 w-4 text-primary" />
                <span>Zero-trust LLM egress control</span>
              </div>
              
              <h1 className="text-5xl md:text-7xl font-bold tracking-tight font-sans text-glow">
                The seatbelt for <br />
                <span className="text-primary">AI-powered</span> teams.
              </h1>
              
              <p className="text-xl md:text-2xl text-muted-foreground max-w-2xl mx-auto leading-relaxed">
                A silent, local guardian that catches credentials, API keys, and PII before they ever reach OpenAI or Anthropic.
              </p>
              
              <div className="flex flex-col sm:flex-row items-center justify-center gap-4 pt-8">
                <div className="relative group">
                  <div className="absolute -inset-0.5 bg-primary/50 blur opacity-30 group-hover:opacity-100 transition duration-500 rounded-lg"></div>
                  <div className="relative flex items-center bg-black border border-white/20 rounded-lg px-4 py-3 font-mono text-sm shadow-xl">
                    <Terminal className="h-4 w-4 text-muted-foreground mr-3" />
                    <span className="text-foreground">pip install killswitch-ai</span>
                    <button 
                      onClick={() => navigator.clipboard.writeText("pip install killswitch-ai")}
                      className="ml-4 text-muted-foreground hover:text-white transition-colors"
                      aria-label="Copy install command"
                    >
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/></svg>
                    </button>
                  </div>
                </div>
                
                <Link href="/quickstart">
                  <Button size="lg" className="h-[50px] px-8 bg-primary hover:bg-primary/90 text-primary-foreground font-semibold shadow-lg hover:shadow-primary/25 transition-all">
                    Get Started <ArrowRight className="ml-2 h-4 w-4" />
                  </Button>
                </Link>
              </div>
            </div>
          </div>
        </section>

        {/* Value Prop Section */}
        <section className="py-24 bg-card/50 border-y border-white/5 relative z-10">
          <div className="container mx-auto px-4 md:px-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-16 items-center">
              <div className="space-y-6">
                <h2 className="text-3xl md:text-4xl font-bold tracking-tight">Stop prompt injections from leaking your infrastructure.</h2>
                <p className="text-lg text-muted-foreground leading-relaxed">
                  When your RAG pipeline blindly appends context to a prompt, you lose control over what gets sent. killswitch-ai sits between your code and the network, scanning every outbound payload.
                </p>
                <ul className="space-y-4 pt-4">
                  {[
                    "Runs entirely locally in your Python process",
                    "Zero external API dependencies or cloud proxies",
                    "Recursively scans nested JSON and dictionaries",
                    "Extensible policy via .killswitch.yaml"
                  ].map((item, i) => (
                    <li key={i} className="flex items-start gap-3">
                      <div className="mt-1 h-5 w-5 rounded-full bg-primary/20 flex items-center justify-center shrink-0">
                        <Check className="h-3 w-3 text-primary" />
                      </div>
                      <span className="text-foreground">{item}</span>
                    </li>
                  ))}
                </ul>
              </div>
              
              <div className="relative">
                <div className="absolute -inset-1 bg-gradient-to-r from-primary/30 to-blue-600/30 blur-xl opacity-50"></div>
                <CodeBlock 
                  language="python"
                  className="shadow-2xl"
                  code={`from killswitch_ai import killswitch
import openai

# A careless developer logs an entire environment dict
unsafe_context = f"Debug info: {os.environ}" 

# killswitch intercepts the payload before the HTTP request
with killswitch(mode="kill"):
    # Raises KillswitchTripped exception.
    # AWS keys never hit the network.
    response = openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": unsafe_context}]
    )`}
                />
              </div>
            </div>
          </div>
        </section>

        {/* Modes Section */}
        <section className="py-32 relative z-10">
          <div className="container mx-auto px-4 md:px-6">
            <div className="text-center max-w-2xl mx-auto mb-16">
              <h2 className="text-3xl md:text-4xl font-bold tracking-tight mb-4">Four modes of control.</h2>
              <p className="text-muted-foreground text-lg">
                Dictate exactly how the firewall responds when it detects sensitive data, from hard blocking to silent redaction.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
              <div className="bg-card border border-border p-8 rounded-xl hover:border-red-500/50 transition-colors group">
                <ShieldBan className="h-10 w-10 text-red-500 mb-6 group-hover:scale-110 transition-transform" />
                <h3 className="text-xl font-bold font-mono mb-3">mode="kill"</h3>
                <p className="text-muted-foreground leading-relaxed">
                  The strictest defense. Instantly halts execution and raises an exception if any sensitive pattern is detected.
                </p>
              </div>
              
              <div className="bg-card border border-border p-8 rounded-xl hover:border-blue-500/50 transition-colors group">
                <ShieldCheck className="h-10 w-10 text-blue-500 mb-6 group-hover:scale-110 transition-transform" />
                <h3 className="text-xl font-bold font-mono mb-3">mode="redact"</h3>
                <p className="text-muted-foreground leading-relaxed">
                  Intelligent masking. Silently replaces the sensitive string with <span className="font-mono text-xs bg-white/10 px-1 py-0.5 rounded">[REDACTED]</span> and allows the API call.
                </p>
              </div>
              
              <div className="bg-card border border-border p-8 rounded-xl hover:border-yellow-500/50 transition-colors group">
                <ShieldAlert className="h-10 w-10 text-yellow-500 mb-6 group-hover:scale-110 transition-transform" />
                <h3 className="text-xl font-bold font-mono mb-3">mode="pause"</h3>
                <p className="text-muted-foreground leading-relaxed">
                  Developer mode. Stops execution and prompts the CLI for manual review of the payload before allowing transmission.
                </p>
              </div>
            </div>
            
            <div className="mt-12 text-center">
              <Link href="/features" className="text-primary hover:text-primary/80 font-medium inline-flex items-center transition-colors">
                View all detection layers <ArrowRight className="ml-1 h-4 w-4" />
              </Link>
            </div>
          </div>
        </section>

        {/* CTA Section */}
        <section className="py-32 bg-black border-t border-white/10 relative overflow-hidden">
          <div className="absolute inset-0 bg-[linear-gradient(to_right,#80808012_1px,transparent_1px),linear-gradient(to_bottom,#80808012_1px,transparent_1px)] bg-[size:24px_24px]"></div>
          <div className="container mx-auto px-4 md:px-6 relative z-10">
            <div className="max-w-3xl mx-auto text-center space-y-8">
              <h2 className="text-4xl md:text-5xl font-bold tracking-tight">Ready to lock down your LLM egress?</h2>
              <p className="text-xl text-muted-foreground">
                Install killswitch-ai today and run the configuration wizard to generate your baseline security policy.
              </p>
              <div className="flex flex-col sm:flex-row items-center justify-center gap-4 pt-4">
                <Link href="/quickstart">
                  <Button size="lg" className="h-[50px] px-8 font-semibold">
                    Read the Quickstart
                  </Button>
                </Link>
                <a href="https://github.com/killswitch-ai/killswitch-ai" target="_blank" rel="noopener noreferrer">
                  <Button size="lg" variant="outline" className="h-[50px] px-8 bg-transparent border-white/20 hover:bg-white/5">
                    <Github className="mr-2 h-5 w-5" /> View on GitHub
                  </Button>
                </a>
              </div>
            </div>
          </div>
        </section>
      </main>
      
      <Footer />
    </div>
  );
}

function Check(props: any) {
  return (
    <svg
      {...props}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="3"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <polyline points="20 6 9 17 4 12" />
    </svg>
  )
}
