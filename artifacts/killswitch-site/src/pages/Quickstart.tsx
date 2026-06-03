import React from "react";
import { Helmet } from "react-helmet-async";
import { Terminal, Shield, ArrowRight } from "lucide-react";
import { Navbar } from "@/components/layout/Navbar";
import { Footer } from "@/components/layout/Footer";
import { CodeBlock } from "@/components/ui/CodeBlock";
import { Link } from "wouter";
import { Button } from "@/components/ui/button";

export default function Quickstart() {
  return (
    <div className="min-h-screen flex flex-col dark">
      <Helmet>
        <title>Quickstart — killswitch-ai</title>
        <meta name="description" content="Get started with killswitch-ai. Step-by-step installation, configuration, and implementation guide for securing your LLM applications." />
        <link rel="canonical" href="https://killswitch-ai.com/quickstart" />
        <meta property="og:url" content="https://killswitch-ai.com/quickstart" />
        <meta property="og:title" content="Quickstart — killswitch-ai" />
        <meta property="og:type" content="website" />
      </Helmet>
      
      <Navbar />
      
      <main className="flex-1">
        <div className="container mx-auto px-4 md:px-6 py-20 max-w-4xl">
          <div className="mb-12">
            <h1 className="text-4xl md:text-5xl font-bold tracking-tight mb-4">Quickstart</h1>
            <p className="text-xl text-muted-foreground">
              Install, configure, and secure your LLM egress traffic in under 5 minutes.
            </p>
          </div>

          <div className="space-y-16">
            {/* Step 1 */}
            <section>
              <div className="flex items-center gap-4 mb-6">
                <div className="flex items-center justify-center h-8 w-8 rounded-full bg-primary/20 text-primary font-mono font-bold border border-primary/30">1</div>
                <h2 className="text-2xl font-semibold">Install the package</h2>
              </div>
              <p className="text-muted-foreground mb-4 ml-12">
                killswitch-ai is available on PyPI. It has zero external dependencies for its core functionality.
              </p>
              <div className="ml-12">
                <CodeBlock language="bash" code="pip install killswitch-ai" />
              </div>
            </section>

            {/* Step 2 */}
            <section>
              <div className="flex items-center gap-4 mb-6">
                <div className="flex items-center justify-center h-8 w-8 rounded-full bg-primary/20 text-primary font-mono font-bold border border-primary/30">2</div>
                <h2 className="text-2xl font-semibold">Initialize Configuration</h2>
              </div>
              <p className="text-muted-foreground mb-4 ml-12">
                Use the interactive CLI wizard to generate your first security policy file. This will guide you through setting up default blocks and custom rules.
              </p>
              <div className="ml-12 mb-4">
                <CodeBlock language="bash" code="killswitch wizard" />
              </div>
              <div className="ml-12 p-6 rounded-lg bg-black border border-white/10 font-mono text-sm space-y-2">
                <div className="text-green-400">Welcome to the killswitch-ai wizard.</div>
                <div className="text-muted-foreground">Let's configure your egress protections.</div>
                <div><span className="text-blue-400">?</span> Default operational mode (kill/pause/redact/report): <span className="text-white">redact</span></div>
                <div><span className="text-blue-400">?</span> Enable high-entropy secret detection? (Y/n): <span className="text-white">Y</span></div>
                <div><span className="text-blue-400">?</span> Enter prohibited terms (comma separated): <span className="text-white">ProjectApollo, InternalDb_Prod</span></div>
                <div className="text-green-400 mt-4">✓ Created .killswitch.yaml</div>
              </div>
            </section>

            {/* Step 3 */}
            <section>
              <div className="flex items-center gap-4 mb-6">
                <div className="flex items-center justify-center h-8 w-8 rounded-full bg-primary/20 text-primary font-mono font-bold border border-primary/30">3</div>
                <h2 className="text-2xl font-semibold">Wrap your LLM calls</h2>
              </div>
              <p className="text-muted-foreground mb-4 ml-12">
                Use the context manager around any code that sends data to an LLM provider. killswitch-ai automatically intercepts the standard HTTP libraries used by OpenAI, Anthropic, and others.
              </p>
              <div className="ml-12">
                <CodeBlock 
                  language="python" 
                  code={`from killswitch_ai import killswitch
import openai

# Any potential secrets in user_input will be caught
user_input = "Can you summarize this config? AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"

with killswitch(mode="redact"):
    # This call is protected. The AWS key will be replaced with [REDACTED] 
    # before the payload leaves your machine.
    response = openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": user_input}]
    )`} />
              </div>
            </section>
            
            {/* CLI Scan */}
            <section>
              <div className="flex items-center gap-4 mb-6">
                <div className="flex items-center justify-center h-8 w-8 rounded-full bg-primary/20 text-primary font-mono font-bold border border-primary/30">4</div>
                <h2 className="text-2xl font-semibold">Test your prompts offline</h2>
              </div>
              <p className="text-muted-foreground mb-4 ml-12">
                You can also use the CLI to scan local files before running your code, ensuring your static prompts are clean.
              </p>
              <div className="ml-12">
                <CodeBlock language="bash" code="killswitch scan ./prompts/system_prompt.txt" />
              </div>
            </section>
          </div>
          
          <div className="mt-16 pt-12 border-t border-white/10 ml-12 flex flex-col sm:flex-row items-center gap-6">
            <Link href="/features">
              <Button size="lg" className="w-full sm:w-auto">
                Explore All Features <ArrowRight className="ml-2 h-4 w-4" />
              </Button>
            </Link>
            <Link href="/why-killswitch" className="text-muted-foreground hover:text-foreground font-medium transition-colors">
              Read why egress control matters
            </Link>
          </div>
        </div>
      </main>
      
      <Footer />
    </div>
  );
}
