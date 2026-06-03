import React from "react";
import { Link } from "wouter";
import { Shield, Github, Terminal } from "lucide-react";

export function Footer() {
  return (
    <footer className="border-t border-white/10 bg-background/50 py-12 mt-20">
      <div className="container mx-auto px-4 md:px-6">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
          <div className="md:col-span-2 space-y-4">
            <div className="flex items-center gap-2 text-primary">
              <Shield className="h-6 w-6" />
              <span className="font-mono font-bold text-lg tracking-tight">killswitch-ai</span>
            </div>
            <p className="text-muted-foreground text-sm max-w-xs">
              The AI Kill Switch. A silent, local guardian that catches credentials and PII before they reach the cloud.
            </p>
            <div className="flex gap-4 pt-2">
              <a href="https://github.com/killswitch-ai/killswitch-ai" target="_blank" rel="noopener noreferrer" className="text-muted-foreground hover:text-foreground">
                <Github className="h-5 w-5" />
                <span className="sr-only">GitHub</span>
              </a>
              <a href="https://pypi.org/project/killswitch/" target="_blank" rel="noopener noreferrer" className="text-muted-foreground hover:text-foreground">
                <Terminal className="h-5 w-5" />
                <span className="sr-only">PyPI</span>
              </a>
            </div>
          </div>
          
          <div className="space-y-4">
            <h4 className="font-semibold text-foreground">Product</h4>
            <ul className="space-y-2">
              <li><Link href="/docs" className="text-sm text-muted-foreground hover:text-primary transition-colors">Docs</Link></li>
              <li><Link href="/features" className="text-sm text-muted-foreground hover:text-primary transition-colors">Features</Link></li>
              <li><Link href="/quickstart" className="text-sm text-muted-foreground hover:text-primary transition-colors">Quickstart</Link></li>
              <li><Link href="/why-killswitch" className="text-sm text-muted-foreground hover:text-primary transition-colors">Why It Matters</Link></li>
            </ul>
          </div>
          
          <div className="space-y-4">
            <h4 className="font-semibold text-foreground">Resources</h4>
            <ul className="space-y-2">
              <li><a href="https://github.com/killswitch-ai/killswitch-ai" className="text-sm text-muted-foreground hover:text-primary transition-colors">GitHub</a></li>
              <li><a href="https://github.com/killswitch-ai/killswitch-ai/issues" className="text-sm text-muted-foreground hover:text-primary transition-colors">Report an Issue</a></li>
              <li><a href="https://github.com/killswitch-ai/killswitch-ai/pulls" className="text-sm text-muted-foreground hover:text-primary transition-colors">Contribute</a></li>
            </ul>
          </div>
        </div>
        
        <div className="mt-12 pt-8 border-t border-white/10 flex flex-col md:flex-row justify-between items-center gap-4 text-xs text-muted-foreground">
          <p>© {new Date().getFullYear()} killswitch-ai. <a href="https://killswitch-ai.com" className="hover:text-primary transition-colors">killswitch-ai.com</a> — MIT License.</p>
          <p className="font-mono">pip install killswitch</p>
        </div>
      </div>
    </footer>
  );
}
