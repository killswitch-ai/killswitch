import React, { useState } from "react";
import { Link } from "wouter";
import { Terminal, Shield, Menu, X, Github } from "lucide-react";
import { Button } from "@/components/ui/button";

export function Navbar() {
  const [isOpen, setIsOpen] = useState(false);

  return (
    <nav className="sticky top-0 z-50 w-full border-b border-white/10 bg-background/80 backdrop-blur-md">
      <div className="container mx-auto px-4 md:px-6">
        <div className="flex h-16 items-center justify-between">
          <Link href="/" className="flex items-center gap-2 text-primary hover:text-primary/80 transition-colors">
            <Shield className="h-6 w-6" />
            <span className="font-mono font-bold text-lg tracking-tight">killswitch-ai</span>
          </Link>

          {/* Desktop Nav */}
          <div className="hidden md:flex items-center gap-6">
            <Link href="/demo" className="text-sm font-medium text-primary hover:text-primary/80 transition-colors border border-primary/30 px-3 py-1 font-mono">▶ Demo</Link>
            <Link href="/docs" className="text-sm font-medium text-muted-foreground hover:text-foreground transition-colors">Docs</Link>
            <Link href="/features" className="text-sm font-medium text-muted-foreground hover:text-foreground transition-colors">Features</Link>
            <Link href="/quickstart" className="text-sm font-medium text-muted-foreground hover:text-foreground transition-colors">Quickstart</Link>
            <Link href="/why-killswitch" className="text-sm font-medium text-muted-foreground hover:text-foreground transition-colors">Why It Matters</Link>
            
            <div className="flex items-center gap-4 ml-4 pl-4 border-l border-white/10">
              <a href="https://github.com/killswitch-ai/killswitch-ai" target="_blank" rel="noopener noreferrer" className="text-muted-foreground hover:text-foreground">
                <Github className="h-5 w-5" />
                <span className="sr-only">GitHub</span>
              </a>
              <Link href="/docs" className="inline-flex">
                <Button size="sm" className="font-mono">
                  <Terminal className="mr-2 h-4 w-4" /> pip install
                </Button>
              </Link>
            </div>
          </div>

          {/* Mobile Menu Button */}
          <button className="md:hidden text-foreground" onClick={() => setIsOpen(!isOpen)}>
            {isOpen ? <X className="h-6 w-6" /> : <Menu className="h-6 w-6" />}
          </button>
        </div>
      </div>

      {/* Mobile Nav */}
      {isOpen && (
        <div className="md:hidden border-t border-white/10 bg-background px-4 py-4 space-y-4">
          <Link href="/demo" className="block text-sm font-medium text-primary hover:text-primary/80 py-2 font-mono" onClick={() => setIsOpen(false)}>▶ Demo</Link>
          <Link href="/docs" className="block text-sm font-medium text-muted-foreground hover:text-foreground py-2" onClick={() => setIsOpen(false)}>Docs</Link>
          <Link href="/features" className="block text-sm font-medium text-muted-foreground hover:text-foreground py-2" onClick={() => setIsOpen(false)}>Features</Link>
          <Link href="/quickstart" className="block text-sm font-medium text-muted-foreground hover:text-foreground py-2" onClick={() => setIsOpen(false)}>Quickstart</Link>
          <Link href="/why-killswitch" className="block text-sm font-medium text-muted-foreground hover:text-foreground py-2" onClick={() => setIsOpen(false)}>Why It Matters</Link>
          <div className="pt-4 border-t border-white/10 flex flex-col gap-4">
            <a href="https://github.com/killswitch-ai/killswitch-ai" target="_blank" rel="noopener noreferrer" className="flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground py-2">
              <Github className="h-5 w-5" /> GitHub Repository
            </a>
            <Link href="/docs" className="inline-flex w-full" onClick={() => setIsOpen(false)}>
              <Button size="sm" className="w-full font-mono justify-center">
                <Terminal className="mr-2 h-4 w-4" /> pip install killswitch-ai
              </Button>
            </Link>
          </div>
        </div>
      )}
    </nav>
  );
}
