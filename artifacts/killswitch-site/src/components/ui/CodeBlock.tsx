import React, { useState } from "react";
import { Check, Copy } from "lucide-react";

interface CodeBlockProps {
  code: string;
  language?: string;
  className?: string;
}

export function CodeBlock({ code, language = "python", className = "" }: CodeBlockProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className={`relative group rounded-lg overflow-hidden border border-white/10 bg-[#0a0a0a] ${className}`}>
      <div className="flex items-center justify-between px-4 py-2 bg-white/5 border-b border-white/10">
        <span className="text-xs font-mono text-muted-foreground">{language}</span>
        <button 
          onClick={handleCopy}
          className="text-muted-foreground hover:text-foreground transition-colors p-1"
          aria-label="Copy code"
        >
          {copied ? <Check className="h-4 w-4 text-green-500" /> : <Copy className="h-4 w-4" />}
        </button>
      </div>
      <div className="p-4 overflow-x-auto">
        <pre className="font-mono text-sm leading-relaxed text-blue-100">
          <code>{code}</code>
        </pre>
      </div>
    </div>
  );
}
