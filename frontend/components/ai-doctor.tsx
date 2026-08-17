"use client";

import { useState } from "react";
import { askScanQuestion, AIInterpretationResponse } from "@/lib/api";
import { MessageCircle, Send, Stethoscope, AlertTriangle, FileSearch } from "lucide-react";

export function AIDoctor({ scanId }: { scanId: string }) {
  const [question, setQuestion] = useState("");
  const [chatHistory, setChatHistory] = useState<
    { role: "user" | "doctor"; content: string; response?: AIInterpretationResponse }[]
  >([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleAsk = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!question.trim() || loading) return;

    const q = question.trim();
    setQuestion("");
    setChatHistory((prev) => [...prev, { role: "user", content: q }]);
    setLoading(true);
    setError(null);

    try {
      const response = await askScanQuestion(scanId, q);
      setChatHistory((prev) => [
        ...prev,
        { role: "doctor", content: response.statement, response },
      ]);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to get an answer.");
      setChatHistory((prev) => [
        ...prev,
        { role: "doctor", content: "Sorry, I encountered an error. Please try again." },
      ]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex flex-col h-[500px] border border-blue-900/50 rounded-xl overflow-hidden bg-slate-950 shadow-2xl relative">
      <div className="bg-gradient-to-r from-blue-900/40 to-indigo-900/40 border-b border-blue-800/50 p-4 flex items-center gap-3">
        <div className="p-2 bg-blue-500/20 rounded-lg text-blue-400">
          <Stethoscope className="w-5 h-5" />
        </div>
        <div>
          <h3 className="font-semibold text-blue-100 flex items-center gap-2">
            AI Doctor <span className="text-xs bg-blue-500/20 text-blue-300 px-2 py-0.5 rounded-full border border-blue-500/30">Beta</span>
          </h3>
          <p className="text-xs text-blue-400/80">Ask questions about this scan&apos;s evidence</p>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {chatHistory.length === 0 && (
          <div className="h-full flex flex-col items-center justify-center text-center space-y-4 opacity-50">
            <MessageCircle className="w-12 h-12 text-blue-400 mb-2" />
            <p className="text-sm text-blue-200 max-w-xs">
              I can analyze the deterministic evidence from this scan. Ask me anything about the site&apos;s security, performance, or content.
            </p>
            <div className="flex flex-wrap justify-center gap-2 mt-4 text-xs">
              <span className="bg-blue-950 border border-blue-800/50 rounded-full px-3 py-1 cursor-pointer hover:bg-blue-900/50 transition-colors" onClick={() => setQuestion("What are the most critical security risks?")}>&quot;What are the most critical security risks?&quot;</span>
              <span className="bg-blue-950 border border-blue-800/50 rounded-full px-3 py-1 cursor-pointer hover:bg-blue-900/50 transition-colors" onClick={() => setQuestion("Summarize the performance issues.")}>&quot;Summarize performance issues&quot;</span>
            </div>
          </div>
        )}

        {chatHistory.map((msg, i) => (
          <div key={i} className={`flex ${msg.role === "user" ? "justify-end" : "justify-start"}`}>
            <div
              className={`max-w-[85%] rounded-2xl p-4 ${
                msg.role === "user"
                  ? "bg-blue-600 text-white rounded-br-sm"
                  : "bg-slate-900 border border-slate-800 text-slate-200 rounded-bl-sm"
              }`}
            >
              {msg.role === "doctor" && msg.response && (
                <div className="flex items-center gap-2 mb-2 pb-2 border-b border-slate-700/50 text-xs font-semibold">
                  <span className={`px-2 py-0.5 rounded-full ${
                    msg.response.category === "SECURITY" ? "bg-red-500/20 text-red-400" :
                    msg.response.category === "PERFORMANCE" ? "bg-amber-500/20 text-amber-400" :
                    msg.response.category === "ERROR" ? "bg-red-900/50 text-red-200" :
                    "bg-blue-500/20 text-blue-400"
                  }`}>
                    {msg.response.category}
                  </span>
                  <span className="text-slate-400">{msg.response.subject}</span>
                </div>
              )}
              
              <div className="text-sm leading-relaxed whitespace-pre-wrap">{msg.content}</div>
              
              {msg.role === "doctor" && msg.response?.evidence && msg.response.evidence.length > 0 && (
                <div className="mt-3 pt-3 border-t border-slate-800/50">
                  <p className="text-xs text-slate-500 mb-2 flex items-center gap-1">
                    <FileSearch className="w-3 h-3" />
                    Cited Evidence
                  </p>
                  <div className="flex flex-wrap gap-2">
                    {msg.response.evidence.map(id => (
                      <a 
                        href={`#evidence-${id}`} 
                        key={id} 
                        onClick={(e) => {
                          const target = document.getElementById(`evidence-${id}`);
                          if (target) {
                            // Find closest parent <details> and open it
                            const details = target.closest('details');
                            if (details) details.open = true;
                            // Smooth scroll to it
                            target.scrollIntoView({ behavior: 'smooth', block: 'center' });
                            e.preventDefault();
                          }
                        }}
                        className="text-[10px] font-mono bg-slate-950 border border-slate-800 rounded px-2 py-1 text-blue-400 hover:text-blue-300 hover:border-blue-700 transition-colors"
                      >
                        {id.substring(0, 8)}...
                      </a>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        ))}
        {loading && (
          <div className="flex justify-start">
            <div className="bg-slate-900 border border-slate-800 rounded-2xl rounded-bl-sm p-4 flex gap-1 items-center">
              <div className="w-2 h-2 bg-blue-500 rounded-full animate-bounce [animation-delay:-0.3s]"></div>
              <div className="w-2 h-2 bg-blue-500 rounded-full animate-bounce [animation-delay:-0.15s]"></div>
              <div className="w-2 h-2 bg-blue-500 rounded-full animate-bounce"></div>
            </div>
          </div>
        )}
        {error && (
          <div className="flex justify-center my-2">
            <div className="bg-red-950/50 border border-red-900/50 text-red-400 text-xs px-3 py-2 rounded-lg flex items-center gap-2">
              <AlertTriangle className="w-4 h-4" />
              {error}
            </div>
          </div>
        )}
      </div>

      <div className="p-3 bg-slate-900/80 border-t border-slate-800/50 backdrop-blur-md">
        <form onSubmit={handleAsk} className="relative flex items-center">
          <input
            type="text"
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            placeholder="Ask a question about the evidence..."
            disabled={loading}
            className="w-full bg-slate-950 border border-slate-800 rounded-full py-3 pl-4 pr-12 text-sm text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-blue-600 focus:ring-1 focus:ring-blue-600 transition-all disabled:opacity-50"
          />
          <button
            type="submit"
            disabled={!question.trim() || loading}
            className="absolute right-2 p-2 bg-blue-600 hover:bg-blue-500 text-white rounded-full disabled:opacity-50 disabled:hover:bg-blue-600 transition-colors"
          >
            <Send className="w-4 h-4" />
          </button>
        </form>
      </div>
    </div>
  );
}
