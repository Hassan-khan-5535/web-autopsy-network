"use client";

import { useState } from "react";
import { askScanQuestion, AIInterpretationResponse } from "@/lib/api";
function Stethoscope({ className = "w-5 h-5" }: { className?: string }) {
  return (
    <svg className={className} fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M4.8 2.3A.3.3 0 0 0 4.5 2.6V11a5 5 0 0 0 10 0V2.6a.3.3 0 0 0-.3-.3h-1.4a.3.3 0 0 0-.3.3V11a3 3 0 0 1-6 0V2.6a.3.3 0 0 0-.3-.3H4.8z" />
      <path d="M8 15v1a6 6 0 0 0 12 0v-3" />
      <circle cx="20" cy="10" r="2" />
    </svg>
  );
}

function MessageCircle({ className = "w-5 h-5" }: { className?: string }) {
  return (
    <svg className={className} fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M7.9 20A9 9 0 1 0 4 16.1L2 22z" />
    </svg>
  );
}

function AlertTriangle({ className = "w-5 h-5" }: { className?: string }) {
  return (
    <svg className={className} fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z" />
      <line x1="12" y1="9" x2="12" y2="13" />
      <line x1="12" y1="17" x2="12.01" y2="17" />
    </svg>
  );
}

function FileSearch({ className = "w-5 h-5" }: { className?: string }) {
  return (
    <svg className={className} fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
      <polyline points="14 2 14 8 20 8" />
      <circle cx="11.5" cy="14.5" r="2.5" />
      <path d="M13.25 16.25 15 18" />
    </svg>
  );
}

function Send({ className = "w-5 h-5" }: { className?: string }) {
  return (
    <svg className={className} fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <line x1="22" y1="2" x2="11" y2="13" />
      <polygon points="22 2 15 22 11 13 2 9 22 2" />
    </svg>
  );
}


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
            AI Doctor <span className="text-xs bg-blue-500/20 text-blue-300 px-2 py-0.5 rounded-full border border-blue-500/30">Citation-Grounded</span>
          </h3>
          <p className="text-xs text-blue-400/80">Ask questions about this scan&apos;s forensic evidence</p>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {chatHistory.length === 0 && (
          <div className="h-full flex flex-col items-center justify-center text-center space-y-4 opacity-75">
            <MessageCircle className="w-12 h-12 text-blue-400 mb-2" />
            <p className="text-sm text-blue-200 max-w-xs">
              I analyze the deterministic evidence from this scan. Ask me anything about security, performance, or content.
            </p>
            <div className="flex flex-wrap justify-center gap-2 mt-4 text-xs">
              <button
                type="button"
                className="bg-blue-950 border border-blue-800/50 rounded-full px-3 py-1 text-blue-300 hover:bg-blue-900/50 transition-colors"
                onClick={() => setQuestion("What are the most critical security risks?")}
              >
                &quot;What are the most critical security risks?&quot;
              </button>
              <button
                type="button"
                className="bg-blue-950 border border-blue-800/50 rounded-full px-3 py-1 text-blue-300 hover:bg-blue-900/50 transition-colors"
                onClick={() => setQuestion("Summarize performance issues.")}
              >
                &quot;Summarize performance issues&quot;
              </button>
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
                <div className="flex items-center gap-2 mb-2 pb-2 border-b border-slate-800 text-xs">
                  <span className="px-2 py-0.5 rounded font-mono font-bold bg-blue-500/20 text-blue-300 border border-blue-500/30">
                    {msg.response.category}
                  </span>
                  <span className="text-slate-300 font-semibold">{msg.response.subject}</span>
                </div>
              )}

              <div className="text-sm leading-relaxed whitespace-pre-wrap">{msg.content}</div>

              {msg.role === "doctor" && msg.response?.evidence && msg.response.evidence.length > 0 && (
                <div className="mt-3 pt-3 border-t border-slate-800/60 flex items-center gap-1.5 flex-wrap">
                  <span className="text-[10px] font-mono text-slate-400 flex items-center gap-1">
                    <FileSearch className="w-3 h-3 text-blue-400" />
                    Cited Evidence:
                  </span>
                  {msg.response.evidence.map((id) => (
                    <span
                      key={id}
                      className="text-[10px] font-mono bg-blue-950 border border-blue-800 rounded px-2 py-0.5 text-blue-300 font-semibold hover:border-blue-500 cursor-pointer transition-colors"
                      title={`Cited Evidence ID: ${id}`}
                    >
                      #{id}
                    </span>
                  ))}
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
