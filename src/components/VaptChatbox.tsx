import { useState, useRef, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { ScrollArea } from "@/components/ui/scroll-area";
import { MessageSquare, X, Send, Loader2, Bot, User, Minimize2, Maximize2 } from "lucide-react";
import ReactMarkdown from "react-markdown";

interface Message {
  role: "user" | "assistant";
  content: string;
}

interface VaptChatboxProps {
  targetId?: string;
}

const CHAT_URL = `${import.meta.env.VITE_SUPABASE_URL}/functions/v1/vapt-chat`;

export default function VaptChatbox({ targetId }: VaptChatboxProps) {
  const [open, setOpen] = useState(false);
  const [expanded, setExpanded] = useState(false);
  const [messages, setMessages] = useState<Message[]>([
    { role: "assistant", content: "🛡️ **CyberScope AI** ready. Ask me anything about your findings, VAPT methodology, CVEs, or scan results." },
  ]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages]);

  const sendMessage = async () => {
    if (!input.trim() || loading) return;
    const userMsg: Message = { role: "user", content: input.trim() };
    const allMessages = [...messages.filter(m => m !== messages[0]), userMsg];
    setMessages(prev => [...prev, userMsg]);
    setInput("");
    setLoading(true);

    let assistantSoFar = "";

    try {
      const resp = await fetch(CHAT_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY}`,
        },
        body: JSON.stringify({ messages: allMessages, targetId }),
      });

      if (!resp.ok || !resp.body) {
        const err = await resp.json().catch(() => ({ error: "Failed" }));
        setMessages(prev => [...prev, { role: "assistant", content: `❌ ${err.error || "Request failed"}` }]);
        setLoading(false);
        return;
      }

      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let textBuffer = "";

      const upsert = (chunk: string) => {
        assistantSoFar += chunk;
        setMessages(prev => {
          const last = prev[prev.length - 1];
          if (last?.role === "assistant" && prev.length > 1 && last.content === assistantSoFar.slice(0, -chunk.length)) {
            return [...prev.slice(0, -1), { role: "assistant", content: assistantSoFar }];
          }
          if (last?.role === "assistant" && prev.length > 1 && assistantSoFar.length > chunk.length) {
            return [...prev.slice(0, -1), { role: "assistant", content: assistantSoFar }];
          }
          return [...prev, { role: "assistant", content: assistantSoFar }];
        });
      };

      let streamDone = false;
      while (!streamDone) {
        const { done, value } = await reader.read();
        if (done) break;
        textBuffer += decoder.decode(value, { stream: true });

        let newlineIndex: number;
        while ((newlineIndex = textBuffer.indexOf("\n")) !== -1) {
          let line = textBuffer.slice(0, newlineIndex);
          textBuffer = textBuffer.slice(newlineIndex + 1);
          if (line.endsWith("\r")) line = line.slice(0, -1);
          if (line.startsWith(":") || line.trim() === "") continue;
          if (!line.startsWith("data: ")) continue;
          const jsonStr = line.slice(6).trim();
          if (jsonStr === "[DONE]") { streamDone = true; break; }
          try {
            const parsed = JSON.parse(jsonStr);
            const content = parsed.choices?.[0]?.delta?.content;
            if (content) upsert(content);
          } catch {
            textBuffer = line + "\n" + textBuffer;
            break;
          }
        }
      }

      // Final flush
      if (textBuffer.trim()) {
        for (let raw of textBuffer.split("\n")) {
          if (!raw) continue;
          if (raw.endsWith("\r")) raw = raw.slice(0, -1);
          if (!raw.startsWith("data: ")) continue;
          const jsonStr = raw.slice(6).trim();
          if (jsonStr === "[DONE]") continue;
          try {
            const parsed = JSON.parse(jsonStr);
            const content = parsed.choices?.[0]?.delta?.content;
            if (content) upsert(content);
          } catch { /* ignore */ }
        }
      }

      if (!assistantSoFar) {
        setMessages(prev => [...prev, { role: "assistant", content: "No response received." }]);
      }
    } catch (e) {
      setMessages(prev => [...prev, { role: "assistant", content: `❌ Error: ${e instanceof Error ? e.message : "Unknown"}` }]);
    } finally {
      setLoading(false);
    }
  };

  if (!open) {
    return (
      <button
        onClick={() => setOpen(true)}
        className="fixed bottom-6 right-6 z-50 h-14 w-14 rounded-full bg-primary text-primary-foreground shadow-lg hover:shadow-primary/40 hover:shadow-xl transition-all flex items-center justify-center glow-green"
      >
        <MessageSquare className="h-6 w-6" />
      </button>
    );
  }

  return (
    <div className={`fixed z-50 ${expanded ? "inset-4" : "bottom-6 right-6 w-[420px] h-[560px]"} bg-card border border-border rounded-xl shadow-2xl shadow-primary/10 flex flex-col overflow-hidden transition-all`}>
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-border bg-muted/30">
        <div className="flex items-center gap-2">
          <Bot className="h-4 w-4 text-primary" />
          <span className="font-mono text-xs font-bold text-primary">CYBERSCOPE AI</span>
          <span className="text-[9px] font-mono text-muted-foreground">VAPT Assistant</span>
        </div>
        <div className="flex items-center gap-1">
          <button onClick={() => setExpanded(!expanded)} className="p-1 hover:bg-muted rounded">
            {expanded ? <Minimize2 className="h-3.5 w-3.5 text-muted-foreground" /> : <Maximize2 className="h-3.5 w-3.5 text-muted-foreground" />}
          </button>
          <button onClick={() => setOpen(false)} className="p-1 hover:bg-muted rounded">
            <X className="h-3.5 w-3.5 text-muted-foreground" />
          </button>
        </div>
      </div>

      {/* Messages */}
      <ScrollArea className="flex-1 p-3" ref={scrollRef}>
        <div className="space-y-3">
          {messages.map((msg, i) => (
            <div key={i} className={`flex gap-2 ${msg.role === "user" ? "justify-end" : "justify-start"}`}>
              {msg.role === "assistant" && <Bot className="h-5 w-5 text-primary mt-1 shrink-0" />}
              <div className={`max-w-[85%] rounded-lg px-3 py-2 text-xs font-mono ${
                msg.role === "user"
                  ? "bg-primary/20 text-foreground border border-primary/30"
                  : "bg-muted/50 text-foreground border border-border"
              }`}>
                <div className="prose prose-sm prose-invert max-w-none [&_p]:m-0 [&_pre]:my-1 [&_code]:text-[10px] [&_code]:text-cyber-cyan [&_h1]:text-sm [&_h2]:text-xs [&_h3]:text-xs [&_ul]:my-1 [&_ol]:my-1 [&_li]:my-0">
                  <ReactMarkdown>{msg.content}</ReactMarkdown>
                </div>
              </div>
              {msg.role === "user" && <User className="h-5 w-5 text-muted-foreground mt-1 shrink-0" />}
            </div>
          ))}
          {loading && !messages[messages.length - 1]?.content && (
            <div className="flex items-center gap-2 text-xs font-mono text-muted-foreground">
              <Loader2 className="h-3 w-3 animate-spin" /> Analyzing...
            </div>
          )}
        </div>
      </ScrollArea>

      {/* Input */}
      <div className="border-t border-border p-3 bg-muted/20">
        <div className="flex gap-2">
          <Textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask about findings, VAPT, CVEs..."
            className="flex-1 min-h-[36px] max-h-[80px] resize-none font-mono text-xs bg-background border-border"
            onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendMessage(); } }}
          />
          <Button size="sm" onClick={sendMessage} disabled={!input.trim() || loading} className="self-end h-9 w-9 p-0">
            {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
          </Button>
        </div>
      </div>
    </div>
  );
}
