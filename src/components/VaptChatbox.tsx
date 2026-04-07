import { useState, useRef, useEffect, useCallback } from "react";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { ScrollArea } from "@/components/ui/scroll-area";
import { MessageSquare, X, Send, Loader2, Bot, User, Minimize2, Maximize2, History, Plus, Wrench } from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import ReactMarkdown from "react-markdown";

interface Message {
  role: "user" | "assistant" | "tool";
  content: string;
  toolName?: string;
  toolCalls?: Array<{ name: string; input: unknown }>;
}

interface ChatSession {
  id: string;
  session_id: string;
  title: string;
  last_message_at: string;
}

interface VaptChatboxProps {
  targetId?: string;
}

const CHAT_URL = `${import.meta.env.VITE_SUPABASE_URL}/functions/v1/vapt-chat`;

function generateSessionId() {
  return `cs-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

export default function VaptChatbox({ targetId }: VaptChatboxProps) {
  const [open, setOpen] = useState(false);
  const [expanded, setExpanded] = useState(false);
  const [showHistory, setShowHistory] = useState(false);
  const [sessions, setSessions] = useState<ChatSession[]>([]);
  const [sessionId, setSessionId] = useState(generateSessionId);
  const [messages, setMessages] = useState<Message[]>([
    { role: "assistant", content: "🛡️ **CyberScope AI** ready. I have full admin access to all scanning tools. Ask me to scan targets, analyze findings, triage vulnerabilities, or run deep audits." },
  ]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
  }, [messages]);

  const loadSessions = useCallback(async () => {
    const { data } = await supabase
      .from("chat_sessions")
      .select("id, session_id, title, last_message_at")
      .order("last_message_at", { ascending: false })
      .limit(20);
    if (data) setSessions(data);
  }, []);

  const loadSessionMessages = useCallback(async (sid: string) => {
    const { data: session } = await supabase
      .from("chat_sessions")
      .select("id")
      .eq("session_id", sid)
      .single();
    if (!session) return;

    const { data: msgs } = await supabase
      .from("chat_messages")
      .select("role, content, tool_name")
      .eq("session_id", session.id)
      .order("created_at", { ascending: true });

    if (msgs) {
      const mapped: Message[] = msgs
        .filter(m => m.role !== "tool")
        .map(m => ({ role: m.role as "user" | "assistant", content: m.content }));
      if (mapped.length > 0) {
        setMessages(mapped);
        setSessionId(sid);
        setShowHistory(false);
      }
    }
  }, []);

  useEffect(() => {
    if (showHistory) loadSessions();
  }, [showHistory, loadSessions]);

  const sendMessage = async () => {
    if (!input.trim() || loading) return;
    const userMsg: Message = { role: "user", content: input.trim() };
    const allMessages = [...messages.filter((_, i) => i > 0), userMsg]; // skip initial greeting
    setMessages(prev => [...prev, userMsg]);
    setInput("");
    setLoading(true);

    try {
      const resp = await fetch(CHAT_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY}`,
        },
        body: JSON.stringify({
          messages: allMessages.map(m => ({ role: m.role === "tool" ? "user" : m.role, content: m.content })),
          targetId,
          sessionId,
          saveChat: true,
        }),
      });

      if (!resp.ok) {
        const err = await resp.json().catch(() => ({ error: "Failed" }));
        setMessages(prev => [...prev, { role: "assistant", content: `❌ ${err.error || "Request failed"}` }]);
        return;
      }

      const data = await resp.json();

      // Show tool calls if any
      if (data.toolCalls?.length > 0) {
        const toolMsg: Message = {
          role: "tool",
          content: `🔧 **Tools executed:** ${data.toolCalls.map((t: any) => `\`${t.name}\``).join(", ")}`,
          toolCalls: data.toolCalls,
        };
        setMessages(prev => [...prev, toolMsg]);
      }

      // Show assistant response
      if (data.content) {
        setMessages(prev => [...prev, { role: "assistant", content: data.content }]);
      } else if (!data.toolCalls?.length) {
        setMessages(prev => [...prev, { role: "assistant", content: "No response received." }]);
      }
    } catch (e) {
      setMessages(prev => [...prev, { role: "assistant", content: `❌ Error: ${e instanceof Error ? e.message : "Unknown"}` }]);
    } finally {
      setLoading(false);
    }
  };

  const startNewChat = () => {
    setSessionId(generateSessionId());
    setMessages([
      { role: "assistant", content: "🛡️ **CyberScope AI** ready. I have full admin access to all scanning tools. Ask me to scan targets, analyze findings, triage vulnerabilities, or run deep audits." },
    ]);
    setShowHistory(false);
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
    <div className={`fixed z-50 ${expanded ? "inset-4" : "bottom-6 right-6 w-[440px] h-[600px]"} bg-card border border-border rounded-xl shadow-2xl shadow-primary/10 flex flex-col overflow-hidden transition-all`}>
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-border bg-muted/30">
        <div className="flex items-center gap-2">
          <Bot className="h-4 w-4 text-primary" />
          <span className="font-mono text-xs font-bold text-primary">CYBERSCOPE AI</span>
          <span className="text-[9px] font-mono text-muted-foreground">ADMIN</span>
        </div>
        <div className="flex items-center gap-1">
          <button onClick={() => setShowHistory(!showHistory)} className="p-1 hover:bg-muted rounded" title="Chat History">
            <History className="h-3.5 w-3.5 text-muted-foreground" />
          </button>
          <button onClick={startNewChat} className="p-1 hover:bg-muted rounded" title="New Chat">
            <Plus className="h-3.5 w-3.5 text-muted-foreground" />
          </button>
          <button onClick={() => setExpanded(!expanded)} className="p-1 hover:bg-muted rounded">
            {expanded ? <Minimize2 className="h-3.5 w-3.5 text-muted-foreground" /> : <Maximize2 className="h-3.5 w-3.5 text-muted-foreground" />}
          </button>
          <button onClick={() => setOpen(false)} className="p-1 hover:bg-muted rounded">
            <X className="h-3.5 w-3.5 text-muted-foreground" />
          </button>
        </div>
      </div>

      {/* History Panel */}
      {showHistory && (
        <div className="border-b border-border bg-muted/20 max-h-48 overflow-y-auto">
          {sessions.length === 0 ? (
            <p className="text-xs text-muted-foreground font-mono p-3">No chat history</p>
          ) : (
            sessions.map(s => (
              <button
                key={s.id}
                onClick={() => loadSessionMessages(s.session_id)}
                className="w-full text-left px-3 py-2 hover:bg-muted/50 border-b border-border/30 last:border-0"
              >
                <p className="text-xs font-mono text-foreground truncate">{s.title}</p>
                <p className="text-[9px] text-muted-foreground">{new Date(s.last_message_at).toLocaleString()}</p>
              </button>
            ))
          )}
        </div>
      )}

      {/* Messages */}
      <ScrollArea className="flex-1 p-3" ref={scrollRef}>
        <div className="space-y-3">
          {messages.map((msg, i) => (
            <div key={i} className={`flex gap-2 ${msg.role === "user" ? "justify-end" : "justify-start"}`}>
              {msg.role === "assistant" && <Bot className="h-5 w-5 text-primary mt-1 shrink-0" />}
              {msg.role === "tool" && <Wrench className="h-5 w-5 text-cyber-cyan mt-1 shrink-0" />}
              <div className={`max-w-[85%] rounded-lg px-3 py-2 text-xs font-mono ${
                msg.role === "user"
                  ? "bg-primary/20 text-foreground border border-primary/30"
                  : msg.role === "tool"
                  ? "bg-cyber-cyan/10 text-foreground border border-cyber-cyan/30"
                  : "bg-muted/50 text-foreground border border-border"
              }`}>
                <div className="prose prose-sm prose-invert max-w-none [&_p]:m-0 [&_pre]:my-1 [&_code]:text-[10px] [&_code]:text-cyber-cyan [&_h1]:text-sm [&_h2]:text-xs [&_h3]:text-xs [&_ul]:my-1 [&_ol]:my-1 [&_li]:my-0">
                  <ReactMarkdown>{msg.content}</ReactMarkdown>
                </div>
              </div>
              {msg.role === "user" && <User className="h-5 w-5 text-muted-foreground mt-1 shrink-0" />}
            </div>
          ))}
          {loading && (
            <div className="flex items-center gap-2 text-xs font-mono text-muted-foreground">
              <Loader2 className="h-3 w-3 animate-spin" /> Executing tools & analyzing...
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
            placeholder="Scan testphp.vulnweb.com, analyze findings, triage CVEs..."
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
