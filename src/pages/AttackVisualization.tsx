import { useState, useEffect, useMemo, useCallback, useRef } from "react";
import { useQuery } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import {
  Shield, Crosshair, AlertTriangle, Zap, Lock, Globe, Server, Eye,
  ShieldCheck, ShieldOff, Activity, Layers, Target, Bug, Swords, Heart,
  Flame, Skull, Crown, ArrowRight, Volume2, VolumeX,
} from "lucide-react";

// ── Sound FX Engine ──
class SoundFX {
  private ctx: AudioContext | null = null;
  enabled = true;

  private getCtx() {
    if (!this.ctx) this.ctx = new AudioContext();
    return this.ctx;
  }

  play(type: "hit" | "block" | "critical" | "ko" | "combo") {
    if (!this.enabled) return;
    try {
      const ctx = this.getCtx();
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.connect(gain);
      gain.connect(ctx.destination);

      const now = ctx.currentTime;
      switch (type) {
        case "hit":
          osc.type = "sawtooth"; osc.frequency.setValueAtTime(200, now);
          osc.frequency.exponentialRampToValueAtTime(80, now + 0.15);
          gain.gain.setValueAtTime(0.15, now); gain.gain.exponentialRampToValueAtTime(0.001, now + 0.15);
          osc.start(now); osc.stop(now + 0.15); break;
        case "block":
          osc.type = "square"; osc.frequency.setValueAtTime(800, now);
          osc.frequency.exponentialRampToValueAtTime(400, now + 0.1);
          gain.gain.setValueAtTime(0.1, now); gain.gain.exponentialRampToValueAtTime(0.001, now + 0.1);
          osc.start(now); osc.stop(now + 0.1); break;
        case "critical":
          osc.type = "sawtooth"; osc.frequency.setValueAtTime(150, now);
          osc.frequency.exponentialRampToValueAtTime(50, now + 0.3);
          gain.gain.setValueAtTime(0.2, now); gain.gain.exponentialRampToValueAtTime(0.001, now + 0.3);
          osc.start(now); osc.stop(now + 0.3); break;
        case "ko":
          osc.type = "sawtooth"; osc.frequency.setValueAtTime(300, now);
          osc.frequency.exponentialRampToValueAtTime(30, now + 0.8);
          gain.gain.setValueAtTime(0.25, now); gain.gain.exponentialRampToValueAtTime(0.001, now + 0.8);
          osc.start(now); osc.stop(now + 0.8); break;
        case "combo":
          osc.type = "triangle"; osc.frequency.setValueAtTime(400, now);
          osc.frequency.exponentialRampToValueAtTime(800, now + 0.1);
          gain.gain.setValueAtTime(0.12, now); gain.gain.exponentialRampToValueAtTime(0.001, now + 0.12);
          osc.start(now); osc.stop(now + 0.12); break;
      }
    } catch { /* audio blocked */ }
  }
}

const sfx = new SoundFX();

// ── Attack & Defense fighters data ──
const ATTACKER_MOVES = [
  { id: "sqli", name: "SQL Injection", icon: Server, power: 90, speed: 70, color: "hsl(var(--destructive))", owasp: "A03", combo: "' OR 1=1--", description: "Weaponize SQL queries to dump entire databases" },
  { id: "xss", name: "Cross-Site Scripting", icon: Globe, power: 75, speed: 85, color: "hsl(var(--cyber-amber))", owasp: "A03", combo: "<script>steal()</script>", description: "Inject scripts to hijack user sessions" },
  { id: "ssrf", name: "Server-Side Request Forgery", icon: Server, power: 85, speed: 60, color: "hsl(var(--accent))", owasp: "A10", combo: "http://169.254.169.254/", description: "Trick server into attacking internal services" },
  { id: "idor", name: "IDOR", icon: Eye, power: 70, speed: 90, color: "hsl(var(--secondary))", owasp: "A01", combo: "/api/users/OTHER_ID", description: "Access other users' data by ID manipulation" },
  { id: "ssti", name: "Template Injection", icon: Zap, power: 95, speed: 50, color: "hsl(var(--primary))", owasp: "A03", combo: "{{7*7}} → RCE", description: "Achieve remote code execution via templates" },
  { id: "lfi", name: "Local File Inclusion", icon: Layers, power: 80, speed: 75, color: "hsl(320, 80%, 55%)", owasp: "A01", combo: "../../../../etc/passwd", description: "Read sensitive server files via path traversal" },
  { id: "cmdi", name: "Command Injection", icon: Target, power: 95, speed: 55, color: "hsl(var(--destructive))", owasp: "A03", combo: "; cat /etc/shadow", description: "Execute OS commands on the server" },
  { id: "xxe", name: "XML External Entity", icon: Bug, power: 80, speed: 65, color: "hsl(var(--cyber-amber))", owasp: "A05", combo: "<!ENTITY xxe SYSTEM>", description: "Exploit XML parsers for file read & SSRF" },
];

const DEFENDER_MOVES = [
  { id: "waf", name: "Web Application Firewall", icon: Shield, power: 85, counter: ["sqli", "xss", "cmdi"], description: "Block malicious payloads at the perimeter" },
  { id: "csp", name: "Content Security Policy", icon: Lock, power: 90, counter: ["xss"], description: "Prevent unauthorized script execution" },
  { id: "parameterized", name: "Parameterized Queries", icon: ShieldCheck, power: 95, counter: ["sqli"], description: "Eliminate SQL injection at the source" },
  { id: "authz", name: "Authorization Middleware", icon: Crown, power: 88, counter: ["idor", "lfi"], description: "Enforce access control on every request" },
  { id: "sandbox", name: "Template Sandboxing", icon: Layers, power: 92, counter: ["ssti"], description: "Restrict template engine capabilities" },
  { id: "network-seg", name: "Network Segmentation", icon: Globe, power: 80, counter: ["ssrf"], description: "Isolate internal services from external reach" },
  { id: "input-val", name: "Input Validation", icon: ShieldCheck, power: 75, counter: ["cmdi", "xxe", "lfi"], description: "Sanitize and validate all user inputs" },
  { id: "dtd-disable", name: "DTD Disabled", icon: ShieldOff, power: 90, counter: ["xxe"], description: "Disable external entity processing" },
];

const KILL_CHAIN = [
  { phase: "RECON", icon: Crosshair, attacks: ["Port scan", "Subdomain enum", "Google Dorking", "JS analysis"], defenses: ["Rate limiting", "Honeypots", "WHOIS privacy"], color: "hsl(var(--secondary))" },
  { phase: "WEAPONIZE", icon: Flame, attacks: ["Payload craft", "WAF bypass", "Polyglot payloads", "Exploit chain"], defenses: ["WAF rules", "Input validation", "Content-Type enforce"], color: "hsl(var(--cyber-amber))" },
  { phase: "DELIVER", icon: ArrowRight, attacks: ["Param injection", "Header manipulation", "File upload", "API fuzz"], defenses: ["Schema validation", "File checks", "CORS policy"], color: "hsl(var(--accent))" },
  { phase: "EXPLOIT", icon: Skull, attacks: ["SQLi execute", "XSS trigger", "RCE via SSTI", "Auth bypass"], defenses: ["Prepared statements", "CSP", "Sandboxing", "MFA"], color: "hsl(var(--destructive))" },
  { phase: "EXFILTRATE", icon: Crown, attacks: ["Data dump", "Privesc", "Lateral move", "Persistence"], defenses: ["DLP", "Least privilege", "Network seg", "Audit logs"], color: "hsl(var(--primary))" },
];

export default function AttackVisualization() {
  const [selectedAttack, setSelectedAttack] = useState<string | null>(null);
  const [battlePhase, setBattlePhase] = useState(0);
  const [attackerHP, setAttackerHP] = useState(100);
  const [defenderHP, setDefenderHP] = useState(100);
  const [battleLog, setBattleLog] = useState<string[]>([]);
  const [isAutoFight, setIsAutoFight] = useState(false);
  const [comboCount, setComboCount] = useState(0);
  const [soundEnabled, setSoundEnabled] = useState(true);
  const [shakeClass, setShakeClass] = useState("");
  const arenaRef = useRef<HTMLDivElement>(null);

  const triggerShake = useCallback((intensity: "light" | "heavy" | "ko") => {
    const cls = intensity === "ko" ? "animate-shake-ko" : intensity === "heavy" ? "animate-shake-heavy" : "animate-shake-light";
    setShakeClass(cls);
    setTimeout(() => setShakeClass(""), intensity === "ko" ? 600 : 300);
  }, []);

  useEffect(() => { sfx.enabled = soundEnabled; }, [soundEnabled]);

  const { data: findings } = useQuery({
    queryKey: ["viz-findings"],
    queryFn: async () => {
      const { data } = await supabase.from("vulnerability_findings").select("severity, title, confidence_score, validation_status").limit(200);
      return data || [];
    },
  });

  const { data: approvals } = useQuery({
    queryKey: ["viz-approvals"],
    queryFn: async () => {
      const { data } = await supabase.from("pending_approvals").select("severity, finding_type, confidence_score, status").limit(200);
      return data || [];
    },
  });

  useEffect(() => {
    const interval = setInterval(() => setBattlePhase(p => (p + 1) % KILL_CHAIN.length), 4000);
    return () => clearInterval(interval);
  }, []);

  // Auto-fight
  useEffect(() => {
    if (!isAutoFight) return;
    const interval = setInterval(() => {
      const atk = ATTACKER_MOVES[Math.floor(Math.random() * ATTACKER_MOVES.length)];
      const countered = DEFENDER_MOVES.some(d => d.counter.includes(atk.id) && Math.random() > 0.4);
      if (countered) {
        const def = DEFENDER_MOVES.find(d => d.counter.includes(atk.id))!;
        const dmg = Math.floor(def.power * 0.15);
        setAttackerHP(p => {
          const next = Math.max(0, p - dmg);
          if (next <= 0) { sfx.play("ko"); triggerShake("ko"); }
          return next;
        });
        setBattleLog(l => [`🛡️ ${def.name} BLOCKED ${atk.name}! -${dmg}HP`, ...l].slice(0, 8));
        setComboCount(0);
        sfx.play("block");
        triggerShake("light");
      } else {
        const dmg = Math.floor(atk.power * 0.12);
        setDefenderHP(p => {
          const next = Math.max(0, p - dmg);
          if (next <= 0) { sfx.play("ko"); triggerShake("ko"); }
          return next;
        });
        setComboCount(c => {
          const next = c + 1;
          if (next > 2) sfx.play("combo");
          return next;
        });
        setBattleLog(l => [`⚔️ ${atk.name} HIT! ${atk.combo} -${dmg}HP ${comboCount > 2 ? "🔥COMBO x" + comboCount : ""}`, ...l].slice(0, 8));
        sfx.play(atk.power >= 90 ? "critical" : "hit");
        triggerShake(atk.power >= 90 ? "heavy" : "light");
      }
    }, 1500);
    return () => clearInterval(interval);
  }, [isAutoFight, comboCount, triggerShake]);

  const resetFight = useCallback(() => {
    setAttackerHP(100); setDefenderHP(100); setBattleLog([]); setComboCount(0);
  }, []);

  const executeAttack = useCallback((atkId: string) => {
    const atk = ATTACKER_MOVES.find(a => a.id === atkId);
    if (!atk) return;
    const countered = DEFENDER_MOVES.some(d => d.counter.includes(atkId) && Math.random() > 0.35);
    if (countered) {
      const def = DEFENDER_MOVES.find(d => d.counter.includes(atkId))!;
      const dmg = Math.floor(def.power * 0.18);
      setAttackerHP(p => {
        const next = Math.max(0, p - dmg);
        if (next <= 0) { sfx.play("ko"); triggerShake("ko"); }
        return next;
      });
      setBattleLog(l => [`🛡️ PARRIED! ${def.name} counters ${atk.name}! -${dmg}HP to attacker`, ...l].slice(0, 10));
      setComboCount(0);
      sfx.play("block");
      triggerShake("light");
    } else {
      const dmg = Math.floor(atk.power * 0.15);
      setDefenderHP(p => {
        const next = Math.max(0, p - dmg);
        if (next <= 0) { sfx.play("ko"); triggerShake("ko"); }
        return next;
      });
      setComboCount(c => {
        const next = c + 1;
        if (next > 1) sfx.play("combo");
        return next;
      });
      setBattleLog(l => [`⚔️ ${atk.name} LANDS! ${atk.combo} -${dmg}HP ${comboCount > 1 ? "🔥COMBO x" + (comboCount + 1) : ""}`, ...l].slice(0, 10));
      sfx.play(atk.power >= 90 ? "critical" : "hit");
      triggerShake(atk.power >= 90 ? "heavy" : "light");
    }
    setSelectedAttack(atkId);
  }, [comboCount, triggerShake]);

  const stats = useMemo(() => {
    const confirmed = findings?.filter(f => f.validation_status === "confirmed").length || 0;
    const fp = findings?.filter(f => f.validation_status === "false_positive").length || 0;
    const pending = approvals?.filter(a => a.status === "pending").length || 0;
    return { confirmed, fp, pending, total: (findings?.length || 0) };
  }, [findings, approvals]);

  const activeAttack = ATTACKER_MOVES.find(a => a.id === selectedAttack);
  const activeDefenses = selectedAttack ? DEFENDER_MOVES.filter(d => d.counter.includes(selectedAttack)) : [];

  return (
    <div className="space-y-4 pb-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold font-mono text-primary text-glow-green flex items-center gap-2">
            <Swords className="h-5 w-5" /> CYBER BATTLE ARENA
          </h1>
          <p className="text-[10px] font-mono text-muted-foreground">Attack vs Defense — Interactive Combat Visualization</p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => { setSoundEnabled(!soundEnabled); }}
            className="px-2 py-1.5 rounded font-mono text-[10px] border border-border text-muted-foreground hover:text-foreground transition-colors"
            title={soundEnabled ? "Mute" : "Unmute"}
          >
            {soundEnabled ? <Volume2 className="h-3.5 w-3.5" /> : <VolumeX className="h-3.5 w-3.5" />}
          </button>
          <button
            onClick={() => { setIsAutoFight(!isAutoFight); if (!isAutoFight) resetFight(); }}
            className={`px-3 py-1.5 rounded font-mono text-[10px] font-bold border transition-all ${
              isAutoFight
                ? "bg-destructive/20 border-destructive text-destructive animate-pulse"
                : "bg-primary/10 border-primary text-primary hover:bg-primary/20"
            }`}
          >
            {isAutoFight ? "⏹ STOP FIGHT" : "▶ AUTO BATTLE"}
          </button>
          <button onClick={resetFight} className="px-3 py-1.5 rounded font-mono text-[10px] font-bold border border-border text-muted-foreground hover:text-foreground transition-colors">
            ↻ RESET
          </button>
        </div>
      </div>

      {/* ═══ BATTLE ARENA ═══ */}
      <Card ref={arenaRef} className={`border-primary/30 bg-gradient-to-b from-card to-background overflow-hidden relative ${shakeClass}`}>
        <div className="absolute inset-0 pointer-events-none">
          <div className="absolute left-0 top-0 w-1/3 h-full bg-gradient-to-r from-destructive/5 to-transparent" />
          <div className="absolute right-0 top-0 w-1/3 h-full bg-gradient-to-l from-primary/5 to-transparent" />
        </div>

        <CardContent className="p-4 relative z-10">
          <div className="text-center mb-3">
            <span className="text-[9px] font-mono text-muted-foreground tracking-[0.3em]">— ROUND {battlePhase + 1} —</span>
          </div>

          <div className="grid grid-cols-[1fr_auto_1fr] gap-4 items-center">
            {/* Attacker Side */}
            <div className="space-y-3">
              <div className="flex items-center gap-2">
                <Skull className="h-5 w-5 text-destructive" />
                <span className="font-mono text-sm font-bold text-destructive">ATTACKER</span>
                {comboCount > 2 && <Badge className="bg-destructive/20 text-destructive border-destructive text-[8px] animate-pulse">🔥 COMBO x{comboCount}</Badge>}
              </div>
              <div className="space-y-1">
                <div className="flex justify-between text-[9px] font-mono">
                  <span className="text-destructive flex items-center gap-1"><Heart className="h-3 w-3" /> HP</span>
                  <span className="text-destructive">{attackerHP}/100</span>
                </div>
                <div className="h-3 w-full rounded-full bg-muted overflow-hidden border border-destructive/30">
                  <div className="h-full rounded-full transition-all duration-500" style={{ width: `${attackerHP}%`, background: `linear-gradient(90deg, hsl(var(--destructive)), hsl(0, 100%, 70%))` }} />
                </div>
              </div>
              <div className="p-2 rounded border border-destructive/20 bg-destructive/5 min-h-[60px]">
                <p className="text-[9px] font-mono text-destructive/70 mb-1">ACTIVE MOVE</p>
                {activeAttack ? (
                  <div className="flex items-center gap-2">
                    <activeAttack.icon className="h-4 w-4 text-destructive" />
                    <div>
                      <p className="text-[10px] font-mono font-bold text-foreground">{activeAttack.name}</p>
                      <code className="text-[8px] font-mono text-destructive/80">{activeAttack.combo}</code>
                    </div>
                  </div>
                ) : (
                  <p className="text-[9px] font-mono text-muted-foreground italic">Select an attack below...</p>
                )}
              </div>
            </div>

            {/* VS Divider */}
            <div className="flex flex-col items-center gap-1">
              <div className="w-px h-8 bg-gradient-to-b from-destructive via-muted-foreground to-primary" />
              <div className="relative">
                <span className="text-lg font-black font-mono text-foreground">VS</span>
                <Swords className="h-4 w-4 text-muted-foreground absolute -top-1 -right-5 animate-pulse" />
              </div>
              <div className="w-px h-8 bg-gradient-to-b from-primary via-muted-foreground to-destructive" />
            </div>

            {/* Defender Side */}
            <div className="space-y-3">
              <div className="flex items-center gap-2 justify-end">
                {stats.confirmed > 0 && <Badge className="bg-primary/20 text-primary border-primary text-[8px]">{stats.confirmed} vulns patched</Badge>}
                <span className="font-mono text-sm font-bold text-primary">DEFENDER</span>
                <ShieldCheck className="h-5 w-5 text-primary" />
              </div>
              <div className="space-y-1">
                <div className="flex justify-between text-[9px] font-mono">
                  <span className="text-primary">{defenderHP}/100</span>
                  <span className="text-primary flex items-center gap-1">HP <Heart className="h-3 w-3" /></span>
                </div>
                <div className="h-3 w-full rounded-full bg-muted overflow-hidden border border-primary/30">
                  <div className="h-full rounded-full transition-all duration-500" style={{ width: `${defenderHP}%`, background: `linear-gradient(90deg, hsl(var(--primary)), hsl(160, 100%, 65%))` }} />
                </div>
              </div>
              <div className="p-2 rounded border border-primary/20 bg-primary/5 min-h-[60px]">
                <p className="text-[9px] font-mono text-primary/70 mb-1 text-right">ACTIVE DEFENSE</p>
                {activeDefenses.length > 0 ? (
                  <div className="space-y-1">
                    {activeDefenses.map(d => (
                      <div key={d.id} className="flex items-center gap-2 justify-end">
                        <div className="text-right">
                          <p className="text-[10px] font-mono font-bold text-foreground">{d.name}</p>
                          <p className="text-[8px] font-mono text-primary/80">{d.description}</p>
                        </div>
                        <d.icon className="h-4 w-4 text-primary" />
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-[9px] font-mono text-muted-foreground italic text-right">Waiting for attack...</p>
                )}
              </div>
            </div>
          </div>

          {/* Battle Log */}
          {battleLog.length > 0 && (
            <div className="mt-3 p-2 rounded border border-border bg-background/50 max-h-[100px] overflow-y-auto">
              <p className="text-[8px] font-mono text-muted-foreground mb-1 flex items-center gap-1">
                <Activity className="h-3 w-3" /> BATTLE LOG
              </p>
              {battleLog.map((log, i) => (
                <p key={i} className={`text-[9px] font-mono ${i === 0 ? "text-foreground font-bold" : "text-muted-foreground"}`}>{log}</p>
              ))}
            </div>
          )}

          {/* KO Banner */}
          {(attackerHP <= 0 || defenderHP <= 0) && (
            <div className="mt-3 p-3 rounded-lg border-2 text-center animate-scale-in" style={{
              borderColor: defenderHP <= 0 ? "hsl(var(--destructive))" : "hsl(var(--primary))",
              background: defenderHP <= 0 ? "hsl(var(--destructive) / 0.1)" : "hsl(var(--primary) / 0.1)",
            }}>
              <p className="text-lg font-black font-mono" style={{ color: defenderHP <= 0 ? "hsl(var(--destructive))" : "hsl(var(--primary))" }}>
                {defenderHP <= 0 ? "💀 ATTACKER WINS — SYSTEM COMPROMISED" : "🛡️ DEFENDER WINS — ATTACK NEUTRALIZED"}
              </p>
              <p className="text-[10px] font-mono text-muted-foreground mt-1">
                {defenderHP <= 0 ? "Deploy countermeasures to prevent this outcome" : "Security controls successfully stopped the attack"}
              </p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* ═══ ATTACK MOVE SELECTOR ═══ */}
      <div>
        <p className="text-[10px] font-mono text-destructive mb-2 flex items-center gap-1">
          <Crosshair className="h-3 w-3" /> SELECT ATTACK MOVE — Click to execute
        </p>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
          {ATTACKER_MOVES.map(atk => {
            const Icon = atk.icon;
            const isActive = selectedAttack === atk.id;
            const count = findings?.filter(f => f.title?.toLowerCase().includes(atk.id) || f.title?.toLowerCase().includes(atk.name.toLowerCase().split(" ")[0])).length || 0;
            return (
              <button
                key={atk.id}
                onClick={() => executeAttack(atk.id)}
                disabled={attackerHP <= 0 || defenderHP <= 0}
                className={`group relative text-left p-3 rounded-lg border transition-all hover:scale-[1.03] active:scale-95 disabled:opacity-30 ${
                  isActive
                    ? "border-destructive bg-destructive/10 shadow-lg shadow-destructive/20"
                    : "border-border bg-card hover:border-destructive/40"
                }`}
              >
                <div className="absolute top-0 left-0 right-0 h-0.5 rounded-t-lg overflow-hidden">
                  <div className="h-full bg-destructive/50" style={{ width: `${atk.power}%` }} />
                </div>
                <div className="flex items-center gap-2 mb-1.5">
                  <div className="p-1 rounded bg-destructive/10 group-hover:bg-destructive/20 transition-colors">
                    <Icon className="h-3.5 w-3.5 text-destructive" />
                  </div>
                  <span className="font-mono text-[10px] font-bold text-foreground">{atk.name}</span>
                </div>
                <p className="text-[8px] font-mono text-muted-foreground leading-relaxed mb-2">{atk.description}</p>
                <div className="flex items-center justify-between">
                  <div className="flex gap-2">
                    <span className="text-[8px] font-mono text-destructive">⚔️{atk.power}</span>
                    <span className="text-[8px] font-mono text-cyber-amber">⚡{atk.speed}</span>
                  </div>
                  <div className="flex items-center gap-1">
                    <Badge variant="outline" className="text-[7px] font-mono border-border h-4">{atk.owasp}</Badge>
                    {count > 0 && <Badge className="bg-destructive/20 text-destructive border-destructive text-[7px] h-4">{count}</Badge>}
                  </div>
                </div>
                <code className="block mt-1.5 text-[7px] font-mono text-destructive/50 truncate">{atk.combo}</code>
              </button>
            );
          })}
        </div>
      </div>

      {/* ═══ EXPANDED MATCHUP ═══ */}
      {activeAttack && (
        <Card className="border-accent/30 bg-gradient-to-r from-destructive/5 via-card to-primary/5 animate-fade-in">
          <CardContent className="p-4">
            <div className="grid grid-cols-[1fr_auto_1fr] gap-6">
              <div>
                <p className="text-xs font-mono font-bold text-destructive mb-2 flex items-center gap-1"><Skull className="h-3.5 w-3.5" /> ATTACK BREAKDOWN</p>
                <p className="text-[10px] font-mono text-foreground/80 mb-2">{activeAttack.description}</p>
                <div className="space-y-1.5">
                  <div className="flex justify-between text-[9px] font-mono"><span className="text-muted-foreground">Power</span><span className="text-destructive">{activeAttack.power}/100</span></div>
                  <Progress value={activeAttack.power} className="h-1.5 [&>div]:bg-destructive" />
                  <div className="flex justify-between text-[9px] font-mono"><span className="text-muted-foreground">Speed</span><span className="text-cyber-amber">{activeAttack.speed}/100</span></div>
                  <Progress value={activeAttack.speed} className="h-1.5 [&>div]:bg-[hsl(var(--cyber-amber))]" />
                </div>
                <div className="mt-3 p-2 rounded bg-background/50 border border-destructive/20">
                  <p className="text-[8px] font-mono text-muted-foreground mb-1">EXAMPLE PAYLOAD:</p>
                  <code className="text-[9px] font-mono text-destructive break-all">{activeAttack.combo}</code>
                </div>
              </div>
              <div className="flex flex-col items-center justify-center">
                <Swords className="h-6 w-6 text-accent animate-pulse" />
                <span className="text-[8px] font-mono text-muted-foreground mt-1">MATCHUP</span>
              </div>
              <div>
                <p className="text-xs font-mono font-bold text-primary mb-2 flex items-center gap-1"><ShieldCheck className="h-3.5 w-3.5" /> COUNTERMEASURES</p>
                {activeDefenses.length > 0 ? (
                  <div className="space-y-2">
                    {activeDefenses.map(def => (
                      <div key={def.id} className="p-2 rounded border border-primary/20 bg-primary/5">
                        <div className="flex items-center gap-2 mb-1">
                          <def.icon className="h-3.5 w-3.5 text-primary" />
                          <span className="text-[10px] font-mono font-bold text-foreground">{def.name}</span>
                          <span className="text-[8px] font-mono text-primary ml-auto">PWR {def.power}</span>
                        </div>
                        <p className="text-[9px] font-mono text-muted-foreground">{def.description}</p>
                        <Progress value={def.power} className="h-1 mt-1.5 [&>div]:bg-primary" />
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="p-3 rounded border border-destructive/30 bg-destructive/5 text-center">
                    <AlertTriangle className="h-5 w-5 text-destructive mx-auto mb-1" />
                    <p className="text-[10px] font-mono text-destructive font-bold">NO COUNTER AVAILABLE</p>
                    <p className="text-[8px] font-mono text-muted-foreground">This attack has no direct countermeasure mapped!</p>
                  </div>
                )}
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* ═══ KILL CHAIN ═══ */}
      <Card className="border-border bg-card overflow-hidden">
        <CardContent className="p-4">
          <p className="text-[10px] font-mono text-primary mb-3 flex items-center gap-1"><Activity className="h-3 w-3" /> CYBER KILL CHAIN — Attack Progression</p>
          <div className="flex items-stretch gap-1 overflow-x-auto pb-2">
            {KILL_CHAIN.map((phase, idx) => {
              const isActive = idx === battlePhase;
              const isPast = idx < battlePhase;
              const Icon = phase.icon;
              return (
                <div key={phase.phase} className="flex items-stretch gap-1 min-w-0">
                  <button
                    onClick={() => setBattlePhase(idx)}
                    className={`relative rounded-lg border p-3 min-w-[160px] transition-all duration-500 text-left ${
                      isActive ? "border-primary bg-primary/10 shadow-lg shadow-primary/20 scale-[1.03]"
                        : isPast ? "border-primary/30 bg-primary/5 opacity-60"
                        : "border-border bg-card opacity-30 hover:opacity-60"
                    }`}
                  >
                    {isActive && <div className="absolute -top-1 -right-1 h-3 w-3 rounded-full bg-primary animate-pulse" />}
                    <div className="flex items-center gap-2 mb-2">
                      <Icon className="h-4 w-4" style={{ color: phase.color }} />
                      <span className="font-mono text-[9px] font-black text-foreground tracking-wide">{phase.phase}</span>
                    </div>
                    <div className="space-y-0.5">
                      <p className="text-[8px] font-mono text-destructive">⚔️ {phase.attacks[0]}</p>
                      <p className="text-[8px] font-mono text-primary">🛡️ {phase.defenses[0]}</p>
                    </div>
                  </button>
                  {idx < KILL_CHAIN.length - 1 && (
                    <div className="flex items-center">
                      <ArrowRight className={`h-3 w-3 shrink-0 ${isPast || isActive ? "text-primary" : "text-muted-foreground/20"}`} />
                    </div>
                  )}
                </div>
              );
            })}
          </div>
          <div className="mt-3 grid grid-cols-2 gap-4 p-3 rounded-lg border border-border bg-background/50">
            <div className="space-y-1.5">
              <p className="text-[9px] font-mono font-bold text-destructive flex items-center gap-1"><Crosshair className="h-3 w-3" /> ATTACKER TECHNIQUES</p>
              {KILL_CHAIN[battlePhase].attacks.map((a, i) => (
                <div key={i} className="flex items-center gap-2 text-[9px] font-mono text-foreground/80">
                  <span className="h-1.5 w-1.5 rounded-full bg-destructive shrink-0" /> {a}
                </div>
              ))}
            </div>
            <div className="space-y-1.5">
              <p className="text-[9px] font-mono font-bold text-primary flex items-center gap-1"><ShieldCheck className="h-3 w-3" /> DEFENSIVE MEASURES</p>
              {KILL_CHAIN[battlePhase].defenses.map((d, i) => (
                <div key={i} className="flex items-center gap-2 text-[9px] font-mono text-foreground/80">
                  <span className="h-1.5 w-1.5 rounded-full bg-primary shrink-0" /> {d}
                </div>
              ))}
            </div>
          </div>
        </CardContent>
      </Card>

      {/* ═══ SCOREBOARD ═══ */}
      <div className="grid grid-cols-4 gap-2">
        {[
          { label: "Vulns Found", value: stats.total, icon: Bug, color: "destructive" },
          { label: "Confirmed", value: stats.confirmed, icon: Skull, color: "destructive" },
          { label: "Defended (FP)", value: stats.fp, icon: ShieldCheck, color: "primary" },
          { label: "Pending Review", value: stats.pending, icon: AlertTriangle, color: "cyber-amber" },
        ].map(s => (
          <Card key={s.label} className="border-border bg-card">
            <CardContent className="p-3 flex items-center gap-2">
              <s.icon className={`h-4 w-4 text-${s.color}`} />
              <div>
                <p className="text-lg font-black font-mono text-foreground">{s.value}</p>
                <p className="text-[8px] font-mono text-muted-foreground">{s.label}</p>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
