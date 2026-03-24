

# CyberScope Scanner — Implementation Plan

## Overview
A dark-mode, Red Team-styled VAPT command center built with React/Tailwind frontend and Supabase backend (database + edge functions + Lovable AI as the reasoning engine).

## Design
- **Theme**: Dark mode with cyber/hacker aesthetic — deep blacks, neon green/cyan accents, monospace fonts for logs, terminal-style UI elements
- **Layout**: Sidebar navigation with collapsible icon mode + main content area

## Pages & Features

### 1. Command Center Dashboard (`/`)
- Stats row: Active Targets, Endpoints Mapped, Pending Approvals, Critical Vulns — each as a glowing stat card
- Recent scan activity feed
- Vulnerability severity breakdown chart (Critical/High/Medium/Low)
- Active agent status indicators

### 2. Target Management (`/targets`)
- Add new targets: domain, IP range, or API schema URL
- Target list with status badges (queued, scanning, completed)
- Target detail view showing discovered endpoints and findings
- Bulk import capability

### 3. Live Neural Log (`/logs`)
- Terminal-style real-time log viewer with color-coded entries (AI thoughts in cyan, actions in green, errors in red)
- Filter by scan/agent/severity
- Auto-scroll with pause capability
- Powered by Supabase Realtime subscriptions

### 4. Scan Engine (Edge Functions + Lovable AI)
- Edge function `scan-orchestrator`: receives a target, uses Lovable AI with ReAct prompting to reason about scanning strategy
- AI outputs structured "thoughts" and "actions" stored in the database
- Scan results written to `vulnerability_findings` table
- Real-time updates via Supabase Realtime

### 5. Findings & Reports (`/findings`)
- Vulnerability findings table with CVSS scores, severity badges
- Detail view with PoC, payload, and remediation suggestions
- Export capability

## Database Schema (Supabase)
- **target_workspaces**: id, name, domain, ip_range, api_schema_url, status, created_at
- **discovered_endpoints**: id, target_id, url, method, headers, parameters, status_code, created_at
- **vulnerability_findings**: id, endpoint_id, title, severity, cvss_score, description, poc, payload, remediation, created_at
- **agent_tasks**: id, target_id, task_type, status, thought_log (jsonb), result, created_at
- **scan_logs**: id, task_id, log_type, message, metadata (jsonb), created_at (for real-time log streaming)

## Architecture Flow
1. User adds target → saved to `target_workspaces`
2. Frontend invokes `scan-orchestrator` edge function
3. Edge function uses Lovable AI (ReAct loop) to reason about scanning approach
4. AI thoughts and actions streamed to `scan_logs` table
5. Frontend subscribes to `scan_logs` via Supabase Realtime → Live Neural Log
6. Discovered endpoints and vulnerabilities saved to respective tables
7. Dashboard aggregates stats from all tables

