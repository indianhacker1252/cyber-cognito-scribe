export type Json =
  | string
  | number
  | boolean
  | null
  | { [key: string]: Json | undefined }
  | Json[]

export type Database = {
  // Allows to automatically instantiate createClient with right options
  // instead of createClient<Database, { PostgrestVersion: 'XX' }>(URL, KEY)
  __InternalSupabase: {
    PostgrestVersion: "14.5"
  }
  public: {
    Tables: {
      adaptation_chains: {
        Row: {
          adaptation_steps: Json | null
          ai_reasoning: string | null
          approval_id: string | null
          audit_report_markdown: string | null
          created_at: string
          cvss_score: number | null
          cvss_vector: string | null
          filter_classification: string | null
          final_poc_language: string | null
          final_poc_script: string | null
          finding_id: string | null
          id: string
          initial_request: Json | null
          target_id: string
          updated_at: string
          verification_status: string
        }
        Insert: {
          adaptation_steps?: Json | null
          ai_reasoning?: string | null
          approval_id?: string | null
          audit_report_markdown?: string | null
          created_at?: string
          cvss_score?: number | null
          cvss_vector?: string | null
          filter_classification?: string | null
          final_poc_language?: string | null
          final_poc_script?: string | null
          finding_id?: string | null
          id?: string
          initial_request?: Json | null
          target_id: string
          updated_at?: string
          verification_status?: string
        }
        Update: {
          adaptation_steps?: Json | null
          ai_reasoning?: string | null
          approval_id?: string | null
          audit_report_markdown?: string | null
          created_at?: string
          cvss_score?: number | null
          cvss_vector?: string | null
          filter_classification?: string | null
          final_poc_language?: string | null
          final_poc_script?: string | null
          finding_id?: string | null
          id?: string
          initial_request?: Json | null
          target_id?: string
          updated_at?: string
          verification_status?: string
        }
        Relationships: [
          {
            foreignKeyName: "adaptation_chains_approval_id_fkey"
            columns: ["approval_id"]
            isOneToOne: false
            referencedRelation: "pending_approvals"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "adaptation_chains_finding_id_fkey"
            columns: ["finding_id"]
            isOneToOne: false
            referencedRelation: "vulnerability_findings"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "adaptation_chains_target_id_fkey"
            columns: ["target_id"]
            isOneToOne: false
            referencedRelation: "target_workspaces"
            referencedColumns: ["id"]
          },
        ]
      }
      adaptive_lessons: {
        Row: {
          attempt_count: number
          context_hash: string | null
          created_at: string
          id: string
          notes: string | null
          payload_hash: string
          strategy: string
          succeeded: boolean
          succeeded_count: number
          target_id: string | null
          vuln_class: string
        }
        Insert: {
          attempt_count?: number
          context_hash?: string | null
          created_at?: string
          id?: string
          notes?: string | null
          payload_hash: string
          strategy: string
          succeeded: boolean
          succeeded_count?: number
          target_id?: string | null
          vuln_class: string
        }
        Update: {
          attempt_count?: number
          context_hash?: string | null
          created_at?: string
          id?: string
          notes?: string | null
          payload_hash?: string
          strategy?: string
          succeeded?: boolean
          succeeded_count?: number
          target_id?: string | null
          vuln_class?: string
        }
        Relationships: [
          {
            foreignKeyName: "adaptive_lessons_target_id_fkey"
            columns: ["target_id"]
            isOneToOne: false
            referencedRelation: "target_workspaces"
            referencedColumns: ["id"]
          },
        ]
      }
      advanced_detector_runs: {
        Row: {
          chain_steps: Json
          created_at: string
          detector: string
          duration_ms: number | null
          endpoint_id: string | null
          error: string | null
          evidence: Json
          finding_id: string | null
          id: string
          primitive: string | null
          proven: boolean
          status: string
          target_id: string
        }
        Insert: {
          chain_steps?: Json
          created_at?: string
          detector: string
          duration_ms?: number | null
          endpoint_id?: string | null
          error?: string | null
          evidence?: Json
          finding_id?: string | null
          id?: string
          primitive?: string | null
          proven?: boolean
          status?: string
          target_id: string
        }
        Update: {
          chain_steps?: Json
          created_at?: string
          detector?: string
          duration_ms?: number | null
          endpoint_id?: string | null
          error?: string | null
          evidence?: Json
          finding_id?: string | null
          id?: string
          primitive?: string | null
          proven?: boolean
          status?: string
          target_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "advanced_detector_runs_endpoint_id_fkey"
            columns: ["endpoint_id"]
            isOneToOne: false
            referencedRelation: "discovered_endpoints"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "advanced_detector_runs_finding_id_fkey"
            columns: ["finding_id"]
            isOneToOne: false
            referencedRelation: "vulnerability_findings"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "advanced_detector_runs_target_id_fkey"
            columns: ["target_id"]
            isOneToOne: false
            referencedRelation: "target_workspaces"
            referencedColumns: ["id"]
          },
        ]
      }
      agent_events: {
        Row: {
          id: number
          kind: string
          payload: Json
          session_id: string
          step: number | null
          target_id: string
          ts: string
        }
        Insert: {
          id?: number
          kind: string
          payload?: Json
          session_id: string
          step?: number | null
          target_id: string
          ts?: string
        }
        Update: {
          id?: number
          kind?: string
          payload?: Json
          session_id?: string
          step?: number | null
          target_id?: string
          ts?: string
        }
        Relationships: [
          {
            foreignKeyName: "agent_events_session_id_fkey"
            columns: ["session_id"]
            isOneToOne: false
            referencedRelation: "agent_sessions"
            referencedColumns: ["id"]
          },
        ]
      }
      agent_sessions: {
        Row: {
          budget_credits: number
          budget_seconds: number
          completed_at: string | null
          created_at: string
          credits_used: number
          error_message: string | null
          goal: string | null
          id: string
          last_heartbeat: string | null
          metadata: Json
          model: string
          provider: string
          runtime_host: string | null
          runtime_pid: string | null
          started_at: string | null
          status: string
          steps_taken: number
          target_id: string
          updated_at: string
          user_id: string | null
        }
        Insert: {
          budget_credits?: number
          budget_seconds?: number
          completed_at?: string | null
          created_at?: string
          credits_used?: number
          error_message?: string | null
          goal?: string | null
          id?: string
          last_heartbeat?: string | null
          metadata?: Json
          model?: string
          provider?: string
          runtime_host?: string | null
          runtime_pid?: string | null
          started_at?: string | null
          status?: string
          steps_taken?: number
          target_id: string
          updated_at?: string
          user_id?: string | null
        }
        Update: {
          budget_credits?: number
          budget_seconds?: number
          completed_at?: string | null
          created_at?: string
          credits_used?: number
          error_message?: string | null
          goal?: string | null
          id?: string
          last_heartbeat?: string | null
          metadata?: Json
          model?: string
          provider?: string
          runtime_host?: string | null
          runtime_pid?: string | null
          started_at?: string | null
          status?: string
          steps_taken?: number
          target_id?: string
          updated_at?: string
          user_id?: string | null
        }
        Relationships: [
          {
            foreignKeyName: "agent_sessions_target_id_fkey"
            columns: ["target_id"]
            isOneToOne: false
            referencedRelation: "target_workspaces"
            referencedColumns: ["id"]
          },
        ]
      }
      agent_tasks: {
        Row: {
          created_at: string
          id: string
          result: Json | null
          status: Database["public"]["Enums"]["task_status"]
          target_id: string
          task_type: string
          thought_log: Json | null
          updated_at: string
        }
        Insert: {
          created_at?: string
          id?: string
          result?: Json | null
          status?: Database["public"]["Enums"]["task_status"]
          target_id: string
          task_type: string
          thought_log?: Json | null
          updated_at?: string
        }
        Update: {
          created_at?: string
          id?: string
          result?: Json | null
          status?: Database["public"]["Enums"]["task_status"]
          target_id?: string
          task_type?: string
          thought_log?: Json | null
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "agent_tasks_target_id_fkey"
            columns: ["target_id"]
            isOneToOne: false
            referencedRelation: "target_workspaces"
            referencedColumns: ["id"]
          },
        ]
      }
      ai_confidence_calibration: {
        Row: {
          created_at: string
          evidence_total: number
          evidence_weights: Json
          id: string
          outcome: string | null
          outcome_marked_at: string | null
          provider: string
          score: number
          target_id: string | null
          verdict: string
          vuln_class: string
        }
        Insert: {
          created_at?: string
          evidence_total?: number
          evidence_weights?: Json
          id?: string
          outcome?: string | null
          outcome_marked_at?: string | null
          provider: string
          score: number
          target_id?: string | null
          verdict: string
          vuln_class: string
        }
        Update: {
          created_at?: string
          evidence_total?: number
          evidence_weights?: Json
          id?: string
          outcome?: string | null
          outcome_marked_at?: string | null
          provider?: string
          score?: number
          target_id?: string | null
          verdict?: string
          vuln_class?: string
        }
        Relationships: []
      }
      ai_provider_config: {
        Row: {
          api_key: string
          created_at: string
          id: string
          is_active: boolean
          priority: number
          provider: string
          updated_at: string
        }
        Insert: {
          api_key: string
          created_at?: string
          id?: string
          is_active?: boolean
          priority?: number
          provider: string
          updated_at?: string
        }
        Update: {
          api_key?: string
          created_at?: string
          id?: string
          is_active?: boolean
          priority?: number
          provider?: string
          updated_at?: string
        }
        Relationships: []
      }
      ai_tutoring_sessions: {
        Row: {
          created_at: string
          delta_score: number | null
          finding_id: string | null
          gemini_correction: string | null
          id: string
          local_model_output: string | null
          saved_to_corpus: boolean | null
          target_id: string | null
        }
        Insert: {
          created_at?: string
          delta_score?: number | null
          finding_id?: string | null
          gemini_correction?: string | null
          id?: string
          local_model_output?: string | null
          saved_to_corpus?: boolean | null
          target_id?: string | null
        }
        Update: {
          created_at?: string
          delta_score?: number | null
          finding_id?: string | null
          gemini_correction?: string | null
          id?: string
          local_model_output?: string | null
          saved_to_corpus?: boolean | null
          target_id?: string | null
        }
        Relationships: []
      }
      app_package_findings: {
        Row: {
          ai_reasoning: string | null
          created_at: string
          cvss_score: number | null
          description: string | null
          file_path: string | null
          id: string
          line_start: number | null
          package_id: string
          remediation: string | null
          severity: string
          snippet: string | null
          title: string
          user_id: string
          vuln_class: string
        }
        Insert: {
          ai_reasoning?: string | null
          created_at?: string
          cvss_score?: number | null
          description?: string | null
          file_path?: string | null
          id?: string
          line_start?: number | null
          package_id: string
          remediation?: string | null
          severity?: string
          snippet?: string | null
          title: string
          user_id: string
          vuln_class: string
        }
        Update: {
          ai_reasoning?: string | null
          created_at?: string
          cvss_score?: number | null
          description?: string | null
          file_path?: string | null
          id?: string
          line_start?: number | null
          package_id?: string
          remediation?: string | null
          severity?: string
          snippet?: string | null
          title?: string
          user_id?: string
          vuln_class?: string
        }
        Relationships: [
          {
            foreignKeyName: "app_package_findings_package_id_fkey"
            columns: ["package_id"]
            isOneToOne: false
            referencedRelation: "app_packages"
            referencedColumns: ["id"]
          },
        ]
      }
      app_packages: {
        Row: {
          ai_summary: string | null
          created_at: string
          error_message: string | null
          extracted_strings_count: number | null
          filename: string
          id: string
          manifest: Json | null
          package_type: string
          size_bytes: number | null
          status: string
          storage_path: string
          target_id: string | null
          updated_at: string
          user_id: string
        }
        Insert: {
          ai_summary?: string | null
          created_at?: string
          error_message?: string | null
          extracted_strings_count?: number | null
          filename: string
          id?: string
          manifest?: Json | null
          package_type?: string
          size_bytes?: number | null
          status?: string
          storage_path: string
          target_id?: string | null
          updated_at?: string
          user_id: string
        }
        Update: {
          ai_summary?: string | null
          created_at?: string
          error_message?: string | null
          extracted_strings_count?: number | null
          filename?: string
          id?: string
          manifest?: Json | null
          package_type?: string
          size_bytes?: number | null
          status?: string
          storage_path?: string
          target_id?: string | null
          updated_at?: string
          user_id?: string
        }
        Relationships: []
      }
      attack_graph_edges: {
        Row: {
          confidence: number
          cost: number
          created_at: string
          evidence: Json
          from_node: string
          id: string
          target_id: string
          technique: string
          to_node: string
        }
        Insert: {
          confidence?: number
          cost?: number
          created_at?: string
          evidence?: Json
          from_node: string
          id?: string
          target_id: string
          technique: string
          to_node: string
        }
        Update: {
          confidence?: number
          cost?: number
          created_at?: string
          evidence?: Json
          from_node?: string
          id?: string
          target_id?: string
          technique?: string
          to_node?: string
        }
        Relationships: [
          {
            foreignKeyName: "attack_graph_edges_from_node_fkey"
            columns: ["from_node"]
            isOneToOne: false
            referencedRelation: "attack_graph_nodes"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "attack_graph_edges_target_id_fkey"
            columns: ["target_id"]
            isOneToOne: false
            referencedRelation: "target_workspaces"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "attack_graph_edges_to_node_fkey"
            columns: ["to_node"]
            isOneToOne: false
            referencedRelation: "attack_graph_nodes"
            referencedColumns: ["id"]
          },
        ]
      }
      attack_graph_nodes: {
        Row: {
          capability_tags: string[]
          created_at: string
          id: string
          label: string
          metadata: Json
          node_type: string
          source_finding_id: string | null
          target_id: string
        }
        Insert: {
          capability_tags?: string[]
          created_at?: string
          id?: string
          label: string
          metadata?: Json
          node_type: string
          source_finding_id?: string | null
          target_id: string
        }
        Update: {
          capability_tags?: string[]
          created_at?: string
          id?: string
          label?: string
          metadata?: Json
          node_type?: string
          source_finding_id?: string | null
          target_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "attack_graph_nodes_target_id_fkey"
            columns: ["target_id"]
            isOneToOne: false
            referencedRelation: "target_workspaces"
            referencedColumns: ["id"]
          },
        ]
      }
      attack_hypotheses: {
        Row: {
          asset_host: string | null
          created_at: string
          endpoint_url: string | null
          expected_proof: string | null
          finding_id: string | null
          hypothesis: string
          id: string
          method: string | null
          mutation: Json
          result: Json | null
          round: number
          status: string
          target_id: string
          updated_at: string
          vuln_class: string | null
        }
        Insert: {
          asset_host?: string | null
          created_at?: string
          endpoint_url?: string | null
          expected_proof?: string | null
          finding_id?: string | null
          hypothesis: string
          id?: string
          method?: string | null
          mutation?: Json
          result?: Json | null
          round?: number
          status?: string
          target_id: string
          updated_at?: string
          vuln_class?: string | null
        }
        Update: {
          asset_host?: string | null
          created_at?: string
          endpoint_url?: string | null
          expected_proof?: string | null
          finding_id?: string | null
          hypothesis?: string
          id?: string
          method?: string | null
          mutation?: Json
          result?: Json | null
          round?: number
          status?: string
          target_id?: string
          updated_at?: string
          vuln_class?: string | null
        }
        Relationships: []
      }
      auth_profiles: {
        Row: {
          auth_type: string
          bearer_token: string | null
          cookie_header: string | null
          created_at: string
          id: string
          is_valid: boolean | null
          last_validated_at: string | null
          login_body_template: string | null
          login_method: string | null
          login_password: string | null
          login_url: string | null
          login_username: string | null
          profile_name: string
          session_extract_regex: string | null
          target_id: string
          updated_at: string
        }
        Insert: {
          auth_type?: string
          bearer_token?: string | null
          cookie_header?: string | null
          created_at?: string
          id?: string
          is_valid?: boolean | null
          last_validated_at?: string | null
          login_body_template?: string | null
          login_method?: string | null
          login_password?: string | null
          login_url?: string | null
          login_username?: string | null
          profile_name?: string
          session_extract_regex?: string | null
          target_id: string
          updated_at?: string
        }
        Update: {
          auth_type?: string
          bearer_token?: string | null
          cookie_header?: string | null
          created_at?: string
          id?: string
          is_valid?: boolean | null
          last_validated_at?: string | null
          login_body_template?: string | null
          login_method?: string | null
          login_password?: string | null
          login_url?: string | null
          login_username?: string | null
          profile_name?: string
          session_extract_regex?: string | null
          target_id?: string
          updated_at?: string
        }
        Relationships: []
      }
      bug_bounty_submissions: {
        Row: {
          created_at: string
          error_message: string | null
          finding_id: string | null
          id: string
          platform: string
          program_handle: string | null
          remote_id: string | null
          request_payload: Json | null
          response_payload: Json | null
          severity: string | null
          status: string
          target_id: string | null
          title: string | null
          user_id: string
        }
        Insert: {
          created_at?: string
          error_message?: string | null
          finding_id?: string | null
          id?: string
          platform: string
          program_handle?: string | null
          remote_id?: string | null
          request_payload?: Json | null
          response_payload?: Json | null
          severity?: string | null
          status?: string
          target_id?: string | null
          title?: string | null
          user_id: string
        }
        Update: {
          created_at?: string
          error_message?: string | null
          finding_id?: string | null
          id?: string
          platform?: string
          program_handle?: string | null
          remote_id?: string | null
          request_payload?: Json | null
          response_payload?: Json | null
          severity?: string | null
          status?: string
          target_id?: string | null
          title?: string | null
          user_id?: string
        }
        Relationships: []
      }
      bug_bounty_tokens: {
        Row: {
          bc_api_token: string | null
          bc_program_handle: string | null
          h1_api_token: string | null
          h1_program_handle: string | null
          h1_username: string | null
          updated_at: string
          user_id: string
        }
        Insert: {
          bc_api_token?: string | null
          bc_program_handle?: string | null
          h1_api_token?: string | null
          h1_program_handle?: string | null
          h1_username?: string | null
          updated_at?: string
          user_id: string
        }
        Update: {
          bc_api_token?: string | null
          bc_program_handle?: string | null
          h1_api_token?: string | null
          h1_program_handle?: string | null
          h1_username?: string | null
          updated_at?: string
          user_id?: string
        }
        Relationships: []
      }
      canary_baselines: {
        Row: {
          baseline_blocked: boolean | null
          baseline_body_hash: string | null
          baseline_body_length: number | null
          baseline_status: number | null
          canary_name: string
          created_at: string
          current_blocked: boolean | null
          current_body_hash: string | null
          current_body_length: number | null
          current_status: number | null
          drift_detected: boolean | null
          id: string
          last_checked_at: string | null
          payload: string
          target_id: string
        }
        Insert: {
          baseline_blocked?: boolean | null
          baseline_body_hash?: string | null
          baseline_body_length?: number | null
          baseline_status?: number | null
          canary_name: string
          created_at?: string
          current_blocked?: boolean | null
          current_body_hash?: string | null
          current_body_length?: number | null
          current_status?: number | null
          drift_detected?: boolean | null
          id?: string
          last_checked_at?: string | null
          payload: string
          target_id: string
        }
        Update: {
          baseline_blocked?: boolean | null
          baseline_body_hash?: string | null
          baseline_body_length?: number | null
          baseline_status?: number | null
          canary_name?: string
          created_at?: string
          current_blocked?: boolean | null
          current_body_hash?: string | null
          current_body_length?: number | null
          current_status?: number | null
          drift_detected?: boolean | null
          id?: string
          last_checked_at?: string | null
          payload?: string
          target_id?: string
        }
        Relationships: []
      }
      chain_finder_runs: {
        Row: {
          created_at: string
          id: string
          primitive: string | null
          proposed_next_step: Json
          queued_exploit_run_id: string | null
          reasoning: string | null
          result: Json
          seed_finding_id: string | null
          status: string
          target_id: string
        }
        Insert: {
          created_at?: string
          id?: string
          primitive?: string | null
          proposed_next_step?: Json
          queued_exploit_run_id?: string | null
          reasoning?: string | null
          result?: Json
          seed_finding_id?: string | null
          status?: string
          target_id: string
        }
        Update: {
          created_at?: string
          id?: string
          primitive?: string | null
          proposed_next_step?: Json
          queued_exploit_run_id?: string | null
          reasoning?: string | null
          result?: Json
          seed_finding_id?: string | null
          status?: string
          target_id?: string
        }
        Relationships: []
      }
      chat_messages: {
        Row: {
          content: string
          created_at: string
          id: string
          role: string
          session_id: string
          tool_input: Json | null
          tool_name: string | null
          tool_result: Json | null
        }
        Insert: {
          content?: string
          created_at?: string
          id?: string
          role?: string
          session_id: string
          tool_input?: Json | null
          tool_name?: string | null
          tool_result?: Json | null
        }
        Update: {
          content?: string
          created_at?: string
          id?: string
          role?: string
          session_id?: string
          tool_input?: Json | null
          tool_name?: string | null
          tool_result?: Json | null
        }
        Relationships: [
          {
            foreignKeyName: "chat_messages_session_id_fkey"
            columns: ["session_id"]
            isOneToOne: false
            referencedRelation: "chat_sessions"
            referencedColumns: ["id"]
          },
        ]
      }
      chat_sessions: {
        Row: {
          created_at: string
          id: string
          last_message_at: string
          session_id: string
          target_id: string | null
          title: string | null
        }
        Insert: {
          created_at?: string
          id?: string
          last_message_at?: string
          session_id: string
          target_id?: string | null
          title?: string | null
        }
        Update: {
          created_at?: string
          id?: string
          last_message_at?: string
          session_id?: string
          target_id?: string | null
          title?: string | null
        }
        Relationships: [
          {
            foreignKeyName: "chat_sessions_target_id_fkey"
            columns: ["target_id"]
            isOneToOne: false
            referencedRelation: "target_workspaces"
            referencedColumns: ["id"]
          },
        ]
      }
      code_findings: {
        Row: {
          ai_reasoning: string | null
          created_at: string
          file_path: string
          id: string
          line_end: number | null
          line_start: number | null
          linked_dast_finding_id: string | null
          reachability_confirmed: boolean | null
          repository_id: string
          severity: string
          sink_snippet: string | null
          source_snippet: string | null
          taint_path: Json | null
          target_id: string
          vuln_class: string
        }
        Insert: {
          ai_reasoning?: string | null
          created_at?: string
          file_path: string
          id?: string
          line_end?: number | null
          line_start?: number | null
          linked_dast_finding_id?: string | null
          reachability_confirmed?: boolean | null
          repository_id: string
          severity?: string
          sink_snippet?: string | null
          source_snippet?: string | null
          taint_path?: Json | null
          target_id: string
          vuln_class: string
        }
        Update: {
          ai_reasoning?: string | null
          created_at?: string
          file_path?: string
          id?: string
          line_end?: number | null
          line_start?: number | null
          linked_dast_finding_id?: string | null
          reachability_confirmed?: boolean | null
          repository_id?: string
          severity?: string
          sink_snippet?: string | null
          source_snippet?: string | null
          taint_path?: Json | null
          target_id?: string
          vuln_class?: string
        }
        Relationships: []
      }
      code_repositories: {
        Row: {
          branch: string | null
          created_at: string
          file_count: number | null
          id: string
          ingestion_log: Json | null
          ingestion_status: string
          language: string | null
          repo_url: string | null
          source_tree: Json | null
          target_id: string
          updated_at: string
        }
        Insert: {
          branch?: string | null
          created_at?: string
          file_count?: number | null
          id?: string
          ingestion_log?: Json | null
          ingestion_status?: string
          language?: string | null
          repo_url?: string | null
          source_tree?: Json | null
          target_id: string
          updated_at?: string
        }
        Update: {
          branch?: string | null
          created_at?: string
          file_count?: number | null
          id?: string
          ingestion_log?: Json | null
          ingestion_status?: string
          language?: string | null
          repo_url?: string | null
          source_tree?: Json | null
          target_id?: string
          updated_at?: string
        }
        Relationships: []
      }
      dead_targets: {
        Row: {
          banned_at: string
          created_at: string
          expires_at: string
          host: string
          id: string
          meta: Json
          reason: string
          target_id: string | null
          zero_streak: number
        }
        Insert: {
          banned_at?: string
          created_at?: string
          expires_at?: string
          host: string
          id?: string
          meta?: Json
          reason?: string
          target_id?: string | null
          zero_streak?: number
        }
        Update: {
          banned_at?: string
          created_at?: string
          expires_at?: string
          host?: string
          id?: string
          meta?: Json
          reason?: string
          target_id?: string | null
          zero_streak?: number
        }
        Relationships: []
      }
      discovered_endpoints: {
        Row: {
          created_at: string
          headers: Json | null
          id: string
          method: string
          parameters: Json | null
          status_code: number | null
          target_id: string
          url: string
        }
        Insert: {
          created_at?: string
          headers?: Json | null
          id?: string
          method?: string
          parameters?: Json | null
          status_code?: number | null
          target_id: string
          url: string
        }
        Update: {
          created_at?: string
          headers?: Json | null
          id?: string
          method?: string
          parameters?: Json | null
          status_code?: number | null
          target_id?: string
          url?: string
        }
        Relationships: [
          {
            foreignKeyName: "discovered_endpoints_target_id_fkey"
            columns: ["target_id"]
            isOneToOne: false
            referencedRelation: "target_workspaces"
            referencedColumns: ["id"]
          },
        ]
      }
      discovered_forms: {
        Row: {
          action_url: string
          created_at: string
          enctype: string
          fields: Json
          has_file_upload: boolean
          id: string
          last_attacked_at: string | null
          method: string
          page_url: string
          target_id: string
        }
        Insert: {
          action_url: string
          created_at?: string
          enctype?: string
          fields?: Json
          has_file_upload?: boolean
          id?: string
          last_attacked_at?: string | null
          method?: string
          page_url: string
          target_id: string
        }
        Update: {
          action_url?: string
          created_at?: string
          enctype?: string
          fields?: Json
          has_file_upload?: boolean
          id?: string
          last_attacked_at?: string | null
          method?: string
          page_url?: string
          target_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "discovered_forms_target_id_fkey"
            columns: ["target_id"]
            isOneToOne: false
            referencedRelation: "target_workspaces"
            referencedColumns: ["id"]
          },
        ]
      }
      endpoint_baselines: {
        Row: {
          body_len: number
          checked_at: string
          content_type: string | null
          id: string
          status: number
          tech: Json
          url: string
        }
        Insert: {
          body_len?: number
          checked_at?: string
          content_type?: string | null
          id?: string
          status: number
          tech?: Json
          url: string
        }
        Update: {
          body_len?: number
          checked_at?: string
          content_type?: string | null
          id?: string
          status?: number
          tech?: Json
          url?: string
        }
        Relationships: []
      }
      evidence_packages: {
        Row: {
          approval_id: string | null
          created_at: string
          cvss_score: number | null
          cvss_vector: string | null
          finding_id: string | null
          http_request_data: Json | null
          http_response_data: Json | null
          id: string
          poc_script: string | null
          report_markdown: string | null
          script_language: string | null
          sensitive: boolean
          target_id: string
          terminal_output: string | null
          validated_at: string | null
          validation_status: string
        }
        Insert: {
          approval_id?: string | null
          created_at?: string
          cvss_score?: number | null
          cvss_vector?: string | null
          finding_id?: string | null
          http_request_data?: Json | null
          http_response_data?: Json | null
          id?: string
          poc_script?: string | null
          report_markdown?: string | null
          script_language?: string | null
          sensitive?: boolean
          target_id: string
          terminal_output?: string | null
          validated_at?: string | null
          validation_status?: string
        }
        Update: {
          approval_id?: string | null
          created_at?: string
          cvss_score?: number | null
          cvss_vector?: string | null
          finding_id?: string | null
          http_request_data?: Json | null
          http_response_data?: Json | null
          id?: string
          poc_script?: string | null
          report_markdown?: string | null
          script_language?: string | null
          sensitive?: boolean
          target_id?: string
          terminal_output?: string | null
          validated_at?: string | null
          validation_status?: string
        }
        Relationships: [
          {
            foreignKeyName: "evidence_packages_approval_id_fkey"
            columns: ["approval_id"]
            isOneToOne: false
            referencedRelation: "pending_approvals"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "evidence_packages_finding_id_fkey"
            columns: ["finding_id"]
            isOneToOne: false
            referencedRelation: "vulnerability_findings"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "evidence_packages_target_id_fkey"
            columns: ["target_id"]
            isOneToOne: false
            referencedRelation: "target_workspaces"
            referencedColumns: ["id"]
          },
        ]
      }
      experience_vault: {
        Row: {
          confidence_score: number | null
          created_at: string
          embedding_vector: string | null
          http_method: string | null
          id: string
          metadata: Json | null
          outcome: string
          payload_used: string
          response_length: number | null
          response_snippet: string | null
          response_status: number | null
          reward_score: number | null
          target_id: string | null
          tech_stack: Json | null
          vuln_class: string
        }
        Insert: {
          confidence_score?: number | null
          created_at?: string
          embedding_vector?: string | null
          http_method?: string | null
          id?: string
          metadata?: Json | null
          outcome: string
          payload_used: string
          response_length?: number | null
          response_snippet?: string | null
          response_status?: number | null
          reward_score?: number | null
          target_id?: string | null
          tech_stack?: Json | null
          vuln_class: string
        }
        Update: {
          confidence_score?: number | null
          created_at?: string
          embedding_vector?: string | null
          http_method?: string | null
          id?: string
          metadata?: Json | null
          outcome?: string
          payload_used?: string
          response_length?: number | null
          response_snippet?: string | null
          response_status?: number | null
          reward_score?: number | null
          target_id?: string | null
          tech_stack?: Json | null
          vuln_class?: string
        }
        Relationships: [
          {
            foreignKeyName: "experience_vault_target_id_fkey"
            columns: ["target_id"]
            isOneToOne: false
            referencedRelation: "target_workspaces"
            referencedColumns: ["id"]
          },
        ]
      }
      exploit_chains: {
        Row: {
          chain_name: string
          chain_steps: Json
          completed_at: string | null
          created_at: string
          execution_log: Json | null
          final_evidence: Json | null
          id: string
          severity: string | null
          state_variables: Json | null
          status: string
          target_id: string
        }
        Insert: {
          chain_name: string
          chain_steps?: Json
          completed_at?: string | null
          created_at?: string
          execution_log?: Json | null
          final_evidence?: Json | null
          id?: string
          severity?: string | null
          state_variables?: Json | null
          status?: string
          target_id: string
        }
        Update: {
          chain_name?: string
          chain_steps?: Json
          completed_at?: string | null
          created_at?: string
          execution_log?: Json | null
          final_evidence?: Json | null
          id?: string
          severity?: string | null
          state_variables?: Json | null
          status?: string
          target_id?: string
        }
        Relationships: []
      }
      exploit_runs: {
        Row: {
          created_at: string
          duration_ms: number | null
          evidence: Json | null
          exploit_ref: string | null
          exploit_source: string
          finding_id: string | null
          id: string
          output: string | null
          proof_tier: string | null
          sensitive: boolean
          status: string
          target_id: string | null
          user_id: string | null
        }
        Insert: {
          created_at?: string
          duration_ms?: number | null
          evidence?: Json | null
          exploit_ref?: string | null
          exploit_source?: string
          finding_id?: string | null
          id?: string
          output?: string | null
          proof_tier?: string | null
          sensitive?: boolean
          status?: string
          target_id?: string | null
          user_id?: string | null
        }
        Update: {
          created_at?: string
          duration_ms?: number | null
          evidence?: Json | null
          exploit_ref?: string | null
          exploit_source?: string
          finding_id?: string | null
          id?: string
          output?: string | null
          proof_tier?: string | null
          sensitive?: boolean
          status?: string
          target_id?: string | null
          user_id?: string | null
        }
        Relationships: []
      }
      exploitdb_index: {
        Row: {
          created_at: string
          cve: string | null
          cwe: string | null
          edb_id: string | null
          exploit_code: string | null
          id: string
          platform: string | null
          source_url: string | null
          tags: Json | null
          title: string
          type: string | null
          vuln_class: string | null
        }
        Insert: {
          created_at?: string
          cve?: string | null
          cwe?: string | null
          edb_id?: string | null
          exploit_code?: string | null
          id?: string
          platform?: string | null
          source_url?: string | null
          tags?: Json | null
          title: string
          type?: string | null
          vuln_class?: string | null
        }
        Update: {
          created_at?: string
          cve?: string | null
          cwe?: string | null
          edb_id?: string | null
          exploit_code?: string | null
          id?: string
          platform?: string | null
          source_url?: string | null
          tags?: Json | null
          title?: string
          type?: string | null
          vuln_class?: string | null
        }
        Relationships: []
      }
      external_db_config: {
        Row: {
          enabled: boolean
          last_error: string | null
          last_test_at: string | null
          last_test_ok: boolean | null
          pg_connection_string: string | null
          updated_at: string
          user_id: string
        }
        Insert: {
          enabled?: boolean
          last_error?: string | null
          last_test_at?: string | null
          last_test_ok?: boolean | null
          pg_connection_string?: string | null
          updated_at?: string
          user_id: string
        }
        Update: {
          enabled?: boolean
          last_error?: string | null
          last_test_at?: string | null
          last_test_ok?: boolean | null
          pg_connection_string?: string | null
          updated_at?: string
          user_id?: string
        }
        Relationships: []
      }
      external_infra_config: {
        Row: {
          auth_token: string | null
          created_at: string
          endpoint_url: string | null
          extra_config: Json | null
          health_status: string | null
          id: string
          is_active: boolean
          last_health_check: string | null
          mode: string
          service: string
          updated_at: string
        }
        Insert: {
          auth_token?: string | null
          created_at?: string
          endpoint_url?: string | null
          extra_config?: Json | null
          health_status?: string | null
          id?: string
          is_active?: boolean
          last_health_check?: string | null
          mode?: string
          service: string
          updated_at?: string
        }
        Update: {
          auth_token?: string | null
          created_at?: string
          endpoint_url?: string | null
          extra_config?: Json | null
          health_status?: string | null
          id?: string
          is_active?: boolean
          last_health_check?: string | null
          mode?: string
          service?: string
          updated_at?: string
        }
        Relationships: []
      }
      finding_evidence: {
        Row: {
          affected_url: string | null
          created_at: string
          evidence: Json
          finding_id: string
          id: string
          method: string | null
          param: string | null
          payload: string | null
          request_raw: string | null
          response_raw: string | null
          status_code: number | null
          target_id: string
        }
        Insert: {
          affected_url?: string | null
          created_at?: string
          evidence?: Json
          finding_id: string
          id?: string
          method?: string | null
          param?: string | null
          payload?: string | null
          request_raw?: string | null
          response_raw?: string | null
          status_code?: number | null
          target_id: string
        }
        Update: {
          affected_url?: string | null
          created_at?: string
          evidence?: Json
          finding_id?: string
          id?: string
          method?: string | null
          param?: string | null
          payload?: string | null
          request_raw?: string | null
          response_raw?: string | null
          status_code?: number | null
          target_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "finding_evidence_finding_id_fkey"
            columns: ["finding_id"]
            isOneToOne: false
            referencedRelation: "vulnerability_findings"
            referencedColumns: ["id"]
          },
        ]
      }
      intel_feeds: {
        Row: {
          affected_tech_stack: Json | null
          ai_interpretation: string | null
          bypass_techniques: Json | null
          extracted_payloads: Json | null
          id: string
          ingested_at: string
          matched_targets: Json | null
          processed_at: string | null
          raw_summary: string | null
          report_id: string | null
          rescan_triggered: boolean | null
          severity: string | null
          signal_strength: string | null
          source: string
          source_url: string | null
          status: string | null
          template_language: string | null
          template_script: string | null
          test_template: Json | null
          title: string
          vulnerability_class: string | null
          waf_bypass_logic: string | null
        }
        Insert: {
          affected_tech_stack?: Json | null
          ai_interpretation?: string | null
          bypass_techniques?: Json | null
          extracted_payloads?: Json | null
          id?: string
          ingested_at?: string
          matched_targets?: Json | null
          processed_at?: string | null
          raw_summary?: string | null
          report_id?: string | null
          rescan_triggered?: boolean | null
          severity?: string | null
          signal_strength?: string | null
          source?: string
          source_url?: string | null
          status?: string | null
          template_language?: string | null
          template_script?: string | null
          test_template?: Json | null
          title: string
          vulnerability_class?: string | null
          waf_bypass_logic?: string | null
        }
        Update: {
          affected_tech_stack?: Json | null
          ai_interpretation?: string | null
          bypass_techniques?: Json | null
          extracted_payloads?: Json | null
          id?: string
          ingested_at?: string
          matched_targets?: Json | null
          processed_at?: string | null
          raw_summary?: string | null
          report_id?: string | null
          rescan_triggered?: boolean | null
          severity?: string | null
          signal_strength?: string | null
          source?: string
          source_url?: string | null
          status?: string | null
          template_language?: string | null
          template_script?: string | null
          test_template?: Json | null
          title?: string
          vulnerability_class?: string | null
          waf_bypass_logic?: string | null
        }
        Relationships: []
      }
      intel_notifications: {
        Row: {
          action_url: string | null
          created_at: string
          id: string
          intel_feed_id: string | null
          is_read: boolean | null
          message: string | null
          notification_type: string
          target_id: string | null
          title: string
        }
        Insert: {
          action_url?: string | null
          created_at?: string
          id?: string
          intel_feed_id?: string | null
          is_read?: boolean | null
          message?: string | null
          notification_type?: string
          target_id?: string | null
          title: string
        }
        Update: {
          action_url?: string | null
          created_at?: string
          id?: string
          intel_feed_id?: string | null
          is_read?: boolean | null
          message?: string | null
          notification_type?: string
          target_id?: string | null
          title?: string
        }
        Relationships: [
          {
            foreignKeyName: "intel_notifications_intel_feed_id_fkey"
            columns: ["intel_feed_id"]
            isOneToOne: false
            referencedRelation: "intel_feeds"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "intel_notifications_target_id_fkey"
            columns: ["target_id"]
            isOneToOne: false
            referencedRelation: "target_workspaces"
            referencedColumns: ["id"]
          },
        ]
      }
      intel_sync_runs: {
        Row: {
          completed_at: string | null
          error_message: string | null
          id: string
          reports_fetched: number | null
          reports_processed: number | null
          rescans_triggered: number | null
          started_at: string
          status: string | null
          templates_generated: number | null
        }
        Insert: {
          completed_at?: string | null
          error_message?: string | null
          id?: string
          reports_fetched?: number | null
          reports_processed?: number | null
          rescans_triggered?: number | null
          started_at?: string
          status?: string | null
          templates_generated?: number | null
        }
        Update: {
          completed_at?: string | null
          error_message?: string | null
          id?: string
          reports_fetched?: number | null
          reports_processed?: number | null
          rescans_triggered?: number | null
          started_at?: string
          status?: string | null
          templates_generated?: number | null
        }
        Relationships: []
      }
      kill_chain_graph_edges: {
        Row: {
          child_finding_id: string | null
          created_at: string
          depth: number
          id: string
          parent_finding_id: string | null
          primitive_consumed: string | null
          primitive_produced: string | null
          target_id: string
        }
        Insert: {
          child_finding_id?: string | null
          created_at?: string
          depth?: number
          id?: string
          parent_finding_id?: string | null
          primitive_consumed?: string | null
          primitive_produced?: string | null
          target_id: string
        }
        Update: {
          child_finding_id?: string | null
          created_at?: string
          depth?: number
          id?: string
          parent_finding_id?: string | null
          primitive_consumed?: string | null
          primitive_produced?: string | null
          target_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "kill_chain_graph_edges_child_finding_id_fkey"
            columns: ["child_finding_id"]
            isOneToOne: false
            referencedRelation: "vulnerability_findings"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "kill_chain_graph_edges_parent_finding_id_fkey"
            columns: ["parent_finding_id"]
            isOneToOne: false
            referencedRelation: "vulnerability_findings"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "kill_chain_graph_edges_target_id_fkey"
            columns: ["target_id"]
            isOneToOne: false
            referencedRelation: "target_workspaces"
            referencedColumns: ["id"]
          },
        ]
      }
      kill_chains: {
        Row: {
          created_at: string
          execution_result: Json | null
          goal: string
          id: string
          node_path: string[]
          severity: string
          status: string
          step_plan: Json
          target_id: string
          total_cost: number
          updated_at: string
        }
        Insert: {
          created_at?: string
          execution_result?: Json | null
          goal: string
          id?: string
          node_path: string[]
          severity?: string
          status?: string
          step_plan: Json
          target_id: string
          total_cost: number
          updated_at?: string
        }
        Update: {
          created_at?: string
          execution_result?: Json | null
          goal?: string
          id?: string
          node_path?: string[]
          severity?: string
          status?: string
          step_plan?: Json
          target_id?: string
          total_cost?: number
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "kill_chains_target_id_fkey"
            columns: ["target_id"]
            isOneToOne: false
            referencedRelation: "target_workspaces"
            referencedColumns: ["id"]
          },
        ]
      }
      method_discoveries: {
        Row: {
          created_at: string
          custom_headers: Json | null
          endpoint_url: string
          http_method: string
          id: string
          is_interesting: boolean | null
          notes: string | null
          response_diff_pct: number | null
          response_status: number | null
          target_id: string | null
        }
        Insert: {
          created_at?: string
          custom_headers?: Json | null
          endpoint_url: string
          http_method: string
          id?: string
          is_interesting?: boolean | null
          notes?: string | null
          response_diff_pct?: number | null
          response_status?: number | null
          target_id?: string | null
        }
        Update: {
          created_at?: string
          custom_headers?: Json | null
          endpoint_url?: string
          http_method?: string
          id?: string
          is_interesting?: boolean | null
          notes?: string | null
          response_diff_pct?: number | null
          response_status?: number | null
          target_id?: string | null
        }
        Relationships: [
          {
            foreignKeyName: "method_discoveries_target_id_fkey"
            columns: ["target_id"]
            isOneToOne: false
            referencedRelation: "target_workspaces"
            referencedColumns: ["id"]
          },
        ]
      }
      mythos_chains: {
        Row: {
          chain_name: string
          chain_narrative: string | null
          combined_cvss: number | null
          combined_severity: string | null
          created_at: string
          execution_evidence: Json | null
          execution_status: string | null
          finding_ids: Json | null
          id: string
          run_id: string | null
          steps: Json
          target_id: string
        }
        Insert: {
          chain_name: string
          chain_narrative?: string | null
          combined_cvss?: number | null
          combined_severity?: string | null
          created_at?: string
          execution_evidence?: Json | null
          execution_status?: string | null
          finding_ids?: Json | null
          id?: string
          run_id?: string | null
          steps?: Json
          target_id: string
        }
        Update: {
          chain_name?: string
          chain_narrative?: string | null
          combined_cvss?: number | null
          combined_severity?: string | null
          created_at?: string
          execution_evidence?: Json | null
          execution_status?: string | null
          finding_ids?: Json | null
          id?: string
          run_id?: string | null
          steps?: Json
          target_id?: string
        }
        Relationships: []
      }
      mythos_debates: {
        Row: {
          agent_a_learning: string | null
          agent_b_learning: string | null
          agreed_payload: string | null
          agreed_rationale: string | null
          confidence_score: number | null
          created_at: string
          endpoint_url: string | null
          fp_reasoning: string | null
          fp_verdict: string | null
          id: string
          param_name: string | null
          param_value: string | null
          run_id: string | null
          target_id: string
          test_result: Json | null
          transcript: Json
          vuln_class: string | null
        }
        Insert: {
          agent_a_learning?: string | null
          agent_b_learning?: string | null
          agreed_payload?: string | null
          agreed_rationale?: string | null
          confidence_score?: number | null
          created_at?: string
          endpoint_url?: string | null
          fp_reasoning?: string | null
          fp_verdict?: string | null
          id?: string
          param_name?: string | null
          param_value?: string | null
          run_id?: string | null
          target_id: string
          test_result?: Json | null
          transcript?: Json
          vuln_class?: string | null
        }
        Update: {
          agent_a_learning?: string | null
          agent_b_learning?: string | null
          agreed_payload?: string | null
          agreed_rationale?: string | null
          confidence_score?: number | null
          created_at?: string
          endpoint_url?: string | null
          fp_reasoning?: string | null
          fp_verdict?: string | null
          id?: string
          param_name?: string | null
          param_value?: string | null
          run_id?: string | null
          target_id?: string
          test_result?: Json | null
          transcript?: Json
          vuln_class?: string | null
        }
        Relationships: []
      }
      mythos_patches: {
        Row: {
          applied: boolean | null
          config_change: string | null
          created_at: string
          finding_id: string | null
          framework: string | null
          id: string
          language: string | null
          patch_diff: string | null
          patch_type: string
          rationale: string | null
          risk_score: number | null
          target_id: string
          validation_id: string | null
          validation_status: string | null
          waf_rule: string | null
        }
        Insert: {
          applied?: boolean | null
          config_change?: string | null
          created_at?: string
          finding_id?: string | null
          framework?: string | null
          id?: string
          language?: string | null
          patch_diff?: string | null
          patch_type?: string
          rationale?: string | null
          risk_score?: number | null
          target_id: string
          validation_id?: string | null
          validation_status?: string | null
          waf_rule?: string | null
        }
        Update: {
          applied?: boolean | null
          config_change?: string | null
          created_at?: string
          finding_id?: string | null
          framework?: string | null
          id?: string
          language?: string | null
          patch_diff?: string | null
          patch_type?: string
          rationale?: string | null
          risk_score?: number | null
          target_id?: string
          validation_id?: string | null
          validation_status?: string | null
          waf_rule?: string | null
        }
        Relationships: []
      }
      mythos_runs: {
        Row: {
          ai_mode: string
          chains_count: number | null
          completed_at: string | null
          created_at: string
          current_phase: string | null
          degraded_reason: string | null
          findings_count: number | null
          id: string
          iteration: number
          max_iterations: number
          seen_cve_ids: string[]
          started_at: string | null
          status: string
          target_id: string
          thought_log: Json | null
          trigger_type: string
          updated_at: string
          variants_count: number | null
        }
        Insert: {
          ai_mode?: string
          chains_count?: number | null
          completed_at?: string | null
          created_at?: string
          current_phase?: string | null
          degraded_reason?: string | null
          findings_count?: number | null
          id?: string
          iteration?: number
          max_iterations?: number
          seen_cve_ids?: string[]
          started_at?: string | null
          status?: string
          target_id: string
          thought_log?: Json | null
          trigger_type?: string
          updated_at?: string
          variants_count?: number | null
        }
        Update: {
          ai_mode?: string
          chains_count?: number | null
          completed_at?: string | null
          created_at?: string
          current_phase?: string | null
          degraded_reason?: string | null
          findings_count?: number | null
          id?: string
          iteration?: number
          max_iterations?: number
          seen_cve_ids?: string[]
          started_at?: string | null
          status?: string
          target_id?: string
          thought_log?: Json | null
          trigger_type?: string
          updated_at?: string
          variants_count?: number | null
        }
        Relationships: []
      }
      mythos_variants: {
        Row: {
          created_at: string
          id: string
          is_zero_day_candidate: boolean | null
          parent_cve: string | null
          root_cause_pattern: string | null
          run_id: string | null
          target_id: string
          test_endpoint: string | null
          test_result: Json | null
          test_status: string | null
          variant_payload: string
          variant_rationale: string | null
          vuln_class: string
        }
        Insert: {
          created_at?: string
          id?: string
          is_zero_day_candidate?: boolean | null
          parent_cve?: string | null
          root_cause_pattern?: string | null
          run_id?: string | null
          target_id: string
          test_endpoint?: string | null
          test_result?: Json | null
          test_status?: string | null
          variant_payload: string
          variant_rationale?: string | null
          vuln_class: string
        }
        Update: {
          created_at?: string
          id?: string
          is_zero_day_candidate?: boolean | null
          parent_cve?: string | null
          root_cause_pattern?: string | null
          run_id?: string | null
          target_id?: string
          test_endpoint?: string | null
          test_result?: Json | null
          test_status?: string | null
          variant_payload?: string
          variant_rationale?: string | null
          vuln_class?: string
        }
        Relationships: []
      }
      nvd_intel: {
        Row: {
          affected_products: Json | null
          created_at: string | null
          cve_id: string
          cvss_score: number | null
          description: string | null
          id: string
          published: string | null
          references: Json | null
          severity: string | null
          synced_at: string | null
          title: string | null
        }
        Insert: {
          affected_products?: Json | null
          created_at?: string | null
          cve_id: string
          cvss_score?: number | null
          description?: string | null
          id?: string
          published?: string | null
          references?: Json | null
          severity?: string | null
          synced_at?: string | null
          title?: string | null
        }
        Update: {
          affected_products?: Json | null
          created_at?: string | null
          cve_id?: string
          cvss_score?: number | null
          description?: string | null
          id?: string
          published?: string | null
          references?: Json | null
          severity?: string | null
          synced_at?: string | null
          title?: string | null
        }
        Relationships: []
      }
      oob_callbacks: {
        Row: {
          callback_type: string
          created_at: string
          escalated_at: string | null
          finding_id: string | null
          id: string
          payload_context: string | null
          received_at: string | null
          request_body: string | null
          request_headers: Json | null
          request_method: string | null
          request_path: string | null
          source_ip: string | null
          target_id: string | null
          token: string
          user_agent: string | null
          vuln_class: string | null
        }
        Insert: {
          callback_type?: string
          created_at?: string
          escalated_at?: string | null
          finding_id?: string | null
          id?: string
          payload_context?: string | null
          received_at?: string | null
          request_body?: string | null
          request_headers?: Json | null
          request_method?: string | null
          request_path?: string | null
          source_ip?: string | null
          target_id?: string | null
          token: string
          user_agent?: string | null
          vuln_class?: string | null
        }
        Update: {
          callback_type?: string
          created_at?: string
          escalated_at?: string | null
          finding_id?: string | null
          id?: string
          payload_context?: string | null
          received_at?: string | null
          request_body?: string | null
          request_headers?: Json | null
          request_method?: string | null
          request_path?: string | null
          source_ip?: string | null
          target_id?: string | null
          token?: string
          user_agent?: string | null
          vuln_class?: string | null
        }
        Relationships: []
      }
      owasp_checklist: {
        Row: {
          category: string
          check_module: string | null
          check_name: string
          created_at: string
          evidence_count: number
          id: string
          last_run_at: string | null
          metadata: Json
          status: string
          target_id: string
          updated_at: string
        }
        Insert: {
          category: string
          check_module?: string | null
          check_name: string
          created_at?: string
          evidence_count?: number
          id?: string
          last_run_at?: string | null
          metadata?: Json
          status?: string
          target_id: string
          updated_at?: string
        }
        Update: {
          category?: string
          check_module?: string | null
          check_name?: string
          created_at?: string
          evidence_count?: number
          id?: string
          last_run_at?: string | null
          metadata?: Json
          status?: string
          target_id?: string
          updated_at?: string
        }
        Relationships: []
      }
      owasp_checklist_audit: {
        Row: {
          action: string
          actor_id: string | null
          confirmation: string | null
          created_at: string
          deleted_count: number
          id: string
          metadata: Json
          target_id: string
          target_label: string
        }
        Insert: {
          action: string
          actor_id?: string | null
          confirmation?: string | null
          created_at?: string
          deleted_count?: number
          id?: string
          metadata?: Json
          target_id: string
          target_label: string
        }
        Update: {
          action?: string
          actor_id?: string | null
          confirmation?: string | null
          created_at?: string
          deleted_count?: number
          id?: string
          metadata?: Json
          target_id?: string
          target_label?: string
        }
        Relationships: []
      }
      owasp_coverage: {
        Row: {
          checks_run: number
          created_at: string
          findings_count: number
          id: string
          last_run_at: string
          metadata: Json
          owasp_category: string
          payloads_sent: number
          scan_run_id: string | null
          target_id: string
          waf_blocked: number
        }
        Insert: {
          checks_run?: number
          created_at?: string
          findings_count?: number
          id?: string
          last_run_at?: string
          metadata?: Json
          owasp_category: string
          payloads_sent?: number
          scan_run_id?: string | null
          target_id: string
          waf_blocked?: number
        }
        Update: {
          checks_run?: number
          created_at?: string
          findings_count?: number
          id?: string
          last_run_at?: string
          metadata?: Json
          owasp_category?: string
          payloads_sent?: number
          scan_run_id?: string | null
          target_id?: string
          waf_blocked?: number
        }
        Relationships: []
      }
      patch_validations: {
        Row: {
          created_at: string
          finding_id: string | null
          id: string
          lint_warnings: Json | null
          passed_threshold: boolean | null
          patch_id: string | null
          risk_factors: Json | null
          risk_score: number | null
          syntax_ok: boolean | null
          target_id: string
          threshold_used: number | null
          validator_notes: string | null
        }
        Insert: {
          created_at?: string
          finding_id?: string | null
          id?: string
          lint_warnings?: Json | null
          passed_threshold?: boolean | null
          patch_id?: string | null
          risk_factors?: Json | null
          risk_score?: number | null
          syntax_ok?: boolean | null
          target_id: string
          threshold_used?: number | null
          validator_notes?: string | null
        }
        Update: {
          created_at?: string
          finding_id?: string | null
          id?: string
          lint_warnings?: Json | null
          passed_threshold?: boolean | null
          patch_id?: string | null
          risk_factors?: Json | null
          risk_score?: number | null
          syntax_ok?: boolean | null
          target_id?: string
          threshold_used?: number | null
          validator_notes?: string | null
        }
        Relationships: []
      }
      pending_approvals: {
        Row: {
          ai_verification_notes: string | null
          ai_verified: boolean | null
          baseline_response: Json | null
          confidence_level: string | null
          confidence_score: number | null
          created_at: string
          cve_ids: string[] | null
          cvss_score: number | null
          description: string | null
          endpoint_id: string | null
          evidence: Json
          finding_id: string | null
          finding_type: string
          id: string
          mutated_response: Json | null
          parameter: string | null
          payload_used: string | null
          reachability_status: string | null
          request_data: Json | null
          response_data: Json | null
          reviewed_at: string | null
          reviewer_notes: string | null
          severity: Database["public"]["Enums"]["severity_level"]
          status: Database["public"]["Enums"]["approval_status"]
          target_id: string
          title: string
          triage_reasoning: string | null
        }
        Insert: {
          ai_verification_notes?: string | null
          ai_verified?: boolean | null
          baseline_response?: Json | null
          confidence_level?: string | null
          confidence_score?: number | null
          created_at?: string
          cve_ids?: string[] | null
          cvss_score?: number | null
          description?: string | null
          endpoint_id?: string | null
          evidence?: Json
          finding_id?: string | null
          finding_type: string
          id?: string
          mutated_response?: Json | null
          parameter?: string | null
          payload_used?: string | null
          reachability_status?: string | null
          request_data?: Json | null
          response_data?: Json | null
          reviewed_at?: string | null
          reviewer_notes?: string | null
          severity?: Database["public"]["Enums"]["severity_level"]
          status?: Database["public"]["Enums"]["approval_status"]
          target_id: string
          title: string
          triage_reasoning?: string | null
        }
        Update: {
          ai_verification_notes?: string | null
          ai_verified?: boolean | null
          baseline_response?: Json | null
          confidence_level?: string | null
          confidence_score?: number | null
          created_at?: string
          cve_ids?: string[] | null
          cvss_score?: number | null
          description?: string | null
          endpoint_id?: string | null
          evidence?: Json
          finding_id?: string | null
          finding_type?: string
          id?: string
          mutated_response?: Json | null
          parameter?: string | null
          payload_used?: string | null
          reachability_status?: string | null
          request_data?: Json | null
          response_data?: Json | null
          reviewed_at?: string | null
          reviewer_notes?: string | null
          severity?: Database["public"]["Enums"]["severity_level"]
          status?: Database["public"]["Enums"]["approval_status"]
          target_id?: string
          title?: string
          triage_reasoning?: string | null
        }
        Relationships: [
          {
            foreignKeyName: "pending_approvals_endpoint_id_fkey"
            columns: ["endpoint_id"]
            isOneToOne: false
            referencedRelation: "discovered_endpoints"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "pending_approvals_finding_id_fkey"
            columns: ["finding_id"]
            isOneToOne: false
            referencedRelation: "vulnerability_findings"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "pending_approvals_target_id_fkey"
            columns: ["target_id"]
            isOneToOne: false
            referencedRelation: "target_workspaces"
            referencedColumns: ["id"]
          },
        ]
      }
      planner_traces: {
        Row: {
          actions: Json
          created_at: string
          id: string
          open_findings: number
          provider: string | null
          reasoning: string | null
          target_id: string
          trace_id: string
          turn: number
          world_snapshot: Json
        }
        Insert: {
          actions?: Json
          created_at?: string
          id?: string
          open_findings?: number
          provider?: string | null
          reasoning?: string | null
          target_id: string
          trace_id: string
          turn?: number
          world_snapshot?: Json
        }
        Update: {
          actions?: Json
          created_at?: string
          id?: string
          open_findings?: number
          provider?: string | null
          reasoning?: string | null
          target_id?: string
          trace_id?: string
          turn?: number
          world_snapshot?: Json
        }
        Relationships: [
          {
            foreignKeyName: "planner_traces_target_id_fkey"
            columns: ["target_id"]
            isOneToOne: false
            referencedRelation: "target_workspaces"
            referencedColumns: ["id"]
          },
        ]
      }
      profiles: {
        Row: {
          created_at: string
          display_name: string | null
          email: string | null
          id: string
          updated_at: string
        }
        Insert: {
          created_at?: string
          display_name?: string | null
          email?: string | null
          id: string
          updated_at?: string
        }
        Update: {
          created_at?: string
          display_name?: string | null
          email?: string | null
          id?: string
          updated_at?: string
        }
        Relationships: []
      }
      rag_corpus: {
        Row: {
          content: string
          created_at: string
          id: string
          phase: string | null
          source: string
          tags: Json | null
          topic: string
          vuln_class: string | null
        }
        Insert: {
          content: string
          created_at?: string
          id?: string
          phase?: string | null
          source?: string
          tags?: Json | null
          topic: string
          vuln_class?: string | null
        }
        Update: {
          content?: string
          created_at?: string
          id?: string
          phase?: string | null
          source?: string
          tags?: Json | null
          topic?: string
          vuln_class?: string | null
        }
        Relationships: []
      }
      rag_exploits: {
        Row: {
          confidence: number
          created_at: string
          exploit_pattern: string | null
          id: string
          severity: string | null
          source: string
          source_ref: string | null
          summary: string
          tech_tags: string[]
          title: string
          vuln_class: string
        }
        Insert: {
          confidence?: number
          created_at?: string
          exploit_pattern?: string | null
          id?: string
          severity?: string | null
          source: string
          source_ref?: string | null
          summary: string
          tech_tags?: string[]
          title: string
          vuln_class: string
        }
        Update: {
          confidence?: number
          created_at?: string
          exploit_pattern?: string | null
          id?: string
          severity?: string | null
          source?: string
          source_ref?: string | null
          summary?: string
          tech_tags?: string[]
          title?: string
          vuln_class?: string
        }
        Relationships: []
      }
      request_replays: {
        Row: {
          created_at: string
          diff: Json | null
          finding_id: string | null
          id: string
          is_interesting: boolean
          label: string | null
          request: Json
          response: Json | null
          target_id: string | null
          user_id: string
        }
        Insert: {
          created_at?: string
          diff?: Json | null
          finding_id?: string | null
          id?: string
          is_interesting?: boolean
          label?: string | null
          request?: Json
          response?: Json | null
          target_id?: string | null
          user_id: string
        }
        Update: {
          created_at?: string
          diff?: Json | null
          finding_id?: string | null
          id?: string
          is_interesting?: boolean
          label?: string | null
          request?: Json
          response?: Json | null
          target_id?: string | null
          user_id?: string
        }
        Relationships: []
      }
      sandbox_executions: {
        Row: {
          created_at: string
          duration_ms: number | null
          evidence: Json | null
          executor: string | null
          exit_code: number | null
          finding_id: string | null
          id: string
          language: string | null
          mode: string
          output: string | null
          proven: boolean | null
          script: string | null
          sensitive: boolean
          status: string
          target_id: string | null
          user_id: string | null
        }
        Insert: {
          created_at?: string
          duration_ms?: number | null
          evidence?: Json | null
          executor?: string | null
          exit_code?: number | null
          finding_id?: string | null
          id?: string
          language?: string | null
          mode?: string
          output?: string | null
          proven?: boolean | null
          script?: string | null
          sensitive?: boolean
          status?: string
          target_id?: string | null
          user_id?: string | null
        }
        Update: {
          created_at?: string
          duration_ms?: number | null
          evidence?: Json | null
          executor?: string | null
          exit_code?: number | null
          finding_id?: string | null
          id?: string
          language?: string | null
          mode?: string
          output?: string | null
          proven?: boolean | null
          script?: string | null
          sensitive?: boolean
          status?: string
          target_id?: string | null
          user_id?: string | null
        }
        Relationships: []
      }
      scan_assets: {
        Row: {
          base_url: string
          created_at: string
          host: string
          id: string
          is_dead: boolean
          last_scanned_at: string | null
          phase_state: Json
          scheme: string
          source: string
          target_id: string
        }
        Insert: {
          base_url: string
          created_at?: string
          host: string
          id?: string
          is_dead?: boolean
          last_scanned_at?: string | null
          phase_state?: Json
          scheme?: string
          source?: string
          target_id: string
        }
        Update: {
          base_url?: string
          created_at?: string
          host?: string
          id?: string
          is_dead?: boolean
          last_scanned_at?: string | null
          phase_state?: Json
          scheme?: string
          source?: string
          target_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "scan_assets_target_id_fkey"
            columns: ["target_id"]
            isOneToOne: false
            referencedRelation: "target_workspaces"
            referencedColumns: ["id"]
          },
        ]
      }
      scan_credits: {
        Row: {
          remaining: number
          total_granted: number
          total_used: number
          updated_at: string
          user_id: string
        }
        Insert: {
          remaining?: number
          total_granted?: number
          total_used?: number
          updated_at?: string
          user_id: string
        }
        Update: {
          remaining?: number
          total_granted?: number
          total_used?: number
          updated_at?: string
          user_id?: string
        }
        Relationships: []
      }
      scan_jobs: {
        Row: {
          attempts: number
          completed_at: string | null
          created_at: string
          error_message: string | null
          id: string
          idempotency_key: string | null
          job_type: string
          max_attempts: number
          next_run_at: string
          payload: Json | null
          priority: number
          result: Json | null
          started_at: string | null
          status: string
          target_id: string
        }
        Insert: {
          attempts?: number
          completed_at?: string | null
          created_at?: string
          error_message?: string | null
          id?: string
          idempotency_key?: string | null
          job_type: string
          max_attempts?: number
          next_run_at?: string
          payload?: Json | null
          priority?: number
          result?: Json | null
          started_at?: string | null
          status?: string
          target_id: string
        }
        Update: {
          attempts?: number
          completed_at?: string | null
          created_at?: string
          error_message?: string | null
          id?: string
          idempotency_key?: string | null
          job_type?: string
          max_attempts?: number
          next_run_at?: string
          payload?: Json | null
          priority?: number
          result?: Json | null
          started_at?: string | null
          status?: string
          target_id?: string
        }
        Relationships: []
      }
      scan_logs: {
        Row: {
          created_at: string
          id: string
          log_type: Database["public"]["Enums"]["log_type"]
          message: string
          metadata: Json | null
          target_id: string | null
          task_id: string | null
        }
        Insert: {
          created_at?: string
          id?: string
          log_type?: Database["public"]["Enums"]["log_type"]
          message: string
          metadata?: Json | null
          target_id?: string | null
          task_id?: string | null
        }
        Update: {
          created_at?: string
          id?: string
          log_type?: Database["public"]["Enums"]["log_type"]
          message?: string
          metadata?: Json | null
          target_id?: string | null
          task_id?: string | null
        }
        Relationships: [
          {
            foreignKeyName: "scan_logs_target_id_fkey"
            columns: ["target_id"]
            isOneToOne: false
            referencedRelation: "target_workspaces"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "scan_logs_task_id_fkey"
            columns: ["task_id"]
            isOneToOne: false
            referencedRelation: "agent_tasks"
            referencedColumns: ["id"]
          },
        ]
      }
      scan_phase_state: {
        Row: {
          checks_attempted: number
          checks_passed: number
          completed_at: string | null
          created_at: string
          expected_modules: string[] | null
          findings_count: number
          id: string
          last_heartbeat: string
          metadata: Json
          phase: string
          phase_order: number | null
          started_at: string | null
          status: string
          target_id: string
          updated_at: string
        }
        Insert: {
          checks_attempted?: number
          checks_passed?: number
          completed_at?: string | null
          created_at?: string
          expected_modules?: string[] | null
          findings_count?: number
          id?: string
          last_heartbeat?: string
          metadata?: Json
          phase: string
          phase_order?: number | null
          started_at?: string | null
          status?: string
          target_id: string
          updated_at?: string
        }
        Update: {
          checks_attempted?: number
          checks_passed?: number
          completed_at?: string | null
          created_at?: string
          expected_modules?: string[] | null
          findings_count?: number
          id?: string
          last_heartbeat?: string
          metadata?: Json
          phase?: string
          phase_order?: number | null
          started_at?: string | null
          status?: string
          target_id?: string
          updated_at?: string
        }
        Relationships: []
      }
      scan_usage: {
        Row: {
          consumed: number
          created_at: string
          id: string
          scan_type: string
          target_id: string | null
          user_id: string
        }
        Insert: {
          consumed?: number
          created_at?: string
          id?: string
          scan_type: string
          target_id?: string | null
          user_id: string
        }
        Update: {
          consumed?: number
          created_at?: string
          id?: string
          scan_type?: string
          target_id?: string | null
          user_id?: string
        }
        Relationships: []
      }
      session_jars: {
        Row: {
          cookies: Json
          created_at: string
          csrf_token: string | null
          headers: Json
          hit_count: number
          id: string
          jwt: string | null
          last_url: string | null
          profile_name: string
          target_id: string
          updated_at: string
        }
        Insert: {
          cookies?: Json
          created_at?: string
          csrf_token?: string | null
          headers?: Json
          hit_count?: number
          id?: string
          jwt?: string | null
          last_url?: string | null
          profile_name?: string
          target_id: string
          updated_at?: string
        }
        Update: {
          cookies?: Json
          created_at?: string
          csrf_token?: string | null
          headers?: Json
          hit_count?: number
          id?: string
          jwt?: string | null
          last_url?: string | null
          profile_name?: string
          target_id?: string
          updated_at?: string
        }
        Relationships: []
      }
      strategy_weights: {
        Row: {
          effectiveness_pct: number | null
          failure_count: number | null
          id: string
          last_updated: string | null
          success_count: number | null
          tech_stack_key: string
          tool_name: string
          vuln_class: string
        }
        Insert: {
          effectiveness_pct?: number | null
          failure_count?: number | null
          id?: string
          last_updated?: string | null
          success_count?: number | null
          tech_stack_key: string
          tool_name: string
          vuln_class: string
        }
        Update: {
          effectiveness_pct?: number | null
          failure_count?: number | null
          id?: string
          last_updated?: string | null
          success_count?: number | null
          tech_stack_key?: string
          tool_name?: string
          vuln_class?: string
        }
        Relationships: []
      }
      suppression_vectors: {
        Row: {
          created_at: string
          created_by: string | null
          finding_type: string
          id: string
          request_pattern: Json | null
          response_pattern: Json | null
          suppression_reason: string | null
          target_id: string | null
          vuln_class: string | null
        }
        Insert: {
          created_at?: string
          created_by?: string | null
          finding_type: string
          id?: string
          request_pattern?: Json | null
          response_pattern?: Json | null
          suppression_reason?: string | null
          target_id?: string | null
          vuln_class?: string | null
        }
        Update: {
          created_at?: string
          created_by?: string | null
          finding_type?: string
          id?: string
          request_pattern?: Json | null
          response_pattern?: Json | null
          suppression_reason?: string | null
          target_id?: string | null
          vuln_class?: string | null
        }
        Relationships: [
          {
            foreignKeyName: "suppression_vectors_target_id_fkey"
            columns: ["target_id"]
            isOneToOne: false
            referencedRelation: "target_workspaces"
            referencedColumns: ["id"]
          },
        ]
      }
      target_workspaces: {
        Row: {
          api_schema_url: string | null
          attestation_accepted: boolean
          attestation_accepted_at: string | null
          attestation_accepted_by: string | null
          authorization_mode: string
          authorization_notes: string | null
          auto_mythos: boolean
          bug_bounty_program: string | null
          bug_bounty_scope_url: string | null
          created_at: string
          custom_payloads: Json
          detected_tech: Json
          domain: string | null
          id: string
          ip_range: string | null
          name: string
          resolved_protocol: string | null
          scan_ai_provider: string
          status: Database["public"]["Enums"]["target_status"]
          tech_fingerprint: Json
          tech_stack: string[]
          updated_at: string
          use_agent_runtime: boolean
          waf_profile: Json
        }
        Insert: {
          api_schema_url?: string | null
          attestation_accepted?: boolean
          attestation_accepted_at?: string | null
          attestation_accepted_by?: string | null
          authorization_mode?: string
          authorization_notes?: string | null
          auto_mythos?: boolean
          bug_bounty_program?: string | null
          bug_bounty_scope_url?: string | null
          created_at?: string
          custom_payloads?: Json
          detected_tech?: Json
          domain?: string | null
          id?: string
          ip_range?: string | null
          name: string
          resolved_protocol?: string | null
          scan_ai_provider?: string
          status?: Database["public"]["Enums"]["target_status"]
          tech_fingerprint?: Json
          tech_stack?: string[]
          updated_at?: string
          use_agent_runtime?: boolean
          waf_profile?: Json
        }
        Update: {
          api_schema_url?: string | null
          attestation_accepted?: boolean
          attestation_accepted_at?: string | null
          attestation_accepted_by?: string | null
          authorization_mode?: string
          authorization_notes?: string | null
          auto_mythos?: boolean
          bug_bounty_program?: string | null
          bug_bounty_scope_url?: string | null
          created_at?: string
          custom_payloads?: Json
          detected_tech?: Json
          domain?: string | null
          id?: string
          ip_range?: string | null
          name?: string
          resolved_protocol?: string | null
          scan_ai_provider?: string
          status?: Database["public"]["Enums"]["target_status"]
          tech_fingerprint?: Json
          tech_stack?: string[]
          updated_at?: string
          use_agent_runtime?: boolean
          waf_profile?: Json
        }
        Relationships: []
      }
      target_world_model: {
        Row: {
          created_at: string
          model: Json
          target_id: string
          updated_at: string
        }
        Insert: {
          created_at?: string
          model?: Json
          target_id: string
          updated_at?: string
        }
        Update: {
          created_at?: string
          model?: Json
          target_id?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "target_world_model_target_id_fkey"
            columns: ["target_id"]
            isOneToOne: true
            referencedRelation: "target_workspaces"
            referencedColumns: ["id"]
          },
        ]
      }
      tool_invocations: {
        Row: {
          args: Json
          cost_credits: number
          created_at: string
          id: number
          latency_ms: number | null
          ok: boolean
          result: Json | null
          session_id: string
          step: number | null
          target_id: string
          tool: string
        }
        Insert: {
          args?: Json
          cost_credits?: number
          created_at?: string
          id?: number
          latency_ms?: number | null
          ok?: boolean
          result?: Json | null
          session_id: string
          step?: number | null
          target_id: string
          tool: string
        }
        Update: {
          args?: Json
          cost_credits?: number
          created_at?: string
          id?: number
          latency_ms?: number | null
          ok?: boolean
          result?: Json | null
          session_id?: string
          step?: number | null
          target_id?: string
          tool?: string
        }
        Relationships: [
          {
            foreignKeyName: "tool_invocations_session_id_fkey"
            columns: ["session_id"]
            isOneToOne: false
            referencedRelation: "agent_sessions"
            referencedColumns: ["id"]
          },
        ]
      }
      user_roles: {
        Row: {
          created_at: string
          id: string
          role: Database["public"]["Enums"]["app_role"]
          user_id: string
        }
        Insert: {
          created_at?: string
          id?: string
          role: Database["public"]["Enums"]["app_role"]
          user_id: string
        }
        Update: {
          created_at?: string
          id?: string
          role?: Database["public"]["Enums"]["app_role"]
          user_id?: string
        }
        Relationships: []
      }
      vulnerability_findings: {
        Row: {
          affected_url: string | null
          ai_verified: boolean | null
          confidence_level: string | null
          confidence_score: number | null
          created_at: string
          cvss_score: number | null
          dedup_key: string | null
          description: string | null
          endpoint_id: string | null
          evidence: Json | null
          evidence_count: number
          evidence_package_id: string | null
          finding_type: string | null
          first_seen_at: string
          group_key: string | null
          hard_evidence: Json | null
          id: string
          last_seen_at: string
          parent_finding_id: string | null
          payload: string | null
          poc: string | null
          proof_tier: string
          reachability_status: string | null
          remediation: string | null
          request_raw: string | null
          response_diff: Json | null
          response_raw: string | null
          sensitive: boolean
          severity: Database["public"]["Enums"]["severity_level"]
          source: string | null
          target_id: string
          title: string
          triage_reasoning: string | null
          validation_status: string | null
          vuln_class: string | null
        }
        Insert: {
          affected_url?: string | null
          ai_verified?: boolean | null
          confidence_level?: string | null
          confidence_score?: number | null
          created_at?: string
          cvss_score?: number | null
          dedup_key?: string | null
          description?: string | null
          endpoint_id?: string | null
          evidence?: Json | null
          evidence_count?: number
          evidence_package_id?: string | null
          finding_type?: string | null
          first_seen_at?: string
          group_key?: string | null
          hard_evidence?: Json | null
          id?: string
          last_seen_at?: string
          parent_finding_id?: string | null
          payload?: string | null
          poc?: string | null
          proof_tier?: string
          reachability_status?: string | null
          remediation?: string | null
          request_raw?: string | null
          response_diff?: Json | null
          response_raw?: string | null
          sensitive?: boolean
          severity?: Database["public"]["Enums"]["severity_level"]
          source?: string | null
          target_id: string
          title: string
          triage_reasoning?: string | null
          validation_status?: string | null
          vuln_class?: string | null
        }
        Update: {
          affected_url?: string | null
          ai_verified?: boolean | null
          confidence_level?: string | null
          confidence_score?: number | null
          created_at?: string
          cvss_score?: number | null
          dedup_key?: string | null
          description?: string | null
          endpoint_id?: string | null
          evidence?: Json | null
          evidence_count?: number
          evidence_package_id?: string | null
          finding_type?: string | null
          first_seen_at?: string
          group_key?: string | null
          hard_evidence?: Json | null
          id?: string
          last_seen_at?: string
          parent_finding_id?: string | null
          payload?: string | null
          poc?: string | null
          proof_tier?: string
          reachability_status?: string | null
          remediation?: string | null
          request_raw?: string | null
          response_diff?: Json | null
          response_raw?: string | null
          sensitive?: boolean
          severity?: Database["public"]["Enums"]["severity_level"]
          source?: string | null
          target_id?: string
          title?: string
          triage_reasoning?: string | null
          validation_status?: string | null
          vuln_class?: string | null
        }
        Relationships: [
          {
            foreignKeyName: "vulnerability_findings_endpoint_id_fkey"
            columns: ["endpoint_id"]
            isOneToOne: false
            referencedRelation: "discovered_endpoints"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "vulnerability_findings_evidence_package_id_fkey"
            columns: ["evidence_package_id"]
            isOneToOne: false
            referencedRelation: "evidence_packages"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "vulnerability_findings_parent_finding_id_fkey"
            columns: ["parent_finding_id"]
            isOneToOne: false
            referencedRelation: "vulnerability_findings"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "vulnerability_findings_target_id_fkey"
            columns: ["target_id"]
            isOneToOne: false
            referencedRelation: "target_workspaces"
            referencedColumns: ["id"]
          },
        ]
      }
      waf_profiles: {
        Row: {
          blocked_techniques: Json | null
          created_at: string
          fingerprint: Json | null
          id: string
          last_updated: string
          target_id: string
          waf_type: string | null
          working_techniques: Json | null
        }
        Insert: {
          blocked_techniques?: Json | null
          created_at?: string
          fingerprint?: Json | null
          id?: string
          last_updated?: string
          target_id: string
          waf_type?: string | null
          working_techniques?: Json | null
        }
        Update: {
          blocked_techniques?: Json | null
          created_at?: string
          fingerprint?: Json | null
          id?: string
          last_updated?: string
          target_id?: string
          waf_type?: string | null
          working_techniques?: Json | null
        }
        Relationships: [
          {
            foreignKeyName: "waf_profiles_target_id_fkey"
            columns: ["target_id"]
            isOneToOne: true
            referencedRelation: "target_workspaces"
            referencedColumns: ["id"]
          },
        ]
      }
    }
    Views: {
      [_ in never]: never
    }
    Functions: {
      abort_target_scan: { Args: { _target_id: string }; Returns: Json }
      assert_finding_submittable: {
        Args: { _finding_id: string }
        Returns: boolean
      }
      claim_agent_session: {
        Args: { _host: string }
        Returns: {
          budget_credits: number
          budget_seconds: number
          completed_at: string | null
          created_at: string
          credits_used: number
          error_message: string | null
          goal: string | null
          id: string
          last_heartbeat: string | null
          metadata: Json
          model: string
          provider: string
          runtime_host: string | null
          runtime_pid: string | null
          started_at: string | null
          status: string
          steps_taken: number
          target_id: string
          updated_at: string
          user_id: string | null
        }
        SetofOptions: {
          from: "*"
          to: "agent_sessions"
          isOneToOne: true
          isSetofReturn: false
        }
      }
      consume_scan_credit: {
        Args: { _scan_type: string; _target_id: string }
        Returns: Json
      }
      delete_owasp_checklist: {
        Args: { _confirmation?: string; _target_id: string }
        Returns: number
      }
      enqueue_missing_owasp_modules: {
        Args: { _force?: boolean; _target_id: string }
        Returns: Json
      }
      fail_stuck_mythos_runs: { Args: never; Returns: number }
      grant_scan_credits: {
        Args: { _amount: number; _user_id: string }
        Returns: Json
      }
      has_role: {
        Args: {
          _role: Database["public"]["Enums"]["app_role"]
          _user_id: string
        }
        Returns: boolean
      }
      merge_world_model: {
        Args: { _patch: Json; _target_id: string }
        Returns: Json
      }
      purge_history: {
        Args: { _scope?: string; _target_id?: string }
        Returns: Json
      }
      run_weekly_retention_cleanup: { Args: never; Returns: Json }
      seed_owasp_checklist: { Args: { _target_id: string }; Returns: number }
      target_is_exploit_authorized: {
        Args: { _target_id: string }
        Returns: boolean
      }
    }
    Enums: {
      app_role: "admin" | "user"
      approval_status: "pending" | "approved" | "rejected" | "escalated"
      log_type: "thought" | "action" | "result" | "error" | "info"
      severity_level: "critical" | "high" | "medium" | "low" | "info"
      target_status: "queued" | "scanning" | "completed" | "error"
      task_status: "pending" | "running" | "completed" | "failed"
    }
    CompositeTypes: {
      [_ in never]: never
    }
  }
}

type DatabaseWithoutInternals = Omit<Database, "__InternalSupabase">

type DefaultSchema = DatabaseWithoutInternals[Extract<keyof Database, "public">]

export type Tables<
  DefaultSchemaTableNameOrOptions extends
    | keyof (DefaultSchema["Tables"] & DefaultSchema["Views"])
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
        DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
      DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])[TableName] extends {
      Row: infer R
    }
    ? R
    : never
  : DefaultSchemaTableNameOrOptions extends keyof (DefaultSchema["Tables"] &
        DefaultSchema["Views"])
    ? (DefaultSchema["Tables"] &
        DefaultSchema["Views"])[DefaultSchemaTableNameOrOptions] extends {
        Row: infer R
      }
      ? R
      : never
    : never

export type TablesInsert<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Insert: infer I
    }
    ? I
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Insert: infer I
      }
      ? I
      : never
    : never

export type TablesUpdate<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Update: infer U
    }
    ? U
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Update: infer U
      }
      ? U
      : never
    : never

export type Enums<
  DefaultSchemaEnumNameOrOptions extends
    | keyof DefaultSchema["Enums"]
    | { schema: keyof DatabaseWithoutInternals },
  EnumName extends DefaultSchemaEnumNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"]
    : never = never,
> = DefaultSchemaEnumNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"][EnumName]
  : DefaultSchemaEnumNameOrOptions extends keyof DefaultSchema["Enums"]
    ? DefaultSchema["Enums"][DefaultSchemaEnumNameOrOptions]
    : never

export type CompositeTypes<
  PublicCompositeTypeNameOrOptions extends
    | keyof DefaultSchema["CompositeTypes"]
    | { schema: keyof DatabaseWithoutInternals },
  CompositeTypeName extends PublicCompositeTypeNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"]
    : never = never,
> = PublicCompositeTypeNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"][CompositeTypeName]
  : PublicCompositeTypeNameOrOptions extends keyof DefaultSchema["CompositeTypes"]
    ? DefaultSchema["CompositeTypes"][PublicCompositeTypeNameOrOptions]
    : never

export const Constants = {
  public: {
    Enums: {
      app_role: ["admin", "user"],
      approval_status: ["pending", "approved", "rejected", "escalated"],
      log_type: ["thought", "action", "result", "error", "info"],
      severity_level: ["critical", "high", "medium", "low", "info"],
      target_status: ["queued", "scanning", "completed", "error"],
      task_status: ["pending", "running", "completed", "failed"],
    },
  },
} as const
