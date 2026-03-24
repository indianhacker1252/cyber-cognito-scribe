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
    PostgrestVersion: "14.4"
  }
  public: {
    Tables: {
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
      pending_approvals: {
        Row: {
          baseline_response: Json | null
          created_at: string
          cve_ids: string[] | null
          cvss_score: number | null
          description: string | null
          endpoint_id: string | null
          evidence: Json
          finding_type: string
          id: string
          mutated_response: Json | null
          parameter: string | null
          payload_used: string | null
          reviewed_at: string | null
          reviewer_notes: string | null
          severity: Database["public"]["Enums"]["severity_level"]
          status: Database["public"]["Enums"]["approval_status"]
          target_id: string
          title: string
        }
        Insert: {
          baseline_response?: Json | null
          created_at?: string
          cve_ids?: string[] | null
          cvss_score?: number | null
          description?: string | null
          endpoint_id?: string | null
          evidence?: Json
          finding_type: string
          id?: string
          mutated_response?: Json | null
          parameter?: string | null
          payload_used?: string | null
          reviewed_at?: string | null
          reviewer_notes?: string | null
          severity?: Database["public"]["Enums"]["severity_level"]
          status?: Database["public"]["Enums"]["approval_status"]
          target_id: string
          title: string
        }
        Update: {
          baseline_response?: Json | null
          created_at?: string
          cve_ids?: string[] | null
          cvss_score?: number | null
          description?: string | null
          endpoint_id?: string | null
          evidence?: Json
          finding_type?: string
          id?: string
          mutated_response?: Json | null
          parameter?: string | null
          payload_used?: string | null
          reviewed_at?: string | null
          reviewer_notes?: string | null
          severity?: Database["public"]["Enums"]["severity_level"]
          status?: Database["public"]["Enums"]["approval_status"]
          target_id?: string
          title?: string
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
            foreignKeyName: "pending_approvals_target_id_fkey"
            columns: ["target_id"]
            isOneToOne: false
            referencedRelation: "target_workspaces"
            referencedColumns: ["id"]
          },
        ]
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
      target_workspaces: {
        Row: {
          api_schema_url: string | null
          created_at: string
          domain: string | null
          id: string
          ip_range: string | null
          name: string
          status: Database["public"]["Enums"]["target_status"]
          updated_at: string
        }
        Insert: {
          api_schema_url?: string | null
          created_at?: string
          domain?: string | null
          id?: string
          ip_range?: string | null
          name: string
          status?: Database["public"]["Enums"]["target_status"]
          updated_at?: string
        }
        Update: {
          api_schema_url?: string | null
          created_at?: string
          domain?: string | null
          id?: string
          ip_range?: string | null
          name?: string
          status?: Database["public"]["Enums"]["target_status"]
          updated_at?: string
        }
        Relationships: []
      }
      vulnerability_findings: {
        Row: {
          created_at: string
          cvss_score: number | null
          description: string | null
          endpoint_id: string | null
          evidence_package_id: string | null
          id: string
          payload: string | null
          poc: string | null
          remediation: string | null
          severity: Database["public"]["Enums"]["severity_level"]
          target_id: string
          title: string
          validation_status: string | null
        }
        Insert: {
          created_at?: string
          cvss_score?: number | null
          description?: string | null
          endpoint_id?: string | null
          evidence_package_id?: string | null
          id?: string
          payload?: string | null
          poc?: string | null
          remediation?: string | null
          severity?: Database["public"]["Enums"]["severity_level"]
          target_id: string
          title: string
          validation_status?: string | null
        }
        Update: {
          created_at?: string
          cvss_score?: number | null
          description?: string | null
          endpoint_id?: string | null
          evidence_package_id?: string | null
          id?: string
          payload?: string | null
          poc?: string | null
          remediation?: string | null
          severity?: Database["public"]["Enums"]["severity_level"]
          target_id?: string
          title?: string
          validation_status?: string | null
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
            foreignKeyName: "vulnerability_findings_target_id_fkey"
            columns: ["target_id"]
            isOneToOne: false
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
      [_ in never]: never
    }
    Enums: {
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
      approval_status: ["pending", "approved", "rejected", "escalated"],
      log_type: ["thought", "action", "result", "error", "info"],
      severity_level: ["critical", "high", "medium", "low", "info"],
      target_status: ["queued", "scanning", "completed", "error"],
      task_status: ["pending", "running", "completed", "failed"],
    },
  },
} as const
