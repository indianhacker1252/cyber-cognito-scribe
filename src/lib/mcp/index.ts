import { auth, defineMcp } from "@lovable.dev/mcp-js";
import listTargetsTool from "./tools/list-targets";
import listFindingsTool from "./tools/list-findings";
import getFindingTool from "./tools/get-finding";
import createTargetTool from "./tools/create-target";

const projectRef = import.meta.env.VITE_SUPABASE_PROJECT_ID ?? "project-ref-unset";

export default defineMcp({
  name: "cyberscope-ai",
  title: "CyberScope AI",
  version: "0.1.0",
  instructions:
    "Tools for CyberScope AI, an autonomous VAPT platform. Use `list_targets` and `list_findings` to inspect the signed-in user's scan targets and vulnerabilities, `get_finding` for full evidence on one finding, and `create_target` to add an authorized in-scope target.",
  auth: auth.oauth.issuer({
    issuer: `https://${projectRef}.supabase.co/auth/v1`,
    acceptedAudiences: "authenticated",
  }),
  tools: [listTargetsTool, listFindingsTool, getFindingTool, createTargetTool],
});
