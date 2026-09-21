import { auth, defineMcp } from "@lovable.dev/mcp-js";
import listTargetsTool from "./tools/list-targets";
import listFindingsTool from "./tools/list-findings";
import getFindingTool from "./tools/get-finding";
import createTargetTool from "./tools/create-target";
import runScanTool from "./tools/run-scan";
import explainFindingTool from "./tools/explain-finding";
import listRunningAgentsTool from "./tools/list-running-agents";

const projectRef = import.meta.env.VITE_SUPABASE_PROJECT_ID ?? "project-ref-unset";

export default defineMcp({
  name: "cyberscope-ai",
  title: "CyberScope AI",
  version: "0.2.0",
  instructions:
    "Tools for CyberScope AI, an autonomous VAPT platform. Read: `list_targets`, `list_findings`, `get_finding`, `explain_finding`, `list_running_agents`. Write: `create_target` to add an authorized in-scope target, `run_scan` to kick off a scan session (quick / deep / chain). Every finding carries proof-oracle evidence — always call `explain_finding` before reporting a vulnerability to a human.",
  auth: auth.oauth.issuer({
    issuer: `https://${projectRef}.supabase.co/auth/v1`,
    acceptedAudiences: "authenticated",
  }),
  tools: [
    listTargetsTool,
    listFindingsTool,
    getFindingTool,
    createTargetTool,
    runScanTool,
    explainFindingTool,
    listRunningAgentsTool,
  ],
});
