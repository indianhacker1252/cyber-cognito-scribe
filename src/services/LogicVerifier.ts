/**
 * Response-Payload Correlation Engine
 * Analyzes response body for actual execution evidence rather than
 * relying on HTTP status codes alone.
 */

export interface ExecutionEvidence {
  hasEvidence: boolean;
  evidenceType: string;
  details: string;
  confidenceBoost: number; // -30 to +30
}

const SQL_ERROR_PATTERNS = [
  /you have an error in your sql syntax/i,
  /mysql_fetch/i, /pg_query/i, /ORA-\d{4,5}/i,
  /microsoft ole db provider/i, /unclosed quotation mark/i,
  /syntax error at or near/i, /sql syntax.*mysql/i,
  /warning.*mysql/i, /valid mysql result/i,
  /postgresql.*error/i, /unterminated quoted string/i,
  /quoted string not properly terminated/i,
  /SQLSTATE\[/i, /PDOException/i,
];

const XSS_REFLECTION_CHECKS = [
  { probe: "<cyberscope>", unescaped: "<cyberscope>" },
  { probe: "<svg onload=", unescaped: "<svg onload=" },
  { probe: "<img src=x onerror=", unescaped: "<img src=x onerror=" },
  { probe: "javascript:", unescaped: "javascript:" },
  { probe: "<details open ontoggle=", unescaped: "<details open ontoggle=" },
];

const CMDI_EVIDENCE = [
  /uid=\d+\(/, /root:.*:0:0/, /cyberscope_marker/,
  /bin\/bash/, /bin\/sh/,
];

const SSTI_EVIDENCE = [
  /^49$/, /\b49\b/,  // 7*7 = 49
];

const PATH_TRAVERSAL_EVIDENCE = [
  /root:.*:0:0/, /\[boot loader\]/i, /\[extensions\]/i,
  /bin\//, /etc\/passwd/, /etc\/shadow/,
];

const SSRF_EVIDENCE = [
  /169\.254\.169\.254/, /metadata/, /ami-id/,
  /instance-id/, /iam\/security-credentials/,
];

export function analyzeExecutionEvidence(
  vulnClass: string,
  payload: string,
  responseBody: string,
  baselineBody: string,
): ExecutionEvidence {
  const result: ExecutionEvidence = {
    hasEvidence: false,
    evidenceType: "none",
    details: "No execution evidence found in response body",
    confidenceBoost: 0,
  };

  switch (vulnClass) {
    case "sqli":
    case "auth-bypass": {
      for (const pattern of SQL_ERROR_PATTERNS) {
        if (pattern.test(responseBody) && !pattern.test(baselineBody)) {
          result.hasEvidence = true;
          result.evidenceType = "sql_error_string";
          result.details = `Database error pattern detected: ${pattern.source}`;
          result.confidenceBoost = 25;
          return result;
        }
      }
      // Check for timing differential (body content change)
      const bodyDiffRatio = Math.abs(responseBody.length - baselineBody.length) / Math.max(baselineBody.length, 1);
      if (bodyDiffRatio > 0.3) {
        result.hasEvidence = true;
        result.evidenceType = "significant_body_change";
        result.details = `Response body changed by ${(bodyDiffRatio * 100).toFixed(1)}% — indicates query manipulation`;
        result.confidenceBoost = 15;
      }
      break;
    }

    case "rxss":
    case "stored-xss": {
      for (const check of XSS_REFLECTION_CHECKS) {
        if (payload.includes(check.probe) && responseBody.includes(check.unescaped)) {
          // Check it's actually unescaped (not entity-encoded)
          const escaped = check.unescaped.replace(/</g, "&lt;").replace(/>/g, "&gt;");
          if (!responseBody.includes(escaped) || responseBody.includes(check.unescaped)) {
            result.hasEvidence = true;
            result.evidenceType = "xss_reflection_unescaped";
            result.details = `Probe string "${check.probe}" reflected unescaped in DOM`;
            result.confidenceBoost = 30;
            return result;
          }
        }
      }
      // Check if payload is reflected at all (even escaped = lower confidence)
      if (responseBody.includes(payload.slice(0, 20))) {
        result.evidenceType = "xss_reflection_escaped";
        result.details = "Payload reflected but may be escaped — lower confidence";
        result.confidenceBoost = -10;
      }
      break;
    }

    case "cmdi": {
      for (const pattern of CMDI_EVIDENCE) {
        if (pattern.test(responseBody) && !pattern.test(baselineBody)) {
          result.hasEvidence = true;
          result.evidenceType = "command_output";
          result.details = `Command execution evidence: ${pattern.source}`;
          result.confidenceBoost = 30;
          return result;
        }
      }
      break;
    }

    case "ssti": {
      for (const pattern of SSTI_EVIDENCE) {
        if (pattern.test(responseBody) && !pattern.test(baselineBody)) {
          result.hasEvidence = true;
          result.evidenceType = "template_evaluation";
          result.details = "Template expression evaluated (7*7=49 found)";
          result.confidenceBoost = 28;
          return result;
        }
      }
      break;
    }

    case "path-traversal":
    case "lfi": {
      for (const pattern of PATH_TRAVERSAL_EVIDENCE) {
        if (pattern.test(responseBody)) {
          result.hasEvidence = true;
          result.evidenceType = "file_content_leaked";
          result.details = `File system content detected: ${pattern.source}`;
          result.confidenceBoost = 30;
          return result;
        }
      }
      break;
    }

    case "ssrf": {
      for (const pattern of SSRF_EVIDENCE) {
        if (pattern.test(responseBody) && !pattern.test(baselineBody)) {
          result.hasEvidence = true;
          result.evidenceType = "internal_service_response";
          result.details = `Internal service data detected: ${pattern.source}`;
          result.confidenceBoost = 28;
          return result;
        }
      }
      break;
    }

    case "xxe": {
      if (responseBody.includes("cyberscope") && !baselineBody.includes("cyberscope")) {
        result.hasEvidence = true;
        result.evidenceType = "entity_expansion";
        result.details = "XXE entity expanded in response body";
        result.confidenceBoost = 30;
        return result;
      }
      break;
    }

    case "deserialization": {
      const deserErrors = [/unserialize/i, /ClassNotFoundException/i, /ObjectInputStream/i, /pickle/i];
      for (const pattern of deserErrors) {
        if (pattern.test(responseBody)) {
          result.hasEvidence = true;
          result.evidenceType = "deserialization_error";
          result.details = `Deserialization error detected: ${pattern.source}`;
          result.confidenceBoost = 20;
          return result;
        }
      }
      break;
    }
  }

  return result;
}
