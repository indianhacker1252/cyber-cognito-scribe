/**
 * Version-Context Override / Backported Patch Checker
 * Handles false positives from CVE matches when the OS has backported patches.
 */

export interface VersionCheckResult {
  shouldSuppress: boolean;
  reason: string;
  osContext: string | null;
  backportLikely: boolean;
}

// Known distributions that heavily backport security fixes
const BACKPORT_DISTRIBUTIONS: Record<string, string[]> = {
  rhel: ["Red Hat Enterprise Linux", "RHEL", "CentOS"],
  debian: ["Debian", "Ubuntu"],
  suse: ["SUSE", "openSUSE", "SLES"],
  fedora: ["Fedora"],
  amazon: ["Amazon Linux", "amzn"],
};

// Known software that is commonly backported
const BACKPORT_SOFTWARE: Record<string, string[]> = {
  apache: ["Apache", "httpd"],
  nginx: ["nginx"],
  openssl: ["OpenSSL"],
  php: ["PHP"],
  python: ["Python"],
  openssh: ["OpenSSH"],
};

export function checkVersionSanity(
  cveId: string,
  detectedVersion: string,
  serverHeader: string,
  techStack: Record<string, string | undefined>
): VersionCheckResult {
  const result: VersionCheckResult = {
    shouldSuppress: false,
    reason: "",
    osContext: null,
    backportLikely: false,
  };

  // Detect OS from server headers or tech stack
  const allHeaders = `${serverHeader} ${techStack.server || ""} ${techStack.os || ""} ${techStack.poweredBy || ""}`.toLowerCase();

  for (const [distro, markers] of Object.entries(BACKPORT_DISTRIBUTIONS)) {
    for (const marker of markers) {
      if (allHeaders.includes(marker.toLowerCase())) {
        result.osContext = distro;
        break;
      }
    }
    if (result.osContext) break;
  }

  // Check if the software is commonly backported
  let isBackportCandidate = false;
  for (const [, markers] of Object.entries(BACKPORT_SOFTWARE)) {
    for (const marker of markers) {
      if (detectedVersion.toLowerCase().includes(marker.toLowerCase())) {
        isBackportCandidate = true;
        break;
      }
    }
    if (isBackportCandidate) break;
  }

  // If running on a backporting distro with backportable software
  if (result.osContext && isBackportCandidate) {
    result.backportLikely = true;
    result.shouldSuppress = true;
    result.reason = `${detectedVersion} on ${result.osContext.toUpperCase()} — security fix likely backported. ` +
      `CVE ${cveId} may not apply. Suppressing to prevent false positive. ` +
      `Verify with: rpm -q --changelog <package> | grep ${cveId}`;
  }

  // Check for specific version patterns that indicate Enterprise builds
  const enterprisePatterns = [
    /\.el\d+/i,    // RHEL: e.g., 2.4.6-97.el7
    /\.deb\d+/i,   // Debian
    /ubuntu/i,     // Ubuntu
    /\.amzn\d+/i,  // Amazon Linux
    /\.fc\d+/i,    // Fedora
  ];

  for (const pattern of enterprisePatterns) {
    if (pattern.test(detectedVersion) || pattern.test(serverHeader)) {
      result.backportLikely = true;
      if (!result.shouldSuppress) {
        result.shouldSuppress = true;
        result.osContext = result.osContext || "enterprise-linux";
        result.reason = `Version string "${detectedVersion}" contains enterprise distribution markers — backported patches likely applied.`;
      }
    }
  }

  if (!result.shouldSuppress) {
    result.reason = `No backport indicators found for ${detectedVersion}. CVE ${cveId} should be investigated.`;
  }

  return result;
}
