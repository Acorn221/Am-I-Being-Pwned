export interface ParsedExtension {
  id: string;
  name: string;
  version: string;
}

export interface ParseResult {
  extensions: ParsedExtension[];
  unparsedLineCount: number;
}

const EXT_ID_RE = /^[a-p]{32}$/;

export function parseExtensionList(text: string): ParseResult {
  const seen = new Set<string>();
  const extensions: ParsedExtension[] = [];
  let unparsedLineCount = 0;

  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line) continue;

    const parts = line.split(" : ");
    const id = parts[0]?.trim();

    if (!id || !EXT_ID_RE.test(id)) {
      unparsedLineCount++;
      continue;
    }

    if (seen.has(id)) continue;
    seen.add(id);

    extensions.push({
      id,
      name: parts[1]?.trim() ?? id,
      version: parts[2]?.trim() ?? "",
    });
  }

  return { extensions, unparsedLineCount };
}
