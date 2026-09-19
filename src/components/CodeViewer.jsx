function tokenize(line, language) {
  const pieces = [];
  const pattern =
    language === "python"
      ? /(#.*$)|("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')|\b(\d+)\b|\b(def|return|import|from|if|not|in|and|or|class|raise|async|await)\b|\b([A-Za-z_][\w]*)\s*(?=\()|([A-Za-z_][\w]*)/g
      : /(\/\/.*$)|("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`)|\b(\d+)\b|\b(export|function|return|const|let|var|if|async|await|from|import|class)\b|\b([A-Za-z_][\w]*)\s*(?=\()|([A-Za-z_][\w]*)/g;

  let last = 0;
  let match;
  while ((match = pattern.exec(line))) {
    if (match.index > last) {
      pieces.push({ text: line.slice(last, match.index) });
    }
    if (match[1]) pieces.push({ text: match[1], cls: "tok-cm" });
    else if (match[2]) pieces.push({ text: match[2], cls: "tok-str" });
    else if (match[3]) pieces.push({ text: match[3], cls: "tok-num" });
    else if (match[4]) pieces.push({ text: match[4], cls: "tok-kw" });
    else if (match[5]) pieces.push({ text: match[5], cls: "tok-fn" });
    else pieces.push({ text: match[6] || match[0] });
    last = match.index + match[0].length;
  }
  if (last < line.length) pieces.push({ text: line.slice(last) });
  return pieces;
}

export default function CodeViewer({
  filename,
  code,
  startLine = 1,
  highlightLines = [],
  language = "python",
  mode = "vulnerable",
}) {
  const lines = String(code || "").replace(/\n$/, "").split("\n");

  return (
    <div className="code-preview">
      <div className="code-toolbar">
        <span className="mono">{filename}</span>
        <span className="dim">{language}</span>
      </div>
      <div>
        {lines.map((line, index) => {
          const number = startLine + index;
          const highlighted = highlightLines.includes(number);
          const lineClass = highlighted ? (mode === "fixed" ? "fixed" : "vulnerable") : "";
          return (
            <div className={`code-line ${lineClass}`} key={`${number}-${line}`}>
              <span className="ln">{number}</span>
              <span className="src">
                {tokenize(line, language).map((piece, pieceIndex) =>
                  piece.cls ? (
                    <span className={piece.cls} key={pieceIndex}>
                      {piece.text}
                    </span>
                  ) : (
                    <span key={pieceIndex}>{piece.text}</span>
                  )
                )}
                {line.length === 0 ? " " : null}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
