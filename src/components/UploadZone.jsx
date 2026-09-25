import { useRef } from "react";
import Icon from "./Icon";

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export default function UploadZone({ file, onSelect }) {
  const inputRef = useRef(null);

  function onDrop(event) {
    event.preventDefault();
    const dropped = event.dataTransfer.files?.[0];
    if (dropped) onSelect(dropped);
  }

  return (
    <div>
      <div
        className="upload-zone"
        onDragOver={(event) => event.preventDefault()}
        onDrop={onDrop}
        onClick={() => inputRef.current?.click()}
        role="button"
        tabIndex={0}
        onKeyDown={(event) => {
          if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            inputRef.current?.click();
          }
        }}
      >
        <div className="upload-icon">
          <Icon name="folder_zip" />
        </div>
        <div style={{ fontSize: 18, fontWeight: 600 }}>Drop your project here</div>
        <p className="muted">Upload a ZIP file or supported source files</p>
        <button
          className="btn btn-secondary"
          type="button"
          onClick={(event) => {
            event.stopPropagation();
            inputRef.current?.click();
          }}
        >
          Browse Files
        </button>
        <input
          ref={inputRef}
          type="file"
          hidden
          onChange={(event) => {
            const selected = event.target.files?.[0];
            if (selected) onSelect(selected);
            event.target.value = "";
          }}
        />
      </div>
      {file ? (
        <div className="file-selected">
          <div>
            <div style={{ fontWeight: 600 }}>{file.name}</div>
            <div className="muted">{formatSize(file.size)}</div>
          </div>
          <span className="badge pass">✓ Ready to scan</span>
        </div>
      ) : null}
    </div>
  );
}
