import { useRef } from "react";
import Icon from "./Icon";
import { mockUpload } from "../data/mockData";

export default function UploadZone({ file, onSelect }) {
  const inputRef = useRef(null);

  function applyMockFile() {
    onSelect(mockUpload);
  }

  function onDrop(event) {
    event.preventDefault();
    applyMockFile();
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
          if (event.key === "Enter" || event.key === " ") applyMockFile();
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
          onChange={applyMockFile}
        />
      </div>
      {file ? (
        <div className="file-selected">
          <div>
            <div style={{ fontWeight: 600 }}>{file.name}</div>
            <div className="muted">{file.size}</div>
          </div>
          <span className="badge pass">✓ {file.status}</span>
        </div>
      ) : null}
    </div>
  );
}
