import JSZip from "jszip";

const EXCLUDED_DIR_PATTERNS = [
  /(^|\/)node_modules\//i,
  /(^|\/)\.git\//i,
  /(^|\/)venv\//i,
  /(^|\/)\.venv\//i,
  /(^|\/)env\//i,
  /(^|\/)__pycache__\//i,
  /(^|\/)\.next\//i,
  /(^|\/)\.nuxt\//i,
  /(^|\/)dist\//i,
  /(^|\/)build\//i,
  /(^|\/)out\//i,
  /(^|\/)\.cache\//i,
  /(^|\/)\.turbo\//i,
  /(^|\/)vendor\//i,
  /(^|\/)target\//i,
  /(^|\/)\.idea\//i,
  /(^|\/)\.vscode\//i,
  /(^|\/)\.pytest_cache\//i,
  /(^|\/)\.mypy_cache\//i,
  /(^|\/)coverage\//i,
  /(^|\/)\.gradle\//i,
  /(^|\/)bin\//i,
  /(^|\/)obj\//i,
];

const EXCLUDED_EXTENSIONS = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp", ".tiff",
  ".mp4", ".mp3", ".wav", ".avi", ".mov", ".mkv", ".webm",
  ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
  ".zip", ".tar", ".gz", ".rar", ".7z", ".bz2", ".xz",
  ".exe", ".dll", ".so", ".dylib", ".bin", ".iso", ".dmg", ".apk", ".ipa",
  ".woff", ".woff2", ".ttf", ".eot", ".otf",
  ".pyc", ".pyo", ".pyd", ".class", ".jar", ".war",
  ".db", ".sqlite", ".sqlite3"
]);

export interface ZipOptimizationResult {
  file: File;
  originalSizeMB: number;
  optimizedSizeMB: number;
  savingsPercent: number;
  retainedFilesCount: number;
  excludedFilesCount: number;
  isOptimized: boolean;
}

/**
 * Strips node_modules, .git, venv, and binary artifacts in-browser from a ZIP archive
 * to drastically reduce file payload from tens of MBs to a few hundred KBs.
 */
export async function optimizeZipFile(originalFile: File): Promise<ZipOptimizationResult> {
  const originalSizeMB = Number((originalFile.size / (1024 * 1024)).toFixed(2));

  // If not a zip file, return as-is
  if (!originalFile.name.toLowerCase().endsWith(".zip") && !originalFile.type.includes("zip")) {
    return {
      file: originalFile,
      originalSizeMB,
      optimizedSizeMB: originalSizeMB,
      savingsPercent: 0,
      retainedFilesCount: 1,
      excludedFilesCount: 0,
      isOptimized: false,
    };
  }

  try {
    const zip = await JSZip.loadAsync(originalFile);
    const newZip = new JSZip();

    let retainedCount = 0;
    let excludedCount = 0;

    const entries = Object.keys(zip.files);

    for (const relativePath of entries) {
      const entry = zip.files[relativePath];

      // Skip directory entries directly
      if (entry.dir) continue;

      // 1. Check directory path against bloat patterns
      const isExcludedDir = EXCLUDED_DIR_PATTERNS.some((pattern) => pattern.test(relativePath));
      if (isExcludedDir) {
        excludedCount++;
        continue;
      }

      // 2. Check file extension against binary/media lists
      const extMatch = relativePath.match(/(\.[a-zA-Z0-9]+)$/);
      const ext = extMatch ? extMatch[1].toLowerCase() : "";
      if (EXCLUDED_EXTENSIONS.has(ext)) {
        excludedCount++;
        continue;
      }

      // 3. Keep source file content
      const content = await entry.async("uint8array");
      
      // Skip excessively large individual non-source files (> 2.5 MB)
      if (content.byteLength > 2.5 * 1024 * 1024 && !relativePath.match(/\.(py|js|ts|tsx|jsx|java|c|cpp|go|rs|php|html|css|json|sql)$/i)) {
        excludedCount++;
        continue;
      }

      newZip.file(relativePath, content);
      retainedCount++;
    }

    // If no files were excluded, return original
    if (excludedCount === 0 || retainedCount === 0) {
      return {
        file: originalFile,
        originalSizeMB,
        optimizedSizeMB: originalSizeMB,
        savingsPercent: 0,
        retainedFilesCount: retainedCount || entries.length,
        excludedFilesCount: 0,
        isOptimized: false,
      };
    }

    // Generate lightweight new ZIP
    const compressedBlob = await newZip.generateAsync({
      type: "blob",
      compression: "DEFLATE",
      compressionOptions: { level: 9 },
    });

    const optimizedSizeMB = Number((compressedBlob.size / (1024 * 1024)).toFixed(2));
    const savingsPercent = Math.max(0, Math.round(((originalFile.size - compressedBlob.size) / originalFile.size) * 100));

    const optimizedFile = new File([compressedBlob], originalFile.name, {
      type: "application/zip",
      lastModified: Date.now(),
    });

    return {
      file: optimizedFile,
      originalSizeMB,
      optimizedSizeMB,
      savingsPercent,
      retainedFilesCount: retainedCount,
      excludedFilesCount: excludedCount,
      isOptimized: true,
    };
  } catch (err) {
    console.warn("[ZipOptimizer]: Fallback to original file due to:", err);
    return {
      file: originalFile,
      originalSizeMB,
      optimizedSizeMB: originalSizeMB,
      savingsPercent: 0,
      retainedFilesCount: 1,
      excludedFilesCount: 0,
      isOptimized: false,
    };
  }
}
