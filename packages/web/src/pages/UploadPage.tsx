import { useState, useCallback, DragEvent, ChangeEvent, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { Upload, Shield, AlertCircle } from 'lucide-react';
import { uploadApk } from '../api';

const MAX_SIZE = 100 * 1024 * 1024; // 100 MB

export default function UploadPage() {
  const navigate = useNavigate();
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState<string | null>(null);

  function validate(file: File): string | null {
    if (!file.name.toLowerCase().endsWith('.apk')) return 'Only .apk files are accepted.';
    if (file.size > MAX_SIZE) return 'File exceeds 100 MB limit.';
    return null;
  }

  const handleFile = useCallback(async (file: File) => {
    const err = validate(file);
    if (err) { setError(err); return; }
    setError(null);
    setUploading(true);
    setProgress(0);
    try {
      const { id } = await uploadApk(file, setProgress);
      navigate(`/scans/${id}`);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Upload failed';
      setError(msg);
      setUploading(false);
    }
  }, [navigate]);

  const onDrop = useCallback((e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) handleFile(file);
  }, [handleFile]);

  const onDragOver = (e: DragEvent<HTMLDivElement>) => { e.preventDefault(); setDragging(true); };
  const onDragLeave = () => setDragging(false);

  const onInputChange = (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) handleFile(file);
  };

  return (
    <div className="min-h-screen flex flex-col items-center justify-center px-4 py-12">
      {/* Header */}
      <div className="flex items-center gap-3 mb-10">
        <Shield className="w-9 h-9 text-indigo-400" />
        <h1 className="text-3xl font-bold tracking-tight">APK Malware Scanner</h1>
      </div>

      {/* Upload zone */}
      <div
        onClick={() => !uploading && inputRef.current?.click()}
        onDrop={onDrop}
        onDragOver={onDragOver}
        onDragLeave={onDragLeave}
        className={`w-full max-w-xl border-2 border-dashed rounded-2xl p-12 flex flex-col items-center gap-4 cursor-pointer transition-colors
          ${dragging ? 'border-indigo-400 bg-indigo-950/30' : 'border-gray-700 hover:border-indigo-500 bg-gray-900'}
          ${uploading ? 'cursor-not-allowed opacity-70' : ''}`}
      >
        <input
          ref={inputRef}
          type="file"
          accept=".apk"
          className="hidden"
          onChange={onInputChange}
          disabled={uploading}
        />
        <Upload className={`w-12 h-12 ${dragging ? 'text-indigo-400' : 'text-gray-500'}`} />
        {uploading ? (
          <div className="w-full flex flex-col items-center gap-3">
            <p className="text-sm text-gray-400">Uploading… {progress}%</p>
            <div className="w-full bg-gray-800 rounded-full h-2">
              <div
                className="bg-indigo-500 h-2 rounded-full transition-all duration-200"
                style={{ width: `${progress}%` }}
              />
            </div>
          </div>
        ) : (
          <>
            <p className="text-lg font-medium text-gray-200">
              {dragging ? 'Drop your APK here' : 'Drag & drop your APK here'}
            </p>
            <p className="text-sm text-gray-500">or click to browse — max 100 MB</p>
          </>
        )}
      </div>

      {/* Error */}
      {error && (
        <div className="mt-5 flex items-center gap-2 text-red-400 text-sm">
          <AlertCircle className="w-4 h-4 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* History link */}
      <a
        href="/scans"
        className="mt-8 text-sm text-indigo-400 hover:text-indigo-300 underline underline-offset-2"
      >
        View scan history
      </a>
    </div>
  );
}
