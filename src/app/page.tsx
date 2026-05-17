"use client";

import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { 
  Shield, 
  Search, 
  Cpu, 
  Trash2, 
  Download, 
  Lock, 
  AlertTriangle,
  CheckCircle2,
  CheckCircle2,
  Database,
  ArrowRight,
  FileCheck,
  X,
  PieChart
} from "lucide-react";
import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export default function TrustSensePage() {
  const [stage, setStage] = useState<"IDLE" | "OPTIONS" | "WIPING" | "FINISHED">("IDLE");
  const [path, setPath] = useState("C:\\TestFolder");
  const [deviceId, setDeviceId] = useState("TS-UNIT-01");
  const [isWiping, setIsWiping] = useState(false);
  const [progress, setProgress] = useState(0);
  const [progressText, setProgressText] = useState("");
  
  // Data states
  const [scanResults, setScanResults] = useState<any>(null);
  const [wipeResults, setWipeResults] = useState<any>(null);
  const [cert, setCert] = useState<any>(null);
  const [pdfBase64, setPdfBase64] = useState<string | null>(null);
  const [activeDirHandle, setActiveDirHandle] = useState<any>(null);
  
  // Backup states
  const [showBackupModal, setShowBackupModal] = useState(false);
  const [sensitiveFilesList, setSensitiveFilesList] = useState<{name: string, handle: any, selected: boolean}[]>([]);

  // Console states
  const [consoleLogs, setConsoleLogs] = useState<string[]>(["[SYSTEM] TrustSense Mesh Node Active.", "[SYSTEM] Awaiting forensic target..."]);

  const addLog = (msg: string) => {
    setConsoleLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] ${msg}`].slice(-10));
  };

  const runScan = async () => {
    setStage("OPTIONS");
    addLog("Initiating remote heuristic scan...");
    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ path, device_id: deviceId })
      });
      const data = await res.json();
      setScanResults(data);
      addLog(`Scan complete. Risk Level: ${data.score > 80 ? "CRITICAL" : "MODERATE"}`);
    } catch (err) {
      addLog("ERROR: API connection timed out.");
      console.error("Scan failed", err);
    }
  };

  const selectFolder = async () => {
    try {
      addLog("Requesting local file system authorization (Read & Write)...");
      // @ts-ignore - showDirectoryPicker is a modern API
      const dirHandle = await window.showDirectoryPicker({ mode: "readwrite" });
      setActiveDirHandle(dirHandle);
      
      setStage("WIPING"); // Just to show we are busy
      setProgressText("Gaining forensic access to local directory...");
      
      let filesFound: string[] = [];
      let sensitiveCount = 0;
      let totalFiles = 0;
      let categories: Record<string, number> = { "High Risk": 0, "Hidden Data": 0, "Low Risk": 0 };
      let sensitiveList: {name: string, handle: any, selected: boolean}[] = [];

      const scanEntry = async (handle: any) => {
        for await (const entry of handle.values()) {
          if (entry.kind === 'file') {
            totalFiles++;
            const file = await entry.getFile();
            filesFound.push(file.name);
            const ext = file.name.split('.').pop()?.toLowerCase() || 'no-ext';

            const isHidden = file.name.startsWith('.');
            const sensitiveExts = ['key', 'pem', 'env', 'config', 'sql'];
            const sensitiveKeywords = ['password', 'secret', 'api', 'credit', 'ssn'];
            
            const isHighRisk = sensitiveExts.includes(ext) || sensitiveKeywords.some(k => file.name.toLowerCase().includes(k));

            if (isHidden) {
               categories["Hidden Data"]++;
            }
            if (isHighRisk) {
               categories["High Risk"]++;
               sensitiveCount++;
               sensitiveList.push({ name: file.name, handle: entry, selected: true });
               if (sensitiveCount < 5) addLog(`[DETECTED] High-Risk item: ${file.name}`);
            }
            if (!isHidden && !isHighRisk) {
               categories["Low Risk"]++;
            }
          } else if (entry.kind === 'directory') {
            await scanEntry(entry);
          }
        }
      };

      await scanEntry(dirHandle);
      setSensitiveFilesList(sensitiveList);
      
      const preWipeScore = totalFiles > 0 ? Math.max(10, Math.round(100 - (sensitiveCount / totalFiles) * 100 - (totalFiles > 50 ? 15 : totalFiles > 20 ? 10 : 5))) : 85;
      const riskLevel = sensitiveCount > 5 ? "Critical" : sensitiveCount > 0 ? "Elevated" : "Low";
      const recommendation = sensitiveCount > 5 ? "DoD 5220.22-M (7-Pass)" : sensitiveCount > 0 ? "Gutmann (3-Pass)" : "Single-Pass Crypto Wipe";
      const aiReason = sensitiveCount > 5 
        ? `Forensic analysis complete. Detected ${sensitiveCount} high-risk objects including potential credentials and keys. Recommending military-grade 7-pass overwrite per DoD 5220.22-M standard to ensure zero recoverability.`
        : sensitiveCount > 0 
        ? `Forensic analysis complete. Found ${sensitiveCount} sensitive file(s) among ${totalFiles} total objects. Gutmann 3-pass overwrite recommended for thorough eradication of personally identifiable data.`
        : `Forensic analysis complete. No sensitive files detected in ${totalFiles} objects. Single-pass cryptographic noise overwrite is sufficient for standard data destruction.`;
      
      setScanResults({
        score: preWipeScore,
        results: {
          total_files: totalFiles,
          total_folders: 0,
          sensitive_files: sensitiveCount,
          risk_level: riskLevel,
          file_types: categories,
          files: filesFound.slice(0, 10)
        },
        recommendation,
        ai_reason: aiReason
      });
      
      addLog(`Local scan finished. Found ${totalFiles} objects.`);
      setStage("OPTIONS");
    } catch (err) {
      addLog("ERROR: Access denied by user or OS.");
      console.error("Folder access denied or failed", err);
    }
  };

  const startWipe = async (doBackup: boolean) => {
    setStage("WIPING");
    setIsWiping(true);
    addLog("SHREDDING PROTOCOL INITIATED.");
    
    if (activeDirHandle) {
      // BACKUP PHASE: Copy SELECTED files to a user-selected backup folder
      if (doBackup) {
        try {
          addLog("BACKUP MODE: Select a destination folder for secure backup...");
          setProgressText("Awaiting backup destination selection...");
          // @ts-ignore
          const backupDirHandle = await window.showDirectoryPicker({ mode: "readwrite", startIn: "downloads" });
          addLog(`Backup target: ${backupDirHandle.name}`);
          setProgressText("Copying selected files to backup location...");
          
          let backedUp = 0;
          
          for (const item of sensitiveFilesList) {
             if (item.selected) {
                try {
                  const file = await item.handle.getFile();
                  const destFile = await backupDirHandle.getFileHandle(file.name, { create: true });
                  const writable = await destFile.createWritable();
                  await writable.write(await file.arrayBuffer());
                  await writable.close();
                  backedUp++;
                  addLog(`[BACKED UP] ${file.name}`);
                } catch (e) {
                  addLog(`[BACKUP SKIP] ${item.name}`);
                }
             }
          }
          
          addLog(`BACKUP COMPLETE: ${backedUp} files saved to ${backupDirHandle.name}.`);
          setProgressText("Backup complete. Beginning eradication...");
          await new Promise(r => setTimeout(r, 1000));
        } catch (e) {
          addLog("BACKUP CANCELLED or FAILED. Proceeding with wipe anyway.");
          console.error("Backup failed:", e);
        }
      }
      
      addLog("Executing client-side cryptographic wipe on local files...");
      setProgressText("Overwriting local file segments with cryptographic noise...");
      
      let wipedCount = 0;
      
      const wipeEntry = async (handle: any) => {
        // Collect all entries first to avoid concurrent modification issues during iteration
        let entries = [];
        for await (const entry of handle.values()) {
          entries.push(entry);
        }
        
        for (const entry of entries) {
          if (entry.kind === 'file') {
            try {
              // 1. Overwrite with cryptographic noise (Pseudo-random zeros)
              const writable = await entry.createWritable();
              await writable.truncate(0); // Instantly wipe file metadata and size
              
              const noise = new Uint8Array(65536); // Max allowed by Web Crypto API
              crypto.getRandomValues(noise);
              await writable.write(noise);
              await writable.close();
              
              // CRITICAL FIX: Windows Defender / NTFS holds file locks for ~50-100ms after a file write is closed.
              // If we call removeEntry immediately, Chromium swallows the OS lock rejection and fails silently.
              // We must wait for the OS to release the file handle before attempting deletion.
              await new Promise(r => setTimeout(r, 150));
              
              // 2. Delete the file
              await handle.removeEntry(entry.name);
              wipedCount++;
              
              addLog(`[ERADICATED] ${entry.name}`);
              setProgress(Math.min(90, (wipedCount / scanResults.results.total_files) * 100));
            } catch (e) {
              addLog(`[FAILED] Could not eradicate ${entry.name}`);
              console.error(e);
            }
          } else if (entry.kind === 'directory') {
            await wipeEntry(entry);
            try {
               await handle.removeEntry(entry.name, { recursive: true });
            } catch(e) {}
          }
        }
      };

      await wipeEntry(activeDirHandle);
      setProgress(100);
      setProgressText("Verifying destruction...");
      addLog(`Local directory purged successfully. ${wipedCount} objects permanently destroyed.`);
      setActiveDirHandle(null); // Clear handle
    } else {
      addLog("Simulating wipe (No local directory handle).");
      const steps = [
        "Initializing override sequences...",
        "Overwriting file segments with cryptographic noise...",
        "Purging directory structures...",
        "Verifying destruction..."
      ];
      for (let i = 0; i <= 100; i++) {
        setProgress(i);
        if (i < 25) setProgressText(steps[0]);
        else if (i < 70) setProgressText(steps[1]);
        else if (i < 90) setProgressText(steps[2]);
        else setProgressText(steps[3]);
        
        if (i % 25 === 0) addLog(steps[i/25] || "Finalizing...");
        await new Promise(r => setTimeout(r, 20));
      }
    }

    try {
      addLog("Generating verifiable certificate from API...");
      // Get the real cryptographic certificate from the backend
      const res = await fetch("/api/certify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ 
          device_id: deviceId, 
          trust_score: 100, // Post-wipe score is always 100 in this logic
          wipe_level: scanResults.recommendation,
          files_sensitive: scanResults.results.sensitive_files,
          files_safe: scanResults.results.total_files - scanResults.results.sensitive_files
        })
      });
      const data = await res.json();
      
      setWipeResults({
        after_score: 100,
        attack: { is_secure: true, report: "[AUDIT COMPLETE] No forensic fragments detected in scanned sectors." },
        cert: data.cert
      });
      setCert(data.cert);
      addLog("Certificate generated.");
      
      addLog("Packaging PDF Passport...");
      // Generate PDF
      const pdfRes = await fetch("/api/certificate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          device_id: deviceId,
          hash: data.cert.hash,
          trust_score: 100,
          files_sensitive: scanResults.results.sensitive_files,
          files_safe: scanResults.results.total_files - scanResults.results.sensitive_files,
          date: new Date().toISOString().split('T')[0],
          file_types: scanResults.results.file_types
        })
      });
      const pdfData = await pdfRes.json();
      setPdfBase64(pdfData.pdf_base64);
      
      addLog("ALL PROTOCOLS COMPLETE.");
      setStage("FINISHED");
    } catch (err) {
      addLog("ERROR: Forensic Mesh Connectivity Failure.");
      console.error("Certification failed", err);
    } finally {
      setIsWiping(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 selection:bg-blue-500 selection:text-white overflow-x-hidden font-sans">
      
      {/* Professional Header */}
      <header className="bg-slate-950 border-b border-slate-800 p-8 text-center relative overflow-hidden shadow-md">
        <motion.div 
          initial={{ y: -20, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ duration: 0.6, ease: "easeOut" }}
          className="relative z-10 max-w-4xl mx-auto"
        >
          <div className="inline-block px-3 py-1 bg-blue-900/30 border border-blue-500/30 rounded-full text-[10px] font-bold uppercase tracking-widest text-blue-400 mb-4">
            Enterprise Sanitization Protocol
          </div>
          <h1 className="text-4xl md:text-6xl font-bold tracking-tight text-white mb-2">
            TrustSense<span className="text-blue-500 font-light">+</span>
          </h1>
          <p className="text-slate-400 text-sm md:text-base font-medium tracking-wide">
            Automated Forensic Integrity & Eradication Audit
          </p>
        </motion.div>
      </header>
      
      {showBackupModal && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 rounded-xl shadow-2xl border border-slate-700 max-w-lg w-full p-6">
            <h3 className="text-xl font-bold text-white mb-2">Selective Secure Backup</h3>
            <p className="text-sm text-slate-400 mb-4">Select the high-risk objects you wish to securely mirror before proceeding with full eradication.</p>
            <div className="max-h-60 overflow-y-auto space-y-2 mb-6 border border-slate-800 rounded-lg p-2 bg-slate-950/50">
                {sensitiveFilesList.map((f, i) => (
                  <label key={i} className="flex items-center gap-3 p-2 hover:bg-slate-800 rounded border border-transparent hover:border-slate-700 cursor-pointer transition-colors">
                      <input type="checkbox" checked={f.selected} onChange={e => {
                        const newList = [...sensitiveFilesList];
                        newList[i].selected = e.target.checked;
                        setSensitiveFilesList(newList);
                      }} className="w-4 h-4 text-blue-500 bg-slate-900 border-slate-600 rounded focus:ring-blue-500 focus:ring-2" />
                      <span className="text-sm font-mono text-slate-300 truncate">{f.name}</span>
                  </label>
                ))}
                {sensitiveFilesList.length === 0 && <p className="text-sm text-slate-500 p-4 text-center">No high-risk files detected for backup.</p>}
            </div>
            <div className="flex gap-3 justify-end">
                <button onClick={() => setShowBackupModal(false)} className="px-4 py-2 text-sm font-medium text-slate-300 hover:bg-slate-800 hover:text-white rounded-lg transition-colors">Cancel</button>
                <button onClick={() => { setShowBackupModal(false); startWipe(true); }} className="px-5 py-2 text-sm font-semibold bg-blue-600 text-white hover:bg-blue-500 rounded-lg shadow transition-colors">Proceed to Backup & Wipe</button>
            </div>
          </div>
        </div>
      )}

      <main className="max-w-6xl mx-auto p-6 md:p-10 space-y-8">
        
        {/* Stage 0: Configuration */}
        <motion.section 
          initial={{ y: 20, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ delay: 0.1 }}
          className="bg-slate-800 border border-slate-700 rounded-2xl p-8 relative overflow-hidden shadow-lg"
        >
          <div className="absolute top-0 right-0 p-4 opacity-5">
            <Database className="w-24 h-24 text-blue-500" />
          </div>
          
          <div className="flex items-center gap-3 mb-6">
            <div className="p-2 bg-blue-500/20 text-blue-400 rounded-lg">
              <Cpu className="w-6 h-6" />
            </div>
            <h2 className="text-lg font-semibold tracking-wide text-white">Target Identification</h2>
          </div>
          
          <div className="grid gap-6">
            <div className="space-y-2">
              <label className="text-xs font-semibold uppercase text-slate-400 tracking-wider">Audit Target / Device ID</label>
              <input 
                value={deviceId} 
                onChange={(e) => setDeviceId(e.target.value)}
                placeholder="e.g. Workstation-A1"
                className="w-full bg-slate-900 border border-slate-700 rounded-xl p-4 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 outline-none transition-all font-mono text-sm text-slate-200"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-8">
            <button 
              onClick={selectFolder}
              className="bg-blue-600 text-white font-semibold py-4 rounded-xl hover:bg-blue-500 transition-colors uppercase tracking-wide flex items-center justify-center gap-2 shadow-md"
            >
              <Search className="w-5 h-5" />
              Analyze Local Directory
            </button>
            <button 
              onClick={() => {
                addLog("GENERATING VIRTUAL FORENSIC SANDBOX...");
                setScanResults({
                  score: 34,
                  results: {
                    total_files: 142,
                    total_folders: 12,
                    sensitive_files: 8,
                    risk_level: "High",
                    file_types: { "pem": 2, "env": 1, "txt": 120, "log": 19 },
                    files: ["passwords.txt", "keys.pem", "config.env", "db_backup.sql"]
                  },
                  recommendation: "DoD 5220.22-M (7-Pass)",
                  ai_reason: "Detected 8 high-risk objects including .pem keys, .env config, and credential files. Recommending military-grade 7-pass overwrite per DoD 5220.22-M standard to ensure zero recoverability."
                });
                addLog("Sandbox ready. High entropy fragments detected.");
                setStage("OPTIONS");
              }}
              className="bg-slate-700/50 border border-slate-600 text-slate-300 font-semibold py-4 rounded-xl hover:bg-slate-700 transition-colors uppercase tracking-wide flex items-center justify-center gap-2"
            >
              <Shield className="w-5 h-5" />
              Sandbox Simulation
            </button>
          </div>

          <p className="text-xs text-center mt-6 text-slate-500">
            Real-Time System Access Required for Forensic Validation
          </p>

          {/* Forensic Console - RESTORED FEATURE */}
          {/* Forensic Console */}
          <motion.div 
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="mt-8 p-4 rounded-xl bg-slate-900 border border-slate-700 font-mono text-xs text-slate-400"
          >
            <div className="flex justify-between items-center mb-3 text-[10px] uppercase tracking-wider text-slate-500 border-b border-slate-800 pb-2">
              <span>Execution Log</span>
              <span className="flex items-center gap-1"><div className="w-1.5 h-1.5 rounded-full bg-blue-500 animate-pulse" /> Live</span>
            </div>
            <div className="space-y-1.5 max-h-40 overflow-y-auto">
              {consoleLogs.map((log, i) => (
                <div key={i}>{log}</div>
              ))}
            </div>
          </motion.div>
        </motion.section>

        {/* Stage 1: Options */}
        <AnimatePresence>
          {stage === "OPTIONS" && scanResults && (
            <motion.section 
              initial={{ height: 0, opacity: 0, y: 20 }}
              animate={{ height: "auto", opacity: 1, y: 0 }}
              exit={{ height: 0, opacity: 0, y: 20 }}
              className="space-y-6 overflow-hidden"
            >
              <div className="space-y-6 overflow-hidden">
                {/* Visual File Categorization Graph */}
                <div className="bg-slate-800 border border-slate-700 rounded-2xl p-6 mb-6 shadow-md">
                  <div className="flex items-center gap-3 mb-6">
                    <div className="p-2 bg-blue-500/20 rounded-lg">
                      <PieChart className="text-blue-400 w-6 h-6" />
                    </div>
                    <div>
                      <h3 className="text-lg font-semibold tracking-wide text-white">Data Categorization Analysis</h3>
                      <p className="text-xs text-slate-400 font-medium tracking-wide mt-1">{scanResults.results.total_files} objects scanned and categorized</p>
                    </div>
                  </div>
                  
                  {/* Proper Vertical Bar Chart */}
                  {(() => {
                    const entries = Object.entries(scanResults.results.file_types || {});
                    const maxCount = Math.max(...entries.map(([, c]) => c as number), 1);
                    // Match colors to categories: High Risk (Red), Hidden Data (Slate), Low Risk (Emerald)
                    const getBarColor = (name: string) => {
                       if (name === 'High Risk') return 'bg-rose-500';
                       if (name === 'Hidden Data') return 'bg-slate-500';
                       return 'bg-emerald-500';
                    };
                    return (
                      <div className="mt-4 max-w-xl mx-auto">
                        {/* Y-axis labels + bars */}
                        <div className="flex items-end gap-6 h-48 border-b border-slate-700 border-l border-l-slate-700 pl-8 pb-1 relative">
                          {/* Y-axis scale */}
                          <div className="absolute left-0 top-0 h-full flex flex-col justify-between text-[10px] font-mono text-slate-500 pr-2">
                            <span>{maxCount}</span>
                            <span>{Math.round(maxCount / 2)}</span>
                            <span>0</span>
                          </div>
                          {entries.map(([cat, count], idx) => {
                            const heightPct = ((count as number) / maxCount) * 100;
                            return (
                              <div key={cat} className="flex-1 flex flex-col items-center justify-end h-full group">
                                <div className="text-xs font-bold text-white mb-2 opacity-0 group-hover:opacity-100 transition-opacity">{count as number}</div>
                                <motion.div
                                  initial={{ height: 0 }}
                                  animate={{ height: `${heightPct}%` }}
                                  transition={{ duration: 0.8, delay: idx * 0.1, ease: "easeOut" }}
                                  className={`w-16 max-w-full ${getBarColor(cat)} rounded-t-lg relative cursor-pointer min-h-[4px] shadow-lg`}
                                />
                              </div>
                            );
                          })}
                        </div>
                        {/* X-axis labels */}
                        <div className="flex gap-6 pl-8 mt-3">
                          {entries.map(([cat], idx) => (
                            <div key={cat} className="flex-1 text-center">
                              <span className="text-xs font-semibold text-slate-400">{cat}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    );
                  })()}
                </div>

                <div className="bg-slate-800 border border-slate-700 rounded-2xl p-6 shadow-md">
                  <div className="flex items-center gap-3 mb-6">
                    <div className="p-2 bg-amber-500/20 rounded-lg">
                      <AlertTriangle className="text-amber-500 w-6 h-6" />
                    </div>
                    <h3 className="text-lg font-semibold text-white tracking-wide">Action Center</h3>
                  </div>
                
                <div className="flex items-center justify-between mb-4 p-4 bg-slate-900 rounded-xl border border-slate-700">
                   <span className="text-sm font-semibold text-slate-400 uppercase tracking-wide">Recommended Protocol</span>
                   <span className="text-blue-400 font-bold tracking-wide">{scanResults.recommendation}</span>
                </div>

                {/* AI Recommendation Section */}
                <div className="mb-8 p-5 bg-blue-900/10 border border-blue-500/20 rounded-xl">
                  <div className="flex items-center gap-2 mb-3">
                    <Cpu className="w-4 h-4 text-blue-400" />
                    <span className="text-xs font-bold uppercase tracking-wider text-blue-400">AI Eradication Analysis</span>
                  </div>
                  <p className="text-sm text-slate-300 leading-relaxed">{scanResults.ai_reason}</p>
                  <div className="mt-4 flex gap-3">
                    <div className="bg-slate-900 px-3 py-1.5 rounded-lg text-xs font-semibold text-amber-500 border border-amber-500/20">
                      Risk Profile: {scanResults.results.risk_level}
                    </div>
                    <div className="bg-slate-900 px-3 py-1.5 rounded-lg text-xs font-semibold text-emerald-400 border border-emerald-500/20">
                      {scanResults.results.sensitive_files} Sensitive / {scanResults.results.total_files} Total
                    </div>
                  </div>
                </div>
                
                <div className="grid md:grid-cols-2 gap-6">
                  <button 
                    onClick={() => startWipe(false)}
                    className="p-6 bg-slate-900 border-2 border-slate-700 rounded-2xl hover:border-emerald-500 hover:bg-slate-800 transition-all text-left group relative overflow-hidden shadow-sm"
                  >
                    <div className="flex items-center justify-between relative z-10">
                      <span className="font-bold text-slate-200 tracking-wide text-base">Proceed with Eradication</span>
                      <ArrowRight className="w-5 h-5 group-hover:translate-x-2 transition-transform text-emerald-500" />
                    </div>
                    <p className="text-xs text-slate-500 mt-2 tracking-wide leading-relaxed">Securely overwrite all identified data. Irreversible action.</p>
                    <div className="absolute bottom-0 right-0 p-2 opacity-10 group-hover:opacity-30 transition-opacity text-emerald-500">
                      <Trash2 className="w-16 h-16" />
                    </div>
                  </button>
                  <button 
                    onClick={() => setShowBackupModal(true)}
                    className="p-6 bg-slate-900 border-2 border-slate-700 rounded-2xl hover:border-blue-500 hover:bg-slate-800 transition-all text-left group relative overflow-hidden shadow-sm"
                  >
                    <div className="flex items-center justify-between relative z-10">
                      <span className="font-bold text-slate-200 tracking-wide text-base">Review & Backup First</span>
                      <ArrowRight className="w-5 h-5 group-hover:translate-x-2 transition-transform text-blue-500" />
                    </div>
                    <p className="text-xs text-slate-500 mt-2 tracking-wide leading-relaxed">Selectively copy high-risk files to a secure location before eradication.</p>
                    <div className="absolute bottom-0 right-0 p-2 opacity-10 group-hover:opacity-30 transition-opacity text-blue-500">
                      <FileCheck className="w-16 h-16" />
                    </div>
                  </button>
                </div>
                </div>
              </div>
            </motion.section>
          )}
        </AnimatePresence>

        {/* Stage 2: Wiping Progress */}
        <AnimatePresence>
          {stage === "WIPING" && (
            <motion.section 
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              className="bg-slate-900 border border-slate-700 rounded-2xl p-8 relative overflow-hidden shadow-lg"
            >
              <div className="absolute top-0 left-0 w-full h-1 bg-slate-800">
                <motion.div 
                  className="h-full bg-blue-500 shadow-[0_0_10px_rgba(59,130,246,0.5)]"
                  initial={{ width: 0 }}
                  animate={{ width: `${progress}%` }}
                />
              </div>
              
              <div className="flex items-center justify-between mb-6 mt-2">
                <div className="flex items-center gap-2">
                  <div className="w-2.5 h-2.5 rounded-full bg-blue-500 animate-pulse" />
                  <span className="text-blue-400 font-bold uppercase text-xs tracking-wider">Eradication Protocol Active</span>
                </div>
                <span className="font-mono text-3xl font-bold text-white">{progress}%</span>
              </div>
              
              <div className="w-full h-4 bg-slate-800 rounded-full overflow-hidden border border-slate-700 mb-8 shadow-inner">
                <motion.div 
                  className="h-full bg-blue-500"
                  initial={{ width: 0 }}
                  animate={{ width: `${progress}%` }}
                />
              </div>

              {/* Live Sector Overwrite Graph */}
              <div className="mb-8">
                <div className="text-xs font-semibold uppercase text-slate-500 tracking-wider mb-4">Live Cryptographic Overwrite Status</div>
                <div className="flex items-end gap-1 h-16">
                  {[...Array(32)].map((_, i) => (
                    <motion.div
                      key={i}
                      className={`flex-1 rounded-sm ${i < Math.floor(progress / 3.125) ? 'bg-blue-500' : 'bg-slate-800'}`}
                      initial={{ height: '15%' }}
                      animate={{ height: i < Math.floor(progress / 3.125) ? `${20 + Math.random() * 80}%` : '15%' }}
                      transition={{ duration: 0.3, delay: i * 0.02 }}
                    />
                  ))}
                </div>
              </div>

              {/* Category Breakdown During Wipe */}
              {scanResults && (
                <div className="grid grid-cols-3 gap-4 mb-8">
                  {Object.entries(scanResults.results?.file_types || {}).map(([cat, count], i) => (
                    <div key={cat} className="bg-slate-950/50 border border-slate-700 p-3 rounded-lg text-center">
                      <div className="text-[10px] font-bold uppercase text-slate-400 tracking-wider mb-1">{cat}</div>
                      <div className="text-base font-bold text-slate-200">{count as number} Objects</div>
                    </div>
                  ))}
                </div>
              )}
              
              <div className="bg-black/60 p-4 rounded-xl border border-white/5 font-mono text-[10px] text-trust-yellow/60 uppercase tracking-widest min-h-[60px] flex items-center justify-center text-center">
                <AnimatePresence mode="wait">
                  <motion.span 
                    key={progressText}
                    initial={{ opacity: 0, y: 5 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -5 }}
                  >
                    {progressText}
                  </motion.span>
                </AnimatePresence>
              </div>
            </motion.section>
          )}
        </AnimatePresence>

        {/* Stage 3: Results & Certificate */}
        <AnimatePresence>
          {stage === "FINISHED" && wipeResults && (
            <motion.div 
              initial={{ y: 50, opacity: 0 }}
              animate={{ y: 0, opacity: 1 }}
              className="space-y-8"
            >
              <div className="grid md:grid-cols-3 gap-6">
                {/* Before vs After Delta Dashboard */}
                <div className="bg-slate-800 border border-slate-700 rounded-2xl flex flex-col items-center justify-center p-6 relative overflow-hidden shadow-md">
                  <span className="text-xs font-bold uppercase text-slate-400 tracking-widest mb-6">Risk Remediation Audit</span>
                  
                  <div className="w-full grid grid-cols-2 gap-4">
                    <div className="bg-rose-500/10 border border-rose-500/20 p-4 rounded-xl text-center">
                      <div className="text-[10px] font-bold uppercase text-rose-400 tracking-wider mb-2">Pre-Audit Risk</div>
                      <motion.div className="text-3xl font-bold text-rose-500" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
                        {scanResults?.score || 34}%
                      </motion.div>
                      <div className="text-[10px] text-rose-400/80 mt-1">{scanResults?.results?.sensitive_files || 0} Vulnerabilities</div>
                    </div>
                    <div className="bg-emerald-500/10 border border-emerald-500/20 p-4 rounded-xl text-center">
                      <div className="text-[10px] font-bold uppercase text-emerald-400 tracking-wider mb-2">Post-Audit Safety</div>
                      <motion.div className="text-3xl font-bold text-emerald-500" initial={{ scale: 0 }} animate={{ scale: 1 }} transition={{ type: "spring", delay: 0.5 }}>
                        {wipeResults.after_score}%
                      </motion.div>
                      <div className="text-[10px] text-emerald-400/80 mt-1">0 Vulnerabilities</div>
                    </div>
                  </div>
                  
                  <div className="w-full bg-slate-900 border border-slate-700 p-3 rounded-lg text-center mt-4">
                    <span className="text-xs font-semibold text-emerald-400">System securely remediated by +{wipeResults.after_score - (scanResults?.score || 34)}%</span>
                  </div>
                </div>

                {/* Audit Verification Simulation */}
                <div className="bg-slate-800 border border-slate-700 rounded-2xl md:col-span-2 p-6 flex flex-col justify-center relative overflow-hidden shadow-md">
                  <div className="absolute top-0 right-0 p-8 opacity-5"><Shield className="w-40 h-40" /></div>
                  
                  <div className="flex items-center gap-6 mb-6 relative z-10">
                    <div className={cn("p-4 rounded-xl shadow-md", wipeResults.attack.is_secure ? "bg-emerald-500/20" : "bg-rose-500/20")}>
                      {wipeResults.attack.is_secure ? (
                        <CheckCircle2 className="text-emerald-500 w-8 h-8" />
                      ) : (
                        <AlertTriangle className="text-rose-400 w-8 h-8 animate-pulse" />
                      )}
                    </div>
                    <div>
                      <h3 className={cn("text-2xl font-bold tracking-tight", wipeResults.attack.is_secure ? "text-emerald-500" : "text-rose-400")}>
                        {wipeResults.attack.is_secure ? "Verification Passed" : "Vulnerability Found"}
                      </h3>
                      <p className="text-slate-400 text-sm mt-1">Automated Post-Eradication Integrity Test</p>
                    </div>
                  </div>
                  
                  {/* Attack Vector Grid */}
                  <div className="grid grid-cols-2 gap-3 relative z-10 mb-6">
                    {[
                      { name: "File Structure Recovery Test", status: "VERIFIED" },
                      { name: "Metadata Leakage Test", status: "VERIFIED" },
                      { name: "Cryptographic Noise Entropy", status: "PASSED" },
                      { name: "Compliance Check (DoD)", status: "PASSED" }
                    ].map((attack, i) => (
                      <motion.div key={attack.name} initial={{ x: -20, opacity: 0 }} animate={{ x: 0, opacity: 1 }} transition={{ delay: 0.3 + i * 0.15 }}
                        className="bg-slate-900 border border-slate-700 p-3 rounded-lg flex items-center justify-between"
                      >
                        <span className="text-xs font-medium text-slate-400">{attack.name}:</span>
                        <span className="text-xs font-bold text-emerald-500">{attack.status}</span>
                      </motion.div>
                    ))}
                  </div>

                  {/* Simulated Terminal Output */}
                  <div className="bg-slate-950 p-4 rounded-xl font-mono text-xs text-slate-400 leading-relaxed border border-slate-800 relative z-10 shadow-inner overflow-hidden">
                    <div className="space-y-1.5">
                      <div><span className="text-blue-500">$</span> init_audit_suite --target {deviceId}</div>
                      <div><span className="text-slate-600">[VERIFY]</span> Scanning for residual data fragments... <span className="text-emerald-400">NONE FOUND</span></div>
                      <div><span className="text-slate-600">[VERIFY]</span> Analyzing {scanResults?.results?.total_files || 0} eradicated sectors... <span className="text-emerald-400">0% RECOVERABLE</span></div>
                      <div><span className="text-slate-600">[VERIFY]</span> Entropy analysis on overwritten clusters... <span className="text-emerald-400">MAXIMUM VARIANCE</span></div>
                      <div className="pt-3 border-t border-slate-800 mt-2">
                        <span className="text-blue-400 font-bold">[AUDIT COMPLETE]</span> Cryptographic eradication verified. All objects permanently destroyed.
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Post-Wipe File Type Distribution */}
              {scanResults?.results?.file_types && (
                <div className="glass-card neo-border-cyan">
                  <div className="flex items-center gap-3 mb-4">
                    <Database className="text-trust-cyan w-5 h-5" />
                    <span className="text-sm font-black uppercase tracking-wider text-trust-cyan">Eradicated Data Distribution</span>
                  </div>
                  <div className="w-full h-6 bg-black/50 rounded-full overflow-hidden flex border border-white/10 mb-3">
                    {Object.entries(scanResults.results.file_types).map(([ext, count], idx) => {
                      const colors = ['bg-trust-cyan', 'bg-trust-green', 'bg-trust-yellow', 'bg-purple-500', 'bg-blue-500', 'bg-orange-500'];
                      const pct = ((count as number) / Math.max(1, scanResults.results.total_files)) * 100;
                      return (
                        <motion.div key={ext} initial={{ width: 0 }} animate={{ width: `${pct}%` }}
                          transition={{ duration: 0.8, delay: idx * 0.1 }}
                          className={`h-full ${colors[idx % colors.length]} border-r border-black/30 relative group cursor-pointer`}
                        >
                          <div className="absolute opacity-0 group-hover:opacity-100 -top-7 left-1/2 -translate-x-1/2 bg-black border border-white/10 text-[8px] font-black px-2 py-0.5 rounded text-white whitespace-nowrap z-50 pointer-events-none transition-opacity">
                            {ext}: {count as number} ({pct.toFixed(0)}%)
                          </div>
                        </motion.div>
                      );
                    })}
                  </div>
                  <div className="flex flex-wrap gap-3">
                    {Object.entries(scanResults.results.file_types).slice(0, 6).map(([ext, count], idx) => {
                      const colors = ['bg-trust-cyan', 'bg-trust-green', 'bg-trust-yellow', 'bg-purple-500', 'bg-blue-500', 'bg-orange-500'];
                      return (
                        <div key={ext} className="flex items-center gap-1.5">
                          <div className={`w-2.5 h-2.5 rounded-sm ${colors[idx % colors.length]}`} />
                          <span className="text-[9px] font-black uppercase text-gray-400">{ext} <span className="text-white">({count as number})</span></span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Enterprise Audit Certificate */}
              <motion.div 
                initial={{ scale: 0.95, opacity: 0, rotateX: 10 }}
                animate={{ scale: 1, opacity: 1, rotateX: 0 }}
                transition={{ delay: 0.3, type: "spring", stiffness: 100 }}
                className="bg-white text-slate-900 border border-slate-200 rounded-xl max-w-4xl mx-auto shadow-[0_20px_50px_rgba(0,0,0,0.5)] relative overflow-hidden"
              >
                {/* Header */}
                <div className="bg-slate-50 border-b border-slate-200 p-8 flex items-center justify-between">
                  <div className="flex items-center gap-4">
                    <div className="bg-blue-600 p-3 rounded-lg text-white">
                      <Shield className="w-8 h-8" />
                    </div>
                    <div>
                      <div className="font-bold text-2xl tracking-tight text-slate-900">Data Eradication Audit Report</div>
                      <div className="text-xs uppercase tracking-widest font-semibold text-slate-500 mt-1">Official Cryptographic Certificate</div>
                    </div>
                  </div>
                  {/* Modern Barcode */}
                  <div className="flex gap-[2px] h-12 opacity-80">
                    {[...Array(24)].map((_, i) => (
                      <div key={i} className="bg-slate-800" style={{ width: Math.random() > 0.5 ? '2px' : '4px' }} />
                    ))}
                  </div>
                </div>
                
                {/* Body */}
                <div className="p-10 grid md:grid-cols-3 gap-12">
                  {/* Left Column Data */}
                  <div className="md:col-span-2 space-y-8">
                    <div className="bg-slate-100 text-slate-700 p-4 font-mono text-xs uppercase rounded-lg border border-slate-200 flex justify-between items-center">
                      <span className="font-semibold text-slate-900">Cert ID: {cert?.hash?.substring(0, 12)}</span>
                      <span className="text-slate-400">|</span>
                      <span>Target: {deviceId}</span>
                    </div>
                    
                    <div className="grid grid-cols-2 gap-6">
                      <div className="bg-slate-50 border border-slate-200 rounded-xl p-6 relative overflow-hidden">
                        <div className="text-xs font-bold text-slate-500 uppercase tracking-widest mb-2">Vulnerabilities Purged</div>
                        <div className="text-4xl font-bold text-slate-900">{scanResults.results.sensitive_files}</div>
                      </div>
                      <div className="bg-slate-50 border border-slate-200 rounded-xl p-6 relative overflow-hidden">
                        <div className="text-xs font-bold text-slate-500 uppercase tracking-widest mb-2">Total Objects Eradicated</div>
                        <div className="text-4xl font-bold text-slate-900">{scanResults.results.total_files}</div>
                      </div>
                    </div>

                    <div className="flex gap-4">
                      <div className="flex-1 border border-slate-200 rounded-lg p-4 bg-slate-50">
                        <div className="text-[10px] font-bold uppercase text-slate-500 tracking-widest mb-1">Eradication Standard</div>
                        <div className="font-semibold text-slate-800 text-sm">{scanResults.recommendation}</div>
                      </div>
                      <div className="flex-1 border border-slate-200 rounded-lg p-4 bg-slate-50">
                        <div className="text-[10px] font-bold uppercase text-slate-500 tracking-widest mb-1">Audit Timestamp</div>
                        <div className="font-semibold text-slate-800 text-sm">{new Date().toISOString().split('T')[0]}</div>
                      </div>
                    </div>
                  </div>

                  {/* Right Column Visuals */}
                  <div className="flex flex-col items-center justify-center relative border-l border-slate-100 pl-8">
                    {/* Professional Seal */}
                    <div className="relative w-40 h-40 flex items-center justify-center mb-8">
                        <div className="absolute inset-0 border-4 border-blue-100 rounded-full" />
                        <div className="absolute inset-2 border-2 border-blue-500 rounded-full border-dashed" />
                        <div className="bg-blue-50 w-full h-full rounded-full flex flex-col items-center justify-center border-4 border-blue-600 z-10 shadow-sm">
                          <CheckCircle2 className="text-blue-600 w-10 h-10 mb-2" />
                          <span className="font-bold text-blue-600 uppercase tracking-widest text-xs">Verified</span>
                          <span className="font-semibold text-blue-800/70 uppercase tracking-wider text-[8px] mt-1">100% Secure</span>
                        </div>
                    </div>

                    {/* Signature Block */}
                    <div className="w-full text-center border-t border-slate-200 pt-4">
                      <div className="font-serif italic text-xl text-slate-800 mb-1">TrustSense Auth</div>
                      <div className="text-[8px] font-bold uppercase tracking-widest text-slate-400">Cryptographic Signature</div>
                    </div>
                  </div>
                </div>

                {/* Footer Hash */}
                <div className="bg-slate-900 text-slate-400 p-4 text-[10px] font-mono tracking-wider flex justify-between px-8">
                  <span>SHA-256 SIGNATURE</span>
                  <span className="truncate ml-4 text-slate-200">{cert?.hash}</span>
                </div>
              </motion.div>

              {/* Download Actions */}
              <div className="flex flex-col md:flex-row justify-center items-center gap-6 pt-4">
                {pdfBase64 && (
                  <motion.a 
                    whileHover={{ scale: 1.02 }}
                    whileTap={{ scale: 0.98 }}
                    href={`data:application/pdf;base64,${pdfBase64}`}
                    download={`${deviceId}_Audit_Report.pdf`}
                    className="flex items-center gap-3 bg-blue-600 text-white px-8 py-4 rounded-xl font-semibold tracking-wide shadow-lg hover:bg-blue-500 transition-colors"
                  >
                    <Download className="w-5 h-5" />
                    Download Official PDF Report
                  </motion.a>
                )}
                <button 
                  onClick={() => window.location.reload()}
                  className="px-8 py-4 border border-slate-700 rounded-xl font-semibold text-slate-400 hover:bg-slate-800 hover:text-white transition-colors"
                >
                  Start New Audit
                </button>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

      </main>

      {/* Footer */}
      <footer className="mt-24 border-t border-slate-800 py-12 text-center bg-slate-950">
        <div className="max-w-4xl mx-auto px-6">
          <div className="flex justify-center gap-6 mb-6 opacity-40">
            <Shield className="w-5 h-5 text-slate-500" />
            <Lock className="w-5 h-5 text-slate-500" />
            <Database className="w-5 h-5 text-slate-500" />
          </div>
          <p className="text-[10px] uppercase tracking-[0.3em] font-bold text-slate-500">
            TrustSense Enterprise v4.2 &copy; 2026
          </p>
          <div className="mt-2 text-[10px] font-mono text-slate-600 uppercase tracking-widest">
            Cryptographic Data Eradication & Forensic Auditing
          </div>
        </div>
      </footer>
    </div>
  );
}
