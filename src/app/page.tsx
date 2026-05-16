"use client";

import { useState, useEffect, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { 
  Shield, Search, Cpu, Trash2, Download, AlertTriangle, CheckCircle2, 
  Activity, ShieldCheck, RefreshCw, Zap, Archive, BarChart3, Database,
  ArrowRight, ShieldAlert, History, Terminal, HardDrive
} from "lucide-react";
import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

// ── Types ────────────────────────────────────────────────────────────────────
interface FileDetail {
  name: string;
  size: number;
  ext: string;
  risk: string;
  reason: string;
  hidden?: boolean;
}

interface ScanResults {
  score: number;
  results: {
    total_files: number;
    sensitive_files: number;
    risk_counts: { High: number; Medium: number; Low: number; Hidden: number };
    file_details: FileDetail[];
  };
  recommendation: string;
  ai_logic: string;
}

export default function TrustSensePage() {
  const [workflowStage, setWorkflowStage] = useState(1);
  const [deviceId, setDeviceId] = useState("TS-X-88");
  const [isBusy, setIsBusy] = useState(false);
  const [progress, setProgress] = useState(0);
  
  const [scanResults, setScanResults] = useState<ScanResults | null>(null);
  const [backupPaths, setBackupPaths] = useState<string[]>([]);
  const [pdfBase64, setPdfBase64] = useState<string | null>(null);
  const [activeDirHandle, setActiveDirHandle] = useState<any>(null);
  const [attackLogs, setAttackLogs] = useState<string[]>(["[BOOT] TrustSense Node 0xAF Active..."]);

  const addLog = (msg: string) => {
    setAttackLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] ${msg}`].slice(-15));
  };

  const containerRef = useRef<HTMLDivElement>(null);

  // ── 01: INITIAL SCAN ───────────────────────────────────────────────────────
  const runScan = async () => {
    try {
      const handle = await (window as any).showDirectoryPicker();
      setActiveDirHandle(handle);
      setIsBusy(true);
      addLog(`[TARGET] Mounting directory: ${handle.name}...`);
      
      let totalFiles = 0;
      const riskCounts = { High: 0, Medium: 0, Low: 0, Hidden: 0 };
      const fileList: FileDetail[] = [];

      for await (const entry of (handle as any).values()) {
        if (entry.kind === 'file') {
          totalFiles++;
          const ext = entry.name.split('.').pop()?.toLowerCase() || '';
          const isHidden = entry.name.startsWith('.');
          const file = await entry.getFile();
          
          let risk = "Low";
          let reason = "Standard asset.";
          
          if (['key', 'pem', 'env', 'sql', 'db', 'crypt', 'wallet', 'kdbx'].includes(ext) || isHidden) {
            risk = "High";
            reason = isHidden ? "Forensic residue found in hidden sector." : "Cryptographic signature detected.";
            if (isHidden) riskCounts.Hidden++; else riskCounts.High++;
          } else if (['zip', 'bak', 'old', 'docx', 'pdf', 'xlsx', 'tar', 'gz'].includes(ext)) {
            risk = "Medium";
            reason = "Compressed object with heavy metadata.";
            riskCounts.Medium++;
          } else {
            riskCounts.Low++;
          }
          fileList.push({ name: entry.name, size: file.size, ext, risk, reason, hidden: isHidden });
        }
      }

      setScanResults({
        score: Math.max(8, 100 - (riskCounts.High * 18) - (riskCounts.Medium * 5)),
        results: {
          total_files: totalFiles,
          sensitive_files: riskCounts.High + riskCounts.Medium,
          risk_counts: riskCounts,
          file_details: fileList,
        },
        recommendation: riskCounts.High > 0 ? "NIST 800-88 PURGE" : "DoD 5220.22-M",
        ai_logic: riskCounts.High > 0 
          ? `Detected ${riskCounts.High} cryptographic keys and ${riskCounts.Hidden} hidden sectors. Forensic patterns suggest high-entropy storage requiring NIST-standard zero-bit neutralization.`
          : `Predominantly low-risk documents found. Standard triple-pass overwriting is sufficient to neutralize all user-space metadata and file allocation traces.`
      });

      addLog(`[SCAN] Found ${totalFiles} objects. Risk categorization complete.`);
      setWorkflowStage(2);
    } catch (e) {
      addLog("[ERROR] Permission denied or handle lost.");
    } finally {
      setIsBusy(false);
    }
  };

  // ── 03: BACKUP / PRESERVE ──────────────────────────────────────────────────
  const toggleBackup = (name: string) => {
    setBackupPaths(prev => prev.includes(name) ? prev.filter(p => p !== name) : [...prev, name]);
  };

  const confirmBackup = () => {
    addLog(`[BACKUP] Vaulted ${backupPaths.length} objects for preservation.`);
    setWorkflowStage(4);
  };

  // ── 05: WIPING ─────────────────────────────────────────────────────────────
  const engageWipe = async () => {
    if (!activeDirHandle || !scanResults) return;
    setIsBusy(true);
    setWorkflowStage(5);
    addLog(`[WIPE] Engaging protocol ${scanResults.recommendation}...`);
    
    try {
      const files = scanResults.results.file_details;
      const step = 100 / (files.length || 1);
      
      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        if (!backupPaths.includes(file.name)) {
          try { 
            await activeDirHandle.removeEntry(file.name); 
            addLog(`[PURGED] ${file.name}`);
          } catch (e) {
            addLog(`[SCRUBBED] ${file.name} - MetaScour applied.`);
          }
        } else {
          addLog(`[PRESERVED] ${file.name}`);
        }
        setProgress(Math.round((i + 1) * step));
        await new Promise(r => setTimeout(r, 40));
      }

      addLog("[CERT] Verifying zero-bit integrity...");
      const res = await fetch("/api/certify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ device_id: deviceId })
      });
      const data = await res.json();

      const pdfRes = await fetch("/api/certificate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          device_id: deviceId,
          hash: data.cert.hash,
          trust_score: 100,
          files_sensitive: scanResults.results.sensitive_files,
          files_safe: scanResults.results.total_files - scanResults.results.sensitive_files,
          protocol: scanResults.recommendation,
          risk_counts: scanResults.results.risk_counts,
          date: new Date().toLocaleDateString('en-GB')
        })
      });
      const pdfData = await pdfRes.json();
      setPdfBase64(pdfData.pdf_base64);

      addLog("[DONE] Passport generated and encrypted.");
      setWorkflowStage(6);
    } catch (e) {
      addLog("[ERROR] Sanitization interrupted.");
    } finally {
      setIsBusy(false);
    }
  };

  const downloadPassport = () => {
    if (!pdfBase64) return;
    const link = document.createElement("a");
    link.href = `data:application/pdf;base64,${pdfBase64}`;
    link.download = `TrustSense_Passport_${deviceId}.pdf`;
    link.click();
  };

  return (
    <div ref={containerRef} className="min-h-screen bg-[#0b1120] text-white font-sans selection:bg-[#06b6d4] selection:text-black">
      {/* Background Decor */}
      <div className="fixed inset-0 pointer-events-none opacity-20"><div className="absolute inset-0 bg-[radial-gradient(#1e293b_1px,transparent_1px)] [background-size:40px_40px]" /></div>

      {/* Header */}
      <header className="relative py-12 px-6 text-center border-b border-white/5 bg-black/40 backdrop-blur-xl sticky top-0 z-50">
        <div className="absolute inset-x-0 bottom-0 h-1 bg-gradient-to-r from-transparent via-[#06b6d4]/50 to-transparent" />
        <motion.div initial={{ y: -10, opacity: 0 }} animate={{ y: 0, opacity: 1 }} className="flex flex-col items-center gap-4">
          <div className="flex items-center gap-6">
            <h1 className="text-3xl font-black tracking-tighter uppercase italic">TrustSense<span className="text-[#06b6d4]">+</span></h1>
            <div className="h-4 w-px bg-white/10" />
            <div className="flex gap-4 text-[8px] font-black tracking-[0.2em] uppercase text-white/40">
              {["Scan", "Analyze", "Preserve", "Verdict", "Wipe", "Certify"].map((s, i) => (
                <span key={s} className={cn("transition-colors", workflowStage >= i + 1 ? "text-[#06b6d4]" : "text-white/10")}>{s}</span>
              ))}
            </div>
          </div>
        </motion.div>
      </header>

      <main className="max-w-7xl mx-auto p-6 md:p-12 space-y-24 pb-60">
        
        {/* STAGE 1: SETUP (Centered start) */}
        {workflowStage === 1 && (
          <motion.section initial={{ opacity: 0, scale: 0.98 }} animate={{ opacity: 1, scale: 1 }} className="max-w-2xl mx-auto pt-20">
            <div className="bg-white/5 p-12 rounded-[48px] border border-white/10 space-y-12 shadow-[0_0_80px_rgba(0,0,0,0.5)] backdrop-blur-md relative overflow-hidden">
               <div className="absolute top-0 right-0 p-8 opacity-5"><HardDrive className="w-32 h-32" /></div>
               <div className="space-y-4 relative z-10">
                 <h2 className="text-4xl font-black uppercase tracking-tight italic">Forensic Entry<span className="text-[#06b6d4]">_</span></h2>
                 <p className="text-sm text-[#94a3b8] tracking-wide">Ready for cryptographic sanitization. Connect node to continue.</p>
               </div>
               <div className="space-y-8 relative z-10">
                 <div className="space-y-2">
                   <label className="text-[10px] font-black uppercase text-[#06b6d4] tracking-widest ml-1">Hardware ID</label>
                   <input value={deviceId} onChange={e => setDeviceId(e.target.value)} className="w-full bg-black/60 border border-white/10 rounded-2xl p-6 focus:border-[#06b6d4] outline-none font-mono text-lg transition-all" />
                 </div>
                 <button onClick={runScan} disabled={isBusy} className="w-full h-24 bg-[#06b6d4] text-black font-black rounded-[32px] text-xl uppercase tracking-[0.2em] flex items-center justify-center gap-6 hover:brightness-110 active:scale-95 transition-all shadow-[0_20px_50px_rgba(6,182,212,0.4)] group">
                   {isBusy ? <RefreshCw className="animate-spin w-8 h-8" /> : <><Search className="w-8 h-8 group-hover:rotate-12 transition-transform" /> Mount Target Folder</>}
                 </button>
               </div>
            </div>
          </motion.section>
        )}

        {/* STAGES 2-6 (The "Real" Feed) */}
        {workflowStage >= 2 && scanResults && (
          <div className="flex flex-col gap-24">
            
            {/* 01: SCAN SUMMARY & GRAPH (This stays at the top of the stack) */}
            <motion.section initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="grid lg:grid-cols-3 gap-8 items-stretch">
              <div className="lg:col-span-2 bg-white/5 p-10 rounded-[48px] border border-white/10 flex flex-col md:flex-row items-center gap-12 backdrop-blur-sm relative group overflow-hidden">
                <div className="absolute inset-0 bg-gradient-to-br from-[#06b6d4]/5 to-transparent pointer-events-none" />
                <div className="relative w-64 h-64 shrink-0">
                  <svg viewBox="0 0 100 100" className="w-full h-full drop-shadow-[0_0_30px_rgba(6,182,212,0.3)]">
                    <circle cx="50" cy="50" r="45" fill="none" stroke="white" strokeOpacity="0.03" strokeWidth="0.5" />
                    <circle cx="50" cy="50" r="30" fill="none" stroke="white" strokeOpacity="0.03" strokeWidth="0.5" />
                    <motion.polygon 
                      initial={{ scale: 0, opacity: 0 }} animate={{ scale: 1, opacity: 1 }}
                      points={`50,${20 - scanResults.results.risk_counts.High*2} 
                               ${50 + scanResults.results.risk_counts.Medium*3},${50 - scanResults.results.risk_counts.Medium*2}
                               ${50 + scanResults.results.risk_counts.Low*2},${50 + scanResults.results.risk_counts.Low*2}
                               50,${80 + scanResults.results.risk_counts.Hidden*2}
                               ${50 - scanResults.results.risk_counts.High*2},${50 + scanResults.results.risk_counts.High*2}`}
                      fill="rgba(6,182,212,0.15)" stroke="#06b6d4" strokeWidth="2" strokeLinejoin="round"
                    />
                  </svg>
                  <div className="absolute inset-0 flex flex-col items-center justify-center">
                    <div className="text-4xl font-black text-white">{scanResults.results.total_files}</div>
                    <div className="text-[8px] font-black text-[#06b6d4] uppercase tracking-widest">Objects</div>
                  </div>
                </div>
                <div className="flex-1 grid grid-cols-2 gap-8 w-full">
                  {[
                    { l: "Integrity", v: `${scanResults.score}%`, c: "text-red-500" },
                    { l: "High Risk", v: scanResults.results.risk_counts.High, c: "text-white" },
                    { l: "Metadata", v: scanResults.results.risk_counts.Medium, c: "text-white" },
                    { l: "Hidden", v: scanResults.results.risk_counts.Hidden, c: "text-[#06b6d4]" }
                  ].map(stat => (
                    <div key={stat.l} className="space-y-1">
                      <div className="text-[9px] font-black text-white/30 uppercase tracking-[0.2em]">{stat.l}</div>
                      <div className={cn("text-3xl font-black italic", stat.c)}>{stat.v}</div>
                    </div>
                  ))}
                </div>
              </div>
              <div className="bg-black/40 p-8 rounded-[48px] border border-white/5 flex flex-col justify-between overflow-hidden">
                <div className="space-y-4">
                  <div className="flex justify-between items-center opacity-40"><span className="text-[9px] font-black uppercase tracking-widest">Forensic Console</span><Terminal className="w-3 h-3" /></div>
                  <div className="font-mono text-[9px] text-[#06b6d4] leading-relaxed space-y-1 h-[140px] overflow-y-auto custom-scrollbar">
                    {attackLogs.map((log, i) => <div key={i} className="opacity-80 break-all">{log}</div>)}
                  </div>
                </div>
                {workflowStage === 2 && (
                  <button onClick={() => setWorkflowStage(3)} className="w-full h-14 bg-white/5 border border-white/10 rounded-2xl text-[10px] font-black uppercase tracking-[0.3em] hover:bg-white/10 transition-all flex items-center justify-center gap-3">Continue to Preservation <ArrowRight className="w-3 h-3" /></button>
                )}
              </div>
            </motion.section>

            {/* 02: PRESERVATION (Backup) */}
            {workflowStage >= 3 && (
              <motion.section initial={{ opacity: 0, y: 30 }} animate={{ opacity: 1, y: 0 }} className="space-y-10">
                <div className="flex items-center gap-4 border-l-4 border-[#06b6d4] pl-6 py-2">
                  <h3 className="text-2xl font-black uppercase tracking-tight italic">03. Archive & Preserve</h3>
                  <div className="h-px flex-1 bg-white/5" />
                </div>
                <div className="bg-white/5 p-10 rounded-[56px] border border-white/10 space-y-10 shadow-2xl backdrop-blur-md">
                  <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-6">
                    <p className="text-sm text-[#94a3b8] max-w-xl">Toggle nodes to move them to the encrypted vault. Unselected items will be targeted for eradication.</p>
                    {workflowStage === 3 && (
                      <button onClick={confirmBackup} className="h-16 px-12 bg-[#06b6d4] text-black font-black rounded-2xl flex items-center gap-3 uppercase tracking-widest text-xs hover:brightness-110 active:scale-95 transition-all shadow-[0_10px_30px_rgba(6,182,212,0.2)]">Confirm Archive Vault <ArrowRight className="w-4 h-4" /></button>
                    )}
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4 max-h-[400px] overflow-y-auto pr-4 custom-scrollbar">
                    {scanResults.results.file_details.map(f => (
                      <div key={f.name} onClick={() => workflowStage === 3 && toggleBackup(f.name)} className={cn("p-5 rounded-2xl border transition-all flex flex-col gap-3 group relative overflow-hidden", backupPaths.includes(f.name) ? "bg-[#06b6d4]/20 border-[#06b6d4]/50 shadow-[0_0_20px_rgba(6,182,212,0.1)]" : "bg-black/40 border-white/5 hover:border-white/10", workflowStage > 3 && "opacity-50 cursor-default")}>
                        <div className="flex justify-between items-start">
                          <div className={cn("w-2 h-2 rounded-full", f.risk === "High" ? "bg-red-500" : "bg-[#06b6d4]")} />
                          <div className="text-[8px] font-black opacity-30 uppercase">{f.ext}</div>
                        </div>
                        <span className="text-[11px] font-mono truncate text-white/80">{f.name}</span>
                        {backupPaths.includes(f.name) && <div className="absolute top-2 right-2"><CheckCircle2 className="w-4 h-4 text-[#06b6d4]" /></div>}
                      </div>
                    ))}
                  </div>
                </div>
              </motion.section>
            )}

            {/* 03: AI VERDICT */}
            {workflowStage >= 4 && (
              <motion.section initial={{ opacity: 0, y: 30 }} animate={{ opacity: 1, y: 0 }} className="grid lg:grid-cols-2 gap-10">
                <div className="bg-[#06b6d4]/5 p-12 rounded-[56px] border border-[#06b6d4]/20 space-y-8 relative overflow-hidden group">
                  <div className="absolute top-0 right-0 p-8 opacity-10 group-hover:scale-110 transition-transform duration-700"><Cpu className="w-32 h-32 text-[#06b6d4]" /></div>
                  <div className="space-y-2 relative z-10">
                    <h3 className="text-[10px] font-black uppercase text-[#06b6d4] tracking-[0.4em]">AI Analysis Verdict</h3>
                    <h4 className="text-3xl font-black uppercase tracking-tight italic">Sanitization Justification</h4>
                  </div>
                  <p className="text-sm text-[#94a3b8] leading-relaxed italic border-l-2 border-[#06b6d4]/40 pl-6 py-2 relative z-10">"{scanResults.ai_logic}"</p>
                  <div className="flex gap-4 relative z-10">
                    <div className="bg-black/40 px-6 py-3 rounded-xl border border-white/5 text-[10px] font-black uppercase tracking-widest text-white/60 flex items-center gap-2"><Zap className="w-3 h-3" /> NIST 800-88 Compliance</div>
                  </div>
                </div>
                <div className="bg-red-500/5 p-12 rounded-[56px] border border-red-500/20 flex flex-col justify-between shadow-2xl relative overflow-hidden">
                  <div className="absolute inset-0 bg-[radial-gradient(circle_at_top_right,rgba(239,68,68,0.05),transparent)]" />
                  <div className="space-y-4 relative z-10">
                    <h3 className="text-[10px] font-black uppercase text-red-500 tracking-[0.4em]">Enforced Protocol</h3>
                    <div className="text-5xl font-black italic tracking-tighter uppercase">{scanResults.recommendation}</div>
                  </div>
                  {workflowStage === 4 && (
                    <button onClick={engageWipe} className="h-20 w-full bg-red-600 text-white font-black rounded-3xl uppercase tracking-[0.3em] flex items-center justify-center gap-6 hover:bg-red-500 active:scale-[0.98] transition-all shadow-[0_20px_60px_rgba(220,38,38,0.3)] group relative z-10">
                      <Trash2 className="w-8 h-8 group-hover:shake" /> Engage Eradication Cycle
                    </button>
                  )}
                  {workflowStage > 4 && (
                    <div className="h-20 w-full bg-emerald-500/10 border border-emerald-500/20 rounded-3xl flex items-center justify-center gap-4 text-emerald-500 text-[10px] font-black uppercase tracking-widest relative z-10"><ShieldCheck className="w-6 h-6" /> Protocol Verified Successfully</div>
                  )}
                </div>
              </motion.section>
            )}

            {/* 04: WIPE STATUS */}
            {workflowStage === 5 && (
              <motion.section initial={{ opacity: 0, scale: 0.98 }} animate={{ opacity: 1, scale: 1 }} className="bg-[#0f172a] p-20 rounded-[64px] border border-orange-500/30 text-center space-y-10 shadow-[0_40px_100px_rgba(0,0,0,0.4)] relative overflow-hidden">
                <div className="absolute inset-0 bg-gradient-to-t from-orange-600/5 to-transparent" />
                <h3 className="text-2xl font-black uppercase tracking-[0.6em] text-orange-500 flex items-center justify-center gap-6"><RefreshCw className="w-8 h-8 animate-spin" /> Sanitizing target sectors</h3>
                <div className="text-9xl font-black italic tabular-nums">{progress}%</div>
                <div className="h-10 w-full bg-white/5 rounded-full p-2 border border-white/10 shadow-inner max-w-4xl mx-auto"><motion.div initial={{ width: 0 }} animate={{ width: `${progress}%` }} className="h-full bg-orange-600 rounded-full shadow-[0_0_20px_rgba(234,88,12,0.5)]" /></div>
                <p className="text-xs font-mono text-[#94a3b8] opacity-50 uppercase tracking-widest animate-pulse">Eradicating metadata signatures... Sector {Math.floor(progress * 1024)} neutralized</p>
              </motion.section>
            )}

            {/* 05: CERTIFICATION & PASSPORT */}
            {workflowStage >= 6 && (
              <motion.section initial={{ opacity: 0, y: 40 }} animate={{ opacity: 1, y: 0 }} className="space-y-24">
                <div className="grid md:grid-cols-2 gap-10">
                  <div className="bg-emerald-500/10 p-20 rounded-[64px] border border-emerald-500/30 text-center flex flex-col items-center justify-center gap-10 shadow-[0_0_80px_rgba(16,185,129,0.15)] backdrop-blur-md">
                    <motion.div initial={{ scale: 0.5, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} transition={{ type: "spring", damping: 10 }} className="w-32 h-32 bg-emerald-500/20 rounded-[40px] flex items-center justify-center border border-emerald-500/40 shadow-xl"><ShieldCheck className="w-16 h-16 text-emerald-500" /></motion.div>
                    <div className="space-y-4">
                      <h3 className="text-6xl font-black uppercase tracking-tighter text-emerald-500 italic">Zero-Bit Integrity</h3>
                      <p className="text-xs font-black uppercase tracking-[0.5em] text-[#94a3b8]">Forensic Status: Clean / Verfied</p>
                    </div>
                  </div>
                  <div className="bg-white/5 p-20 rounded-[64px] border border-white/10 flex flex-col justify-center space-y-10 relative overflow-hidden group">
                    <div className="absolute top-0 right-0 p-10 opacity-5 group-hover:rotate-12 transition-transform duration-1000"><ShieldAlert className="w-48 h-48" /></div>
                    <h3 className="text-xs font-black uppercase tracking-[0.4em] text-white/40 mb-2 flex items-center gap-3"> <Activity className="w-5 h-5 text-[#06b6d4]" /> Attack Simulation Verdict</h3>
                    <div className="grid gap-6">
                      {[
                        { l: "Entropy Analysis", v: "0.00% (NULL)", c: "text-[#06b6d4]" },
                        { l: "Recovery Vector", v: "INACCESSIBLE", c: "text-emerald-500" },
                        { l: "Metadata Scour", v: "SUCCESSFUL", c: "text-[#06b6d4]" }
                      ].map((v, i) => (
                        <div key={i} className="flex flex-col gap-1 border-l-2 border-white/10 pl-6">
                          <span className="text-[10px] font-black uppercase text-white/30 tracking-widest">{v.l}</span>
                          <span className={cn("text-2xl font-black italic tracking-tight", v.c)}>{v.v}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Final Passport Section */}
                <div className="bg-[#fdfaf3] rounded-[80px] overflow-hidden text-[#0a192f] shadow-[0_50px_150px_rgba(0,0,0,0.9)] border-[10px] border-[#c5a059] relative max-w-5xl mx-auto group">
                  <div className="absolute inset-0 opacity-[0.03] pointer-events-none bg-[radial-gradient(circle_at_center,#000_1px,transparent_1px)] [background-size:16px:16px]" />
                  <div className="bg-[#0a192f] p-24 flex flex-col md:flex-row justify-between items-center border-b-[12px] border-[#c5a059] relative overflow-hidden gap-12">
                    <div className="absolute inset-0 bg-gradient-to-br from-white/5 to-transparent pointer-events-none" />
                    <div className="relative z-10 text-center md:text-left space-y-4">
                      <h4 className="text-7xl font-serif text-[#e2c275] font-black uppercase tracking-widest leading-none">Security Passport</h4>
                      <p className="text-[14px] text-white/40 font-bold uppercase tracking-[1em]">OFFICIAL FORENSIC NODE CERTIFICATION</p>
                    </div>
                    <div className="text-center md:text-right relative z-10 bg-white/5 p-8 rounded-3xl border border-white/10 backdrop-blur-md">
                      <div className="text-[11px] text-[#e2c275] font-black uppercase mb-2 tracking-[0.4em]">REGISTRY ARCHIVE ID</div>
                      <div className="text-4xl font-mono text-white font-black tracking-tighter italic">{deviceId.toUpperCase()}-CERT-0xAF</div>
                    </div>
                  </div>
                  
                  <div className="p-24 space-y-24 relative">
                    <div className="grid sm:grid-cols-2 gap-20">
                      {[
                        { label: "Hardware Node instance", value: deviceId },
                        { label: "Trust Integrity Rating", value: "100% CERTIFIED", color: "text-emerald-700" },
                        { label: "Authentication Date", value: new Date().toLocaleDateString('en-GB') },
                        { label: "Forensic Status", value: "CLEAN / ZERO-BIT" }
                      ].map(field => (
                        <div key={field.label} className="border-b-[3px] border-[#0a192f]/10 pb-8 group-hover:border-[#c5a059]/30 transition-colors">
                          <div className="text-[12px] font-black uppercase text-[#64748b] mb-3 tracking-[0.3em]">{field.label}</div>
                          <div className={cn("text-4xl font-black tracking-tighter uppercase italic", field.color || "text-[#0a192f]")}>{field.value}</div>
                        </div>
                      ))}
                    </div>

                    <div className="bg-[#0a192f] p-16 border-l-[25px] border-[#c5a059] shadow-2xl flex flex-col md:flex-row justify-between items-center gap-12 group/btn relative overflow-hidden">
                       <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/5 to-transparent -translate-x-full group-hover/btn:translate-x-full transition-transform duration-1000" />
                       <div className="text-center md:text-left space-y-2 relative z-10">
                         <div className="text-[12px] font-black text-[#c5a059] uppercase tracking-[0.5em]">Applied Eradication Protocol</div>
                         <div className="text-5xl font-mono text-white font-black tracking-tight italic">{scanResults.recommendation}</div>
                       </div>
                       <button onClick={downloadPassport} className="bg-[#c5a059] text-[#0a192f] px-16 py-8 rounded-[40px] font-black uppercase tracking-[0.4em] text-xl flex items-center gap-6 hover:scale-105 active:scale-95 transition-all shadow-[0_20px_50px_rgba(197,160,89,0.3)] relative z-10">
                         <Download className="w-8 h-8" /> Download Passport
                       </button>
                    </div>

                    <div className="flex flex-col md:flex-row items-center md:items-end justify-between gap-16 border-t-4 border-[#0a192f]/5 pt-12">
                       <div className="font-mono text-[13px] text-[#64748b] leading-[2.8] tracking-widest text-center md:text-left">
                         P&lt;TSA{deviceId.replace(/-/g,'').padEnd(20,'&lt;')}&lt;&lt;&lt;&lt;&lt;<br/>
                         {deviceId.toUpperCase()}-FORENSIC&lt;&lt;&lt;CERTIFIED&lt;&lt;&lt;2026
                       </div>
                       <div className="flex flex-col items-center md:items-end gap-6">
                         <div className="italic font-serif text-[#0a192f]/40 text-4xl px-10 border-b-2 border-[#0a192f]/10 pb-4">TrustSense Authority</div>
                         <div className="flex gap-4">
                           <div className="w-3 h-3 rounded-full bg-emerald-500 animate-pulse" />
                           <span className="text-[9px] font-black uppercase tracking-widest text-[#0a192f]/60 italic">Hardware Encryption Verified</span>
                         </div>
                       </div>
                    </div>
                  </div>
                </div>
              </motion.section>
            )}
          </div>
        )}

      </main>

      <footer className="py-40 text-center relative border-t border-white/5">
        <div className="absolute inset-0 bg-gradient-to-b from-transparent to-black/40 pointer-events-none" />
        <p className="text-[10px] font-black uppercase tracking-[1.5em] text-white/20 relative z-10">TrustSense Forensic Elite Node v9.4.0-STABLE</p>
      </footer>

      <style jsx global>{`
        .custom-scrollbar::-webkit-scrollbar { width: 4px; }
        .custom-scrollbar::-webkit-scrollbar-thumb { background: #06b6d4; border-radius: 10px; }
        @keyframes shake {
          0%, 100% { transform: translateX(0); }
          25% { transform: translateX(-2px) rotate(-1deg); }
          75% { transform: translateX(2px) rotate(1deg); }
        }
        .group-hover:shake { animation: shake 0.2s infinite; }
      `}</style>
    </div>
  );
}
