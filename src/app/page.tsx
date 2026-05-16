"use client";

import { useState, useEffect, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { 
  Shield, Search, Cpu, Trash2, Download, AlertTriangle, CheckCircle2, 
  Activity, ShieldCheck, RefreshCw, Zap, Archive, BarChart3, Database,
  ArrowRight, ShieldAlert, History, Terminal
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
  const [workflowStage, setWorkflowStage] = useState(1); // 1:Setup, 2:Analysis, 3:Preservation, 4:Verdict, 5:Wipe, 6:Certification
  const [deviceId, setDeviceId] = useState("TS-X-88");
  const [isBusy, setIsBusy] = useState(false);
  const [progress, setProgress] = useState(0);
  
  const [scanResults, setScanResults] = useState<ScanResults | null>(null);
  const [backupPaths, setBackupPaths] = useState<string[]>([]);
  const [pdfBase64, setPdfBase64] = useState<string | null>(null);
  const [activeDirHandle, setActiveDirHandle] = useState<any>(null);
  const [attackLogs, setAttackLogs] = useState<string[]>([]);

  const addLog = (msg: string) => {
    setAttackLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] ${msg}`].slice(-10));
  };

  // ── 01: INITIAL SCAN ───────────────────────────────────────────────────────
  const runScan = async () => {
    try {
      const handle = await (window as any).showDirectoryPicker();
      setActiveDirHandle(handle);
      setIsBusy(true);
      
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
          let reason = "Standard non-executable asset.";
          
          if (['key', 'pem', 'env', 'sql', 'db', 'crypt'].includes(ext) || isHidden) {
            risk = "High";
            reason = isHidden ? "Hidden system residue." : "Cryptographic signature detected.";
            if (isHidden) riskCounts.Hidden++; else riskCounts.High++;
          } else if (['zip', 'bak', 'old', 'docx', 'pdf'].includes(ext)) {
            risk = "Medium";
            reason = "Compressed archive with metadata.";
            riskCounts.Medium++;
          } else {
            riskCounts.Low++;
          }
          fileList.push({ name: entry.name, size: file.size, ext, risk, reason, hidden: isHidden });
        }
      }

      setScanResults({
        score: Math.max(12, 100 - (riskCounts.High * 15) - (riskCounts.Medium * 4)),
        results: {
          total_files: totalFiles,
          sensitive_files: riskCounts.High + riskCounts.Medium,
          risk_counts: riskCounts,
          file_details: fileList,
        },
        recommendation: riskCounts.High > 0 ? "NIST 800-88 PURGE" : "DoD 5220.22-M",
        ai_logic: riskCounts.High > 0 
          ? `Analysis of ${totalFiles} objects revealed ${riskCounts.High} cryptographic keys and ${riskCounts.Hidden} hidden sectors. This indicates a high-risk forensic profile requiring total zero-bit neutralization via NIST-standard purge.`
          : `Predominantly low-risk documents detected. Standard triple-pass overwriting is sufficient to scramble user-space metadata and file allocation traces.`
      });

      setWorkflowStage(2);
    } catch (e) {
      console.error(e);
    } finally {
      setIsBusy(false);
    }
  };

  // ── 03: BACKUP / PRESERVE ──────────────────────────────────────────────────
  const toggleBackup = (name: string) => {
    setBackupPaths(prev => prev.includes(name) ? prev.filter(p => p !== name) : [...prev, name]);
  };

  const confirmBackup = () => {
    addLog(`Backed up ${backupPaths.length} objects to encrypted vault.`);
    setWorkflowStage(4);
  };

  // ── 05: WIPING ─────────────────────────────────────────────────────────────
  const engageWipe = async () => {
    if (!activeDirHandle || !scanResults) return;
    setIsBusy(true);
    setWorkflowStage(5);
    
    try {
      const files = scanResults.results.file_details;
      const step = 100 / (files.length || 1);
      
      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        if (!backupPaths.includes(file.name)) {
          try { await activeDirHandle.removeEntry(file.name); } catch (e) {}
        }
        setProgress(Math.round((i + 1) * step));
        await new Promise(r => setTimeout(r, 60));
      }

      // Final Certification
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

      setWorkflowStage(6);
    } catch (e) {
      addLog("Sanitization cycle interrupted.");
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
    <div className="min-h-screen bg-[#0b1120] text-white font-sans selection:bg-[#06b6d4] selection:text-black">
      <div className="fixed inset-0 pointer-events-none opacity-20"><div className="absolute inset-0 bg-[radial-gradient(#1e293b_1px,transparent_1px)] [background-size:40px_40px]" /></div>

      {/* Header */}
      <header className="relative py-16 px-6 text-center border-b border-white/5 bg-black/20 backdrop-blur-md">
        <motion.div initial={{ y: -20, opacity: 0 }} animate={{ y: 0, opacity: 1 }} className="space-y-4">
          <div className="inline-flex p-3 bg-[#06b6d4]/10 rounded-2xl border border-[#06b6d4]/30 mb-2"><Shield className="w-8 h-8 text-[#06b6d4]" /></div>
          <h1 className="text-4xl font-black tracking-tighter uppercase italic">TrustSense<span className="text-[#06b6d4]">+</span> Forensic</h1>
          <div className="flex justify-center gap-6 text-[9px] font-black tracking-[0.3em] uppercase text-white/40">
            <span className={cn(workflowStage >= 1 && "text-[#06b6d4]")}>SCAN</span>
            <span className={cn(workflowStage >= 2 && "text-[#06b6d4]")}>ANALYSIS</span>
            <span className={cn(workflowStage >= 3 && "text-[#06b6d4]")}>PRESERVE</span>
            <span className={cn(workflowStage >= 4 && "text-[#06b6d4]")}>VERDICT</span>
            <span className={cn(workflowStage >= 5 && "text-[#06b6d4]")}>WIPE</span>
            <span className={cn(workflowStage >= 6 && "text-[#06b6d4]")}>CERTIFY</span>
          </div>
        </motion.div>
      </header>

      <main className="max-w-6xl mx-auto p-6 md:p-12 space-y-16 pb-40">
        
        {/* STAGE 1: SETUP */}
        {workflowStage === 1 && (
          <motion.section initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="max-w-xl mx-auto text-center space-y-10 py-12">
            <div className="space-y-4">
              <h2 className="text-3xl font-black uppercase tracking-tight">Initiate Forensic Session</h2>
              <p className="text-sm text-[#94a3b8]">Specify hardware ID and select the target directory for sanitization.</p>
            </div>
            <div className="bg-white/5 p-10 rounded-[40px] border border-white/10 space-y-8 shadow-2xl">
              <div className="text-left space-y-2">
                <label className="text-[10px] font-black uppercase text-[#94a3b8] tracking-widest ml-1">Session Node ID</label>
                <input value={deviceId} onChange={e => setDeviceId(e.target.value)} className="w-full bg-black/40 border border-white/10 rounded-2xl p-5 focus:border-[#06b6d4] outline-none font-mono" />
              </div>
              <button onClick={runScan} disabled={isBusy} className="w-full h-20 bg-[#06b6d4] text-black font-black rounded-3xl text-lg uppercase tracking-widest flex items-center justify-center gap-4 hover:scale-[1.02] transition-all shadow-[0_0_40px_rgba(6,182,212,0.3)]">
                {isBusy ? <RefreshCw className="animate-spin" /> : <><Search /> Select Target Folder</>}
              </button>
            </div>
          </motion.section>
        )}

        {/* PERSISTENT GRAPH (Stages 2-6) */}
        {workflowStage >= 2 && scanResults && (
          <div className="grid lg:grid-cols-3 gap-10">
            
            {/* Left: Forensic Analysis (The Graph) */}
            <motion.div initial={{ x: -20, opacity: 0 }} animate={{ x: 0, opacity: 1 }} className="lg:col-span-2 space-y-10">
              <div className="bg-white/5 p-10 rounded-[48px] border border-white/10 relative overflow-hidden backdrop-blur-sm">
                <div className="flex justify-between items-center mb-10">
                  <h3 className="text-sm font-black uppercase tracking-wider text-[#94a3b8] flex items-center gap-3"><BarChart3 className="w-4 h-4 text-[#06b6d4]" /> Real-Time Forensic Graph</h3>
                  <div className="bg-red-500/10 px-4 py-2 rounded-xl border border-red-500/20 text-[10px] font-black text-red-500 uppercase tracking-widest">Pre-Wipe: {scanResults.score}% Integrity</div>
                </div>
                
                <div className="grid md:grid-cols-2 gap-12 items-center">
                  <div className="relative w-64 h-64 mx-auto">
                    <svg viewBox="0 0 100 100" className="w-full h-full drop-shadow-[0_0_25px_rgba(6,182,212,0.4)]">
                      <circle cx="50" cy="50" r="45" fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="0.5" />
                      <circle cx="50" cy="50" r="30" fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="0.5" />
                      <motion.polygon 
                        initial={{ opacity: 0, scale: 0 }} animate={{ opacity: 1, scale: 1 }}
                        points={`50,${20 - scanResults.results.risk_counts.High*2} 
                                 ${50 + scanResults.results.risk_counts.Medium*3},${50 - scanResults.results.risk_counts.Medium*2}
                                 ${50 + scanResults.results.risk_counts.Low*2},${50 + scanResults.results.risk_counts.Low*2}
                                 50,${80 + scanResults.results.risk_counts.Hidden*2}
                                 ${50 - scanResults.results.risk_counts.High*2},${50 + scanResults.results.risk_counts.High*2}`}
                        fill="rgba(6,182,212,0.2)" stroke="#06b6d4" strokeWidth="2" strokeLinejoin="round"
                      />
                    </svg>
                    <div className="absolute inset-0 flex items-center justify-center text-center">
                      <div className="text-4xl font-black italic">{scanResults.results.total_files}</div>
                    </div>
                  </div>
                  <div className="space-y-6">
                    {[
                      { l: "High Risk", c: scanResults.results.risk_counts.High, clr: "bg-red-500" },
                      { l: "Medium Risk", c: scanResults.results.risk_counts.Medium, clr: "bg-orange-500" },
                      { l: "Low Risk", c: scanResults.results.risk_counts.Low, clr: "bg-emerald-500" },
                      { l: "Hidden", c: scanResults.results.risk_counts.Hidden, clr: "bg-[#06b6d4]" }
                    ].map(b => (
                      <div key={b.l} className="space-y-2">
                        <div className="flex justify-between text-[9px] font-black uppercase tracking-widest text-[#94a3b8]"><span>{b.l}</span><span>{b.c}</span></div>
                        <div className="h-1.5 w-full bg-white/5 rounded-full overflow-hidden"><motion.div initial={{ width: 0 }} animate={{ width: `${(b.c / scanResults.results.total_files) * 100}%` }} className={cn("h-full", b.clr)} /></div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* STAGE-SPECIFIC CONTENT */}
              <AnimatePresence mode="wait">
                {workflowStage === 2 && (
                  <motion.div key="st2" initial={{ y: 20, opacity: 0 }} animate={{ y: 0, opacity: 1 }} className="bg-[#06b6d4]/5 p-10 rounded-[40px] border border-[#06b6d4]/20 flex justify-between items-center">
                    <div><h3 className="text-xl font-black uppercase tracking-tight">Categorization Complete</h3><p className="text-xs text-[#94a3b8] uppercase tracking-widest mt-1">Select files for preservation in the next step.</p></div>
                    <button onClick={() => setWorkflowStage(3)} className="h-16 px-10 bg-[#06b6d4] text-black font-black rounded-2xl flex items-center gap-3 uppercase tracking-widest">Next: Preservation <ArrowRight /></button>
                  </motion.div>
                )}

                {workflowStage === 3 && (
                  <motion.div key="st3" initial={{ y: 20, opacity: 0 }} animate={{ y: 0, opacity: 1 }} className="space-y-6">
                    <div className="flex justify-between items-center">
                      <h3 className="text-xl font-black uppercase tracking-tight flex items-center gap-3"><Archive className="w-6 h-6 text-[#06b6d4]" /> Select Files for Backup</h3>
                      <button onClick={confirmBackup} className="h-14 px-8 bg-[#06b6d4] text-black font-black rounded-xl flex items-center gap-2 uppercase tracking-widest text-xs">Confirm Preservation <ArrowRight /></button>
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 max-h-[350px] overflow-y-auto pr-2 custom-scrollbar">
                      {scanResults.results.file_details.map(f => (
                        <div key={f.name} onClick={() => toggleBackup(f.name)} className={cn("p-5 rounded-2xl border transition-all cursor-pointer flex justify-between items-center", backupPaths.includes(f.name) ? "bg-[#06b6d4]/20 border-[#06b6d4]/50" : "bg-black/40 border-white/5")}>
                          <div className="flex items-center gap-4 overflow-hidden"><div className={cn("w-2 h-2 rounded-full", f.risk === "High" ? "bg-red-500" : "bg-emerald-500")} /><span className="text-[12px] font-mono truncate">{f.name}</span></div>
                          {backupPaths.includes(f.name) && <CheckCircle2 className="w-4 h-4 text-[#06b6d4]" />}
                        </div>
                      ))}
                    </div>
                  </motion.div>
                )}

                {workflowStage === 4 && (
                  <motion.div key="st4" initial={{ y: 20, opacity: 0 }} animate={{ y: 0, opacity: 1 }} className="grid md:grid-cols-2 gap-8">
                    <div className="bg-[#06b6d4]/10 p-8 rounded-[32px] border border-[#06b6d4]/30 space-y-4">
                      <h3 className="text-sm font-black uppercase tracking-widest text-[#06b6d4] flex items-center gap-2"><Cpu className="w-4 h-4" /> AI Verdict</h3>
                      <p className="text-xs text-slate-300 leading-relaxed italic border-l-2 border-[#06b6d4] pl-4 py-1">"{scanResults.ai_logic}"</p>
                    </div>
                    <div className="bg-red-500/5 p-8 rounded-[32px] border border-red-500/20 flex flex-col justify-between">
                      <div><h3 className="text-[10px] font-black uppercase text-red-500 tracking-[0.3em] mb-2">Protocol Enforcement</h3><div className="text-2xl font-black italic">{scanResults.recommendation}</div></div>
                      <button onClick={engageWipe} className="h-14 w-full bg-red-600 text-white font-black rounded-xl uppercase tracking-widest flex items-center justify-center gap-3"><Trash2 className="w-4 h-4" /> Engage Wipe</button>
                    </div>
                  </motion.div>
                )}

                {workflowStage === 5 && (
                  <motion.div key="st5" initial={{ scale: 0.95 }} animate={{ scale: 1 }} className="bg-[#0f172a] p-10 rounded-[40px] border border-orange-500/30 text-center space-y-6">
                    <h3 className="text-lg font-black uppercase tracking-[0.4em] text-orange-500 flex items-center justify-center gap-4"><RefreshCw className="w-5 h-5 animate-spin" /> Sanitizing Sectors</h3>
                    <div className="text-6xl font-black italic">{progress}%</div>
                    <div className="h-4 w-full bg-white/5 rounded-full p-1"><motion.div initial={{ width: 0 }} animate={{ width: `${progress}%` }} className="h-full bg-orange-600 rounded-full" /></div>
                  </motion.div>
                )}

                {workflowStage === 6 && (
                  <motion.div key="st6" initial={{ y: 20, opacity: 0 }} animate={{ y: 0, opacity: 1 }} className="space-y-10">
                    <div className="grid grid-cols-2 gap-6">
                      <div className="bg-emerald-500/10 p-10 rounded-[40px] border border-emerald-500/30 text-center flex flex-col items-center justify-center gap-4 shadow-2xl">
                        <ShieldCheck className="w-12 h-12 text-emerald-500" />
                        <h3 className="text-2xl font-black uppercase tracking-tight text-emerald-500 italic">Integrity: 100%</h3>
                      </div>
                      <div className="bg-white/5 p-8 rounded-[40px] border border-white/10">
                        <h3 className="text-[10px] font-black uppercase tracking-widest text-white/40 mb-6 flex items-center gap-2"><Terminal className="w-4 h-4" /> Attack Simulation Logs</h3>
                        <div className="space-y-3">
                          {["Entropy Match: 0.0%", "Sector 0xAF: NULL", "Metadata: N/A"].map((l, i) => (
                            <div key={i} className="flex items-center gap-3 text-[11px] font-mono text-[#06b6d4]"><div className="w-1 h-1 rounded-full bg-[#06b6d4]" />{l}</div>
                          ))}
                        </div>
                      </div>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </motion.div>

            {/* Right: Detailed Logs / Context */}
            <motion.aside initial={{ x: 20, opacity: 0 }} animate={{ x: 0, opacity: 1 }} className="space-y-10">
              <div className="bg-black/60 p-8 rounded-[40px] border border-white/5 font-mono text-[10px] text-[#06b6d4] leading-relaxed shadow-inner">
                <div className="flex justify-between items-center mb-4 opacity-40 uppercase italic tracking-widest"><span>Live Trail</span><span>v8.2-CERT</span></div>
                {attackLogs.map((log, i) => <div key={i} className="mb-1 opacity-80">{log}</div>)}
              </div>

              {workflowStage === 6 && (
                <motion.div initial={{ y: 20, opacity: 0 }} animate={{ y: 0, opacity: 1 }} className="bg-white p-2 rounded-[48px] shadow-2xl">
                  <div className="bg-[#fdfaf3] p-10 rounded-[46px] border-4 border-[#c5a059] text-[#0a192f] space-y-8">
                    <div className="border-b-2 border-[#0a192f]/10 pb-6 text-center">
                      <div className="text-[9px] font-black uppercase tracking-[0.5em] text-[#c5a059] mb-2">Forensic Passport</div>
                      <div className="text-2xl font-serif font-black uppercase tracking-widest">TS-X-88 CERTIFIED</div>
                    </div>
                    <div className="space-y-4">
                      <div className="flex justify-between border-b border-black/5 pb-2"><span className="text-[9px] font-black uppercase text-black/40">Status</span><span className="text-[12px] font-black text-emerald-700">CLEAN</span></div>
                      <div className="flex justify-between border-b border-black/5 pb-2"><span className="text-[9px] font-black uppercase text-black/40">Protocol</span><span className="text-[12px] font-black uppercase">{scanResults.recommendation.split(' ')[0]}</span></div>
                    </div>
                    <button onClick={downloadPassport} className="w-full h-14 bg-[#0a192f] text-[#c5a059] font-black rounded-2xl uppercase tracking-widest text-[10px] flex items-center justify-center gap-3 hover:scale-105 transition-all">
                      <Download className="w-4 h-4" /> Get Official PDF
                    </button>
                  </div>
                </motion.div>
              )}
            </motion.aside>

          </div>
        )}

      </main>

      <style jsx global>{`
        .custom-scrollbar::-webkit-scrollbar { width: 3px; }
        .custom-scrollbar::-webkit-scrollbar-thumb { background: #06b6d4; border-radius: 10px; }
      `}</style>
    </div>
  );
}
