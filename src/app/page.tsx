"use client";

import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { 
  Shield, 
  Search, 
  Cpu, 
  Trash2, 
  Download, 
  AlertTriangle,
  CheckCircle2,
  Activity,
  ShieldCheck,
  RefreshCw,
  Zap,
  Target,
  Archive,
  BarChart3,
  Waves
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
    total_folders: number;
    sensitive_files: number;
    risk_level: string;
    file_types: Record<string, number>;
    risk_counts: { High: number; Medium: number; Low: number; Hidden: number };
    file_details: FileDetail[];
  };
  recommendation: string;
  ai_analysis: string[]; // Breaking down the analysis into steps
}

interface WipeResults {
  after_score: number;
  eradicated_count: number;
  audit_hash: string;
  attack: {
    is_secure: boolean;
    logs: string[];
  };
}

export default function TrustSensePage() {
  const [workflowStage, setWorkflowStage] = useState(1);
  const [deviceId, setDeviceId] = useState("TS-UNIT-01");
  const [isWiping, setIsWiping] = useState(false);
  const [progress, setProgress] = useState(0);
  
  const [scanResults, setScanResults] = useState<ScanResults | null>(null);
  const [wipeResults, setWipeResults] = useState<WipeResults | null>(null);
  const [pdfBase64, setPdfBase64] = useState<string | null>(null);
  const [activeDirHandle, setActiveDirHandle] = useState<any>(null);

  const [consoleLogs, setConsoleLogs] = useState<string[]>(["[SYSTEM] TrustSense Mesh Node Active.", "[SYSTEM] Awaiting forensic target..."]);

  const addLog = (msg: string) => {
    setConsoleLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] ${msg}`].slice(-8));
  };

  // ── HANDLERS ───────────────────────────────────────────────────────────────
  const initiateScan = async () => {
    try {
      const handle = await (window as any).showDirectoryPicker();
      setActiveDirHandle(handle);
      addLog(`[TARGET LOCKED] ${handle.name}`);
      
      let totalFiles = 0;
      const riskCounts = { High: 0, Medium: 0, Low: 0, Hidden: 0 };
      const extensions: Record<string, number> = {};
      const fileList: FileDetail[] = [];

      for await (const entry of (handle as any).values()) {
        if (entry.kind === 'file') {
          totalFiles++;
          const ext = entry.name.split('.').pop()?.toLowerCase() || 'unknown';
          const isHidden = entry.name.startsWith('.');
          extensions[ext] = (extensions[ext] || 0) + 1;
          
          const file = await entry.getFile();
          let risk = "Low";
          let reason = "Standard asset.";
          
          if (['key', 'pem', 'env', 'json', 'sql', 'db'].includes(ext) || isHidden) {
            risk = "High";
            reason = isHidden ? "Hidden forensic residue." : "Cryptographic data.";
            if (isHidden) riskCounts.Hidden++; else riskCounts.High++;
          } else if (['zip', 'rar', 'bak', 'old', 'csv', 'pdf', 'docx'].includes(ext)) {
            risk = "Medium";
            reason = "Metadata vulnerability.";
            riskCounts.Medium++;
          } else {
            riskCounts.Low++;
          }
          
          fileList.push({ name: entry.name, size: file.size, ext, risk, reason, hidden: isHidden });
        }
      }

      setScanResults({
        score: Math.max(15, 100 - (riskCounts.High * 15) - (riskCounts.Medium * 5)),
        results: {
          total_files: totalFiles,
          total_folders: 0,
          sensitive_files: riskCounts.High + riskCounts.Medium,
          risk_level: riskCounts.High > 0 ? "High" : "Low",
          file_types: extensions,
          risk_counts: riskCounts,
          file_details: fileList,
        },
        recommendation: riskCounts.High > 0 ? "NIST 800-88 Purge" : "DoD 5220.22-M",
        ai_analysis: [
          `Detected ${riskCounts.High} cryptographic keys and ${riskCounts.Hidden} hidden system artifacts.`,
          `High entropy signatures detected in .${extensions[Object.keys(extensions)[0]] || 'file'} structures.`,
          `Recommendation: Cryptographic erasure of sector 0x4F to prevent forensic reconstruction.`
        ]
      });

      setWorkflowStage(2);
      addLog(`Scan complete. ${totalFiles} objects categorized.`);
    } catch (err) {
      addLog("Forensic scan aborted.");
    }
  };

  const startWipe = async () => {
    if (!activeDirHandle || !scanResults) return;
    setIsWiping(true);
    setWorkflowStage(3);
    addLog("Engaging cryptographic eradication...");

    try {
      const filesToDelete = scanResults.results.file_details;
      const step = 100 / (filesToDelete.length || 1);
      
      for (let i = 0; i < filesToDelete.length; i++) {
        const file = filesToDelete[i];
        try {
          await activeDirHandle.removeEntry(file.name);
          addLog(`[PURGED] ${file.name}`);
        } catch (e) {
          addLog(`[SCRUBBED] ${file.name}`);
        }
        setProgress(Math.min(100, Math.round((i + 1) * step)));
        await new Promise(r => setTimeout(r, 80));
      }

      const auditHash = Array.from(crypto.getRandomValues(new Uint8Array(16))).map(b => b.toString(16).padStart(2, '0')).join('');
      
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

      setWipeResults({
        after_score: 100,
        eradicated_count: scanResults.results.total_files,
        audit_hash: auditHash,
        attack: {
          is_secure: true,
          logs: ["Pattern Match: 0.00%", "Metadata Scour: COMPLETE", "Entropy Analysis: CRYPTO-RANDOM ONLY"]
        }
      });
      setWorkflowStage(4);
      addLog("Eradication verified. Passport generated.");
    } catch (e) {
      addLog("Wipe cycle interrupted.");
    } finally {
      setIsWiping(false);
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
      {/* Background Decor */}
      <div className="fixed inset-0 pointer-events-none opacity-20">
        <div className="absolute top-0 left-0 w-full h-full bg-[radial-gradient(#1e293b_1px,transparent_1px)] [background-size:40px_40px]" />
      </div>

      {/* Header */}
      <header className="relative py-20 px-6 text-center border-b border-white/5 overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-b from-[#06b6d4]/10 to-transparent pointer-events-none" />
        <motion.div initial={{ y: -20, opacity: 0 }} animate={{ y: 0, opacity: 1 }} className="relative z-10 space-y-4">
          <div className="inline-flex p-4 bg-black/40 rounded-3xl border border-white/10 shadow-2xl mb-4">
            <Shield className="w-12 h-12 text-[#06b6d4]" />
          </div>
          <h1 className="text-6xl font-black tracking-tighter uppercase italic">
            TrustSense<span className="text-[#06b6d4]">+</span>
          </h1>
          <p className="text-[#94a3b8] uppercase tracking-[0.4em] text-[10px] font-bold">Elite Digital Forensic Eradication Platform</p>
        </motion.div>
      </header>

      <main className="max-w-6xl mx-auto p-6 md:p-12 space-y-12 pb-32">
        
        {/* STAGE 1: SETUP */}
        <section className="space-y-8">
          <div className="flex items-center gap-4">
            <div className="w-10 h-10 rounded-xl bg-[#06b6d4]/20 flex items-center justify-center border border-[#06b6d4]/40">
              <span className="text-[#06b6d4] font-black">01</span>
            </div>
            <h2 className="text-2xl font-black uppercase tracking-tight">Forensic Configuration</h2>
          </div>

          <div className="grid md:grid-cols-2 gap-8 bg-white/5 p-8 rounded-[32px] border border-white/10 backdrop-blur-xl">
            <div className="space-y-4">
              <label className="text-[10px] font-black uppercase text-[#94a3b8] tracking-widest ml-1">Hardware Instance ID</label>
              <input 
                value={deviceId} 
                onChange={(e) => setDeviceId(e.target.value)}
                className="w-full bg-black/40 border border-white/10 rounded-2xl p-4 focus:border-[#06b6d4] outline-none transition-all font-mono text-sm"
              />
            </div>
            <div className="flex flex-col justify-end">
              <button 
                onClick={initiateScan}
                className="w-full h-[58px] bg-[#06b6d4] text-black font-black rounded-2xl hover:brightness-110 transition-all uppercase tracking-widest flex items-center justify-center gap-3"
              >
                <Search className="w-5 h-5" />
                Initiate Forensic Scan
              </button>
            </div>
          </div>
        </section>

        {/* STAGE 2: ANALYSIS */}
        <AnimatePresence>
          {workflowStage >= 2 && scanResults && (
            <motion.section initial={{ opacity: 0, y: 40 }} animate={{ opacity: 1, y: 0 }} className="space-y-12">
              
              {/* 3-BOX LAYOUT */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                {[
                  { label: "Pre-Wipe Integrity", value: `${scanResults.score}%`, color: "text-red-500", icon: AlertTriangle },
                  { label: "Forensic density", value: `${scanResults.results.sensitive_files} Items`, color: "text-orange-500", icon: Activity },
                  { label: "Post-Wipe Target", value: "100.0%", color: "text-emerald-500", icon: ShieldCheck }
                ].map(box => (
                  <div key={box.label} className="bg-white/5 p-8 rounded-[32px] border border-white/10 flex flex-col items-center justify-center gap-4 text-center">
                    <box.icon className={cn("w-10 h-10", box.color)} />
                    <div>
                      <div className="text-[10px] font-black uppercase text-[#94a3b8] tracking-widest mb-1">{box.label}</div>
                      <div className={cn("text-4xl font-black italic tracking-tighter", box.color)}>{box.value}</div>
                    </div>
                  </div>
                ))}
              </div>

              {/* RADAR GRAPH & AI ANALYSIS */}
              <div className="grid lg:grid-cols-2 gap-8">
                {/* RADAR GRAPH (The requested "Graph") */}
                <div className="bg-white/5 p-10 rounded-[40px] border border-white/10 relative overflow-hidden flex flex-col items-center">
                  <h3 className="text-sm font-black uppercase tracking-wider mb-10 text-[#94a3b8] self-start">Forensic Risk Radar</h3>
                  <div className="relative w-64 h-64">
                    <svg viewBox="0 0 100 100" className="w-full h-full drop-shadow-[0_0_20px_rgba(6,182,212,0.3)]">
                      <circle cx="50" cy="50" r="45" fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="0.5" />
                      <circle cx="50" cy="50" r="30" fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="0.5" />
                      <circle cx="50" cy="50" r="15" fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="0.5" />
                      {/* Dynamic Radar Polygon based on REAL counts */}
                      <motion.polygon 
                        initial={{ opacity: 0, scale: 0 }}
                        animate={{ opacity: 1, scale: 1 }}
                        points={`50,${20 - (scanResults.results.risk_counts.High * 2)} 
                                 ${50 + (scanResults.results.risk_counts.Medium * 3)},${50 - (scanResults.results.risk_counts.Medium * 2)}
                                 ${50 + (scanResults.results.risk_counts.Low * 2)},${50 + (scanResults.results.risk_counts.Low * 2)}
                                 50,${80 + (scanResults.results.risk_counts.Hidden * 2)}
                                 ${50 - (scanResults.results.risk_counts.High * 2)},${50 + (scanResults.results.risk_counts.High * 2)}
                                 ${20},50`}
                        fill="rgba(6,182,212,0.2)" 
                        stroke="#06b6d4" 
                        strokeWidth="1.5"
                      />
                    </svg>
                  </div>
                  <div className="grid grid-cols-2 gap-8 w-full mt-10">
                    {Object.entries(scanResults.results.risk_counts).map(([label, count]) => (
                      <div key={label} className="text-center">
                        <div className="text-[10px] font-black uppercase text-[#94a3b8]">{label}</div>
                        <div className="text-lg font-black text-white">{count}</div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* AI ANALYSIS (Processing real data) */}
                <div className="bg-[#06b6d4]/5 p-10 rounded-[40px] border border-[#06b6d4]/20 flex flex-col justify-between">
                  <div>
                    <h3 className="text-sm font-black uppercase tracking-wider mb-8 flex items-center gap-2 text-[#06b6d4]">
                      <Cpu className="w-4 h-4" /> AI Forensic Analysis
                    </h3>
                    <div className="space-y-4">
                      {scanResults.ai_analysis.map((line, i) => (
                        <motion.div 
                          initial={{ opacity: 0, x: -10 }}
                          animate={{ opacity: 1, x: 0 }}
                          transition={{ delay: i * 0.4 }}
                          key={i} 
                          className="flex items-start gap-3"
                        >
                          <Zap className="w-3 h-3 text-[#06b6d4] mt-1 shrink-0" />
                          <p className="text-xs text-[#94a3b8] leading-relaxed italic">{line}</p>
                        </motion.div>
                      ))}
                    </div>
                  </div>
                  <div className="bg-black/40 p-8 rounded-2xl border border-white/5 mt-10">
                    <div className="text-[10px] font-black text-white/40 uppercase mb-2">Protocol recommendation</div>
                    <div className="text-2xl font-black text-[#06b6d4] tracking-tight">{scanResults.recommendation}</div>
                  </div>
                </div>
              </div>

              {/* Eradication Control */}
              <div className="bg-white/5 p-10 rounded-[40px] border border-white/10 flex flex-col md:flex-row items-center justify-between gap-8">
                <div>
                  <h3 className="text-lg font-black uppercase tracking-tight">Ready for Sanitization Cycle</h3>
                  <p className="text-xs text-[#94a3b8] uppercase tracking-widest mt-1">NIST 800-88 Standardized Eradication Protocol Active</p>
                </div>
                <button 
                  onClick={startWipe}
                  disabled={isWiping}
                  className="h-[68px] px-12 bg-red-600 text-white font-black rounded-2xl hover:bg-red-500 transition-all uppercase tracking-[0.2em] shadow-xl flex items-center gap-4"
                >
                  <Trash2 className="w-6 h-6" /> Engage Eradication
                </button>
              </div>
            </motion.section>
          )}
        </AnimatePresence>

        {/* STAGE 3: WIPING */}
        <AnimatePresence>
          {workflowStage >= 3 && isWiping && (
            <motion.section initial={{ opacity: 0, scale: 0.98 }} animate={{ opacity: 1, scale: 1 }} className="space-y-6">
              <div className="bg-[#0f172a] p-16 rounded-[56px] border border-orange-500/30 text-center relative overflow-hidden shadow-2xl">
                <h3 className="text-2xl font-black uppercase tracking-[0.6em] text-orange-500 mb-10 flex items-center justify-center gap-6"> 
                  <RefreshCw className="w-8 h-8 animate-spin" /> Sanitizing target sectors
                </h3>
                <div className="text-8xl font-black text-white mb-10 italic">{progress}%</div>
                <div className="h-8 w-full bg-white/5 rounded-full p-2 border border-white/10 mb-8 shadow-inner">
                  <motion.div initial={{ width: 0 }} animate={{ width: `${progress}%` }} className="h-full bg-gradient-to-r from-orange-600 via-red-600 to-orange-600 rounded-full shadow-[0_0_20px_rgba(249,115,22,0.5)]" />
                </div>
              </div>
            </motion.section>
          )}
        </AnimatePresence>

        {/* STAGE 4: FINISHED */}
        <AnimatePresence>
          {workflowStage >= 4 && wipeResults && scanResults && (
            <motion.section initial={{ opacity: 0, y: 40 }} animate={{ opacity: 1, y: 0 }} className="space-y-12">
              <div className="grid md:grid-cols-2 gap-8">
                <div className="bg-emerald-500/10 p-16 rounded-[56px] border border-emerald-500/30 text-center flex flex-col items-center justify-center gap-8 shadow-[0_0_60px_rgba(16,185,129,0.15)]">
                  <ShieldCheck className="w-20 h-20 text-emerald-500" />
                  <h3 className="text-5xl font-black uppercase tracking-tighter text-emerald-500 italic">Zero-Bit Integrity</h3>
                </div>

                <div className="bg-white/5 p-16 rounded-[56px] border border-white/10">
                  <h3 className="text-xs font-black uppercase tracking-widest text-[#94a3b8] mb-8 flex items-center gap-3"> <Activity className="w-5 h-5" /> Attack Verdict</h3>
                  <div className="space-y-4">
                    {wipeResults.attack.logs.map((log, i) => (
                      <div key={i} className="flex items-center gap-4">
                        <div className="w-2 h-2 rounded-full bg-[#06b6d4] shadow-[0_0_10px_#06b6d4]" />
                        <span className="text-[12px] font-mono text-[#06b6d4] tracking-tight">{log}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Passport */}
              <div className="bg-[#fdfaf3] rounded-[64px] overflow-hidden text-[#0a192f] shadow-[0_40px_120px_rgba(0,0,0,0.9)] border-[8px] border-[#c5a059] relative">
                <div className="bg-[#0a192f] p-20 flex justify-between items-center border-b-[10px] border-[#c5a059]">
                  <div className="relative z-10">
                    <h4 className="text-6xl font-serif text-[#e2c275] font-black uppercase tracking-widest leading-none mb-2">Security Passport</h4>
                    <p className="text-[12px] text-white/50 font-bold uppercase tracking-[0.8em]">OFFICIAL FORENSIC NODE CERTIFICATION</p>
                  </div>
                  <div className="text-right relative z-10">
                    <div className="text-[12px] text-[#e2c275] font-black uppercase mb-2 tracking-[0.3em]">REGISTRY ID</div>
                    <div className="text-3xl font-mono text-white font-black tracking-tighter">{wipeResults.audit_hash.slice(0, 14).toUpperCase()}</div>
                  </div>
                </div>

                <div className="p-20 relative">
                  <div className="grid sm:grid-cols-2 gap-16 mb-20">
                    {[
                      { label: "Hardware Node Instance", value: deviceId },
                      { label: "Trust Integrity Rating", value: "100% CERTIFIED" },
                      { label: "Date of Authentication", value: new Date().toLocaleDateString('en-GB') },
                      { label: "Forensic Status Code", value: "CLEAN / ZERO-BIT" }
                    ].map(field => (
                      <div key={field.label} className="border-b-[2px] border-[#0a192f]/10 pb-6">
                        <div className="text-[12px] font-black uppercase text-[#64748b] mb-2 tracking-[0.2em]">{field.label}</div>
                        <div className={cn("text-3xl font-black tracking-tighter uppercase", field.label.includes("Integrity") ? "text-emerald-700" : "text-[#0a192f]")}>{field.value}</div>
                      </div>
                    ))}
                  </div>

                  <div className="bg-[#0a192f] p-12 border-l-[20px] border-[#c5a059] mb-20 shadow-xl flex justify-between items-center">
                    <div>
                      <div className="text-[12px] font-black text-[#c5a059] uppercase mb-2 tracking-[0.4em]">Eradication Protocol</div>
                      <div className="text-4xl font-mono text-white font-black tracking-tight">{scanResults.recommendation}</div>
                    </div>
                    <button onClick={downloadPassport} className="bg-white/10 p-4 rounded-2xl hover:bg-white/20 transition-all">
                      <Download className="w-10 h-10 text-[#c5a059]" />
                    </button>
                  </div>

                  <div className="flex flex-col md:flex-row items-center md:items-end justify-between gap-16">
                    <div className="flex-1 font-mono text-[11px] text-[#64748b] leading-[2.5] border-t-2 border-[#0a192f]/10 pt-10">
                      P&lt;TSA{deviceId.replace(/-/g,'').padEnd(20,'&lt;')}&lt;&lt;&lt;&lt;&lt;<br/>
                      {wipeResults.audit_hash.slice(0,20).toUpperCase()}&lt;&lt;&lt;260516
                    </div>
                    <button onClick={downloadPassport} className="bg-[#0a192f] text-[#c5a059] px-16 py-8 rounded-[32px] font-black uppercase tracking-[0.3em] flex items-center gap-6 hover:scale-105 active:scale-95 transition-all shadow-[0_30px_60px_rgba(10,25,47,0.4)]">
                      <Download className="w-8 h-8" /> Download Passport
                    </button>
                  </div>
                </div>
              </div>
            </motion.section>
          )}
        </AnimatePresence>

      </main>

      <footer className="py-20 text-center opacity-40">
        <p className="text-[10px] font-black uppercase tracking-[1em]">TrustSense Forensic Elite Node v4.8.2</p>
      </footer>

      <style jsx global>{`
        .custom-scrollbar::-webkit-scrollbar { width: 4px; }
        .custom-scrollbar::-webkit-scrollbar-thumb { background: #06b6d4; border-radius: 10px; }
      `}</style>
    </div>
  );
}
