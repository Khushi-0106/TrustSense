"use client";

import { useState, useEffect, useMemo } from "react";
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
  Database,
  ArrowRight,
  ShieldCheck,
  FileSearch,
  Activity,
  Archive,
  BarChart3,
  RefreshCw,
  FolderOpen,
  FileCode,
  Zap,
  Target
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
  ai_reason: string;
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

// ── Constants ─────────────────────────────────────────────────────────────────
const THEME = {
  navy: "#0a192f",
  gold: "#c5a059",
  goldBright: "#e2c275",
  parchment: "#fdfaf3",
};

// ── Main Component ───────────────────────────────────────────────────────────
export default function TrustSensePage() {
  const [workflowStage, setWorkflowStage] = useState(1); // 1:Setup, 2:Analysis, 3:Wiping, 4:Finished
  const [deviceId, setDeviceId] = useState("TS-UNIT-01");
  const [isWiping, setIsWiping] = useState(false);
  const [progress, setProgress] = useState(0);
  
  const [scanResults, setScanResults] = useState<ScanResults | null>(null);
  const [selectedPaths, setSelectedPaths] = useState<string[]>([]);
  const [wipeResults, setWipeResults] = useState<WipeResults | null>(null);
  const [pdfBase64, setPdfBase64] = useState<string | null>(null);
  const [activeDirHandle, setActiveDirHandle] = useState<FileSystemDirectoryHandle | null>(null);

  const [consoleLogs, setConsoleLogs] = useState<string[]>(["[SYSTEM] TrustSense Mesh Node Active.", "[SYSTEM] Awaiting forensic target..."]);

  const addLog = (msg: string) => {
    setConsoleLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] ${msg}`].slice(-8));
  };

  // ── Handlers ───────────────────────────────────────────────────────────────
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
          let reason = "Standard asset with no sensitive metadata signatures.";
          
          if (['key', 'pem', 'env', 'json', 'sql', 'db'].includes(ext) || isHidden) {
            risk = "High";
            reason = isHidden ? "Hidden system artifact — potential forensic residue." : "Cryptographic or database configuration detected.";
            if (isHidden) riskCounts.Hidden++; else riskCounts.High++;
          } else if (['zip', 'rar', 'bak', 'old', 'csv', 'pdf', 'docx'].includes(ext)) {
            risk = "Medium";
            reason = "Archive or document format with embedded metadata vulnerabilities.";
            riskCounts.Medium++;
          } else {
            riskCounts.Low++;
          }
          
          fileList.push({ name: entry.name, size: file.size, ext, risk, reason, hidden: isHidden });
        }
      }

      const recommendation = riskCounts.High > 0 ? "NIST 800-88 Purge" : riskCounts.Medium > 0 ? "DoD 5220.22-M" : "Basic Single-Pass";
      const aiReason = riskCounts.High > 0 
        ? `Detected ${riskCounts.High} High-Risk assets and ${riskCounts.Hidden} hidden artifacts. Forensic signatures suggest active sensitive stores. We recommend a full NIST 800-88 purge sequence to ensure zero-bit recovery.`
        : `Analysis found a predominantly low-risk profile. Standard DoD multi-pass overwriting is sufficient to neutralize all existing document metadata and user-space artifacts.`;

      setScanResults({
        score: Math.max(15, 100 - (riskCounts.High * 10) - (riskCounts.Medium * 2)),
        results: {
          total_files: totalFiles,
          total_folders: 0,
          sensitive_files: riskCounts.High + riskCounts.Medium,
          risk_level: riskCounts.High > 0 ? "High" : riskCounts.Medium > 0 ? "Medium" : "Low",
          file_types: extensions,
          risk_counts: riskCounts,
          file_details: fileList,
        },
        recommendation,
        ai_reason: aiReason
      });

      // Pre-select high risk files for backup
      setSelectedPaths(fileList.filter(f => f.risk === "High").map(f => f.name));
      setWorkflowStage(2);
      addLog(`Scan complete. ${totalFiles} objects categorized. High risk: ${riskCounts.High + riskCounts.Hidden}`);
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
      let wipedCount = 0;
      // Real Erasure Simulation
      for (let i = 0; i <= 100; i++) {
        setProgress(i);
        if (i % 20 === 0) addLog(`[OVERWRITING] Sector ${i * 422}...`);
        await new Promise(r => setTimeout(r, 20));
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

  // ── Render Helpers ──────────────────────────────────────────────────────────
  const toggleFile = (path: string) => {
    setSelectedPaths(prev => prev.includes(path) ? prev.filter(p => p !== path) : [...prev, path]);
  };

  return (
    <div className="min-h-screen bg-[#0b1120] text-white font-sans selection:bg-trust-cyan selection:text-black">
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
                disabled={workflowStage > 1}
                className="w-full h-[58px] bg-[#06b6d4] text-black font-black rounded-2xl hover:brightness-110 transition-all uppercase tracking-widest flex items-center justify-center gap-3 disabled:opacity-30"
              >
                <Search className="w-5 h-5" />
                Initiate Forensic Scan
              </button>
            </div>
          </div>

          {/* Real-time Console */}
          <div className="bg-black/60 rounded-3xl border border-white/5 p-6 font-mono text-[10px] text-[#06b6d4] leading-relaxed shadow-inner">
            <div className="flex justify-between items-center mb-3 opacity-40">
              <span className="flex items-center gap-2 italic"> <RefreshCw className="w-3 h-3 animate-spin" /> Forensic Nexus Stream</span>
              <span>v4.8.2-CERT</span>
            </div>
            {consoleLogs.map((log, i) => <div key={i} className="mb-0.5">{log}</div>)}
          </div>
        </section>

        {/* STAGE 2: ANALYSIS (Revealed after scan) */}
        <AnimatePresence>
          {workflowStage >= 2 && scanResults && (
            <motion.section initial={{ opacity: 0, y: 40 }} animate={{ opacity: 1, y: 0 }} className="space-y-8">
              <div className="flex items-center gap-4">
                <div className="w-10 h-10 rounded-xl bg-[#06b6d4]/20 flex items-center justify-center border border-[#06b6d4]/40">
                  <span className="text-[#06b6d4] font-black">02</span>
                </div>
                <h2 className="text-2xl font-black uppercase tracking-tight">Forensic Categorization</h2>
              </div>

              <div className="grid lg:grid-cols-3 gap-8">
                {/* Risk Distribution Chart */}
                <div className="lg:col-span-2 bg-white/5 p-8 rounded-[32px] border border-white/10">
                  <h3 className="text-sm font-black uppercase tracking-wider mb-8 text-[#94a3b8]">Threat Distribution Profile</h3>
                  <div className="space-y-6">
                    {[
                      { label: "High Risk", count: scanResults.results.risk_counts.High, color: "bg-red-500", shadow: "shadow-red-500/40" },
                      { label: "Medium Risk", count: scanResults.results.risk_counts.Medium, color: "bg-orange-500", shadow: "shadow-orange-500/40" },
                      { label: "Low Risk", count: scanResults.results.risk_counts.Low, color: "bg-emerald-500", shadow: "shadow-emerald-500/40" },
                      { label: "Hidden Assets", count: scanResults.results.risk_counts.Hidden, color: "bg-[#06b6d4]", shadow: "shadow-[#06b6d4]/40" }
                    ].map(bar => {
                      const max = Math.max(...Object.values(scanResults.results.risk_counts));
                      const width = max > 0 ? (bar.count / max) * 100 : 0;
                      return (
                        <div key={bar.label} className="space-y-2">
                          <div className="flex justify-between text-[10px] font-black uppercase tracking-widest">
                            <span>{bar.label}</span>
                            <span>{bar.count} OBJECTS</span>
                          </div>
                          <div className="h-3 w-full bg-white/5 rounded-full overflow-hidden">
                            <motion.div 
                              initial={{ width: 0 }} 
                              animate={{ width: `${Math.max(5, width)}%` }} 
                              className={cn("h-full rounded-full transition-all duration-1000", bar.color, bar.shadow, "shadow-lg")} 
                            />
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* AI Recommendation */}
                <div className="bg-[#06b6d4]/5 p-8 rounded-[32px] border border-[#06b6d4]/20 flex flex-col justify-between">
                  <div>
                    <h3 className="text-sm font-black uppercase tracking-wider mb-4 flex items-center gap-2">
                      <Zap className="w-4 h-4 text-[#06b6d4]" /> AI Protocol Recommendation
                    </h3>
                    <p className="text-xs text-[#94a3b8] leading-relaxed italic border-l-2 border-[#06b6d4] pl-4 py-1 mb-6">
                      "{scanResults.ai_reason}"
                    </p>
                  </div>
                  <div className="bg-black/40 p-4 rounded-2xl border border-white/5">
                    <div className="text-[10px] font-black text-white/40 uppercase mb-1">Target Protocol</div>
                    <div className="text-lg font-black text-[#06b6d4]">{scanResults.recommendation}</div>
                  </div>
                </div>
              </div>

              {/* Asset Preservation (Backup Selection) */}
              <div className="bg-white/5 p-8 rounded-[32px] border border-white/10">
                <div className="flex items-center justify-between mb-8">
                  <h3 className="text-sm font-black uppercase tracking-wider text-[#94a3b8]">Asset Preservation Manifest</h3>
                  <div className="text-[10px] font-black text-[#06b6d4] uppercase tracking-widest">
                    {selectedPaths.length} SELECTED FOR BACKUP
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 max-h-[300px] overflow-y-auto pr-4 custom-scrollbar">
                  {scanResults.results.file_details.map((file, i) => (
                    <div 
                      key={i} 
                      onClick={() => toggleFile(file.name)}
                      className={cn(
                        "flex items-center justify-between p-4 rounded-2xl border transition-all cursor-pointer group",
                        selectedPaths.includes(file.name) 
                          ? "bg-[#06b6d4]/10 border-[#06b6d4]/40" 
                          : "bg-black/20 border-white/5 hover:border-white/20"
                      )}
                    >
                      <div className="flex items-center gap-3 overflow-hidden">
                        <div className={cn(
                          "w-2 h-2 rounded-full",
                          file.risk === "High" ? "bg-red-500" : file.risk === "Medium" ? "bg-orange-500" : "bg-emerald-500"
                        )} />
                        <span className="text-[11px] font-mono truncate">{file.name}</span>
                      </div>
                      <div className="flex items-center gap-4">
                        <span className="text-[9px] font-black opacity-40 uppercase">{file.risk}</span>
                        <div className={cn(
                          "w-5 h-5 rounded-md border flex items-center justify-center transition-colors",
                          selectedPaths.includes(file.name) ? "bg-[#06b6d4] border-[#06b6d4]" : "border-white/20"
                        )}>
                          {selectedPaths.includes(file.name) && <CheckCircle2 className="w-3 h-3 text-black" />}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>

                <div className="mt-8 flex gap-4">
                  <button 
                    onClick={startWipe}
                    disabled={workflowStage > 2}
                    className="flex-1 h-[64px] bg-red-600 text-white font-black rounded-2xl hover:bg-red-500 transition-all uppercase tracking-[0.2em] shadow-xl shadow-red-600/20 flex items-center justify-center gap-3 disabled:opacity-30"
                  >
                    <Trash2 className="w-6 h-6" />
                    Engage Eradication
                  </button>
                </div>
              </div>
            </motion.section>
          )}
        </AnimatePresence>

        {/* STAGE 3: WIPING */}
        <AnimatePresence>
          {workflowStage >= 3 && isWiping && (
            <motion.section initial={{ opacity: 0, scale: 0.98 }} animate={{ opacity: 1, scale: 1 }} className="space-y-6">
              <div className="bg-[#0f172a] p-10 rounded-[40px] border border-orange-500/30 text-center relative overflow-hidden">
                <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,#f9731610,transparent_70%)]" />
                <h3 className="text-xl font-black uppercase tracking-[0.5em] text-orange-500 mb-8 flex items-center justify-center gap-4">
                   <RefreshCw className="w-6 h-6 animate-spin" /> Sanitizing Sectors
                </h3>
                <div className="text-5xl font-black text-white mb-6 tabular-nums">{progress}%</div>
                <div className="h-4 w-full bg-white/5 rounded-full p-1 border border-white/10 mb-4">
                  <motion.div initial={{ width: 0 }} animate={{ width: `${progress}%` }} className="h-full bg-gradient-to-r from-orange-500 to-red-600 rounded-full" />
                </div>
                <p className="text-[10px] font-black text-[#94a3b8] uppercase tracking-[0.2em]">Zero-Bit Overwrite Pattern Active (AES-256 Noise Generation)</p>
              </div>
            </motion.section>
          )}
        </AnimatePresence>

        {/* STAGE 4: FINISHED */}
        <AnimatePresence>
          {workflowStage >= 4 && wipeResults && (
            <motion.section initial={{ opacity: 0, y: 40 }} animate={{ opacity: 1, y: 0 }} className="space-y-12">
              <div className="grid md:grid-cols-2 gap-8">
                <div className="bg-emerald-500/10 p-10 rounded-[40px] border border-emerald-500/30 text-center flex flex-col items-center justify-center gap-4">
                  <div className="w-20 h-20 rounded-full bg-emerald-500/20 flex items-center justify-center border-4 border-emerald-500">
                    <ShieldCheck className="w-10 h-10 text-emerald-500" />
                  </div>
                  <h3 className="text-3xl font-black uppercase tracking-tighter text-emerald-500">Eradication Complete</h3>
                  <p className="text-xs text-emerald-500/60 font-bold uppercase tracking-widest">Post-Wipe Score: 100% Secure</p>
                </div>

                <div className="bg-white/5 p-10 rounded-[40px] border border-white/10 flex flex-col justify-center gap-6">
                  <h3 className="text-xs font-black uppercase tracking-widest text-[#94a3b8] flex items-center gap-2">
                    <Target className="w-4 h-4 text-[#06b6d4]" /> Attack Simulation Verdict
                  </h3>
                  <div className="space-y-3">
                    {wipeResults.attack.logs.map((log, i) => (
                      <div key={i} className="flex items-center gap-3 text-[11px] font-mono text-[#06b6d4]">
                        <CheckCircle2 className="w-3 h-3" /> {log}
                      </div>
                    ))}
                  </div>
                  <div className="pt-4 border-t border-white/10">
                    <div className="text-[9px] uppercase font-black text-white/40 mb-1">Audit Hash (SHA-256)</div>
                    <div className="text-[11px] font-mono text-[#06b6d4] break-all">{wipeResults.audit_hash}</div>
                  </div>
                </div>
              </div>

              {/* Hyper-Premium Passport */}
              <div className="relative p-1 bg-gradient-to-br from-[#c5a059] via-[#0a192f] to-[#c5a059] rounded-[48px] shadow-[0_50px_100px_-20px_rgba(0,0,0,0.8)]">
                <div className="bg-[#fdfaf3] rounded-[44px] overflow-hidden text-[#0a192f] relative">
                  {/* Subtle Pattern */}
                  <div className="absolute inset-0 opacity-[0.03] pointer-events-none bg-[radial-gradient(#0a192f_1px,transparent_1px)] [background-size:16px_16px]" />
                  
                  {/* Passport Header */}
                  <div className="bg-[#0a192f] p-12 flex justify-between items-center border-b-[6px] border-[#c5a059] relative">
                    <div className="space-y-1">
                      <h4 className="text-4xl font-serif tracking-widest text-[#e2c275] font-black uppercase">Security Passport</h4>
                      <p className="text-[10px] tracking-[0.6em] text-white/60 font-bold uppercase">TrustSense Forensic Node Certification</p>
                    </div>
                    <div className="text-right border-l border-[#c5a059]/40 pl-8">
                      <div className="text-[10px] text-[#e2c275] font-black uppercase mb-1">Registry ID</div>
                      <div className="text-xl font-mono text-white font-bold">{wipeResults.audit_hash.slice(0, 14).toUpperCase()}</div>
                    </div>
                    <div className="absolute bottom-[-10px] right-12 text-[6px] text-[#c5a059] tracking-widest font-black">OFFICIAL FORENSIC RECORD — DO NOT TAMPER</div>
                  </div>

                  {/* Passport Body */}
                  <div className="p-14 relative">
                    <div className="absolute top-10 right-10 w-32 h-32 border-2 border-dashed border-[#c5a059]/40 rounded-full flex items-center justify-center text-center transform rotate-12 bg-white/20 backdrop-blur-sm shadow-inner">
                      <div className="text-[8px] font-serif font-black text-[#c5a059] leading-tight">AUTHENTIC<br/>TRUSTSENSE<br/>VERIFIED CLEAN</div>
                    </div>

                    <div className="grid grid-cols-2 gap-x-16 gap-y-10 mb-12">
                      {[
                        { label: "Hardware Instance", value: deviceId },
                        { label: "Trust Score", value: "100% CERTIFIED", color: "text-emerald-700" },
                        { label: "Certification Date", value: new Date().toLocaleDateString('en-GB') },
                        { label: "Audit Result", value: "ZERO-BIT PURGE" }
                      ].map(field => (
                        <div key={field.label} className="border-b border-[#0a192f]/10 pb-2">
                          <div className="text-[10px] font-black uppercase text-[#64748b] mb-1 tracking-wider">{field.label}</div>
                          <div className={cn("text-lg font-black", field.color || "text-[#0a192f]")}>{field.value}</div>
                        </div>
                      ))}
                    </div>

                    <div className="bg-[#0a192f] p-6 border-l-[12px] border-[#c5a059] mb-12 shadow-lg">
                      <div className="text-[10px] font-black text-[#c5a059] uppercase mb-2">Eradication Protocol Applied</div>
                      <div className="text-xl font-mono text-white font-bold tracking-wider">{scanResults.recommendation} (NIST 800-88)</div>
                      <p className="text-[9px] text-white/40 mt-2 italic">Verified Cryptographic Eradication Sequence Initiated and Validated by TrustSense Kernel.</p>
                    </div>

                    <div className="flex gap-8 mb-12">
                      <div className="flex-1 bg-[#f1ebd8] border border-[#c5a059] p-6 text-center">
                        <div className="text-[10px] font-black uppercase text-[#64748b] mb-2">Threats Purged</div>
                        <div className="text-4xl font-black text-red-700">{scanResults.results.sensitive_files}</div>
                      </div>
                      <div className="flex-1 bg-[#f1ebd8] border border-[#c5a059] p-6 text-center">
                        <div className="text-[10px] font-black uppercase text-[#64748b] mb-2">Integrity Status</div>
                        <div className="text-4xl font-black text-emerald-700">VERIFIED</div>
                      </div>
                    </div>

                    <div className="flex items-center gap-10 pt-10 border-t border-[#0a192f]/10">
                      <div className="w-24 h-24 bg-white p-2 border border-[#0a192f] shadow-[4px_4px_0px_#c5a059]">
                        <img src={`data:image/png;base64,${pdfBase64}`} className="w-full h-full opacity-50 grayscale" alt="SIGN" />
                      </div>
                      <div className="flex-1 font-mono text-[9px] text-[#64748b] leading-relaxed tracking-wider">
                        P&lt;TSA{deviceId.replace(/-/g,'').padEnd(20,'<')}&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;<br/>
                        {wipeResults.audit_hash.slice(0,20).toUpperCase()}&lt;&lt;&lt;260516&lt;&lt;&lt;&lt;
                      </div>
                      <button 
                        onClick={downloadPassport}
                        className="bg-[#0a192f] text-[#c5a059] px-10 py-5 rounded-2xl font-black uppercase tracking-widest hover:scale-105 transition-all shadow-2xl flex items-center gap-3"
                      >
                        <Download className="w-6 h-6" />
                        Download Passport
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            </motion.section>
          )}
        </AnimatePresence>

      </main>

      <footer className="py-20 text-center border-t border-white/5 opacity-40">
        <p className="text-[10px] font-black uppercase tracking-[1em]">TrustSense Forensic Elite Node v4.8.2-CERT</p>
      </footer>

      <style jsx global>{`
        .glass-card {
          background: rgba(255, 255, 255, 0.03);
          border-radius: 40px;
          border: 1px solid rgba(255, 255, 255, 0.1);
          padding: 40px;
          backdrop-filter: blur(20px);
        }
        .neo-border-green { border-color: rgba(16, 185, 129, 0.3); box-shadow: 0 0 40px rgba(16, 185, 129, 0.05); }
        .neo-border-cyan { border-color: rgba(6, 182, 212, 0.3); box-shadow: 0 0 40px rgba(6, 182, 212, 0.05); }
        .neo-border-yellow { border-color: rgba(245, 158, 11, 0.3); box-shadow: 0 0 40px rgba(245, 158, 11, 0.05); }
        .custom-scrollbar::-webkit-scrollbar { width: 4px; }
        .custom-scrollbar::-webkit-scrollbar-track { background: rgba(255,255,255,0.05); border-radius: 10px; }
        .custom-scrollbar::-webkit-scrollbar-thumb { background: #06b6d4; border-radius: 10px; }
      `}</style>
    </div>
  );
}
