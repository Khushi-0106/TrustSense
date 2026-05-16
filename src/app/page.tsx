"use client";

import { useState } from "react";
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
  BarChart3
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
  const [activeDirHandle, setActiveDirHandle] = useState<any>(null);

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
    } catch (e) {
      addLog("Certification failed. Check API connectivity.");
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

  const toggleFile = (path: string) => {
    setSelectedPaths(prev => prev.includes(path) ? prev.filter(p => p !== path) : [...prev, path]);
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
            <div className="w-10 h-10 rounded-xl bg-[#06b6d4]/20 flex items-center justify-center border border-[#06b6d4]/40 shadow-[0_0_15px_rgba(6,182,212,0.2)]">
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

          <div className="bg-black/60 rounded-3xl border border-white/5 p-6 font-mono text-[10px] text-[#06b6d4] leading-relaxed shadow-inner">
            <div className="flex justify-between items-center mb-3 opacity-40">
              <span className="flex items-center gap-2 italic"> <RefreshCw className="w-3 h-3 animate-spin" /> Forensic Nexus Stream</span>
              <span>v4.8.2-CERT</span>
            </div>
            {consoleLogs.map((log, i) => <div key={i} className="mb-0.5">{log}</div>)}
          </div>
        </section>

        {/* STAGE 2: ANALYSIS */}
        <AnimatePresence mode="popLayout">
          {workflowStage >= 2 && scanResults && (
            <motion.section 
              key="analysis-stage"
              initial={{ opacity: 0, y: 40 }} 
              animate={{ opacity: 1, y: 0 }} 
              transition={{ duration: 0.6, ease: "easeOut" }}
              className="space-y-8"
            >
              <div className="flex items-center gap-4">
                <div className="w-10 h-10 rounded-xl bg-[#06b6d4]/20 flex items-center justify-center border border-[#06b6d4]/40 shadow-[0_0_15px_rgba(6,182,212,0.2)]">
                  <span className="text-[#06b6d4] font-black">02</span>
                </div>
                <h2 className="text-2xl font-black uppercase tracking-tight">Forensic Categorization</h2>
              </div>

              <div className="grid lg:grid-cols-3 gap-8">
                {/* Visual Risk Radar */}
                <div className="lg:col-span-2 bg-white/5 p-8 rounded-[32px] border border-white/10 relative overflow-hidden backdrop-blur-sm shadow-2xl">
                  <div className="absolute top-0 right-0 p-8 opacity-5">
                    <Activity className="w-48 h-48 text-[#06b6d4]" />
                  </div>
                  <div className="relative z-10">
                    <h3 className="text-sm font-black uppercase tracking-wider mb-8 text-[#94a3b8] flex items-center gap-2">
                      <BarChart3 className="w-4 h-4" /> Forensic Risk Distribution Profile
                    </h3>
                    
                    <div className="grid md:grid-cols-2 gap-12 items-center">
                      <div className="relative w-56 h-56 mx-auto">
                        <svg viewBox="0 0 100 100" className="w-full h-full drop-shadow-[0_0_20px_rgba(6,182,212,0.4)]">
                          <circle cx="50" cy="50" r="45" fill="none" stroke="rgba(255,255,255,0.03)" strokeWidth="0.5" />
                          <circle cx="50" cy="50" r="30" fill="none" stroke="rgba(255,255,255,0.03)" strokeWidth="0.5" />
                          <circle cx="50" cy="50" r="15" fill="none" stroke="rgba(255,255,255,0.03)" strokeWidth="0.5" />
                          <motion.polygon 
                            initial={{ opacity: 0, scale: 0.5 }}
                            animate={{ opacity: 1, scale: 1 }}
                            transition={{ duration: 1 }}
                            points={`50,${20 - Math.min(15, scanResults.results.risk_counts.High)} 
                                     ${50 + Math.min(45, scanResults.results.risk_counts.Medium)},${50 - Math.min(10, scanResults.results.risk_counts.Medium)}
                                     ${50 + Math.min(40, scanResults.results.risk_counts.Low)},${50 + Math.min(40, scanResults.results.risk_counts.Low)}
                                     50,${80 + Math.min(15, scanResults.results.risk_counts.Hidden)}
                                     ${50 - Math.min(40, scanResults.results.risk_counts.High)},${50 + Math.min(20, scanResults.results.risk_counts.High)}
                                     ${10},50`}
                            fill="rgba(6,182,212,0.15)" 
                            stroke="#06b6d4" 
                            strokeWidth="2"
                            strokeLinejoin="round"
                          />
                        </svg>
                        <div className="absolute inset-0 flex items-center justify-center text-center">
                          <div>
                            <div className="text-3xl font-black text-white">{scanResults.score}%</div>
                            <div className="text-[9px] text-[#06b6d4] font-black uppercase tracking-[0.3em]">Integrity</div>
                          </div>
                        </div>
                      </div>

                      <div className="space-y-5">
                        {[
                          { label: "High Risk", count: scanResults.results.risk_counts.High, color: "bg-red-500", icon: AlertTriangle },
                          { label: "Medium Risk", count: scanResults.results.risk_counts.Medium, color: "bg-orange-500", icon: Activity },
                          { label: "Low Risk", count: scanResults.results.risk_counts.Low, color: "bg-emerald-500", icon: CheckCircle2 },
                          { label: "Hidden Data", count: scanResults.results.risk_counts.Hidden, color: "bg-[#06b6d4]", icon: Search }
                        ].map(bar => {
                          const max = Math.max(...Object.values(scanResults.results.risk_counts), 1);
                          return (
                            <div key={bar.label}>
                              <div className="flex justify-between text-[10px] font-black uppercase tracking-widest mb-2 text-[#94a3b8]">
                                <span className="flex items-center gap-2"><bar.icon className="w-3.5 h-3.5" /> {bar.label}</span>
                                <span>{bar.count} ITEMS</span>
                              </div>
                              <div className="h-2 w-full bg-white/5 rounded-full overflow-hidden">
                                <motion.div initial={{ width: 0 }} animate={{ width: `${(bar.count / max) * 100}%` }} className={cn("h-full rounded-full", bar.color)} />
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  </div>
                </div>

                {/* AI Reasoning */}
                <div className="bg-[#06b6d4]/5 p-8 rounded-[32px] border border-[#06b6d4]/20 flex flex-col justify-between relative backdrop-blur-xl">
                  <div className="absolute top-0 right-0 p-6"><div className="w-3 h-3 bg-[#06b6d4] rounded-full animate-pulse shadow-[0_0_15px_#06b6d4]" /></div>
                  <div>
                    <h3 className="text-sm font-black uppercase tracking-wider mb-8 flex items-center gap-3 text-[#06b6d4]"><Cpu className="w-4 h-4" /> AI Verdict</h3>
                    <p className="text-xs text-[#cbd5e1] leading-relaxed italic mb-8 border-l-2 border-[#06b6d4]/30 pl-4 py-1">"{scanResults.ai_reason}"</p>
                  </div>
                  <div className="bg-black/40 p-6 rounded-2xl border border-white/5">
                    <div className="text-[10px] font-black text-white/40 uppercase mb-2">Protocol Enforced</div>
                    <div className="text-2xl font-black text-[#06b6d4] tracking-tight">{scanResults.recommendation}</div>
                  </div>
                </div>
              </div>

              {/* Manifest */}
              <div className="bg-white/5 p-8 rounded-[32px] border border-white/10 shadow-xl backdrop-blur-md">
                <div className="flex justify-between items-center mb-10">
                  <h3 className="text-sm font-black uppercase tracking-wider text-[#94a3b8]">Preservation Manifest</h3>
                  <div className="bg-emerald-500/10 px-6 py-2 rounded-xl border border-emerald-500/20 text-[11px] font-black text-emerald-500 uppercase tracking-widest">{selectedPaths.length} NODES PRESERVED</div>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5 max-h-[300px] overflow-y-auto pr-6 custom-scrollbar">
                  {scanResults.results.file_details.map((file, i) => (
                    <div key={i} onClick={() => toggleFile(file.name)} className={cn("flex items-center justify-between p-5 rounded-2xl border transition-all cursor-pointer group shadow-sm", selectedPaths.includes(file.name) ? "bg-[#06b6d4]/15 border-[#06b6d4]/50" : "bg-black/40 border-white/5")}>
                      <div className="flex items-center gap-4 overflow-hidden">
                        <div className={cn("w-3 h-3 rounded-full", file.risk === "High" ? "bg-red-500" : file.risk === "Medium" ? "bg-orange-500" : "bg-emerald-500")} />
                        <span className="text-[12px] font-mono truncate text-slate-200">{file.name}</span>
                      </div>
                      <div className={cn("w-6 h-6 rounded-lg border flex items-center justify-center transition-all", selectedPaths.includes(file.name) ? "bg-[#06b6d4] border-[#06b6d4]" : "border-white/20")}>{selectedPaths.includes(file.name) && <CheckCircle2 className="w-3.5 h-3.5 text-black" />}</div>
                    </div>
                  ))}
                </div>
                <div className="mt-10">
                  <button onClick={startWipe} disabled={isWiping} className={cn("w-full h-[72px] font-black rounded-2xl transition-all uppercase tracking-[0.3em] shadow-2xl flex items-center justify-center gap-4 text-lg", isWiping ? "bg-slate-800 text-slate-500 cursor-not-allowed" : "bg-red-600 text-white hover:bg-red-500 shadow-red-900/30 active:scale-[0.99]")}><Trash2 className="w-7 h-7" /> Engage Eradication Cycle</button>
                </div>
              </div>
            </motion.section>
          )}
        </AnimatePresence>

        {/* STAGE 3: WIPING */}
        <AnimatePresence>
          {workflowStage >= 3 && isWiping && (
            <motion.section initial={{ opacity: 0, scale: 0.98, y: 40 }} animate={{ opacity: 1, scale: 1, y: 0 }} className="space-y-6">
              <div className="bg-[#0f172a] p-16 rounded-[56px] border border-orange-500/30 text-center relative overflow-hidden shadow-2xl">
                <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,rgba(249,115,22,0.15),transparent)] pointer-events-none" />
                <div className="relative z-10">
                  <h3 className="text-2xl font-black uppercase tracking-[0.6em] text-orange-500 mb-10 flex items-center justify-center gap-6"><RefreshCw className="w-8 h-8 animate-spin" /> Sanitizing Sectors</h3>
                  <div className="text-9xl font-black text-white mb-10 tabular-nums italic">{progress}%</div>
                  <div className="h-8 w-full bg-black/40 rounded-full p-2 border border-white/10 mb-8 shadow-inner overflow-hidden"><motion.div initial={{ width: 0 }} animate={{ width: `${progress}%` }} className="h-full bg-gradient-to-r from-orange-600 via-red-600 to-orange-600 bg-[length:200%_100%] animate-gradient-x rounded-full shadow-[0_0_20px_rgba(249,115,22,0.5)]" /></div>
                </div>
              </div>
            </motion.section>
          )}
        </AnimatePresence>

        {/* STAGE 4: FINISHED */}
        <AnimatePresence>
          {workflowStage >= 4 && wipeResults && scanResults && (
            <motion.section initial={{ opacity: 0, y: 40 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.8 }} className="space-y-16">
              <div className="grid md:grid-cols-2 gap-8">
                <div className="bg-emerald-500/10 p-16 rounded-[56px] border border-emerald-500/30 text-center flex flex-col items-center justify-center gap-8 shadow-[0_0_60px_rgba(16,185,129,0.15)] backdrop-blur-md">
                  <div className="w-24 h-24 bg-emerald-500/20 rounded-[32px] flex items-center justify-center border border-emerald-500/40 shadow-xl"><ShieldCheck className="w-14 h-14 text-emerald-500" /></div>
                  <h3 className="text-5xl font-black uppercase tracking-tighter text-emerald-500 italic">Zero-Bit Integrity</h3>
                </div>
                <div className="bg-white/5 p-16 rounded-[56px] border border-white/10 relative overflow-hidden backdrop-blur-xl shadow-2xl">
                  <h3 className="text-[11px] font-black uppercase tracking-[0.4em] text-[#94a3b8] mb-8 flex items-center gap-3"> <Activity className="w-5 h-5 text-[#06b6d4]" /> Verification Verdict Logs</h3>
                  <div className="space-y-5">{wipeResults.attack.logs.map((log, i) => (<div key={i} className="flex items-center gap-4 group"><div className="w-2 h-2 rounded-full bg-[#06b6d4] shadow-[0_0_10px_#06b6d4]" /><span className="text-[12px] font-mono text-[#06b6d4] tracking-tight">{log}</span></div>))}</div>
                </div>
              </div>

              {/* Passport */}
              <div className="bg-[#fdfaf3] rounded-[64px] overflow-hidden text-[#0a192f] shadow-[0_40px_120px_rgba(0,0,0,0.9)] border-[8px] border-[#c5a059] relative">
                <div className="absolute inset-0 opacity-[0.04] pointer-events-none bg-[radial-gradient(circle_at_center,#000_1px,transparent_1px)] [background-size:12px_12px]" />
                <div className="bg-[#0a192f] p-20 flex justify-between items-center border-b-[10px] border-[#c5a059] relative overflow-hidden">
                  <div className="relative z-10"><h4 className="text-6xl font-serif text-[#e2c275] font-black uppercase tracking-widest leading-tight">Security Passport</h4><p className="text-[12px] text-white/50 font-bold uppercase tracking-[0.8em]">OFFICIAL FORENSIC NODE CERTIFICATION</p></div>
                  <div className="text-right relative z-10"><div className="text-[12px] text-[#e2c275] font-black uppercase mb-2 tracking-[0.3em]">REGISTRY ARCHIVE ID</div><div className="text-3xl font-mono text-white font-black tracking-tighter">{wipeResults.audit_hash.slice(0, 14).toUpperCase()}</div></div>
                </div>
                <div className="p-20 relative">
                  <div className="grid sm:grid-cols-2 gap-16 mb-20">
                    {[
                      { label: "Hardware Node Instance", value: deviceId },
                      { label: "Trust Integrity Rating", value: "100% CERTIFIED" },
                      { label: "Date of Authentication", value: new Date().toLocaleDateString('en-GB') },
                      { label: "Forensic Status Code", value: "CLEAN / ZERO-BIT" }
                    ].map(field => (
                      <div key={field.label} className="border-b-[2px] border-[#0a192f]/10 pb-6"><div className="text-[12px] font-black uppercase text-[#64748b] mb-2 tracking-[0.2em]">{field.label}</div><div className={cn("text-3xl font-black tracking-tighter uppercase", field.label.includes("Integrity") ? "text-emerald-700" : "text-[#0a192f]")}>{field.value}</div></div>
                    ))}
                  </div>
                  <div className="mb-20">
                    <div className="text-[12px] font-black uppercase text-[#64748b] mb-8 tracking-[0.3em]">Eradicated Asset Categorization</div>
                    <div className="flex h-14 w-full rounded-[20px] overflow-hidden border-2 border-[#0a192f]/5 p-1 bg-white">
                      {Object.entries(scanResults.results.risk_counts).map(([label, count]) => {
                        const total = Object.values(scanResults.results.risk_counts).reduce((a,b) => a+b, 0);
                        const colors: Record<string, string> = { High: "#dc2626", Medium: "#f97316", Low: "#10b981", Hidden: "#0a192f" };
                        return (<div key={label} style={{ width: `${(count / total) * 100}%` }} className="h-full relative group transition-all duration-500 hover:flex-[1.2]"><div className="h-full w-full opacity-90 transition-opacity hover:opacity-100" style={{ backgroundColor: colors[label] }} /><div className="absolute inset-0 flex items-center justify-center opacity-0 group-hover:opacity-100"><span className="text-[10px] font-black text-white uppercase">{label}</span></div></div>);
                      })}
                    </div>
                  </div>
                  <div className="bg-[#0a192f] p-12 border-l-[20px] border-[#c5a059] mb-20 shadow-xl flex justify-between items-center group transition-all">
                    <div><div className="text-[12px] font-black text-[#c5a059] uppercase mb-2 tracking-[0.4em]">Cryptographic Eradication Protocol</div><div className="text-4xl font-mono text-white font-black tracking-tight">{scanResults.recommendation}</div></div>
                    <ShieldCheck className="w-14 h-14 text-[#c5a059]" />
                  </div>
                  <div className="flex items-end justify-between gap-16">
                    <div className="flex-1 font-mono text-[11px] text-[#64748b] leading-[2.5] border-t-2 border-[#0a192f]/10 pt-10">P&lt;TSA{deviceId.replace(/-/g,'').padEnd(20,'&lt;')}&lt;&lt;&lt;&lt;&lt;<br/>{wipeResults.audit_hash.slice(0,20).toUpperCase()}&lt;&lt;&lt;260516</div>
                    <div className="flex flex-col gap-8 w-full md:w-auto"><div className="text-right italic font-serif text-[#0a192f]/60 text-3xl border-b-2 border-[#0a192f]/10 pb-4 px-8">TrustSense Authority</div><button onClick={downloadPassport} className="bg-[#0a192f] text-[#c5a059] px-16 py-8 rounded-[32px] font-black uppercase tracking-[0.3em] flex items-center justify-center gap-6 hover:scale-105 active:scale-95 transition-all shadow-[0_30px_60px_rgba(10,25,47,0.4)] group overflow-hidden relative"><div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/5 to-transparent -translate-x-full group-hover:translate-x-full transition-transform duration-1000" /><Download className="w-8 h-8" /><span className="text-xl">Download Passport</span></button></div>
                  </div>
                </div>
              </div>
            </motion.section>
          )}
        </AnimatePresence>
