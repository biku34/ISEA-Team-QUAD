"""
DISK ENTROPY ANALYZER
─────────────────────
Phase 1  Disk Reader · Shannon Entropy · Threshold Detection · Region Aggregation
Phase 2  Chi-Square Test · Compression Test · Sliding Window
Phase 3  Entropy Heatmap · Histogram · Suspicious Region Report (Risk Score)

UI matches the reference design: dark forensics terminal aesthetic,
orange accent, monospace typography, split-panel layout.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import math, zlib, threading, os, datetime, json, csv
from collections import Counter
from dataclasses import dataclass, field
from typing import List


# ══════════════════════════════════════════════════════════════════════════════
#  ANALYSIS ENGINE
# ══════════════════════════════════════════════════════════════════════════════

def byte_frequency(data: bytes) -> dict:
    return Counter(data)

def shannon_entropy(data: bytes) -> float:
    if not data: return 0.0
    freq  = byte_frequency(data)
    total = len(data)
    ent   = 0.0
    for c in freq.values():
        p = c / total
        if p > 0: ent -= p * math.log2(p)
    return ent

def read_in_chunks(filepath: str, block_size: int):
    with open(filepath, "rb") as fh:
        idx = 0
        while True:
            chunk = fh.read(block_size)
            if not chunk: break
            yield idx, chunk
            idx += 1

def chi_square_test(data: bytes):
    if len(data) < 256: return 0.0, 1.0
    obs  = [0]*256
    for b in data: obs[b] += 1
    exp  = len(data)/256.0
    chi2 = sum((o-exp)**2/exp for o in obs)
    return chi2, _chi2_sf(chi2, 255)

def _reg_gamma(a, x, it=200):
    if x<=0: return 0.0
    if x>a+100: return 1.0
    lnGa = math.lgamma(a)
    t = math.exp(-x + a*math.log(x) - lnGa)/a
    s = t
    for n in range(1, it):
        t *= x/(a+n); s += t
        if t < 1e-12*s: break
    return min(s, 1.0)

def _chi2_sf(chi2, df):
    return 1.0 - _reg_gamma(df/2.0, chi2/2.0)

def compression_ratio(data: bytes) -> float:
    if not data: return 0.0
    return len(zlib.compress(data, level=9)) / len(data)

def comp_verdict(r: float) -> str:
    if r>0.98:  return "Incompressible"
    if r>0.90:  return "Barely Comp."
    if r>0.70:  return "Moderate"
    return "Compressible"


@dataclass
class WindowRecord:
    window_index: int; offset: int; size: int
    entropy: float; chi2: float; p_value: float
    comp_ratio: float; suspicious: bool = False

@dataclass
class BlockRecord:
    index: int; offset: int; size: int; entropy: float
    chi2: float=0.0; p_value: float=1.0; comp_ratio: float=0.0
    suspicious: bool=False; sw_peak: float=0.0
    windows: List[WindowRecord]=field(default_factory=list, repr=False)
    @property
    def verdict(self) -> str:
        if self.suspicious: return "Encrypted/Rand"
        if self.entropy>6.5: return "Compressed"
        if self.entropy>4.0: return "Mixed"
        return "Normal"

@dataclass
class Region:
    start_block:int; end_block:int; start_offset:int; end_offset:int
    block_count:int; total_bytes:int; avg_entropy:float; peak_entropy:float
    avg_comp:float; avg_chi2:float
    blocks: List[BlockRecord]=field(default_factory=list, repr=False)
    @property
    def size_kb(self): return self.total_bytes/1024
    @property
    def risk_score(self):
        avg_pval = sum(b.p_value for b in self.blocks)/max(len(self.blocks),1)
        return min((self.avg_entropy/8)*50 + min(self.avg_comp,1)*30 + avg_pval*20, 100.0)
    @property
    def risk_label(self):
        s=self.risk_score
        if s>=85: return "CRITICAL"
        if s>=65: return "HIGH"
        if s>=45: return "MEDIUM"
        return "LOW"
    @property
    def noise(self): return "No" if self.total_bytes>=4096 else "Yes"

def flag_blocks(records, threshold, alpha=0.05, comp_thresh=0.90):
    for r in records:
        r.suspicious = (r.entropy>threshold and r.comp_ratio>comp_thresh and r.p_value>=alpha)

def aggregate_regions(records, min_bytes=4096):
    regions=[]; run=[]
    def _fl(run):
        if not run: return
        tot=sum(r.size for r in run)
        if tot<min_bytes: return
        regions.append(Region(
            start_block=run[0].index, end_block=run[-1].index,
            start_offset=run[0].offset, end_offset=run[-1].offset+run[-1].size,
            block_count=len(run), total_bytes=tot,
            avg_entropy=sum(r.entropy for r in run)/len(run),
            peak_entropy=max(r.entropy for r in run),
            avg_comp=sum(r.comp_ratio for r in run)/len(run),
            avg_chi2=sum(r.chi2 for r in run)/len(run),
            blocks=list(run)))
    for rec in records:
        if rec.suspicious: run.append(rec)
        else: _fl(run); run=[]
    _fl(run); return regions

def sliding_window_analysis(data, offset, wsize, step, threshold):
    results=[]; wi=0
    for s in range(0, len(data)-wsize+1, step):
        w=data[s:s+wsize]; ent=shannon_entropy(w)
        c2,pv=chi_square_test(w); cr=compression_ratio(w)
        results.append(WindowRecord(wi, offset+s, len(w), ent, c2, pv, cr,
                                    ent>threshold and cr>0.90))
        wi+=1
    return results

def build_report(regions, records, filepath, threshold, block_size):
    now=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sep="═"*80; sep2="─"*80
    L=[sep,
       "  AD1 ENTROPY ANALYZER — SUSPICIOUS REGION REPORT",sep,
       f"  File      : {filepath}",
       f"  Generated : {now}",
       f"  Block Size: {block_size:,} B   Threshold: {threshold} bits",
       f"  Blocks: {len(records)}   Suspicious: {sum(1 for r in records if r.suspicious)}   Regions: {len(regions)}",
       sep,""]
    if not regions:
        L+=["  ✅  No suspicious regions found.",""]
    else:
        for i,reg in enumerate(regions,1):
            sc=reg.risk_score
            L+=[f"  REGION {i:>3}  ·  Risk: {reg.risk_label}  ·  Score: {sc:.1f}/100",sep2,
                f"  Start Offset : {reg.start_offset:>15,} B  (Block {reg.start_block})",
                f"  End Offset   : {reg.end_offset:>15,} B  (Block {reg.end_block})",
                f"  Size         : {reg.total_bytes:>15,} B  ({reg.size_kb:.2f} KB)",
                f"  Blocks       : {reg.block_count}",
                f"  Avg Entropy  : {reg.avg_entropy:.6f} bits/byte",
                f"  Peak Entropy : {reg.peak_entropy:.6f} bits/byte",
                f"  Avg Comp     : {reg.avg_comp:.4f}  ({'incompressible' if reg.avg_comp>0.90 else 'compressible'})",
                f"  Avg χ²       : {reg.avg_chi2:.1f}","",
                f"  {'Blk':>5}  {'Offset':>12}  {'Entropy':>9}  {'Comp':>6}  {'p-val':>7}  Verdict",
                f"  {'─'*5}  {'─'*12}  {'─'*9}  {'─'*6}  {'─'*7}  {'─'*16}"]
            for b in reg.blocks:
                L.append(f"  {b.index:>5}  {b.offset:>12,}  {b.entropy:>9.4f}  "
                         f"{b.comp_ratio:>6.4f}  {b.p_value:>7.4f}  {b.verdict}")
            L+=["",sep,""]
    L+=["  RISK FORMULA: (avg_entropy/8)×50 + min(avg_comp,1)×30 + avg_p_value×20",
        "  CRITICAL≥85 · HIGH≥65 · MEDIUM≥45 · LOW<45", sep]
    return "\n".join(L)


# ══════════════════════════════════════════════════════════════════════════════
#  COLOUR SCHEME  (matches reference screenshot)
# ══════════════════════════════════════════════════════════════════════════════

BG       = "#0b0c10"       # near-black background
BG2      = "#0f1117"       # slightly lighter panels
BG3      = "#141720"       # header / section bg
BORDER   = "#1e2230"       # subtle borders
ORANGE   = "#ff6600"       # primary accent (logo, headers, highlights)
ORANGE2  = "#ff8c00"       # hover / lighter orange
CYAN     = "#00d4ff"       # secondary accent (nav links, values)
CYAN2    = "#00aacc"       # dimmer cyan
GREEN    = "#00ff88"       # normal / low entropy
GREEN2   = "#00cc66"       # analyze button
YELLOW   = "#ffcc00"       # medium entropy / warning
RED      = "#ff3355"       # high entropy / suspicious / stop btn
RED2     = "#cc1133"
MAGENTA  = "#ff44cc"       # encrypted/random
TEAL     = "#00ccaa"       # compressed
BLUE     = "#4488ff"       # region overlay
TEXT     = "#c8ccd8"       # main text
TEXT2    = "#7a8099"       # muted text
MONO     = ("Consolas", 9) # monospace body
MONO_S   = ("Consolas", 8) # small mono
MONO_L   = ("Consolas", 11)
HEAD_F   = ("Consolas", 10, "bold")

# Legend colours matching the bottom legend in the screenshot
LEG = [
    ("#00ff88", "Normal"), ("#ffcc00", "Medium"), ("#ff6600", "High"),
    ("#ff3355", "Enc/Rand"), ("#00d4ff", "Susp."), ("#ff44cc", "Encrypted"),
    ("#00ccaa", "Compressed"), ("#4488ff", "O Region"), ("#88ff44", "SW Peak"),
]


# ══════════════════════════════════════════════════════════════════════════════
#  HEATMAP CANVAS
# ══════════════════════════════════════════════════════════════════════════════

def _lerp(c1, c2, t):
    h = lambda s: tuple(int(s.lstrip("#")[i:i+2],16) for i in (0,2,4))
    r1,g1,b1=h(c1); r2,g2,b2=h(c2)
    return f"#{int(r1+(r2-r1)*t):02x}{int(g1+(g2-g1)*t):02x}{int(b1+(b2-b1)*t):02x}"

def _ent_color(e, thr):
    t=e/8.0
    if e>=thr:   return _lerp("#ff6600","#ff3355", min((e-thr)/(8-thr),1.0)) if thr<8 else "#ff3355"
    if t>0.625: return _lerp("#ffcc00","#ff6600", (t-0.625)/0.25)
    if t>0.375: return _lerp("#00ff88","#ffcc00", (t-0.375)/0.25)
    return _lerp("#2244aa","#00ff88", t/0.375)

class HeatmapCanvas(tk.Canvas):
    PAD_L=52; PAD_R=10; PAD_T=22; PAD_B=34; PH=190; BW=5
    def __init__(self, parent, **kw):
        super().__init__(parent, bg=BG2, highlightthickness=0, **kw)
        self._records=[]; self._regions=[]; self._thr=7.0; self._bw=self.BW
        self.bind("<Configure>", lambda e: self._draw())
        self.bind("<Motion>",  self._tip)
        self.bind("<Leave>",   lambda e: self._tip_lbl.place_forget() if hasattr(self,'_tip_lbl') else None)
        self._tip_lbl=tk.Label(parent, text="", fg=BG, bg=CYAN, font=MONO_S,
                                relief="flat", bd=1, padx=4)

    def load(self, records, regions, thr, bw=None):
        self._records=records; self._regions=regions; self._thr=thr
        if bw: self._bw=bw
        self._draw()

    def _draw(self, *_):
        self.delete("all")
        if not self._records:
            self.create_text(10,10,text="Run analysis to see heatmap.",
                             fill=TEXT2, font=MONO, anchor="nw"); return
        n=len(self._records); bw=self._bw
        W=self.PAD_L + n*bw + self.PAD_R
        H=self.PAD_T + self.PH + self.PAD_B
        self.configure(scrollregion=(0,0,W,H))
        pl=self.PAD_L; pt=self.PAD_T; ph=self.PH
        # grid
        for v in range(0,9):
            y=pt+ph-int(v/8*ph)
            self.create_line(pl,y,W-self.PAD_R,y,fill=BORDER,dash=(2,6))
            self.create_text(pl-4,y,text=f"{v}",fill=TEXT2,font=MONO_S,anchor="e")
        # region overlays
        for reg in self._regions:
            x1=pl+reg.start_block*bw; x2=pl+(reg.end_block+1)*bw
            self.create_rectangle(x1,pt,x2,pt+ph,fill="#1a0a2e",outline=BLUE,width=1)
        # threshold line
        ty=pt+ph-int(self._thr/8*ph)
        self.create_line(pl,ty,W-self.PAD_R,ty,fill=RED,width=1,dash=(6,3))
        self.create_text(pl-4,ty,text=f"▶{self._thr:.1f}",fill=RED,font=MONO_S,anchor="e")
        # bars
        for rec in self._records:
            x1=pl+rec.index*bw; x2=x1+bw-1
            bh=int(rec.entropy/8*ph); y2=pt+ph; y1=y2-bh
            col=_ent_color(rec.entropy,self._thr)
            self.create_rectangle(x1,y1,x2,y2,fill=col,outline="")
            if rec.sw_peak>0:
                spy=y2-int(rec.sw_peak/8*ph)
                self.create_line(x1,spy,x2,spy,fill="#88ff44",width=1)
            if rec.suspicious:
                self.create_rectangle(x1,y1,x2,y2,fill="",outline=CYAN,width=1)
        # x-axis ticks
        step=max(1,n//16)
        for i in range(0,n,step):
            x=pl+i*bw; self.create_text(x,pt+ph+10,text=str(i),
                fill=TEXT2,font=MONO_S,angle=40,anchor="ne")
        self.create_text(pl//2,pt+ph//2,text="bits",fill=TEXT2,font=MONO_S,angle=90)

    def _tip(self, ev):
        cx=self.canvasx(ev.x); bw=self._bw
        idx=int((cx-self.PAD_L)/bw)
        if 0<=idx<len(self._records):
            r=self._records[idx]
            self._tip_lbl.config(
                text=f" Blk {r.index} | H={r.entropy:.3f} | C={r.comp_ratio:.3f} "
                     f"| {'⚠ SUSP' if r.suspicious else 'ok'} ")
            self._tip_lbl.place(x=ev.x+12,y=ev.y-18)
        else: self._tip_lbl.place_forget()


class HistCanvas(tk.Canvas):
    PAD_L=50; PAD_R=16; PAD_T=24; PAD_B=44
    def __init__(self, parent, **kw):
        super().__init__(parent, bg=BG2, highlightthickness=0, **kw)
        self._records=[]; self._thr=7.0; self._nbins=32
        self.bind("<Configure>", lambda e: self._draw())

    def load(self, records, thr, nbins=32):
        self._records=records; self._thr=thr; self._nbins=nbins; self._draw()

    def _draw(self, *_):
        self.delete("all")
        if not self._records:
            self.create_text(10,10,text="Run analysis to see histogram.",
                             fill=TEXT2,font=MONO,anchor="nw"); return
        W=self.winfo_width() or 400; H=self.winfo_height() or 280
        pl=self.PAD_L; pr=self.PAD_R; pt=self.PAD_T; pb=self.PAD_B
        pw=W-pl-pr; ph=H-pt-pb
        nb=self._nbins; bw_f=8.0/nb
        counts=[0]*nb
        for r in self._records:
            b=min(int(r.entropy/bw_f),nb-1); counts[b]+=1
        mc=max(counts) if counts else 1; bpx=pw/nb
        for i in range(5):
            y=pt+int(ph*i/4); v=mc*(4-i)/4
            self.create_line(pl,y,W-pr,y,fill=BORDER,dash=(2,6))
            self.create_text(pl-4,y,text=f"{int(v)}",fill=TEXT2,font=MONO_S,anchor="e")
        for i,cnt in enumerate(counts):
            lo=i*bw_f
            x1=pl+i*bpx+1; x2=pl+(i+1)*bpx-1
            bh=int(ph*cnt/mc) if mc else 0; y1=pt+ph-bh; y2=pt+ph
            fill=_ent_color(lo+bw_f/2,self._thr)
            self.create_rectangle(x1,y1,x2,y2,fill=fill,outline=BG3)
            if cnt>0:
                self.create_text((x1+x2)//2,y1-3,text=str(cnt),
                                 fill=TEXT2,font=MONO_S)
        tx=pl+(self._thr/8.0)*pw
        self.create_line(tx,pt,tx,pt+ph,fill=RED,width=2,dash=(5,3))
        self.create_text(tx+3,pt+6,text=f"thr={self._thr:.1f}",
                         fill=RED,font=MONO_S,anchor="w")
        step=max(1,nb//8)
        for i in range(0,nb+1,step):
            x=pl+i*bpx
            self.create_text(x,pt+ph+12,text=f"{i*bw_f:.1f}",
                             fill=TEXT2,font=MONO_S)
        self.create_text(pl//2,pt+ph//2,text="count",fill=TEXT2,font=MONO_S,angle=90)
        self.create_text(pl+pw//2,pt+ph+30,text="entropy (bits/byte)",
                         fill=TEXT2,font=MONO_S)
        self.create_text(pl+pw//2,10,text="Entropy Distribution",
                         fill=CYAN,font=HEAD_F)


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN APPLICATION
# ══════════════════════════════════════════════════════════════════════════════

class DiskEntropyAnalyzer(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Disk Entropy Analyzer")
        self.geometry("1400x860")
        self.configure(bg=BG)
        self.resizable(True,True)

        # state
        self._filepath    = tk.StringVar(value="No file selected")
        self._fileinfo    = tk.StringVar(value="")
        self._block_size  = tk.IntVar(value=4096)
        self._custom_bs   = tk.StringVar(value="512")
        self._threshold   = tk.DoubleVar(value=7.00)
        self._min_region  = tk.DoubleVar(value=4.00)
        # chi2
        self._chi2_en     = tk.BooleanVar(value=True)
        self._chi2_alpha  = tk.StringVar(value="0.05")
        # compression
        self._comp_en     = tk.BooleanVar(value=True)
        self._comp_thr    = tk.StringVar(value="0.95")
        # sliding window
        self._sw_en       = tk.BooleanVar(value=True)
        self._sw_win      = tk.StringVar(value="128")
        self._sw_step     = tk.StringVar(value="64")
        # options
        self._hl_sus      = tk.BooleanVar(value=True)
        self._reg_ov      = tk.BooleanVar(value=True)
        self._store_freq  = tk.BooleanVar(value=False)
        # runtime
        self._running     = False
        self._records: List[BlockRecord]=[]
        self._regions: List[Region]=[]
        self._bs_btns     = {}

        self._build_ui()
        self._apply_style()

    # ─────────────────────────────────────────────────────────────────
    #  STYLE
    # ─────────────────────────────────────────────────────────────────

    def _apply_style(self):
        s=ttk.Style(self)
        s.theme_use("clam")
        s.configure("Treeview", background=BG2, foreground=TEXT,
                    fieldbackground=BG2, rowheight=20, font=MONO)
        s.configure("Treeview.Heading", background=BG3, foreground=ORANGE,
                    font=HEAD_F, relief="flat", borderwidth=0)
        s.map("Treeview", background=[("selected","#1e2a3a")])
        s.configure("TSeparator", background=BORDER)
        s.configure("TScrollbar", background=BG3, troughcolor=BG,
                    arrowcolor=TEXT2, bordercolor=BG)
        s.configure("Horizontal.TProgressbar",
                    troughcolor=BG3, background=ORANGE,
                    bordercolor=BG, lightcolor=ORANGE, darkcolor=ORANGE2)

    # ─────────────────────────────────────────────────────────────────
    #  TOP BAR
    # ─────────────────────────────────────────────────────────────────

    def _build_topbar(self, parent):
        bar=tk.Frame(parent, bg=BG3, pady=0)
        bar.pack(fill="x")
        # left: logo + title
        left=tk.Frame(bar, bg=BG3)
        left.pack(side="left", padx=(10,0))
        logo=tk.Canvas(left, width=28, height=28, bg=BG3, highlightthickness=0)
        logo.pack(side="left", pady=6, padx=(0,8))
        logo.create_oval(3,3,25,25,fill=ORANGE,outline="")
        logo.create_oval(8,8,20,20,fill=BG3,outline="")
        tk.Label(left, text="AD1 ENTROPY ANALYZER",
                 font=("Consolas",14,"bold"), fg=ORANGE, bg=BG3
                 ).pack(side="left")
        # nav pills
        nav=tk.Frame(bar, bg=BG3)
        nav.pack(side="left", padx=20, pady=8)
        pills=["Shannon","χ²","Compression","Sliding Window","Heatmap","Histogram","Risk Report"]
        for i,p in enumerate(pills):
            sep=" · " if i<len(pills)-1 else ""
            tk.Label(nav, text=p+sep, font=MONO, fg=CYAN2, bg=BG3,
                     cursor="hand2").pack(side="left")
        tk.Label(nav, text="  |  ", font=MONO, fg=BORDER, bg=BG3).pack(side="left")
        tk.Label(nav, text="Raw / E01", font=MONO, fg=TEXT2, bg=BG3).pack(side="left")

    # ─────────────────────────────────────────────────────────────────
    #  CONFIGURATION PANEL
    # ─────────────────────────────────────────────────────────────────

    def _build_config(self, parent):
        cf=tk.Frame(parent, bg=BG, pady=0)
        cf.pack(fill="x", padx=10, pady=(6,0))

        # section header
        tk.Label(cf, text="Configuration", font=("Consolas",10,"bold"),
                 fg=ORANGE, bg=BG).pack(anchor="w", padx=2)

        row1=tk.Frame(cf, bg=BG); row1.pack(fill="x", pady=1)
        tk.Label(row1, text="Image File:", font=MONO, fg=TEXT2, bg=BG,
                 width=11, anchor="w").pack(side="left", padx=(2,6))
        tk.Label(row1, textvariable=self._filepath,
                 font=MONO, fg=CYAN, bg=BG, anchor="w").pack(side="left", fill="x", expand=True)
        self._browse_btn=tk.Button(row1, text="Browse...",
                 command=self._browse,
                 font=HEAD_F, fg=TEXT, bg="#1a4a9a",
                 activebackground="#2255bb", activeforeground=TEXT,
                 relief="flat", padx=14, pady=3, cursor="hand2", bd=0)
        self._browse_btn.pack(side="right", padx=4)

        row2=tk.Frame(cf, bg=BG); row2.pack(fill="x", pady=1)
        tk.Label(row2, text="Image Info:", font=MONO, fg=TEXT2, bg=BG,
                 width=11, anchor="w").pack(side="left", padx=(2,6))
        tk.Label(row2, textvariable=self._fileinfo,
                 font=MONO, fg=TEXT2, bg=BG).pack(side="left")

        row3=tk.Frame(cf, bg=BG); row3.pack(fill="x", pady=3)
        tk.Label(row3, text="Block Size:", font=MONO, fg=TEXT2, bg=BG,
                 width=11, anchor="w").pack(side="left", padx=(2,6))
        sizes=[("512B",512),("1KB",1024),("4KB",4096),("16KB",16384),
               ("64KB",65536),("1MB",1048576)]
        for label,val in sizes:
            b=tk.Button(row3, text=label, font=MONO_S,
                        command=lambda v=val,l=label: self._set_bs(v,l),
                        relief="flat", padx=6, pady=2, cursor="hand2", bd=0)
            b.pack(side="left", padx=2)
            self._bs_btns[label]=b
        # custom
        ce=tk.Entry(row3, textvariable=self._custom_bs, width=6,
                    font=MONO, bg=BG3, fg=CYAN, insertbackground=CYAN,
                    relief="flat", bd=1, highlightthickness=1,
                    highlightbackground=BORDER, highlightcolor=ORANGE)
        ce.pack(side="left", padx=2)
        tk.Label(row3, text="B", font=MONO, fg=TEXT2, bg=BG).pack(side="left", padx=1)
        tk.Button(row3, text="Set", font=MONO_S, command=self._set_custom_bs,
                  bg=BG3, fg=CYAN, relief="flat", padx=4, pady=2, cursor="hand2"
                  ).pack(side="left", padx=2)

        # threshold + min region sliders (right side of row3)
        rp=tk.Frame(cf, bg=BG); rp.pack(fill="x", pady=2)
        r4=tk.Frame(rp, bg=BG); r4.pack(side="right", padx=4)
        # threshold
        t1=tk.Frame(r4, bg=BG); t1.pack(side="left", padx=(0,12))
        tk.Label(t1, text="⚠ Ent. Threshold:", font=MONO_S, fg=ORANGE, bg=BG
                 ).pack(side="left", padx=(0,4))
        tk.Scale(t1, variable=self._threshold, from_=0, to=8, resolution=0.05,
                 orient="horizontal", length=140, bg=BG3, fg=CYAN,
                 troughcolor=BG3, highlightthickness=0, sliderrelief="flat",
                 activebackground=ORANGE, font=MONO_S, showvalue=False,
                 command=lambda v: self._thr_lbl.config(text=f"{float(v):.2f}")
                 ).pack(side="left")
        self._thr_lbl=tk.Label(t1, text="7.00", font=MONO, fg=CYAN, bg=BG, width=5)
        self._thr_lbl.pack(side="left")
        # min region
        t2=tk.Frame(r4, bg=BG); t2.pack(side="left")
        tk.Label(t2, text="○ Min Region:", font=MONO_S, fg=TEXT2, bg=BG
                 ).pack(side="left", padx=(0,4))
        tk.Scale(t2, variable=self._min_region, from_=0.5, to=64, resolution=0.5,
                 orient="horizontal", length=140, bg=BG3, fg=CYAN,
                 troughcolor=BG3, highlightthickness=0, sliderrelief="flat",
                 activebackground=ORANGE, font=MONO_S, showvalue=False,
                 command=lambda v: self._mr_lbl.config(text=f"{float(v):.2f} KB")
                 ).pack(side="left")
        self._mr_lbl=tk.Label(t2, text="4.00 KB", font=MONO, fg=CYAN, bg=BG, width=8)
        self._mr_lbl.pack(side="left")

        self._set_bs(4096,"4KB")  # default highlight

    # ─────────────────────────────────────────────────────────────────
    #  ANALYSIS TESTS PANEL
    # ─────────────────────────────────────────────────────────────────

    def _build_tests(self, parent):
        outer=tk.Frame(parent, bg=BG, pady=0)
        outer.pack(fill="x", padx=10, pady=(4,0))
        tk.Label(outer, text="Analysis Tests", font=("Consolas",10,"bold"),
                 fg=ORANGE, bg=BG).pack(anchor="w", padx=2)

        cols=tk.Frame(outer, bg=BG); cols.pack(fill="x")

        def col(parent, expand=True):
            f=tk.Frame(parent, bg=BG3, bd=0, relief="flat",
                       highlightthickness=1, highlightbackground=BORDER)
            f.pack(side="left", fill="both", expand=expand, padx=3, pady=2, ipadx=8, ipady=6)
            return f

        # χ² column
        c1=col(cols)
        tk.Label(c1, text="χ² Randomness Test", font=("Consolas",9,"bold"),
                 fg=ORANGE, bg=BG3).pack(anchor="w")
        r=tk.Frame(c1,bg=BG3); r.pack(anchor="w",pady=2)
        tk.Checkbutton(r, text="Enable", variable=self._chi2_en, bg=BG3, fg=GREEN,
                       selectcolor=BG, activebackground=BG3, font=MONO,
                       highlightthickness=0).pack(side="left")
        tk.Label(r, text="α:", font=MONO, fg=TEXT2, bg=BG3).pack(side="left",padx=(8,2))
        tk.Entry(r, textvariable=self._chi2_alpha, width=6, font=MONO,
                 bg=BG, fg=CYAN, insertbackground=CYAN, relief="flat",
                 highlightthickness=1, highlightbackground=BORDER).pack(side="left")
        tk.Label(c1, text="Tests if byte distribution\nis uniform (random-like).\nHigh χ² + low p → structured.",
                 font=MONO_S, fg=TEXT2, bg=BG3, justify="left").pack(anchor="w",pady=(4,0))

        # Compression column
        c2=col(cols)
        tk.Label(c2, text="Compression Ratio Test", font=("Consolas",9,"bold"),
                 fg=ORANGE, bg=BG3).pack(anchor="w")
        r2=tk.Frame(c2,bg=BG3); r2.pack(anchor="w",pady=2)
        tk.Checkbutton(r2, text="Enable", variable=self._comp_en, bg=BG3, fg=GREEN,
                       selectcolor=BG, activebackground=BG3, font=MONO,
                       highlightthickness=0).pack(side="left")
        tk.Label(r2, text="Thresh:", font=MONO, fg=TEXT2, bg=BG3).pack(side="left",padx=(8,2))
        tk.Entry(r2, textvariable=self._comp_thr, width=6, font=MONO,
                 bg=BG, fg=CYAN, insertbackground=CYAN, relief="flat",
                 highlightthickness=1, highlightbackground=BORDER).pack(side="left")
        tk.Label(c2, text="ratio = compressed/original.\nratio > thresh → incompressible\n→ likely encrypted.",
                 font=MONO_S, fg=TEXT2, bg=BG3, justify="left").pack(anchor="w",pady=(4,0))

        # Sliding Window column
        c3=col(cols)
        tk.Label(c3, text="Sliding Window Mode", font=("Consolas",9,"bold"),
                 fg=ORANGE, bg=BG3).pack(anchor="w")
        r3=tk.Frame(c3,bg=BG3); r3.pack(anchor="w",pady=2)
        tk.Checkbutton(r3, text="Enable", variable=self._sw_en, bg=BG3, fg=GREEN,
                       selectcolor=BG, activebackground=BG3, font=MONO,
                       highlightthickness=0).pack(side="left")
        tk.Label(r3, text="Win:", font=MONO, fg=TEXT2, bg=BG3).pack(side="left",padx=(8,2))
        tk.Entry(r3, textvariable=self._sw_win, width=5, font=MONO,
                 bg=BG, fg=CYAN, insertbackground=CYAN, relief="flat",
                 highlightthickness=1, highlightbackground=BORDER).pack(side="left")
        tk.Label(r3, text="Step:", font=MONO, fg=TEXT2, bg=BG3).pack(side="left",padx=(6,2))
        tk.Entry(r3, textvariable=self._sw_step, width=4, font=MONO,
                 bg=BG, fg=CYAN, insertbackground=CYAN, relief="flat",
                 highlightthickness=1, highlightbackground=BORDER).pack(side="left")
        tk.Label(c3, text="Overlapping sub-windows for\nfine-grained detection of\nmixed-content blocks.",
                 font=MONO_S, fg=TEXT2, bg=BG3, justify="left").pack(anchor="w",pady=(4,0))

        # options + action buttons
        act=tk.Frame(outer, bg=BG); act.pack(fill="x", pady=(6,2))
        for var, lbl in [(self._hl_sus,"Highlight suspicious"),
                         (self._reg_ov,"Region overlays"),
                         (self._store_freq,"Store byte freq")]:
            tk.Checkbutton(act, text=lbl, variable=var, bg=BG, fg=TEXT2,
                           selectcolor=BG3, activebackground=BG, font=MONO_S,
                           highlightthickness=0).pack(side="left", padx=(0,12))

        act2=tk.Frame(outer, bg=BG); act2.pack(fill="x", pady=(2,4))
        self._analyze_btn=tk.Button(act2, text="▶  Analyze", command=self._start,
                 font=("Consolas",10,"bold"), fg=BG, bg=GREEN2,
                 activebackground=GREEN, activeforeground=BG,
                 relief="flat", padx=18, pady=5, cursor="hand2", bd=0)
        self._analyze_btn.pack(side="left", padx=(0,4))
        self._stop_btn=tk.Button(act2, text="■  Stop", command=self._stop,
                 font=("Consolas",10,"bold"), fg=BG, bg=RED,
                 activebackground=RED2, activeforeground=BG,
                 relief="flat", padx=14, pady=5, cursor="hand2", bd=0, state="disabled")
        self._stop_btn.pack(side="left", padx=(0,12))
        for lbl, cmd in [("Blocks CSV", self._export_csv_blocks),
                         ("Regions CSV", self._export_csv_regions),
                         ("Windows CSV", self._export_csv_windows),
                         ("JSON", self._export_json)]:
            tk.Button(act2, text=lbl, command=cmd,
                      font=MONO_S, fg=TEXT, bg=BG3,
                      activebackground=BORDER, activeforeground=CYAN,
                      relief="flat", padx=10, pady=5, cursor="hand2", bd=0,
                      highlightthickness=1, highlightbackground=BORDER
                      ).pack(side="left", padx=3)

    # ─────────────────────────────────────────────────────────────────
    #  PROGRESS BAR
    # ─────────────────────────────────────────────────────────────────

    def _build_progress(self, parent):
        pf=tk.Frame(parent, bg=BG)
        pf.pack(fill="x", padx=10, pady=(3,0))
        self._pvar=tk.DoubleVar()
        self._pbar=ttk.Progressbar(pf, variable=self._pvar, maximum=100,
                                    style="Horizontal.TProgressbar")
        self._pbar.pack(fill="x")
        self._svar=tk.StringVar(value="")
        tk.Label(pf, textvariable=self._svar, font=MONO_S, fg=TEXT2, bg=BG,
                 anchor="w").pack(fill="x")

    # ─────────────────────────────────────────────────────────────────
    #  BOTTOM SPLIT LAYOUT
    # ─────────────────────────────────────────────────────────────────

    def _build_bottom(self, parent):
        bot=tk.Frame(parent, bg=BG)
        bot.pack(fill="both", expand=True, padx=10, pady=(4,0))

        # LEFT 58% — two stacked tables
        left=tk.Frame(bot, bg=BG)
        left.pack(side="left", fill="both", expand=True, padx=(0,6))

        # Block Results table
        self._build_block_table(left)

        # High-Entropy Regions table
        self._build_region_table(left)

        # RIGHT 42% — visualization panel
        right=tk.Frame(bot, bg=BG3,
                       highlightthickness=1, highlightbackground=BORDER)
        right.pack(side="left", fill="both", expand=False, ipadx=0)
        right.pack_propagate(False)
        right.configure(width=520)
        self._build_viz_panel(right)

    def _build_block_table(self, parent):
        hdr=tk.Frame(parent, bg=BG)
        hdr.pack(fill="x")
        tk.Label(hdr, text="Block Results", font=HEAD_F, fg=ORANGE, bg=BG
                 ).pack(side="left", pady=(2,1))

        cols=("blk","offset","entropy","chi2","pval","comp","swpeak","verdict","flag")
        self._btree=ttk.Treeview(parent, columns=cols, show="headings",
                                  height=10, selectmode="browse")
        headers=[("blk","Block #",60),("offset","Offset",110),
                 ("entropy","Entropy",80),("chi2","χ²",80),
                 ("pval","p-value",72),("comp","Comp Ratio",90),
                 ("swpeak","SW Peak",72),("verdict","Verdict",110),
                 ("flag","⚠",40)]
        for col,lbl,w in headers:
            self._btree.heading(col,text=lbl,
                                command=lambda c=col: self._sort(self._btree,c,False))
            self._btree.column(col,width=w,anchor="center",minwidth=w)

        vsb=ttk.Scrollbar(parent, orient="vertical",   command=self._btree.yview)
        hsb=ttk.Scrollbar(parent, orient="horizontal", command=self._btree.xview)
        self._btree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.pack(side="right", fill="y")
        hsb.pack(side="bottom", fill="x")
        self._btree.pack(fill="both", expand=True)

        self._btree.tag_configure("normal",  background=BG2,          foreground=GREEN)
        self._btree.tag_configure("medium",  background=BG2,          foreground=YELLOW)
        self._btree.tag_configure("high",    background="#1a1000",    foreground=ORANGE)
        self._btree.tag_configure("enc",     background="#1a0010",    foreground=RED)
        self._btree.tag_configure("susp",    background="#100010",    foreground=MAGENTA)

    def _build_region_table(self, parent):
        hdr=tk.Frame(parent, bg=BG)
        hdr.pack(fill="x")
        tk.Label(hdr, text="High-Entropy Regions", font=HEAD_F, fg=ORANGE, bg=BG
                 ).pack(side="left", pady=(4,1))

        cols=("rid","start","end","offset_range","size","blocks","avg","maxe","verdict","noise")
        self._rtree=ttk.Treeview(parent, columns=cols, show="headings",
                                  height=7, selectmode="browse")
        rheaders=[("rid","ID",40),("start","Start",65),("end","End",65),
                  ("offset_range","Offset Range",160),("size","Size",80),
                  ("blocks","Blocks",55),("avg","Avg Ent",72),
                  ("maxe","Max Ent",72),("verdict","Verdict",90),("noise","Noise?",55)]
        for col,lbl,w in rheaders:
            self._rtree.heading(col,text=lbl)
            self._rtree.column(col,width=w,anchor="center",minwidth=w)

        rvsb=ttk.Scrollbar(parent, orient="vertical",   command=self._rtree.yview)
        rhsb=ttk.Scrollbar(parent, orient="horizontal", command=self._rtree.xview)
        self._rtree.configure(yscrollcommand=rvsb.set, xscrollcommand=rhsb.set)
        rvsb.pack(side="right", fill="y")
        rhsb.pack(side="bottom", fill="x")
        self._rtree.pack(fill="both", expand=True)
        self._rtree.bind("<<TreeviewSelect>>", self._on_reg_sel)

        for tag,fg,bg in [("crit",RED,"#1a0000"),("high",ORANGE,"#1a0a00"),
                           ("med",YELLOW,"#161200"),("low",GREEN,BG2)]:
            self._rtree.tag_configure(tag, foreground=fg, background=bg)

    # ─────────────────────────────────────────────────────────────────
    #  VISUALIZATION PANEL  (right side)
    # ─────────────────────────────────────────────────────────────────

    def _build_viz_panel(self, parent):
        tk.Label(parent, text="Visualization", font=HEAD_F, fg=ORANGE, bg=BG3
                 ).pack(anchor="w", padx=8, pady=(6,2))

        # tab buttons
        tb=tk.Frame(parent, bg=BG3)
        tb.pack(fill="x", padx=6, pady=(0,4))
        self._viz_btns={}
        self._viz_frame=tk.Frame(parent, bg=BG2)
        self._viz_frame.pack(fill="both", expand=True, padx=4, pady=(0,4))

        for i,(name,sym) in enumerate([("Heatmap","○"),("Histogram","≡"),("Report","⎙")]):
            b=tk.Button(tb, text=f"{sym} {name}",
                        command=lambda n=name: self._show_viz(n),
                        font=MONO, relief="flat", padx=10, pady=3,
                        cursor="hand2", bd=0)
            b.pack(side="left", padx=2)
            self._viz_btns[name]=b

        # frames for each viz
        self._viz_frames={}

        # Heatmap
        hf=tk.Frame(self._viz_frame, bg=BG2)
        self._viz_frames["Heatmap"]=hf
        htoolbar=tk.Frame(hf, bg=BG2); htoolbar.pack(fill="x", padx=4, pady=2)
        tk.Label(htoolbar, text="Bar:", font=MONO_S, fg=TEXT2, bg=BG2).pack(side="left")
        self._hm_bw=tk.IntVar(value=5)
        tk.Spinbox(htoolbar, from_=2, to=30, increment=1, textvariable=self._hm_bw,
                   width=3, bg=BG3, fg=CYAN, insertbackground=CYAN,
                   buttonbackground=BG3, relief="flat", font=MONO_S,
                   command=self._redraw_heatmap).pack(side="left", padx=(2,8))
        self._hm_canvas=HeatmapCanvas(hf, height=260)
        self._hm_canvas.pack(fill="both", expand=True, padx=2)
        hsb2=ttk.Scrollbar(hf, orient="horizontal", command=self._hm_canvas.xview)
        hsb2.pack(fill="x")
        self._hm_canvas.configure(xscrollcommand=hsb2.set)

        # Histogram
        hisf=tk.Frame(self._viz_frame, bg=BG2)
        self._viz_frames["Histogram"]=hisf
        hist_tb=tk.Frame(hisf, bg=BG2); hist_tb.pack(fill="x", padx=4, pady=2)
        tk.Label(hist_tb, text="Bins:", font=MONO_S, fg=TEXT2, bg=BG2).pack(side="left")
        self._hist_bins=tk.IntVar(value=32)
        tk.Spinbox(hist_tb, from_=8, to=128, increment=4, textvariable=self._hist_bins,
                   width=4, bg=BG3, fg=CYAN, insertbackground=CYAN,
                   buttonbackground=BG3, relief="flat", font=MONO_S,
                   command=self._redraw_hist).pack(side="left", padx=(2,8))
        self._hist_canvas=HistCanvas(hisf)
        self._hist_canvas.pack(fill="both", expand=True, padx=2, pady=2)

        # Report
        rf=tk.Frame(self._viz_frame, bg=BG2)
        self._viz_frames["Report"]=rf
        rtb=tk.Frame(rf, bg=BG2); rtb.pack(fill="x", padx=4, pady=2)
        tk.Label(rtb, text="Risk Report", font=HEAD_F, fg=ORANGE, bg=BG2
                 ).pack(side="left")
        tk.Button(rtb, text="💾 Export", command=self._export_report,
                  font=MONO_S, fg=TEXT, bg=BG3, relief="flat", padx=8,
                  cursor="hand2").pack(side="right", padx=4)
        rsb=ttk.Scrollbar(rf, orient="vertical")
        rsb_h=ttk.Scrollbar(rf, orient="horizontal")
        self._report_txt=tk.Text(rf, bg=BG2, fg=TEXT, font=MONO_S,
                                  insertbackground=CYAN, relief="flat",
                                  state="disabled", wrap="none",
                                  yscrollcommand=rsb.set, xscrollcommand=rsb_h.set)
        rsb.config(command=self._report_txt.yview)
        rsb_h.config(command=self._report_txt.xview)
        rsb.pack(side="right", fill="y")
        rsb_h.pack(side="bottom", fill="x")
        self._report_txt.pack(fill="both", expand=True)
        # tags
        self._report_txt.tag_config("sep",  foreground=BORDER)
        self._report_txt.tag_config("head", foreground=ORANGE, font=("Consolas",9,"bold"))
        self._report_txt.tag_config("crit", foreground=RED)
        self._report_txt.tag_config("high", foreground=ORANGE)
        self._report_txt.tag_config("med",  foreground=YELLOW)
        self._report_txt.tag_config("low",  foreground=GREEN)
        self._report_txt.tag_config("fld",  foreground=CYAN)
        self._report_txt.tag_config("dim",  foreground=TEXT2)

        self._show_viz("Heatmap")

    def _show_viz(self, name):
        for n,f in self._viz_frames.items():
            f.pack_forget()
        self._viz_frames[name].pack(fill="both", expand=True)
        for n,b in self._viz_btns.items():
            if n==name:
                b.config(bg=BG, fg=CYAN, relief="flat")
            else:
                b.config(bg=BG3, fg=TEXT2, relief="flat")

    # ─────────────────────────────────────────────────────────────────
    #  LEGEND BAR
    # ─────────────────────────────────────────────────────────────────

    def _build_legend(self, parent):
        lf=tk.Frame(parent, bg=BG3, pady=3)
        lf.pack(fill="x", side="bottom")
        for col,lbl in LEG:
            dot=tk.Canvas(lf, width=10, height=10, bg=BG3, highlightthickness=0)
            dot.pack(side="left", padx=(6,2))
            dot.create_oval(1,1,9,9, fill=col, outline="")
            tk.Label(lf, text=lbl, font=MONO_S, fg=TEXT2, bg=BG3
                     ).pack(side="left", padx=(0,4))

    # ─────────────────────────────────────────────────────────────────
    #  MAIN LAYOUT ASSEMBLY
    # ─────────────────────────────────────────────────────────────────

    def _build_ui(self):
        self._build_topbar(self)
        ttk.Separator(self, orient="horizontal").pack(fill="x")
        self._build_config(self)
        ttk.Separator(self, orient="horizontal").pack(fill="x", padx=10, pady=2)
        self._build_tests(self)
        self._build_progress(self)
        ttk.Separator(self, orient="horizontal").pack(fill="x", padx=10, pady=1)
        self._build_bottom(self)
        self._build_legend(self)

    # ─────────────────────────────────────────────────────────────────
    #  BLOCK SIZE BUTTONS
    # ─────────────────────────────────────────────────────────────────

    def _set_bs(self, val, label):
        self._block_size.set(val)
        for lbl,btn in self._bs_btns.items():
            if lbl==label:
                btn.config(bg=ORANGE, fg=BG, font=("Consolas",8,"bold"))
            else:
                btn.config(bg=BG3, fg=TEXT, font=MONO_S)

    def _set_custom_bs(self):
        try:
            v=int(self._custom_bs.get())
            if v<=0: raise ValueError
            self._block_size.set(v)
            for btn in self._bs_btns.values():
                btn.config(bg=BG3, fg=TEXT, font=MONO_S)
        except ValueError:
            messagebox.showerror("Invalid","Block size must be a positive integer.")

    # ─────────────────────────────────────────────────────────────────
    #  BROWSE
    # ─────────────────────────────────────────────────────────────────

    def _browse(self):
        path=filedialog.askopenfilename(
            title="Select Image File",
            filetypes=[("AD1/E01/Raw","*.ad1 *.e01 *.raw *.img *.bin"),
                       ("All Files","*.*")])
        if path:
            self._filepath.set(path)
            sz=os.path.getsize(path)
            self._fileinfo.set(f"{os.path.basename(path)}   {sz:,} bytes  "
                               f"({sz/1024/1024:.2f} MB)")
            self._svar.set(f"Loaded: {os.path.basename(path)}")

    # ─────────────────────────────────────────────────────────────────
    #  START / STOP
    # ─────────────────────────────────────────────────────────────────

    def _start(self):
        path=self._filepath.get()
        if path=="No file selected" or not os.path.isfile(path):
            messagebox.showwarning("No File","Please select a valid image file.")
            return
        try:
            bs=int(self._block_size.get()); thr=float(self._threshold.get())
            alpha=float(self._chi2_alpha.get()); cthr=float(self._comp_thr.get())
            wsize=int(self._sw_win.get()); step=int(self._sw_step.get())
            min_bytes=int(float(self._min_region.get())*1024)
            if bs<=0 or not 0<=thr<=8: raise ValueError
        except ValueError:
            messagebox.showerror("Invalid Settings","Check all numeric parameters."); return

        self._clear_data()
        self._running=True
        self._analyze_btn.config(state="disabled")
        self._stop_btn.config(state="normal")
        threading.Thread(target=self._worker,
                         args=(path,bs,thr,alpha,cthr,
                               self._sw_en.get(),wsize,step,
                               self._chi2_en.get(),self._comp_en.get(),
                               min_bytes),
                         daemon=True).start()

    def _stop(self):
        self._running=False
        self._svar.set("⛔  Stopped by user.")

    def _clear_data(self):
        self._records.clear(); self._regions.clear()
        for tree in (self._btree, self._rtree):
            for r in tree.get_children(): tree.delete(r)
        self._pvar.set(0); self._svar.set("")
        self._hm_canvas.load([],[],self._threshold.get())
        self._hist_canvas.load([],self._threshold.get())
        self._report_txt.config(state="normal"); self._report_txt.delete("1.0","end")
        self._report_txt.config(state="disabled")

    # ─────────────────────────────────────────────────────────────────
    #  WORKER THREAD
    # ─────────────────────────────────────────────────────────────────

    def _worker(self, filepath, bs, thr, alpha, cthr,
                sw_en, wsize, step, chi2_en, comp_en, min_bytes):
        try:
            fsize=os.path.getsize(filepath)
            total=math.ceil(fsize/bs)
            done=0; esum=0.0; records=[]

            for idx, chunk in read_in_chunks(filepath, bs):
                if not self._running: break
                ent=shannon_entropy(chunk)
                chi2,pval=(chi_square_test(chunk) if chi2_en else (0.0,1.0))
                cr=(compression_ratio(chunk) if comp_en else 0.0)
                offset=idx*bs

                windows=[]
                sw_peak=0.0
                if sw_en and len(chunk)>=wsize:
                    windows=sliding_window_analysis(chunk,offset,wsize,step,thr)
                    sw_peak=max((w.entropy for w in windows),default=0.0)

                rec=BlockRecord(index=idx,offset=offset,size=len(chunk),
                                entropy=ent,chi2=chi2,p_value=pval,
                                comp_ratio=cr,sw_peak=sw_peak,windows=windows)
                records.append(rec)
                esum+=ent; done+=1
                prog=(done/total*100) if total else 100
                self.after(0, self._add_blk_row, rec, thr)
                self.after(0, self._pvar.set, prog)
                self.after(0, self._svar.set,
                    f"  Blk {idx}/{total}  ent={ent:.3f}  χ²p={pval:.3f}  "
                    f"comp={cr:.3f}  {'⚠ SUSPICIOUS' if ent>thr and cr>cthr else 'ok'}")

            flag_blocks(records, thr, alpha, cthr)
            regions=aggregate_regions(records, min_bytes)
            self._records=records; self._regions=regions

            avg=esum/done if done else 0
            rpt=build_report(regions,records,filepath,thr,bs)
            self.after(0, self._repaint_susp)
            self.after(0, self._pop_regions)
            self.after(0, self._hm_canvas.load, records, regions, thr,
                       self._hm_bw.get())
            self.after(0, self._hist_canvas.load, records, thr,
                       self._hist_bins.get())
            self.after(0, self._load_report, rpt)
            self.after(0, self._finish, done, avg, fsize, thr)
        except Exception as ex:
            self.after(0, messagebox.showerror, "Error", str(ex))
            self.after(0, self._reset_btns)

    # ─────────────────────────────────────────────────────────────────
    #  TABLE UPDATERS
    # ─────────────────────────────────────────────────────────────────

    def _add_blk_row(self, rec: BlockRecord, thr: float):
        e=rec.entropy
        if e>thr and rec.comp_ratio>0.90: tag="susp"
        elif e>7.2: tag="enc"
        elif e>6.5: tag="high"
        elif e>4.0: tag="medium"
        else:       tag="normal"
        flag="⚠" if (e>thr and rec.comp_ratio>0.90) else ""
        self._btree.insert("","end",tags=(tag,),values=(
            rec.index, f"{rec.offset:,}", f"{rec.entropy:.4f}",
            f"{rec.chi2:.1f}", f"{rec.p_value:.4f}",
            f"{rec.comp_ratio:.4f}", f"{rec.sw_peak:.4f}",
            rec.verdict, flag))
        kids=self._btree.get_children()
        if kids: self._btree.see(kids[-1])

    def _repaint_susp(self):
        for item in self._btree.get_children():
            idx=int(self._btree.item(item,"values")[0])
            if idx<len(self._records) and self._records[idx].suspicious:
                self._btree.item(item,tags=("susp",))
                self._btree.set(item,"flag","⚠")

    def _pop_regions(self):
        for r in self._rtree.get_children(): self._rtree.delete(r)
        for i,reg in enumerate(self._regions,1):
            sc=reg.risk_score; rl=reg.risk_label
            tag=("crit" if sc>=85 else "high" if sc>=65 else "med" if sc>=45 else "low")
            self._rtree.insert("","end",tags=(tag,),values=(
                i, reg.start_block, reg.end_block,
                f"{reg.start_offset:,}–{reg.end_offset:,}",
                f"{reg.size_kb:.1f} KB", reg.block_count,
                f"{reg.avg_entropy:.3f}", f"{reg.peak_entropy:.3f}",
                rl, reg.noise))

    def _on_reg_sel(self, _=None):
        sel=self._rtree.selection()
        if not sel: return
        rid=int(self._rtree.item(sel[0],"values")[0])-1
        if 0<=rid<len(self._regions):
            reg=self._regions[rid]
            self._svar.set(
                f"  Region {rid+1}  |  Blocks {reg.start_block}–{reg.end_block}  "
                f"|  {reg.size_kb:.1f} KB  |  Risk: {reg.risk_label} ({reg.risk_score:.1f})")

    def _load_report(self, text):
        self._report_txt.config(state="normal")
        self._report_txt.delete("1.0","end")
        for line in text.splitlines():
            tag=""
            if line.startswith("═") or line.startswith("─"): tag="sep"
            elif "CRITICAL" in line: tag="crit"
            elif "HIGH" in line and "Avg" not in line: tag="high"
            elif "MEDIUM" in line: tag="med"
            elif "LOW" in line and "Avg" not in line: tag="low"
            elif "DISK ENTROPY" in line or "REPORT" in line: tag="head"
            elif ":" in line[:30] and line.startswith("  "): tag="fld"
            else: tag="dim"
            self._report_txt.insert("end", line+"\n", tag)
        self._report_txt.config(state="disabled")

    def _finish(self, total, avg, fsize, thr):
        self._reset_btns()
        self._pvar.set(100)
        conf=sum(1 for r in self._records if r.suspicious)
        crit=sum(1 for r in self._regions if r.risk_score>=85)
        self._svar.set(
            f"  ✅ Done  Blocks:{total}  AvgH:{avg:.3f}  ⚠ Suspicious:{conf}  "
            f"Regions:{len(self._regions)}  🔴 Critical:{crit}")

    def _reset_btns(self):
        self._running=False
        self._analyze_btn.config(state="normal")
        self._stop_btn.config(state="disabled")

    def _redraw_heatmap(self):
        if self._records:
            self._hm_canvas.load(self._records, self._regions,
                                  self._threshold.get(), self._hm_bw.get())

    def _redraw_hist(self):
        if self._records:
            self._hist_canvas.load(self._records, self._threshold.get(),
                                    self._hist_bins.get())

    # ─────────────────────────────────────────────────────────────────
    #  SORTING
    # ─────────────────────────────────────────────────────────────────

    def _sort(self, tree, col, desc):
        rows=[(tree.set(k,col),k) for k in tree.get_children("")]
        try:    rows.sort(key=lambda t: float(t[0].replace(",","").replace("–","0")), reverse=desc)
        except: rows.sort(reverse=desc)
        for i,(_,k) in enumerate(rows): tree.move(k,"",i)
        tree.heading(col, command=lambda: self._sort(tree,col,not desc))

    # ─────────────────────────────────────────────────────────────────
    #  EXPORT
    # ─────────────────────────────────────────────────────────────────

    def _save_path(self, ext):
        return filedialog.asksaveasfilename(
            defaultextension=ext,
            filetypes=[(ext.upper().lstrip(".")+" File", f"*{ext}"),
                       ("All Files","*.*")])

    def _export_csv_blocks(self):
        if not self._records: return
        p=self._save_path(".csv")
        if not p: return
        with open(p,"w",newline="",encoding="utf-8") as f:
            w=csv.writer(f)
            w.writerow(["Block","Offset","Size","Entropy","Chi2","P-value",
                        "CompRatio","SWPeak","Suspicious","Verdict"])
            for r in self._records:
                w.writerow([r.index,r.offset,r.size,f"{r.entropy:.6f}",
                            f"{r.chi2:.2f}",f"{r.p_value:.4f}",
                            f"{r.comp_ratio:.4f}",f"{r.sw_peak:.4f}",
                            r.suspicious,r.verdict])
        messagebox.showinfo("Exported",f"Blocks CSV saved:\n{p}")

    def _export_csv_regions(self):
        if not self._regions: return
        p=self._save_path(".csv")
        if not p: return
        with open(p,"w",newline="",encoding="utf-8") as f:
            w=csv.writer(f)
            w.writerow(["Region","StartBlock","EndBlock","StartOffset","EndOffset",
                        "Bytes","KB","AvgEntropy","PeakEntropy","AvgComp",
                        "RiskScore","RiskLabel"])
            for i,r in enumerate(self._regions,1):
                w.writerow([i,r.start_block,r.end_block,r.start_offset,r.end_offset,
                            r.total_bytes,f"{r.size_kb:.2f}",
                            f"{r.avg_entropy:.4f}",f"{r.peak_entropy:.4f}",
                            f"{r.avg_comp:.4f}",f"{r.risk_score:.1f}",r.risk_label])
        messagebox.showinfo("Exported",f"Regions CSV saved:\n{p}")

    def _export_csv_windows(self):
        p=self._save_path(".csv")
        if not p: return
        with open(p,"w",newline="",encoding="utf-8") as f:
            w=csv.writer(f)
            w.writerow(["Block","Window","Offset","Size","Entropy","Chi2","P-value","CompRatio","Suspicious"])
            for rec in self._records:
                for wn in rec.windows:
                    w.writerow([rec.index,wn.window_index,wn.offset,wn.size,
                                f"{wn.entropy:.4f}",f"{wn.chi2:.2f}",
                                f"{wn.p_value:.4f}",f"{wn.comp_ratio:.4f}",wn.suspicious])
        messagebox.showinfo("Exported","Windows CSV saved.")

    def _export_json(self):
        if not self._records: return
        p=self._save_path(".json")
        if not p: return
        out={"blocks":[{"index":r.index,"offset":r.offset,"size":r.size,
                        "entropy":round(r.entropy,6),"chi2":round(r.chi2,2),
                        "p_value":round(r.p_value,4),"comp_ratio":round(r.comp_ratio,4),
                        "sw_peak":round(r.sw_peak,4),"suspicious":r.suspicious,
                        "verdict":r.verdict} for r in self._records],
             "regions":[{"id":i+1,"start_block":r.start_block,"end_block":r.end_block,
                         "start_offset":r.start_offset,"end_offset":r.end_offset,
                         "bytes":r.total_bytes,"avg_entropy":round(r.avg_entropy,4),
                         "peak_entropy":round(r.peak_entropy,4),
                         "avg_comp":round(r.avg_comp,4),
                         "risk_score":round(r.risk_score,1),"risk_label":r.risk_label}
                        for i,r in enumerate(self._regions)]}
        with open(p,"w",encoding="utf-8") as f:
            json.dump(out,f,indent=2)
        messagebox.showinfo("Exported",f"JSON saved:\n{p}")

    def _export_report(self):
        self._report_txt.config(state="normal")
        txt=self._report_txt.get("1.0","end")
        self._report_txt.config(state="disabled")
        if not txt.strip(): return
        p=self._save_path(".txt")
        if not p: return
        with open(p,"w",encoding="utf-8") as f: f.write(txt)
        messagebox.showinfo("Exported",f"Report saved:\n{p}")


# ══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    app=DiskEntropyAnalyzer()
    app.mainloop()