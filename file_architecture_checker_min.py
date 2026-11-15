import datetime,os,struct,tkinter as tk
from tkinter import filedialog,messagebox,ttk
try:from tkinterdnd2 import DND_FILES,TkinterDnD
except ImportError:TkinterDnD=None
M={0x14C:"32-bit (x86)",0x8664:"64-bit (x64)",0xAA64:"64-bit (ARM64)",0xA641:"64-bit (ARM64EC)",0x1C0:"32-bit (ARM)",0x1C4:"32-bit (ARM Thumb-2)",0x200:"64-bit (Itanium / IA64)"}
class E(Exception):pass
def rd(f,n,w):
 d=f.read(n)
 if len(d)!=n:raise E(f"File is truncated or corrupted (could not read {w}).")
 return d
def A(p):
 if os.path.isdir(p):raise E("This is a folder, not a file.")
 with open(p,"rb")as f:
  S=os.fstat(f.fileno()).st_size
  if rd(f,2,"DOS header")!=b"MZ":raise E("Not a valid Windows PE file (missing MZ header).")
  f.seek(60)
  o=struct.unpack("<I",rd(f,4,"PE header offset"))[0]
  if o>=S:raise E("Corrupted file (PE header offset is outside the file).")
  f.seek(o)
  if rd(f,4,"PE signature")!=b"PE\0\0":raise E("Not a valid Windows PE file (missing PE signature).")
  m,n,t,_,_,z,c=struct.unpack("<HHIIIHH",rd(f,20,"COFF header"))
  b=f.read(z)
  q=0;ss=None;cr=cz=0
  if len(b)>=2:
   q=struct.unpack_from("<H",b,0)[0]==0x20B
   if len(b)>=70:ss=struct.unpack_from("<H",b,68)[0]
   k=108 if q else 92
   e=(112 if q else 96)+112
   if len(b)>=e+8 and struct.unpack_from("<I",b,k)[0]>14:cr,cz=struct.unpack_from("<II",b,e)
  v=[]
  f.seek(o+24+z)
  for _ in range(min(n,96)):
   w=f.read(40)
   if len(w)!=40:break
   v.append(struct.unpack_from("<8sIIII",w)[1:])
  d=bool(cr and cz);g=None
  if d:
   for vs,va,rs,rp in v:
    if va<=cr<va+max(vs,rs):
     f.seek(cr-va+rp);h=f.read(20)
     if len(h)==20:g=struct.unpack_from("<I",h,16)[0]
     break
 a=M.get(m,f"Unknown architecture (0x{m:04X})")
 if d and g is not None and m==0x14C and not q and g&1 and not g&2:a="AnyCPU (32-bit preferred)"if g&0x20000 else"AnyCPU (runs as 32-bit or 64-bit)"
 y="DLL (Dynamic Link Library)"if c&0x2000 else"SYS (Native / Driver)"if ss==1 else"EXE (Executable)"if c&2 else"Unknown"
 try:T=datetime.datetime.fromtimestamp(t,tz=datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")if t else"Not available"
 except(OverflowError,OSError,ValueError):T="Not available"
 s=float(S)
 for u in("B","KB","MB","GB"):
  if s<1024 or u=="GB":break
  s/=1024
 return a,y,"Yes (.NET)"if d else"No (native)",f"{int(s)} B"if u=="B"else f"{s:.2f} {u}",T
class App:
 def __init__(s,r):
  s.r=r;D=hasattr(r,"drop_target_register");r.title("File Architecture Checker");r.geometry("560x470");r.resizable(False,False)
  s.p,s.a,s.t,s.n,s.z,s.c=[tk.StringVar(value=x)for x in("No file selected","Architecture: Unknown","-","-","-","-")]
  ttk.Label(r,text="File Architecture Checker",font=("Arial",20,"bold")).pack(pady=(20,10))
  ttk.Button(r,text="Select File",width=22,command=s.sel).pack(pady=5,ipady=6)
  ttk.Label(r,text="or drag & drop a file here"if D else"(install tkinterdnd2 to enable drag & drop)",font=("Arial",9),foreground="gray").pack()
  ttk.Label(r,textvariable=s.p,font=("Arial",9),wraplength=520,justify="center").pack(pady=8)
  s.l=ttk.Label(r,textvariable=s.a,font=("Arial",16,"bold"),foreground="#1565c0",wraplength=520,justify="center");s.l.pack(pady=8)
  f=ttk.LabelFrame(r,text="Details");f.pack(padx=20,pady=5,fill="x")
  for i,(x,v)in enumerate((("File type:",s.t),(".NET:",s.n),("File size:",s.z),("Compile time:",s.c))):
   ttk.Label(f,text=x,font=("Arial",10,"bold")).grid(row=i,column=0,sticky="w",padx=10,pady=2)
   ttk.Label(f,textvariable=v,font=("Arial",10)).grid(row=i,column=1,sticky="w",padx=10,pady=2)
  s.b=ttk.Button(r,text="Copy Result",width=22,command=s.cp,state="disabled");s.b.pack(pady=12)
  tk.Label(r,text="Developer : Apex_beat",font=("Arial",9,"italic"),fg="gray40").place(relx=1,rely=1,anchor="se",x=-10,y=-6)
  if D:r.drop_target_register(DND_FILES);r.dnd_bind("<<Drop>>",s.drop)
 def sel(s):
  p=filedialog.askopenfilename(title="Select a file",filetypes=[("Windows Executable Files",("*.exe","*.dll","*.sys")),("All Files","*.*")])
  if p:s.chk(p)
 def drop(s,e):
  p=s.r.tk.splitlist(e.data)
  if p:s.chk(p[0])
 def chk(s,p):
  s.p.set("File: "+p)
  try:i=A(p)
  except E as x:return s.err(str(x))
  except FileNotFoundError:return s.err("File not found.")
  except PermissionError:return s.err("Permission denied: cannot read this file.")
  except OSError as x:return s.err(f"Could not read the file: {x.strerror or x}")
  except Exception as x:return s.err(f"Unexpected error: {x}")
  s.a.set("Architecture: "+i[0]);s.l.config(foreground="#1a7f37")
  for v,x in zip((s.t,s.n,s.z,s.c),i[1:]):v.set(x)
  s.b.config(state="normal")
 def err(s,m):
  s.a.set(m);s.l.config(foreground="#c62828")
  for v in(s.t,s.n,s.z,s.c):v.set("-")
  s.b.config(state="disabled");messagebox.showerror("Error",m)
 def cp(s):
  s.r.clipboard_clear();s.r.clipboard_append("\n".join((s.p.get(),s.a.get(),"File type: "+s.t.get(),".NET: "+s.n.get(),"File size: "+s.z.get(),"Compile time: "+s.c.get())));messagebox.showinfo("Copied","Result copied to clipboard.")
def main():
 try:r=TkinterDnD.Tk()
 except Exception:r=tk.Tk()
 App(r);r.mainloop()
if __name__=="__main__":main()
