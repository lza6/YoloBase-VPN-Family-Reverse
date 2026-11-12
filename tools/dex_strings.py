import zipfile,re,sys,os
p=sys.argv[1]; out=sys.argv[2]
z=zipfile.ZipFile(p)
buf=[]
for n in z.namelist():
    if re.fullmatch(r'classes\d*\.dex',n):
        b=z.read(n)
        for m in re.finditer(rb'[ -~]{6,200}',b): buf.append(m.group())
seen=set(); lines=[]
for b in buf:
    s=b.decode('ascii','ignore')
    if s not in seen: seen.add(s); lines.append(s)
open(out,'w',encoding='utf-8').write('\n'.join(lines))
print(p,'strings',len(lines))
