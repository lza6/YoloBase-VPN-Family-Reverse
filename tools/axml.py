import struct,sys,zipfile

def parse(buf):
    # AXML header
    typ,hs,sz=struct.unpack_from('<HHI',buf,0)
    assert typ==0x0003,hex(typ)
    off=8; strings=[]; resids=[]
    nodes=[]
    while off<len(buf):
        t,hs,sz=struct.unpack_from('<HHI',buf,off)
        if t==0x0001:  # string pool
            cnt,scnt=struct.unpack_from('<II',buf,off+8)
            flags,_soff,_=struct.unpack_from('<III',buf,off+16)
            utf8=bool(flags&0x100)
            offs=[struct.unpack_from('<I',buf,off+28+4*i)[0] for i in range(cnt)]
            base=off+28+4*cnt
            for o in offs:
                p=base+o
                if utf8:
                    # u16len,v8len
                    i=p; l=0
                    while buf[i]>=0x80: i+=1
                    i+=1
                    l=buf[i]
                    if l&0x80:
                        l=((l&0x7f)<<8)|buf[i+1]; i+=1
                    i+=1
                    strings.append(buf[i:i+l].decode('utf-8','replace'))
                else:
                    l=struct.unpack_from('<H',buf,p)[0]
                    strings.append(buf[p+2:p+2+l*2].decode('utf-16-le','replace'))
        elif t==0x0180:  # resource map
            resids=[struct.unpack_from('<I',buf,off+8+4*i)[0] for i in range((sz-8)//4)]
        elif t==0x0102:  # start element
            ns,nm=struct.unpack_from('<II',buf,off+16)
            attrStart,attrSize,attrCnt=struct.unpack_from('<HHH',buf,off+24)
            attrs=[]
            for i in range(attrCnt):
                a=off+16+attrStart+i*attrSize
                ans,anm,rawv=struct.unpack_from('<III',buf,a)
                typ2=buf[a+15]
                data=struct.unpack_from('<I',buf,a+16)[0]
                name=strings[anm] if anm<len(strings) else '?'
                if typ2==0x03:
                    val=strings[data] if data<len(strings) else '?'
                else:
                    val=str(data)
                attrs.append((name,val))
            nodes.append((strings[nm],attrs))
        off+=sz
        if sz<=0: break
    return nodes

if __name__=='__main__':
    p=sys.argv[1]
    buf=zipfile.ZipFile(p).read('AndroidManifest.xml')
    for el,attrs in parse(buf):
        keep=[f'{k}={v}' for k,v in attrs if k in ('package','versionName','versionCode','name','exported','permission','targetSdkVersion','minSdkVersion','allowBackup','usesCleartextTraffic')]
        print(el.split('.')[-1] if el.startswith('com') else el, '|', ' '.join(keep)[:260])
