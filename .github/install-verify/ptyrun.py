#!/usr/bin/env python3
# ptyrun.py SECS 'k1|k2|..' -- cmd... : keys sent 2s apart; prints top of screen after each key and the final screen.
import os,pty,sys,time,select,struct,fcntl,termios,codecs,pyte
secs=float(sys.argv[1]); keys=[codecs.decode(k,'unicode_escape').encode() for k in sys.argv[2].split('|')] if sys.argv[2] else []; cmd=sys.argv[4:]
pid,fd=pty.fork()
if pid==0:
    os.environ['TERM']='xterm-256color'; os.execvp(cmd[0],cmd)
fcntl.ioctl(fd,termios.TIOCSWINSZ,struct.pack('HHHH',32,100,0,0))
sc=pyte.Screen(100,32); st=pyte.Stream(sc); t0=time.time(); n=0
def pump(w):
    end=time.time()+w
    while time.time()<end:
        if select.select([fd],[],[],0.1)[0]:
            try: d=os.read(fd,65536)
            except OSError: return False
            if not d: return False
            if b'\x1b[6n' in d: os.write(fd,b'\x1b[1;1R')
            st.feed(d.decode('utf8','replace'))
    return True
ok=pump(2)
while ok and n<len(keys):
    os.write(fd,keys[n]); n+=1; ok=pump(2)
    print('after key %d %r: %s'%(n,keys[n-1],' / '.join(l.strip() for l in sc.display[:3] if l.strip())[:110]))
if ok: pump(max(0,secs-(time.time()-t0)))
try: os.kill(pid,9)
except Exception: pass
print('--- final screen'); print('\n'.join(l.rstrip() for l in sc.display).rstrip())
