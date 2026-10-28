#!/usr/bin/env python3
"""EduManage AI V6 - lõi backend (Python stdlib + SQLite). Quyền kiểm tra ở máy chủ cho mọi API."""
import hashlib,hmac,json,os,re,secrets,sqlite3,sys,time
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
DB=os.environ.get('EDM_DB','edumanage.db')
TYPES={'Kế hoạch bài dạy','Kế hoạch giáo dục','Biên bản sinh hoạt','Phiếu dự giờ','Báo cáo chuyên môn'}
# hành động: (vai trò, trạng thái nguồn, trạng thái đích, bắt buộc lý do, chỉ chủ hồ sơ)
TRANS={'nop':({'gv'},{'Chưa nộp','Bản nháp','Thu hồi','Cần chỉnh sửa'},'Đã nộp',0,1),
'thuhoi':({'gv'},{'Đã nộp'},'Thu hồi',1,1),'ver':({'gv'},{'Đã duyệt'},'Đã nộp',1,1),
'rs':({'tt'},{'Đã nộp'},'Đang rà soát',0,0),'cho':({'tt'},{'Đang rà soát'},'Chờ duyệt',0,0),
'duyet':({'bgh'},{'Chờ duyệt'},'Đã duyệt',0,0),'sua':({'tt','bgh'},{'Đang rà soát','Chờ duyệt'},'Cần chỉnh sửa',1,0),
'tc':({'bgh'},{'Chờ duyệt'},'Từ chối',1,0)}
SCHEMA='''create table if not exists users(id integer primary key,username text unique not null,name text,pw text not null,role text not null check(role in('bgh','tt','gv','ad')),sid text,to_ text,active integer default 1);
create table if not exists sessions(th text primary key,uid integer not null,exp real not null);
create table if not exists docs(id text primary key,name text not null,ty text not null,owner integer not null references users(id),sid text,to_ text,st text not null,due text,ver integer default 0,rev integer default 1,rv_ok integer default 0,created text);
create table if not exists log(id integer primary key,doc text,at text,by text,act text,note text);
create table if not exists reviews(doc text,ver integer,data text,ok integer,by text,at text,primary key(doc,ver));
create table if not exists audit(id integer primary key,at text,uid integer,act text,target text,result text);'''
class Err(Exception):
    def __init__(s,code,msg):s.code,s.msg=code,msg
now=lambda:time.strftime('%Y-%m-%d %H:%M:%S',time.gmtime(time.time()+7*3600))  # Asia/Ho_Chi_Minh
sha=lambda t:hashlib.sha256(t.encode()).hexdigest()
def db():
    c=sqlite3.connect(DB,timeout=10,isolation_level=None);c.row_factory=sqlite3.Row;c.execute('pragma foreign_keys=on');c.executescript(SCHEMA);return c
def hp(pw,salt=None):
    salt=salt or secrets.token_hex(16);return salt+'$'+hashlib.pbkdf2_hmac('sha256',pw.encode(),bytes.fromhex(salt),200_000).hex()
chk=lambda pw,s:hmac.compare_digest(hp(pw,s.split('$')[0]),s)
def audit(c,uid,act,tg,res):c.execute('insert into audit(at,uid,act,target,result) values(?,?,?,?,?)',(now(),uid,act,tg,res))
def fail(c,u,act,tg,code,msg):
    audit(c,u['id'] if u else None,act,tg,'từ chối: '+msg)
    try:c.execute('COMMIT')
    except Exception:pass
    raise Err(code,msg)
def rb(c):
    try:c.execute('ROLLBACK')
    except Exception:pass
def add_user(c,username,pw,role,name='',sid=None,to=None):
    if role not in('bgh','tt','gv','ad'):raise Err(422,'Vai trò không hợp lệ')
    if len(pw)<10:raise Err(422,'Mật khẩu tối thiểu 10 ký tự')
    if not re.fullmatch(r'[a-z0-9._-]{3,40}',username):raise Err(422,'Tên đăng nhập 3–40 ký tự a-z, 0-9, . _ -')
    if role=='gv' and not(sid and to) or role=='tt' and not to:raise Err(422,'Thiếu điểm trường hoặc tổ chuyên môn')
    try:cur=c.execute('insert into users(username,name,pw,role,sid,to_) values(?,?,?,?,?,?)',(username,name[:100],hp(pw),role,sid,to))
    except sqlite3.IntegrityError:raise Err(409,'Tên đăng nhập đã tồn tại')
    return cur.lastrowid
LOCK={}
def login(c,b):
    un=str(b.get('username',''))[:64].lower();pw=str(b.get('password',''))[:200];f=LOCK.get(un,(0,0))
    if f[0]>=5 and time.time()>=f[1]:f=(0,0)
    if f[0]>=5:raise Err(429,'Đăng nhập sai nhiều lần. Thử lại sau 1 phút')
    u=c.execute('select * from users where username=? and active=1',(un,)).fetchone()
    if not u or not chk(pw,u['pw']):
        LOCK[un]=(f[0]+1,time.time()+60);audit(c,u['id'] if u else None,'đăng nhập',un,'thất bại');raise Err(401,'Sai tên đăng nhập hoặc mật khẩu')
    LOCK.pop(un,None);tok=secrets.token_urlsafe(32);c.execute('insert into sessions values(?,?,?)',(sha(tok),u['id'],time.time()+8*3600));audit(c,u['id'],'đăng nhập',un,'thành công')
    return 200,{'token':tok,'role':u['role'],'name':u['name']}
def auth(c,tok):
    r=tok and c.execute('select u.* from sessions s join users u on u.id=s.uid where s.th=? and s.exp>? and u.active=1',(sha(tok),time.time())).fetchone()
    if not r:raise Err(401,'Chưa đăng nhập hoặc phiên đã hết hạn')
    return r
def can_see(u,d):return u['role'] in('ad','bgh') or u['role']=='tt' and d['to_']==u['to_'] or u['role']=='gv' and d['owner']==u['id']
def getdoc(c,u,did):
    d=c.execute('select * from docs where id=?',(did,)).fetchone()
    if not d or not can_see(u,d):raise Err(404,'Không tìm thấy hồ sơ')  # không tiết lộ hồ sơ ngoài phạm vi
    return d
def docs_for(c,u):return[r for r in c.execute('select * from docs order by id') if can_see(u,r)]
def new_doc(c,u,b):
    if u['role']!='gv':raise Err(403,'Chỉ giáo viên tạo hồ sơ')
    name=str(b.get('name','')).strip()[:200];ty=b.get('ty');due=b.get('due') or None
    if not name or ty not in TYPES:raise Err(422,'Thiếu tên hồ sơ hoặc loại hồ sơ không hợp lệ')
    if due:
        try:time.strptime(due,'%Y-%m-%d')
        except Exception:raise Err(422,'Hạn nộp không hợp lệ')
    c.execute('BEGIN IMMEDIATE');n=c.execute("select coalesce(max(cast(substr(id,3) as integer)),0) from docs").fetchone()[0]+1;did='HS%04d'%n
    # điểm trường và tổ lấy từ tài khoản, bỏ qua giá trị client gửi
    c.execute('insert into docs(id,name,ty,owner,sid,to_,st,due,created) values(?,?,?,?,?,?,?,?,?)',(did,name,ty,u['id'],u['sid'],u['to_'],'Bản nháp',due,now()))
    c.execute('insert into log(doc,at,by,act,note) values(?,?,?,?,?)',(did,now(),u['username'],'Tạo hồ sơ',''));audit(c,u['id'],'tạo hồ sơ',did,'thành công');c.execute('COMMIT')
    return 201,{'id':did,'rev':1}
def act(c,u,did,b):
    c.execute('BEGIN IMMEDIATE');d=getdoc(c,u,did);k=b.get('action');t=TRANS.get(k)
    if not t:fail(c,u,'hành động '+str(k)[:20],did,400,'Hành động không hợp lệ')
    roles,frm,to,need,own=t
    if u['role'] not in roles or own and d['owner']!=u['id']:fail(c,u,k,did,403,'Không có quyền thực hiện thao tác này')
    if d['st'] not in frm:fail(c,u,k,did,409,'Trạng thái hồ sơ đã thay đổi hoặc không hợp lệ cho thao tác')
    if b.get('rev')!=d['rev']:fail(c,u,k,did,409,'Hồ sơ vừa được người khác cập nhật; hãy tải lại')
    note=str(b.get('note') or '').strip()[:2000]
    if need and not note:fail(c,u,k,did,422,'Cần nhập lý do hoặc nhận xét')
    if k in('cho','sua') and u['role']=='tt' and d['st']=='Đang rà soát' and not d['rv_ok']:fail(c,u,k,did,422,'Tổ trưởng cần hoàn tất và xác nhận phiếu rà soát trước')
    nv=1 if k in('nop','ver') else 0
    r=c.execute('update docs set st=?,rev=rev+1,ver=ver+?,rv_ok=case when ? then 0 else rv_ok end where id=? and rev=?',(to,nv,nv,did,d['rev']))
    if r.rowcount!=1:fail(c,u,k,did,409,'Xung đột cập nhật')
    c.execute('insert into log(doc,at,by,act,note) values(?,?,?,?,?)',(did,now(),u['username']+' ('+u['role']+')',k,note));audit(c,u['id'],k,did,'thành công');c.execute('COMMIT')
    return 200,{'st':to,'rev':d['rev']+1}
def review(c,u,did,b):
    c.execute('BEGIN IMMEDIATE');d=getdoc(c,u,did)
    if u['role']!='tt':fail(c,u,'phiếu rà soát',did,403,'Chỉ tổ trưởng được ghi phiếu rà soát')
    if d['st']!='Đang rà soát':fail(c,u,'phiếu rà soát',did,409,'Hồ sơ không ở trạng thái Đang rà soát')
    cc=b.get('c');ok=bool(b.get('confirm'));ai=b.get('ai','')
    if not(isinstance(cc,list) and len(cc)==9 and all(x in('d','c','k','') for x in cc)):raise Err(422,'Phiếu cần đúng 9 tiêu chí (d, c hoặc k)')
    if ok:
        m=b.get('minutes')
        if ai not in('Có','Không'):raise Err(422,'Hãy chọn có dùng AI hay không')
        if not isinstance(m,int) or not 0<=m<=600:raise Err(422,'Thời gian rà soát phải là số phút từ 0 đến 600')
        if ai=='Có' and (not str(b.get('gem','')).strip() or not isinstance(b.get('wrong'),int) or b['wrong']<0):raise Err(422,'Có dùng AI: cần nhận xét của AI và số nhận định sai')
        if d['ty']=='Kế hoạch bài dạy' and '' in cc:raise Err(422,'Cần đánh giá đủ 9 tiêu chí')
    c.execute('insert or replace into reviews values(?,?,?,?,?,?)',(did,d['ver'],json.dumps({k:b.get(k) for k in('ai','minutes','gem','wrong','note')}|{'c':cc},ensure_ascii=False),int(ok),u['username'],now()))
    c.execute('update docs set rv_ok=? where id=?',(int(ok),did));audit(c,u['id'],'phiếu rà soát '+('xác nhận' if ok else 'nháp'),did,'thành công');c.execute('COMMIT')
    return 200,{'confirmed':ok}
def new_user(c,u,b):
    if u['role']!='ad':fail(c,u,'tạo tài khoản','',403,'Chỉ quản trị viên được tạo tài khoản')
    i=add_user(c,str(b.get('username','')).lower(),str(b.get('password','')),b.get('role'),str(b.get('name','')),b.get('sid'),b.get('to'));audit(c,u['id'],'tạo tài khoản',str(i),'thành công');return 201,{'id':i}
def deactivate(c,u,i):
    if u['role']!='ad':fail(c,u,'khóa tài khoản',i,403,'Chỉ quản trị viên được khóa tài khoản')
    c.execute('update users set active=0 where id=?',(i,));c.execute('delete from sessions where uid=?',(i,));audit(c,u['id'],'khóa tài khoản',i,'thành công');return 200,{}
def backup(c,u):
    if u['role']!='ad':fail(c,u,'sao lưu','',403,'Chỉ quản trị viên được sao lưu')
    T=lambda q:[dict(r) for r in c.execute(q)];audit(c,u['id'],'sao lưu','','thành công')
    return 200,{'exported':now(),'users':T('select id,username,name,role,sid,to_,active from users'),'docs':T('select * from docs'),'log':T('select * from log'),'reviews':T('select * from reviews'),'audit':T('select * from audit')}
def handle(m,p,b,tok):
    c=db()
    try:
        try:
            if(m,p)==('POST','/api/login'):return login(c,b)
            u=auth(c,tok)
            if(m,p)==('GET','/api/docs'):return 200,{'docs':[dict(r) for r in docs_for(c,u)]}
            if(m,p)==('POST','/api/docs'):return new_doc(c,u,b)
            if(m,p)==('POST','/api/users'):return new_user(c,u,b)
            if(m,p)==('GET','/api/backup'):return backup(c,u)
            r=re.fullmatch(r'/api/docs/(HS\d+)/(action|review)',p)
            if m=='POST' and r:return(act if r[2]=='action' else review)(c,u,r[1],b)
            r=re.fullmatch(r'/api/users/(\d+)/deactivate',p)
            if m=='POST' and r:return deactivate(c,u,r[1])
            raise Err(404,'Không tìm thấy')
        except Err as e:rb(c);return e.code,{'error':e.msg}
    except Exception as e:
        rb(c);print('LỖI',repr(e),file=sys.stderr);return 500,{'error':'Lỗi hệ thống'}
    finally:c.close()
class H(BaseHTTPRequestHandler):
    def _do(s,m):
        n=int(s.headers.get('Content-Length') or 0)
        try:
            if n>1_000_000:code,o=413,{'error':'Yêu cầu quá lớn'}
            else:
                b=json.loads(s.rfile.read(n) or b'{}');b=b if isinstance(b,dict) else {}
                a=s.headers.get('Authorization') or '';code,o=handle(m,s.path.split('?')[0],b,a[7:] if a.startswith('Bearer ') else '')
        except ValueError:code,o=400,{'error':'JSON không hợp lệ'}
        d=json.dumps(o,ensure_ascii=False).encode();s.send_response(code)
        for k,v in(('Content-Type','application/json; charset=utf-8'),('Content-Length',len(d)),('X-Content-Type-Options','nosniff'),('Cache-Control','no-store')):s.send_header(k,str(v))
        s.end_headers();s.wfile.write(d)
    do_GET=lambda s:s._do('GET');do_POST=lambda s:s._do('POST')
    log_message=lambda *a:None
if __name__=='__main__':
    if sys.argv[1:2]==['init-admin']:
        import getpass;c=db();pw=os.environ.get('EDM_ADMIN_PASSWORD') or getpass.getpass('Mật khẩu quản trị (>=10 ký tự): ');add_user(c,sys.argv[2],pw,'ad','Quản trị viên');print('Đã tạo quản trị viên')
    else:ThreadingHTTPServer(('127.0.0.1',int(sys.argv[1]) if len(sys.argv)>1 else 8000),H).serve_forever()
