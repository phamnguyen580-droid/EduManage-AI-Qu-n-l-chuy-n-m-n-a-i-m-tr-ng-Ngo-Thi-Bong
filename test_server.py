import os,tempfile,threading,unittest,json,urllib.request,urllib.error
os.environ['EDM_DB']=tempfile.mktemp(suffix='.db')
import server as S
PW='matkhau-dai-123'
def call(m,p,b=None,tok=None):return S.handle(m,p,b or {},tok)
class T(unittest.TestCase):
    @classmethod
    def setUpClass(k):
        c=S.db();k.ids={}
        for un,role,sid,to in[('admin','ad',None,None),('bgh','bgh',None,None),('tt1','tt','DT01','To1'),('tt2','tt','DT01','To2'),('gv1','gv','DT01','To1'),('gv2','gv','DT02','To2')]:k.ids[un]=S.add_user(c,un,PW,role,un,sid,to)
        c.close();k.tok={u:call('POST','/api/login',{'username':u,'password':PW})[1]['token'] for u in k.ids}
    def mk(s,u='gv1',**kw):
        r=call('POST','/api/docs',{'name':'KHBD','ty':'Kế hoạch bài dạy',**kw},s.tok[u]);s.assertEqual(r[0],201);return r[1]['id']
    def go(s,did,k,u,note='',rev=None):
        if rev is None:rev=[d for d in call('GET','/api/docs',tok=s.tok['bgh'])[1]['docs'] if d['id']==did][0]['rev']
        return call('POST',f'/api/docs/{did}/action',{'action':k,'note':note,'rev':rev},s.tok[u])
    def rv(s,did,u='tt1',confirm=True):return call('POST',f'/api/docs/{did}/review',{'c':['d']*8+['k'],'ai':'Không','minutes':10,'confirm':confirm},s.tok[u])
    def test_unauth(s):s.assertEqual(call('GET','/api/docs')[0],401);s.assertEqual(call('GET','/api/docs',tok='x')[0],401)
    def test_scope_and_spoof(s):
        d=s.mk(sid='DT99',to_='ToX');row=[x for x in call('GET','/api/docs',tok=s.tok['gv1'])[1]['docs'] if x['id']==d][0]
        s.assertEqual((row['sid'],row['to_']),('DT01','To1'))  # bỏ qua giá trị client gửi
        s.assertEqual(call('GET','/api/docs',tok=s.tok['gv2'])[1]['docs'].__len__() , len([x for x in call('GET','/api/docs',tok=s.tok['gv2'])[1]['docs'] if x['owner']==s.ids['gv2']]))
        s.assertEqual(s.go(d,'nop','gv2')[0],404)           # giáo viên khác không thấy, không sửa được
        s.assertEqual(s.go(d,'rs','tt2')[0],404)            # tổ trưởng tổ khác
    def test_full_flow_and_permissions(s):
        d=s.mk();s.assertEqual(s.go(d,'duyet','gv1')[0],403);s.assertEqual(s.go(d,'nop','gv1')[0],200)
        s.assertEqual(s.go(d,'duyet','bgh')[0],409)          # sai trạng thái
        s.assertEqual(s.go(d,'rs','gv1')[0],403);s.assertEqual(s.go(d,'rs','tt1')[0],200)
        s.assertEqual(s.go(d,'cho','tt1')[0],422)            # chưa xác nhận phiếu
        s.assertEqual(s.rv(d,'gv1')[0],403);s.assertEqual(s.rv(d,'tt2')[0],404)
        s.assertEqual(call('POST',f'/api/docs/{d}/review',{'c':['d'],'confirm':True},s.tok['tt1'])[0],422)
        s.assertEqual(s.rv(d)[0],200);s.assertEqual(s.go(d,'cho','tt1')[0],200)
        s.assertEqual(s.go(d,'duyet','tt1')[0],403);s.assertEqual(s.go(d,'duyet','bgh')[0],200)
    def test_note_required(s):
        d=s.mk();s.go(d,'nop','gv1');s.go(d,'rs','tt1');s.rv(d);s.go(d,'cho','tt1')
        s.assertEqual(s.go(d,'tc','bgh')[0],422);s.assertEqual(s.go(d,'sua','bgh')[0],422);s.assertEqual(s.go(d,'tc','bgh','không đạt')[0],200)
    def test_conflict(s):
        d=s.mk();s.assertEqual(s.go(d,'nop','gv1',rev=1)[0],200);s.assertEqual(s.go(d,'thuhoi','gv1','x',rev=1)[0],409)
    def test_new_version_resets_review(s):
        d=s.mk();s.go(d,'nop','gv1');s.go(d,'rs','tt1');s.rv(d);s.go(d,'cho','tt1');s.go(d,'duyet','bgh')
        s.assertEqual(s.go(d,'ver','gv1')[0],422);s.assertEqual(s.go(d,'ver','gv1','cập nhật')[0],200)
        s.go(d,'rs','tt1');s.assertEqual(s.go(d,'cho','tt1')[0],422)   # phiếu cũ không dùng lại được
    def test_review_na_not_failed(s):
        d=s.mk();s.go(d,'nop','gv1');s.go(d,'rs','tt1');s.rv(d)
        import sqlite3;c=sqlite3.connect(os.environ['EDM_DB']);data=json.loads(c.execute('select data from reviews where doc=?',(d,)).fetchone()[0]);s.assertEqual(data['c'][8],'k')
    def test_accounts(s):
        c=S.db();S.add_user(c,'tmp','matkhau-dai-123','gv','t','DT01','To1');c.close()
        t=call('POST','/api/login',{'username':'tmp','password':PW})[1]['token'];i=S.db().execute("select id from users where username='tmp'").fetchone()[0]
        s.assertEqual(call('POST',f'/api/users/{i}/deactivate',tok=s.tok['bgh'])[0],403);s.assertEqual(call('POST',f'/api/users/{i}/deactivate',tok=s.tok['admin'])[0],200)
        s.assertEqual(call('GET','/api/docs',tok=t)[0],401)
        s.assertEqual(call('POST','/api/users',{'username':'x1','password':'ngan','role':'gv'},s.tok['admin'])[0],422)
    def test_lockout(s):
        for _ in range(5):s.assertEqual(call('POST','/api/login',{'username':'gv2','password':'sai'})[0],401)
        s.assertEqual(call('POST','/api/login',{'username':'gv2','password':PW})[0],429);S.LOCK.clear()
    def test_backup_admin_only_no_hash(s):
        s.assertEqual(call('GET','/api/backup',tok=s.tok['bgh'])[0],403);r=call('GET','/api/backup',tok=s.tok['admin']);s.assertEqual(r[0],200)
        s.assertNotIn('pw',json.dumps(r[1]));s.assertIn('Kế hoạch bài dạy',json.dumps(r[1],ensure_ascii=False))
    def test_http(s):
        h=S.ThreadingHTTPServer(('127.0.0.1',0),S.H);threading.Thread(target=h.serve_forever,daemon=True).start();u=f'http://127.0.0.1:{h.server_address[1]}'
        with s.assertRaises(urllib.error.HTTPError) as e:urllib.request.urlopen(u+'/api/docs')
        s.assertEqual(e.exception.code,401)
        r=urllib.request.urlopen(urllib.request.Request(u+'/api/login',json.dumps({'username':'bgh','password':PW}).encode(),{'Content-Type':'application/json'}))
        s.assertEqual(r.headers['X-Content-Type-Options'],'nosniff');s.assertIn('token',json.loads(r.read()));h.shutdown()
if __name__=='__main__':unittest.main(verbosity=1)
