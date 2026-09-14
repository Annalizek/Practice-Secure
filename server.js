'use strict';

const express = require('express');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const archiver = require('archiver');
const { Pool } = require('pg');

const PORT = Number(process.env.PORT || 10000);
const DATABASE_URL = process.env.DATABASE_URL || '';
const ADMIN_EMAIL = 'info@amcems.co.za';
const ADMIN_NAME = 'Annalize';
const ADMIN_SURNAME = 'Keyser';
const ADMIN_PRACTICE = 'Practice Secure Admin';
const SESSION_TTL = 8 * 60 * 60 * 1000;
const MAX_FILE = 20 * 1024 * 1024;
const PRACTICES = new Set(['Cupido NC','Pata L','Pekeur E','Iyiola T','Shushu L','Kifumbi Z','Visagie A','Skosana L','Advanced Med Care','Practice Secure Admin']);
const HOSPITALS = new Set(['Lenmed Royal Hospital & Heart Centre','Lenmed Kathu Private Hospital','Kimmed']);
const FUNDERS = new Set(['Annlyn','Valomate','Accicare']);
const PROGRESS = new Set(['Submitted','Claims Review','Bill Review','Finalized for Payment','Paid']);
const REG_DOCS = ['identityDoc','referralLetter','refHospitalRecords','accidentReport','clinicalNotes','admittingHospitalRecords'];
const CLAIM_DOCS = ['invoice','raf2','proofSubmission','ackLetter'];
const LABELS = {identityDoc:'ID / Passport',portEntry:'Port Entry',referralLetter:'Referral Letter',refHospitalRecords:'Referring Hospital Records',accidentReport:'Accident Report',clinicalNotes:"Doctor's Clinical Notes",admittingHospitalRecords:'Admitting Hospital File Records',invoice:'Invoice',raf2:'RAF 2',proofSubmission:'Proof of Submission',ackLetter:'Acknowledgement Letter'};

if (!DATABASE_URL) throw new Error('DATABASE_URL is required.');
const pool = new Pool({connectionString:DATABASE_URL,ssl:/render\.com|render\.internal/i.test(DATABASE_URL)?{rejectUnauthorized:false}:undefined,max:8,connectionTimeoutMillis:10000});

function keyFrom(raw,purpose){ if(!raw)return null; let b; try{b=/^[A-Fa-f0-9]{64}$/.test(raw)?Buffer.from(raw,'hex'):Buffer.from(raw,'base64'); if(!b.length)b=Buffer.from(raw);}catch{b=Buffer.from(raw);} return crypto.createHash('sha256').update(purpose).update(b).digest(); }
const docKey=keyFrom(process.env.DOC_ENCRYPTION_KEY||'','practice-secure-documents-v1');
const sessionKey=keyFrom(process.env.SESSION_SECRET||process.env.DOC_ENCRYPTION_KEY||process.env.REGISTRATION_CODE||'','practice-secure-session-v1');
if(!sessionKey) throw new Error('A session secret source is required.');
if(!docKey) console.warn('DOC_ENCRYPTION_KEY missing; document operations are unavailable.');

const clean=(v,n=250)=>String(v??'').trim().slice(0,n);
const ip=req=>clean((req.headers['x-forwarded-for']||'').split(',')[0]||req.ip||'',100);
const safe=n=>String(n||'document').replace(/[\\/:*?"<>|\x00-\x1F]/g,'_').replace(/\s+/g,' ').trim().slice(0,150)||'document';
const send=(res,status,data)=>res.status(status).json(data);
function cookies(req){const o={};for(const p of String(req.headers.cookie||'').split(';')){const i=p.indexOf('=');if(i>0)o[decodeURIComponent(p.slice(0,i).trim())]=decodeURIComponent(p.slice(i+1).trim());}return o;}
function makeSession(uid){const p=Buffer.from(JSON.stringify({uid,exp:Date.now()+SESSION_TTL})).toString('base64url');const s=crypto.createHmac('sha256',sessionKey).update(p).digest('base64url');return `${p}.${s}`;}
function readSession(t){if(!t||!t.includes('.'))return null;const [p,s]=t.split('.');const e=crypto.createHmac('sha256',sessionKey).update(p).digest('base64url');if(s.length!==e.length||!crypto.timingSafeEqual(Buffer.from(s),Buffer.from(e)))return null;try{const d=JSON.parse(Buffer.from(p,'base64url').toString());return d.uid&&d.exp>Date.now()?d:null;}catch{return null;}}
function setCookie(res,uid){res.setHeader('Set-Cookie',`ps_session=${encodeURIComponent(makeSession(uid))}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_TTL/1000}`);}
function clearCookie(res){res.setHeader('Set-Cookie','ps_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0');}
function encrypt(buf){if(!docKey)throw new Error('Document encryption is not configured.');const iv=crypto.randomBytes(12),c=crypto.createCipheriv('aes-256-gcm',docKey,iv),data=Buffer.concat([c.update(buf),c.final()]);return Buffer.concat([Buffer.from('PS2'),iv,c.getAuthTag(),data]);}
function decrypt(buf){if(!docKey)throw new Error('Document encryption is not configured.');if(buf.subarray(0,3).toString()==='PS2'){const d=crypto.createDecipheriv('aes-256-gcm',docKey,buf.subarray(3,15));d.setAuthTag(buf.subarray(15,31));return Buffer.concat([d.update(buf.subarray(31)),d.final()]);}throw new Error('Unsupported encrypted document format.');}
async function audit(user,event,patient,details,req,db=pool){try{await db.query('INSERT INTO audit_log (user_id,event_type,patient_id,details,ip_address) VALUES ($1,$2,$3,$4::jsonb,$5)',[user||null,event,patient||null,JSON.stringify(details||{}),req?ip(req):null]);}catch(e){console.error('audit:',e.message);}}

const app=express();
app.set('trust proxy',1);app.disable('x-powered-by');
app.use((req,res,next)=>{res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('X-Frame-Options','DENY');res.setHeader('Referrer-Policy','no-referrer');res.setHeader('Permissions-Policy','camera=(), microphone=(), geolocation=()');res.setHeader('Cache-Control','no-store');res.setHeader('Content-Security-Policy',"default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");next();});
app.use(express.json({limit:'1mb'}));
app.use((req,res,next)=>{if(['GET','HEAD','OPTIONS'].includes(req.method)||!req.headers.origin)return next();try{if(new URL(req.headers.origin).host!==req.headers.host)return send(res,403,{error:'Invalid request origin.'});next();}catch{return send(res,403,{error:'Invalid request origin.'});}});

const attempts=new Map();
function rate(req,res,next){const k=ip(req)||'unknown',now=Date.now(),a=(attempts.get(k)||[]).filter(t=>now-t<600000);if(a.length>=20)return send(res,429,{error:'Too many attempts. Please try again later.'});a.push(now);attempts.set(k,a);next();}
async function auth(req,res,next){const s=readSession(cookies(req).ps_session);if(!s)return send(res,401,{error:'Please log in.'});try{const q=await pool.query('SELECT id,name,surname,practice,email,role,active,approval_status,created_at,last_login_at FROM users WHERE id=$1',[s.uid]);if(!q.rowCount||!q.rows[0].active){clearCookie(res);return send(res,403,{error:'Your account is pending approval or has been disabled.'});}req.user=q.rows[0];next();}catch(e){next(e);}}
function admin(req,res,next){if(req.user?.role!=='admin'||String(req.user.email).toLowerCase()!==ADMIN_EMAIL)return send(res,403,{error:'Administrator access required.'});next();}

const allowedTypes=new Set(['application/pdf','image/jpeg','image/png','application/msword','application/vnd.openxmlformats-officedocument.wordprocessingml.document','text/plain']);
const upload=multer({storage:multer.memoryStorage(),limits:{fileSize:MAX_FILE,files:10},fileFilter:(_r,f,cb)=>allowedTypes.has(f.mimetype)?cb(null,true):cb(new Error('Unsupported file type. Use PDF, JPG, PNG, DOC, DOCX or TXT.'))});

app.get('/livez',(_q,r)=>send(r,200,{ok:true}));
app.get('/healthz',async(_q,r)=>{try{await pool.query('SELECT 1');send(r,200,{ok:true});}catch{send(r,503,{ok:false});}});

app.post('/api/register',rate,async(req,res,next)=>{try{
  let name=clean(req.body.name,80),surname=clean(req.body.surname,80);
  const practice=clean(req.body.practice,120),email=clean(req.body.email,160).toLowerCase(),password=String(req.body.password||'');
  if(!name||!surname||!email||!PRACTICES.has(practice)||password.length<8)return send(res,400,{error:'Complete all fields. Password must be at least 8 characters.'});
  const adminEmail=email===ADMIN_EMAIL,adminPractice=practice===ADMIN_PRACTICE,isAdminRegistration=adminEmail&&adminPractice;
  if(adminEmail!==adminPractice)return send(res,400,{error:`Practice Secure Admin may only be registered with ${ADMIN_EMAIL}.`});
  if((await pool.query('SELECT 1 FROM users WHERE lower(email)=lower($1)',[email])).rowCount)return send(res,409,{error:'An account already exists for this email address.'});
  const id=crypto.randomUUID(),hash=await bcrypt.hash(password,12);
  if(isAdminRegistration){
    name=ADMIN_NAME;surname=ADMIN_SURNAME;
    await pool.query("INSERT INTO users (id,name,surname,practice,email,password_hash,role,active,approval_status,approved_at) VALUES ($1,$2,$3,$4,$5,$6,'admin',true,'approved',now())",[id,name,surname,practice,email,hash]);
    await audit(id,'administrator_registered',null,{email,practice},req);
    return send(res,201,{ok:true,message:'Administrator account created successfully. You can now log in.'});
  }
  await pool.query("INSERT INTO users (id,name,surname,practice,email,password_hash,role,active,approval_status) VALUES ($1,$2,$3,$4,$5,$6,'user',false,'pending')",[id,name,surname,practice,email,hash]);
  await audit(id,'user_registration_pending',null,{email,practice,approvalAdmin:ADMIN_EMAIL},req);
  send(res,201,{ok:true,message:`Registration submitted. Annalize Keyser (${ADMIN_EMAIL}) must approve your access before you can log in.`});
}catch(e){next(e);}});

app.post('/api/login',rate,async(req,res,next)=>{try{const email=clean(req.body.email,160).toLowerCase(),password=String(req.body.password||''),q=await pool.query('SELECT * FROM users WHERE lower(email)=lower($1)',[email]);if(!q.rowCount||!(await bcrypt.compare(password,q.rows[0].password_hash))){await audit(null,'login_failed',null,{email},req);return send(res,401,{error:'Invalid email address or password.'});}const u=q.rows[0];if(!u.active)return send(res,403,{error:u.approval_status==='pending'?'Your registration is awaiting administrator approval.':'Your account has been disabled.'});await pool.query('UPDATE users SET last_login_at=now() WHERE id=$1',[u.id]);setCookie(res,u.id);await audit(u.id,'login',null,{},req);send(res,200,{ok:true,user:{id:u.id,name:u.name,surname:u.surname,practice:u.practice,email:u.email,role:u.role}});}catch(e){next(e);}});
app.post('/api/logout',auth,async(req,res)=>{await audit(req.user.id,'logout',null,{},req);clearCookie(res);send(res,200,{ok:true});});
app.get('/api/me',auth,(req,res)=>send(res,200,{user:req.user}));
app.post('/api/change-password',auth,async(req,res,next)=>{try{const current=String(req.body.currentPassword||''),nextPass=String(req.body.newPassword||'');if(nextPass.length<8)return send(res,400,{error:'New password must be at least 8 characters.'});const q=await pool.query('SELECT password_hash FROM users WHERE id=$1',[req.user.id]);if(!q.rowCount||!(await bcrypt.compare(current,q.rows[0].password_hash)))return send(res,400,{error:'Current password is incorrect.'});await pool.query('UPDATE users SET password_hash=$1 WHERE id=$2',[await bcrypt.hash(nextPass,12),req.user.id]);await audit(req.user.id,'password_changed',null,{},req);send(res,200,{ok:true,message:'Password updated.'});}catch(e){next(e);}});

app.get('/api/admin/users',auth,admin,async(req,res,next)=>{try{const q=await pool.query('SELECT id,name,surname,practice,email,role,active,approval_status,approved_by,approved_at,created_at,last_login_at FROM users ORDER BY CASE WHEN lower(email)=lower($1) THEN 0 ELSE 1 END,created_at DESC',[ADMIN_EMAIL]);send(res,200,{users:q.rows});}catch(e){next(e);}});
app.patch('/api/admin/users/:id',auth,admin,async(req,res,next)=>{try{const q=await pool.query('SELECT id,email,role FROM users WHERE id=$1',[req.params.id]);if(!q.rowCount)return send(res,404,{error:'User not found.'});if(String(q.rows[0].email).toLowerCase()===ADMIN_EMAIL||q.rows[0].role==='admin')return send(res,400,{error:'The protected administrator account cannot be changed.'});const active=req.body.active===true;await pool.query("UPDATE users SET active=$1,approval_status=$2,approved_by=CASE WHEN $1 THEN $3 ELSE approved_by END,approved_at=CASE WHEN $1 THEN now() ELSE approved_at END WHERE id=$4",[active,active?'approved':'disabled',req.user.id,req.params.id]);await audit(req.user.id,active?'user_approved':'user_disabled',null,{targetUserId:req.params.id},req);send(res,200,{ok:true});}catch(e){next(e);}});

async function fileNo(db){const d=new Date(),prefix=`PS-${d.getUTCFullYear()}${String(d.getUTCMonth()+1).padStart(2,'0')}${String(d.getUTCDate()).padStart(2,'0')}-`,q=await db.query('SELECT file_no FROM patients WHERE file_no LIKE $1 ORDER BY file_no DESC LIMIT 1',[prefix+'%']),n=q.rowCount?Number(q.rows[0].file_no.slice(-4))+1:1;return prefix+String(n).padStart(4,'0');}
async function addDoc(db,patient,section,category,file,user){const id=crypto.randomUUID(),enc=encrypt(file.buffer),sha=crypto.createHash('sha256').update(file.buffer).digest('hex');await db.query('INSERT INTO documents (id,patient_id,section,category,original_name,mime_type,byte_size,sha256,encrypted_data,uploaded_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)',[id,patient,section,category,safe(file.originalname),file.mimetype,file.size,sha,enc,user]);return id;}
const regFields=REG_DOCS.concat('portEntry').map(name=>({name,maxCount:1}));
app.post('/api/patients',auth,upload.fields(regFields),async(req,res,next)=>{const db=await pool.connect();try{const b=req.body||{},name=clean(b.patientName,100),surname=clean(b.patientSurname,100),hospital=clean(b.admittingHospital,180),doctor=clean(b.admittingDoctor,120),funder=clean(b.funder,80),identityType=clean(b.identityType,20),identityNumber=clean(b.identityNumber,100);if(!name||!surname||!identityNumber||!HOSPITALS.has(hospital)||!PRACTICES.has(doctor)||doctor===ADMIN_PRACTICE||!FUNDERS.has(funder)||!['ID','Passport'].includes(identityType))return send(res,400,{error:'Complete all required patient fields.'});for(const k of REG_DOCS)if(!req.files?.[k]?.[0])return send(res,400,{error:`${LABELS[k]} is required.`});if(identityType==='Passport'&&!req.files?.portEntry?.[0])return send(res,400,{error:'Port Entry is required for passport registrations.'});await db.query('BEGIN');await db.query("SELECT pg_advisory_xact_lock(hashtext('practice-secure-file-number'))");const id=crypto.randomUUID(),no=await fileNo(db);await db.query('INSERT INTO patients (id,file_no,patient_name,patient_surname,admitting_hospital,admitting_doctor,funder,identity_type,identity_number,allocated_user_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)',[id,no,name,surname,hospital,doctor,funder,identityType,identityNumber,req.user.id]);for(const k of REG_DOCS)await addDoc(db,id,'registration',k,req.files[k][0],req.user.id);if(identityType==='Passport')await addDoc(db,id,'registration','portEntry',req.files.portEntry[0],req.user.id);await audit(req.user.id,'patient_registered',id,{fileNo:no},req,db);await db.query('COMMIT');send(res,201,{ok:true,patientId:id,fileNumber:no});}catch(e){await db.query('ROLLBACK').catch(()=>{});next(e);}finally{db.release();}});

app.get('/api/patients',auth,async(req,res,next)=>{try{const q=await pool.query('SELECT p.*,u.name AS allocated_name,u.surname AS allocated_surname,u.practice AS allocated_practice FROM patients p JOIN users u ON u.id=p.allocated_user_id ORDER BY p.created_at DESC');send(res,200,{patients:q.rows});}catch(e){next(e);}});
app.get('/api/patients/:id',auth,async(req,res,next)=>{try{const p=await pool.query('SELECT p.*,u.name AS allocated_name,u.surname AS allocated_surname,u.practice AS allocated_practice FROM patients p JOIN users u ON u.id=p.allocated_user_id WHERE p.id=$1',[req.params.id]);if(!p.rowCount)return send(res,404,{error:'Patient file not found.'});const d=await pool.query('SELECT id,section,category,original_name,mime_type,byte_size,uploaded_at FROM documents WHERE patient_id=$1 ORDER BY section,category,uploaded_at DESC',[req.params.id]);send(res,200,{patient:p.rows[0],documents:d.rows});}catch(e){next(e);}});
app.post('/api/patients/:id/documents/:category',auth,upload.single('file'),async(req,res,next)=>{const db=await pool.connect();try{const category=req.params.category;if(!CLAIM_DOCS.includes(category)||!req.file)return send(res,400,{error:'Select a valid claim document.'});if(!(await db.query('SELECT 1 FROM patients WHERE id=$1',[req.params.id])).rowCount)return send(res,404,{error:'Patient file not found.'});await db.query('BEGIN');await db.query("DELETE FROM documents WHERE patient_id=$1 AND section='claim' AND category=$2",[req.params.id,category]);const id=await addDoc(db,req.params.id,'claim',category,req.file,req.user.id);await audit(req.user.id,'claim_document_uploaded',req.params.id,{category,documentId:id},req,db);await db.query('COMMIT');send(res,201,{ok:true,documentId:id});}catch(e){await db.query('ROLLBACK').catch(()=>{});next(e);}finally{db.release();}});
app.patch('/api/patients/:id/case',auth,async(req,res,next)=>{try{const date=clean(req.body.dateSubmission,20),link=clean(req.body.linkNumber,120),progress=clean(req.body.progress,80);if(!/^\d{4}-\d{2}-\d{2}$/.test(date)||!link||!PROGRESS.has(progress))return send(res,400,{error:'Complete Date of Submission, Link Number and Progress.'});const d=await pool.query("SELECT category FROM documents WHERE patient_id=$1 AND section='claim'",[req.params.id]),have=new Set(d.rows.map(x=>x.category));if(CLAIM_DOCS.some(k=>!have.has(k)))return send(res,400,{error:'Upload all four Claim Documents before saving/updating the case.'});const q=await pool.query('UPDATE patients SET date_submission=$1,link_number=$2,progress=$3,updated_at=now() WHERE id=$4 RETURNING id',[date,link,progress,req.params.id]);if(!q.rowCount)return send(res,404,{error:'Patient file not found.'});await audit(req.user.id,'case_saved_updated',req.params.id,{dateSubmission:date,linkNumber:link,progress},req);send(res,200,{ok:true,message:'Case saved / updated successfully.'});}catch(e){next(e);}});
app.get('/api/documents/:id',auth,async(req,res,next)=>{try{const q=await pool.query('SELECT * FROM documents WHERE id=$1',[req.params.id]);if(!q.rowCount)return send(res,404,{error:'Document not found.'});const d=q.rows[0],plain=decrypt(d.encrypted_data);res.setHeader('Content-Type',d.mime_type||'application/octet-stream');res.setHeader('Content-Disposition',`${req.query.download==='1'?'attachment':'inline'}; filename="${safe(d.original_name).replace(/"/g,'')}"`);await audit(req.user.id,'document_view_download',d.patient_id,{documentId:d.id,category:d.category},req);res.end(plain);}catch(e){next(e);}});
app.get('/api/patients/:id/download-all',auth,async(req,res,next)=>{try{const p=await pool.query('SELECT file_no,patient_name,patient_surname FROM patients WHERE id=$1',[req.params.id]);if(!p.rowCount)return send(res,404,{error:'Patient file not found.'});const docs=await pool.query('SELECT * FROM documents WHERE patient_id=$1 ORDER BY section,category,uploaded_at',[req.params.id]),filename=safe(`${p.rows[0].file_no}-${p.rows[0].patient_surname}-${p.rows[0].patient_name}.zip`);res.setHeader('Content-Type','application/zip');res.setHeader('Content-Disposition',`attachment; filename="${filename}"`);const z=archiver('zip',{zlib:{level:6}});z.on('error',next);z.pipe(res);for(const d of docs.rows)z.append(decrypt(d.encrypted_data),{name:`${d.section==='claim'?'Claim Documents':'Practice Secure Documents'}/${safe((LABELS[d.category]||d.category)+' - '+d.original_name)}`});await audit(req.user.id,'claim_pack_downloaded',req.params.id,{documentCount:docs.rowCount},req);await z.finalize();}catch(e){next(e);}});

app.use(express.static(path.join(__dirname,'public'),{index:'index.html'}));
app.use((req,res,next)=>{if(req.method==='GET'&&!req.path.startsWith('/api/'))return res.sendFile(path.join(__dirname,'public','index.html'));next();});
app.use((err,req,res,_next)=>{console.error(err?.stack||err);if(res.headersSent)return;if(err instanceof multer.MulterError)return send(res,400,{error:err.code==='LIMIT_FILE_SIZE'?'A file is too large. Maximum file size is 20 MB.':err.message});send(res,500,{error:err?.message?.startsWith('Unsupported file type')?err.message:'Unable to complete the request.'});});

async function bootstrap(){
  await pool.query('SELECT 1');
  await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS approval_status text NOT NULL DEFAULT 'approved'");
  await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS approved_by uuid NULL');
  await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS approved_at timestamptz NULL');
  await pool.query("UPDATE users SET role='admin',active=true,practice=$2,name=$3,surname=$4,approval_status='approved',approved_at=COALESCE(approved_at,now()) WHERE lower(email)=lower($1)",[ADMIN_EMAIL,ADMIN_PRACTICE,ADMIN_NAME,ADMIN_SURNAME]);
  const q=await pool.query('SELECT id FROM users WHERE lower(email)=lower($1)',[ADMIN_EMAIL]);
  if(!q.rowCount) console.log(`Administrator onboarding ready for ${ADMIN_EMAIL}.`);
  console.log('Practice Secure database ready.');
}
bootstrap().then(()=>app.listen(PORT,'0.0.0.0',()=>console.log(`Practice Secure server listening on port ${PORT}`))).catch(e=>{console.error('Startup failed:',e);process.exit(1);});
