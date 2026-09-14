(()=>{
'use strict';

const DEFAULT_REGISTRATION_PRACTICE='PR Admin';
const DOCTORS=['Cupido NC','Pata L','Pekeur E','Iyiola T','Shushu L','Kifumbi Z','Visagie A','Skosana L','PR Admin','Advanced Med Care','Solomons A','Williams N'];
const PROGRESS=['Submitted','Claims Review','Bill Review','Finalized for Payment','Paid'];

const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fmtDate=d=>d?new Date(`${String(d).slice(0,10)}T00:00:00`).toLocaleDateString('en-ZA'):'—';
const optionList=(list,placeholder)=>`<option value="">${esc(placeholder)}</option>`+list.map(v=>`<option value="${esc(v)}">${esc(v)}</option>`).join('');

function applyRegistration(){
  const select=document.getElementById('regPractice');
  if(!select)return;
  select.innerHTML=`<option value="${DEFAULT_REGISTRATION_PRACTICE}" selected>${DEFAULT_REGISTRATION_PRACTICE}</option>`;
  select.value=DEFAULT_REGISTRATION_PRACTICE;
  const field=select.closest('.field');
  if(field)field.classList.add('hidden');
}

async function getPatients(){
  const response=await fetch('/api/patients',{credentials:'same-origin'});
  const data=await response.json().catch(()=>({}));
  if(!response.ok)throw new Error(data.error||'Unable to load reporting data.');
  return data.patients||[];
}

function filteredRows(patients){
  const doctor=document.getElementById('rDoctor')?.value||'';
  const dateFrom=document.getElementById('rDateFrom')?.value||'';
  const dateTo=document.getElementById('rDateTo')?.value||'';
  const progress=document.getElementById('rProgress')?.value||'';
  return patients.filter(p=>{
    const submitted=String(p.date_submission||'').slice(0,10);
    return (!doctor||p.admitting_doctor===doctor)
      &&(!dateFrom||(submitted&&submitted>=dateFrom))
      &&(!dateTo||(submitted&&submitted<=dateTo))
      &&(!progress||p.progress===progress);
  });
}

function tableHtml(rows){
  if(!rows.length)return '<div class="empty">No cases match the selected filters.</div>';
  return `<div class="table-wrap"><table><thead><tr><th>File No.</th><th>Patient</th><th>Doctor</th><th>Funder</th><th>Date Submitted</th><th>Progress</th><th>Allocated User</th></tr></thead><tbody>${rows.map(p=>`<tr><td>${esc(p.file_no)}</td><td>${esc(p.patient_surname)}, ${esc(p.patient_name)}</td><td>${esc(p.admitting_doctor)}</td><td>${esc(p.funder)}</td><td>${esc(fmtDate(p.date_submission))}</td><td>${esc(p.progress||'')}</td><td>${esc(`${p.allocated_name||''} ${p.allocated_surname||''}`.trim())}</td></tr>`).join('')}</tbody></table></div>`;
}

function renderRows(patients){
  const target=document.getElementById('reportOverrideTable');
  if(target)target.innerHTML=tableHtml(filteredRows(patients));
}

function exportExcel(patients){
  const rows=filteredRows(patients);
  const headers=['File No.','Patient','Doctor','Funder','Date Submitted','Progress','Allocated User'];
  const html=`<table><tr>${headers.map(h=>`<th>${h}</th>`).join('')}</tr>${rows.map(p=>`<tr><td>${esc(p.file_no)}</td><td>${esc(`${p.patient_surname}, ${p.patient_name}`)}</td><td>${esc(p.admitting_doctor)}</td><td>${esc(p.funder)}</td><td>${esc(String(p.date_submission||'').slice(0,10))}</td><td>${esc(p.progress||'')}</td><td>${esc(`${p.allocated_name||''} ${p.allocated_surname||''}`.trim())}</td></tr>`).join('')}</table>`;
  const blob=new Blob([html],{type:'application/vnd.ms-excel'});
  const a=document.createElement('a');
  a.href=URL.createObjectURL(blob);
  a.download=`practice-secure-report-${new Date().toISOString().slice(0,10)}.xls`;
  a.click();
  setTimeout(()=>URL.revokeObjectURL(a.href),1000);
}

function printRows(patients){
  const rows=filteredRows(patients);
  const target=document.getElementById('printReport');
  if(!target)return;
  target.innerHTML=`<h1>Practice Secure Claim Report</h1><p>Generated ${esc(new Date().toLocaleString('en-ZA'))} · ${rows.length} case(s)</p>${tableHtml(rows)}`;
  window.print();
}

async function applyReporting(){
  if(document.getElementById('pageTitle')?.textContent.trim()!=='Reporting')return;
  const content=document.getElementById('pageContent');
  if(!content||document.getElementById('reportingOverride'))return;

  content.innerHTML=`<div id="reportingOverride" class="card"><h3>Claim Reporting</h3><p class="sub">Filter current cases by doctor, submission date range and progress.</p><div class="filters"><div class="field" style="margin:0"><label>Doctor</label><select id="rDoctor">${optionList(DOCTORS,'All Doctors')}</select></div><div class="field" style="margin:0"><label>Date From</label><input id="rDateFrom" type="date"></div><div class="field" style="margin:0"><label>Date To</label><input id="rDateTo" type="date"></div><div class="field" style="margin:0"><label>Progress</label><select id="rProgress">${optionList(PROGRESS,'All Progress')}</select></div></div><div class="toolbar"><button id="reportOverrideExport" class="btn btn-outline">Export Excel (.xls)</button><button id="reportOverridePrint" class="btn btn-outline">Print / Save PDF</button></div><div id="reportOverrideTable"><div class="sub">Loading reporting data...</div></div></div>`;

  try{
    const patients=await getPatients();
    ['rDoctor','rDateFrom','rDateTo','rProgress'].forEach(id=>document.getElementById(id)?.addEventListener('input',()=>renderRows(patients)));
    document.getElementById('reportOverrideExport')?.addEventListener('click',()=>exportExcel(patients));
    document.getElementById('reportOverridePrint')?.addEventListener('click',()=>printRows(patients));
    renderRows(patients);
  }catch(err){
    const target=document.getElementById('reportOverrideTable');
    if(target)target.innerHTML=`<div class="notice error">${esc(err.message)}</div>`;
  }
}

function apply(){
  applyRegistration();
  applyReporting();
}

const observer=new MutationObserver(()=>apply());
observer.observe(document.documentElement,{subtree:true,childList:true});
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',apply,{once:true});else apply();
})();
