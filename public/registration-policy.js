(()=>{
'use strict';
const DOCTOR_PRACTICES=['Cupido NC','Pata L','Pekeur E','Iyiola T','Shushu L','Kifumbi Z','Visagie A','Skosana L'];
function apply(){
  const select=document.getElementById('regPractice');
  if(!select)return;
  select.innerHTML='<option value="">Select doctor\'s practice...</option>'+DOCTOR_PRACTICES.map(v=>`<option value="${v}">${v}</option>`).join('');
}
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',apply,{once:true});else apply();
})();
