import {$,api,element,notice,labels,stages,order,rank,statusClass} from './common.js';
import {selectGroups, worstStatus} from './report-data.js';
let report=null,loadId=0;
function badge(status){return element('span',labels[status]||status,`badge ${statusClass(status)}`);}
function hideErrors(){
    $('error-panel').hidden=true;
    $('error-toggle')?.setAttribute('aria-expanded','false');
    $('error-toggle')?.focus();
}
function options(id,values,title,label=(x)=>x){const select=$(id);select.replaceChildren(new Option(title,''));values.forEach(value=>select.add(new Option(label(value),value)));}
function showErrors(){ $('error-panel').hidden=false;$('errors').replaceChildren();if(!report.errors.length)$('errors').append(element('p','기록된 오류가 없습니다.','hint'));for(const error of report.errors){const row=element('div',undefined,'error-row');row.append(element('strong',`${error.target_id||'대상 미상'} · ${error.param||'파라미터 미상'}`),element('span',error.stage||'request','tag'),element('p',error.url||'URL 정보 없음'),element('p',error.error||'원인 정보 없음','reason'));if(error.case_id)row.append(element('p',error.case_id,'hint'));$('errors').append(row);}$('error-panel').scrollIntoView({block:'nearest'}); }
function renderKpis(){
    $('kpis').replaceChildren();
    const statuses=[...order,...report.statuses.filter(x=>!order.includes(x))];
    for(const status of statuses){const node=element('div',undefined,`kpi ${statusClass(status)}`);node.append(element('span',labels[status]||status),element('strong',String(report.counts[status]||0)));$('kpis').append(node);}
    const node=element('button',undefined,'kpi error-kpi vulnerable');
    node.id='error-toggle';
    node.setAttribute('aria-controls','error-panel');
    node.setAttribute('aria-expanded','false');
    node.title='클릭하면 오류 상세 보기 · 더블클릭하면 접기';
    node.append(element('span','에러 · 상세 보기'),element('strong',String(report.error_count)));
    node.onclick=()=>{showErrors();node.setAttribute('aria-expanded','true');};
    node.ondblclick=hideErrors;
    $('kpis').append(node);
}
function renderGroups(){
    if(!report)return;
    const status=$('status-filter').value,technique=$('technique-filter').value;
    const groups=selectGroups(report.groups,status,technique,$('sort').value);
    $('groups').replaceChildren();$('result-count').textContent=`${groups.length}개 항목 · ${groups.reduce((n,g)=>n+g.items.length,0)}개 판정`;
    $('empty').hidden=groups.length>0;
    const filtered=report.groups.length>0;
    $('empty').querySelector('h2').textContent=filtered?'조건에 맞는 결과가 없습니다':'아직 스캔 결과가 없습니다';
    $('empty').querySelector('p').textContent=filtered?'판정기준이나 공격기법 필터를 변경해 보세요.':report.error_count?'오류 상세에서 검사하지 못한 항목을 확인하세요.':'스캔을 실행하면 URL과 파라미터별 결과가 표시됩니다.';
    for(const group of groups){
        const block=element('details',undefined,'result-group');const summary=element('summary');const title=element('div',undefined,'group-name');title.append(element('strong',group.param),element('div',`${group.method} ${group.url||group.target_id}`,'group-url'));
        summary.append(badge(worstStatus(group)),title,element('span',`${group.items.length}개 판정`,'group-total'));block.append(summary);
        for(const item of [...group.items].sort((a,b)=>rank(a.final_status)-rank(b.final_status))){const detail=element('div',undefined,'finding');const head=element('div',undefined,'finding-head');head.append(badge(item.final_status),element('strong',`${(item.vuln_type||'').toUpperCase()} · ${item.technique||'기법 정보 없음'}`));if(item.attack_id)head.append(element('span',item.attack_id,'hint'));detail.append(head);
            if(item.payload!==null&&item.payload!==undefined)detail.append(element('pre',item.payload));
            detail.append(element('p',item.evidence||'추가 판정 근거가 없습니다.'));
            const raw=element('details');raw.append(element('summary','판정 상세 데이터'),element('pre',JSON.stringify(item,null,2)));detail.append(raw);block.append(detail);
        }
        $('groups').append(block);
    }
}
async function loadReport(run){
    const id=++loadId;
    try{const data=await api(`/api/results${run?'?run='+encodeURIComponent(run):''}`);if(id!==loadId)return;report=data;
        options('status-filter',report.statuses,'모든 판정',x=>labels[x]||x);options('technique-filter',report.techniques,'모든 기법');$('sort').value='severity';$('error-panel').hidden=true;
        $('run-meta').textContent=report.run?`${stages[report.meta.stage||'legacy']||report.meta.stage} · ${report.run}`:'저장된 실행 기록이 없습니다.';
        $('run-error').hidden=!report.meta.error;$('run-error').textContent=report.meta.error||'';
        if(report.run){$('runs').value=report.run;history.replaceState(null,'',`/scan?run=${encodeURIComponent(report.run)}`);}
        notice('');renderKpis();renderGroups();
    }catch(error){notice(error.message,true);}
}
async function refresh(){try{const selected=$('runs').value||new URLSearchParams(location.search).get('run');const data=await api('/api/scans');$('runs').replaceChildren();data.runs.forEach(run=>$('runs').add(new Option(`${run.label} · ${stages[run.stage]||run.stage}`,run.id)));if(!data.runs.length)$('runs').add(new Option('저장된 실행 없음',''));await loadReport(data.runs.some(x=>x.id===selected)?selected:data.runs[0]?.id);}catch(error){notice(error.message,true);}}
for(const id of ['status-filter','technique-filter','sort'])$(id).onchange=renderGroups;
$('reset').onclick=()=>{$('status-filter').value='';$('technique-filter').value='';$('sort').value='severity';renderGroups();};
$('runs').onchange=()=>loadReport($('runs').value);$('refresh').onclick=refresh;
$('close-errors').onclick=hideErrors;
$('error-panel').ondblclick=hideErrors;
$('error-panel').title='더블클릭하면 오류 상세 접기';
$('runs').replaceChildren();await refresh();
