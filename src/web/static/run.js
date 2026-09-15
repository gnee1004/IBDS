import {$,api,element,notice,stages} from './common.js';
let run=null,lastLog=0,connected=false;
function render(state){
    if(run!==state.run){run=state.run;lastLog=0;$('logs').replaceChildren();}
    $('stage').textContent=stages[state.stage]||state.stage;
    $('percent').textContent=state.percent===null?'—':`${Number(state.percent.toFixed(1))}%`;
    $('progress').value=state.percent||0;$('progress').className=state.stage==='failed'?'failed':state.stage==='stopped'?'stopped':'';
    $('count').textContent=state.total===null?(state.running?'수집 중 · 진행률 산정 전':'검사 시작 전'):`ScanPoint ${state.completed.toLocaleString()} / ${state.total.toLocaleString()} 완료`;
    $('failed').textContent=state.failed.toLocaleString();$('start').disabled=state.running||!connected;$('stop').disabled=!state.running||state.stop_requested||!connected;
    $('stop-note').hidden=!state.stop_requested||!state.running;
    $('settings-note').hidden=!state.running;
    $('fatal').hidden=!state.error;$('fatal').textContent=state.error?`스캔이 중단되었습니다. ${state.error}`:'';
    $('report-link').hidden=state.running||!state.run;$('report-link').href=`/scan?run=${encodeURIComponent(state.run||'')}`;
    const follow=$('autoscroll').checked;
    for(const line of state.logs||[]){if(line.id<=lastLog)continue;$('logs').querySelector('.log-placeholder')?.remove();$('logs').append(element('div',line.text,`log-line ${line.level}`));lastLog=line.id;}
    while($('logs').children.length>2000)$('logs').firstChild.remove();
    if(follow)$('logs').scrollTop=$('logs').scrollHeight;
}
$('start').disabled=true;
for(const action of ['start','stop'])$(action).onclick=async()=>{ $(action).disabled=true;try{notice('');render(await api(`/api/scan/${action}`,{}));}catch(error){notice(error.message,true);$(action).disabled=false;} };
try{const cfg=await api('/api/config');$('target').textContent=cfg.target_url||'타겟 URL을 먼저 설정하세요.';}catch(error){notice(error.message,true);}
const stream=new EventSource('/api/scan/stream');
stream.onmessage=(event)=>{connected=true;$('connection').textContent='실시간 연결됨';render(JSON.parse(event.data));};
stream.onerror=()=>{connected=false;$('connection').textContent='연결이 끊겼습니다. 자동 재연결 중…';$('start').disabled=true;$('stop').disabled=true;};
window.addEventListener('pagehide',()=>stream.close());
