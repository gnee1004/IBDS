export const $ = (id) => document.getElementById(id);
export const labels = {vulnerable:'취약',reflected_only:'반사됨',inconclusive:'판단보류',safe:'안전'};
export const stages = {idle:'실행 대기',collecting:'요청 수집 중',scanning:'검사 진행 중',completed:'검사 완료',stopped:'사용자에 의해 중단됨',failed:'실패로 중단됨',interrupted:'서버 종료로 중단됨',legacy:'이전 실행 · 상태 정보 없음'};
export const order = ['vulnerable','reflected_only','inconclusive','safe'];
export const rank = (s) => order.includes(s) ? order.indexOf(s) : 2.5;
export const statusClass = (s) => order.includes(s) ? s : 'unknown';
export function element(tag, text, className) { const node=document.createElement(tag); if(text!==undefined)node.textContent=text; if(className)node.className=className; return node; }
export function notice(text, bad=false) { $('message').textContent=text; $('message').className=bad?'notice danger':'notice success'; $('message').hidden=!text; }
export async function api(path, data) {
    const options=data===undefined?{}:{method:'POST',headers:{'Content-Type':'application/json','X-IBDS-Client':'local-ui'},body:JSON.stringify(data)};
    const response=await fetch(path,options);
    const body=await response.json();
    if(!response.ok) { const detail=body.detail; throw new Error(Array.isArray(detail)?detail.map(x=>x.msg).join(' / '):detail||'요청을 처리하지 못했습니다.'); }
    return body;
}
