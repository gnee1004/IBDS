export const $ = (id) => document.getElementById(id);
export const labels = {potential_high:'취약 가능성 높음',potential_medium:'취약 신호 관찰',inconclusive:'판단 보류',potential_low:'공격 근거 미확인'};
export const progressLabels = {completed:'완료',partial:'부분 완료',failed:'실패',not_run:'미실행'};
export const reasonLabels = {delivery_unknown:'전송 결과 불명',attack_request_failed:'공격 요청 실패',baseline_failed:'기준 요청 실패',auth_failed:'인증 실패',session_expired:'세션 만료',discovery_failed:'사전 확인 요청 실패',prepare_failed:'준비 단계 실패',revisit_url_missing:'재조회 주소 없음',revisit_failed:'재조회 실패',sink_not_confirmed:'저장 위치 미확인',browser_timeout:'브라우저 시간 초과',browser_failed:'브라우저 실행 실패',state_unclear:'이번 시도와 구분 불가',cancelled_by_user:'사용자 중단',out_of_scope:'범위 밖 이동',not_reached:'앞 단계 실패로 미도달'};
export const stages = {idle:'실행 대기',collecting:'요청 수집 중',scanning:'검사 진행 중',completed:'검사 완료',stopped:'사용자에 의해 중단됨',failed:'실패로 중단됨',interrupted:'서버 종료로 중단됨',legacy:'이전 실행 · 상태 정보 없음'};
export const order = ['potential_high','potential_medium','inconclusive','potential_low'];
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
