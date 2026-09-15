import assert from 'node:assert/strict';
import {selectGroups} from '../src/web/static/report-data.js';

const source=[
    {url:'https://b.test',param:'q',method:'GET',items:[
        {final_status:'vulnerable',technique:'dom'},
        {final_status:'safe',technique:'stored'}]},
    {url:'https://a.test',param:'q',method:'GET',items:[
        {final_status:'inconclusive',technique:'stored'}]},
    {url:'https://a.test',param:'a',method:'GET',items:[
        {final_status:'future_status',technique:'future_technique'}]}
];
assert.equal(selectGroups(source,'vulnerable','stored').length,0);
assert.equal(selectGroups(source,'safe','stored')[0].items.length,1);
assert.equal(selectGroups(source)[0].url,'https://b.test');
assert.equal(selectGroups(source,'','','name')[0].param,'a');
assert.equal(selectGroups(source,'future_status','future_technique').length,1);
assert.equal(source[0].items.length,2);
console.log('PASS: AND 필터, 상세 필터, 심각도 정렬, 이름 정렬, 새 상태/기법, 원본 보존');
