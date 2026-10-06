import {rank} from './common.js';

export function selectGroups(source, status='', vulnType='', sort='severity') {
    const groups = source.filter(group => (!status || group.final_status===status) &&
                                          (!vulnType || group.vuln_type===vulnType));
    const byName = (a,b) => a.url.localeCompare(b.url) || a.param.localeCompare(b.param) ||
                            a.method.localeCompare(b.method) || a.vuln_type.localeCompare(b.vuln_type);
    groups.sort(sort==='name' ? byName : (a,b) => rank(a.final_status)-rank(b.final_status) || byName(a,b));
    return groups;
}
