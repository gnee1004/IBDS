import {rank} from './common.js';

export function worstStatus(group) {
    return group.items.map(item => item.final_status).sort((a,b) => rank(a)-rank(b))[0];
}

export function selectGroups(source, status='', technique='', sort='severity') {
    const groups = source.map(group => ({
        ...group,
        items: group.items.filter(item => (!status || item.final_status===status) &&
                                         (!technique || item.technique===technique))
    })).filter(group => group.items.length);
    const byName = (a,b) => a.url.localeCompare(b.url) || a.param.localeCompare(b.param) ||
                            a.method.localeCompare(b.method);
    groups.sort(sort==='name' ? byName : (a,b) => rank(worstStatus(a))-rank(worstStatus(b)) || byName(a,b));
    return groups;
}
