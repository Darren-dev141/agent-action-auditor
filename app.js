/* DOM adapter: uses only the three confirmed engine seams. No uploads/persistence. */
(function(){
'use strict';
const $=id=>document.getElementById(id);
const input=$('trace'), headline=$('headline'), stats=$('stats'), list=$('findings');
const error=$('error'), warning=$('secret-warning');
const LIMIT=1048576;
let reportText='';
const patterns=AAA.SECRET_PATTERNS.map(([,re])=>re);
const mask=value=>patterns.reduce((text,re)=>text.replace(new RegExp(re.source,'g'),'[REDACTED]'),String(value));
const hasSecret=text=>patterns.some(re=>re.test(text));
const decision={R1:'Review authorization and the target before any irreversible action. A prior read alone is not permission.',R2:'Inspect repeated calls and stop an unintended retry loop.',R3:'Remove secret echoes from tool results; rotate credentials if exposed.',R4:'Avoid literal credentials in tool arguments; use a credential vault or scoped secret injection.',R5:'Read back the exact external target and verify the result before claiming success.',R6:'Check whether the operation executed already; use an idempotency key before retrying.',R7:'Attach execution evidence, or change the final message to state that work was not performed.'};
const example={messages:[{role:'user',content:'Read the project notes.'},{role:'assistant',tool_calls:[{id:'example_read',type:'function',function:{name:'read_file',arguments:'{"path":"notes.md"}'}}]},{role:'tool',tool_call_id:'example_read',content:'Project notes read successfully.'},{role:'assistant',content:'Read the notes.'}]};
function resetReport(){reportText='';list.replaceChildren();headline.textContent='Ready for a trace';delete headline.dataset.state;stats.textContent='Results stay in this tab. Nothing is submitted.';$('empty-report').hidden=false;$('copy').disabled=true;$('copy-status').textContent='';}
function updateInput(){const size=new TextEncoder().encode(input.value).length;$('size').textContent=size.toLocaleString()+' bytes';warning.hidden=!hasSecret(input.value);error.hidden=true;error.textContent='';input.setAttribute('aria-invalid','false');resetReport();}
function fail(message){error.textContent=message;error.hidden=false;input.setAttribute('aria-invalid','true');headline.textContent='Audit not run';stats.textContent='Fix the input to continue.';}
function audit(){resetReport();error.hidden=true;error.textContent='';input.setAttribute('aria-invalid','false');warning.hidden=!hasSecret(input.value);
if(!input.value.trim()){fail('Paste a trace to begin.');return;}
if(new TextEncoder().encode(input.value).length>LIMIT){fail('Trace exceeds 1 MiB. Paste a smaller excerpt.');return;}
try{
const events=AAA.parse_trace(input.value), findings=AAA.run_rules(events), report=AAA.render_report(findings);
headline.textContent=mask(report.headline);headline.dataset.state=report.counts.HIGH?'HIGH':report.counts.MEDIUM?'MEDIUM':'CLEAN';
stats.textContent=mask(report.lines[0]||'No tool calls.');
const safeLines=report.lines.map(mask);
const order={HIGH:0,MEDIUM:1,LOW:2};
findings.slice().sort((a,b)=>order[a.severity]-order[b.severity]||a.rule.localeCompare(b.rule)).forEach(f=>{
const row=document.createElement('article');row.className='finding '+f.severity;
const badge=document.createElement('span');badge.className='badge';badge.textContent=f.severity+' / '+f.rule;
const title=document.createElement('h4');title.textContent=mask(f.title);
const evidence=document.createElement('p');evidence.className='evidence';evidence.textContent=mask(f.evidence);
const action=document.createElement('p');action.className='decision';action.textContent='Review action: '+(decision[f.rule]||'Review the trace context.');
row.append(badge,title,evidence,action);list.append(row);
});
$('empty-report').hidden=findings.length>0;$('empty-report').textContent='No selected patterns found. This is not proof of safety or task completion.';
reportText=['# Agent Action Auditor',mask(report.headline),'',...safeLines,'','## Review actions',...findings.map(f=>f.rule+': '+(decision[f.rule]||'Review trace context.')),'','Trace-based heuristics only; not deployment certification.'].join('\n');
$('copy').disabled=false;
}catch(e){fail(e instanceof AAA.ParseError?mask(e.message):'Unsupported or malformed trace structure. Use OpenAI messages with tool_calls and matched results.');}
}
input.addEventListener('input',updateInput);
$('audit').addEventListener('click',audit);
$('example').addEventListener('click',()=>{input.value=JSON.stringify(example,null,2);updateInput();input.focus();});
$('clear').addEventListener('click',()=>{input.value='';updateInput();input.focus();});
$('copy').addEventListener('click',async()=>{try{await navigator.clipboard.writeText(reportText);$('copy-status').textContent='Report copied. Matching secret values are masked.';}catch{$('copy-status').textContent='Clipboard unavailable. Select the report text and copy manually.';}});
input.addEventListener('keydown',e=>{if((e.ctrlKey||e.metaKey)&&e.key==='Enter'){e.preventDefault();audit();}});
window.addEventListener('pageshow',updateInput);
})();