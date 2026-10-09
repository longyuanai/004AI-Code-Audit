'use strict';
/* global document, fetch, FileReader, clearTimeout, setTimeout */
const $ = id => document.getElementById(id);
let token = '', selected = [], activeTask = null, detail = null, timer = null;
const labels = {queued:'等待扫描',running:'扫描中',completed:'完成',failed:'失败',interrupted:'已中断',not_requested:'尚未请求',unavailable:'不可用',partial:'部分完成',not_applicable:'无发现，无需分析'};
const aiLabels = {...labels, queued:'等待分析', running:'分析中'};
function message(text, error = false) { $('message').textContent = text; $('message').className = error ? 'error' : ''; }
async function api(path, data) {
  const response = await fetch(path, data === undefined ? {} : {method:'POST',headers:{'Content-Type':'application/json','X-Audit-Token':token},body:JSON.stringify(data)});
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || `请求失败 (${response.status})`);
  return result;
}
function element(tag, text, className) { const node=document.createElement(tag); if(text!==undefined)node.textContent=text; if(className)node.className=className; return node; }
function action(text, handler, disabled=false) { const button=element('button',text);button.disabled=disabled;button.addEventListener('click',()=>handler().catch(error=>message(error.message,true)));return button; }
function choose(files, directory) {
  selected = Array.from(files).filter(file=>!directory || (file.name.toLowerCase().endsWith('.py') && !(file.webkitRelativePath.split('/').some(part=>part.startsWith('.') || ['node_modules','dist','build'].includes(part)))));
  $('selection').textContent=`已选择 ${selected.length} 个文件，共 ${selected.reduce((sum,file)=>sum+file.size,0)} 字节${directory?'（仅导入 Python 文件）':''}`;
}
$('file-input').addEventListener('change',event=>{ $('directory-input').value='';choose(event.target.files,false); });
$('directory-input').addEventListener('change',event=>{ $('file-input').value='';choose(event.target.files,true); });
function base64(file) { return new Promise((resolve,reject)=>{const reader=new FileReader();reader.onload=()=>resolve(reader.result.split(',')[1]);reader.onerror=()=>reject(new Error('读取文件失败'));reader.readAsDataURL(file);}); }
$('import-button').addEventListener('click',async()=>{
  const button=$('import-button');button.disabled=true;
  try {
    const name=$('project-name').value.trim();if(!name || !selected.length)throw new Error('填写项目名称并选择源码');
    if(selected.length>100 || selected.reduce((sum,file)=>sum+file.size,0)>8*1024*1024)throw new Error('文件数量或总大小超限');
    let data={name};
    if(selected.length===1 && selected[0].name.toLowerCase().endsWith('.zip')) data.zip_base64=await base64(selected[0]);
    else {
      if(selected.some(file=>!file.name.toLowerCase().endsWith('.py') || file.size>512*1024))throw new Error('仅支持 .py，单文件最多 512 KiB');
      data.files=await Promise.all(selected.map(async file=>({path:file.webkitRelativePath || file.name,content_base64:await base64(file)})));
    }
    const project=await api('/api/projects',data);message(`项目 ${project.name} 已导入。选择“开始扫描”创建任务。`);await refresh();
  } catch(error) {message(error.message,true);} finally {button.disabled=false;}
});
async function refresh() {
  const [projects,tasks]=await Promise.all([api('/api/projects'),api('/api/tasks')]);
  $('projects').replaceChildren();
  if(!projects.length)$('projects').append(element('p','尚无项目。请先导入源码。'));
  for(const project of projects){const row=element('div');const text=element('span',project.name);text.append(element('small',`${project.file_count} 个文件 · ${project.total_bytes} 字节`));row.append(text,action('开始扫描',async()=>{const task=await api('/api/tasks',{project_id:project.id});activeTask=task.id;message('扫描任务已创建');await refresh();}));$('projects').append(row);}
  $('tasks').replaceChildren();
  if(!tasks.length)$('tasks').append(element('p','尚无扫描记录。'));
  for(const task of tasks){const row=element('div');const text=element('span',`${task.project_name} · ${labels[task.status] || task.status}`);text.append(element('small',`${new Date(task.created_at).toLocaleString()} · AI ${aiLabels[task.ai_status] || task.ai_status}`));row.append(text,action('查看结果',async()=>{activeTask=task.id;await showTask();}));$('tasks').append(row);}
  if(activeTask)await showTask();
  clearTimeout(timer);
  if(tasks.some(task=>['queued','running'].includes(task.status) || ['queued','running'].includes(task.ai_status)))timer=setTimeout(()=>refresh().catch(error=>message(error.message,true)),1500);
}
async function showTask() {
  detail=await api(`/api/tasks/${activeTask}`);$('detail').hidden=false;
  $('detail-title').textContent=`${detail.project_name} · 任务详情`;
  const summary=detail.envelope.summary;
  $('task-summary').textContent=`扫描：${labels[detail.status] || detail.status}\nAI：${aiLabels[detail.ai_status] || detail.ai_status}\n${detail.error || detail.ai_error || ''}\n扫描文件：${summary.files_scanned ?? '—'} · 发现：${detail.envelope.findings.length}\n工具：${summary.tool || '—'} ${summary.tool_version || ''} · 规则集：${summary.ruleset || '—'}\n耗时：${detail.duration_seconds?.toFixed(3) ?? '—'} 秒`;
  $('ai-button').disabled=detail.status!=='completed' || !['not_requested','unavailable'].includes(detail.ai_status);
  $('exports').replaceChildren();
  if(detail.status==='completed')for(const format of ['html','json','sarif']){const link=element('a',`导出 ${format.toUpperCase()}`,'download');link.href=`/api/tasks/${activeTask}/report.${format}`;link.download=`audit-${activeTask}.${format}`;$('exports').append(link);}
  renderFindings();
}
function renderFindings() {
  $('findings').replaceChildren();if(!detail)return;
  const findings=detail.envelope.findings.filter(finding=>$('severity-filter').value==='all' || finding.severity===$('severity-filter').value);
  if(!findings.length)$('findings').append(element('p',detail.status==='completed'?'当前筛选下无发现；零发现不代表安全。':'扫描尚未完成。'));
  for(const finding of findings){const metadata=finding.metadata;const card=element('article',undefined,finding.severity);card.append(element('h3',`${finding.title} · ${finding.severity}`),element('p',`静态规则发现 · 潜在风险 · 未人工确认/未验证 | ${metadata.rule_id} | ${metadata.relative_path}:${metadata.line}`));const expanded=element('details');expanded.append(element('summary','查看证据与修复建议'),element('p',finding.description),element('pre',finding.evidence.join('\n')),element('p',`修复建议：${metadata.remediation || '需人工复核'}`));if(metadata.llm_triage){expanded.append(element('h4','AI 推断（不等同于人工确认/已验证漏洞）'),element('pre',JSON.stringify(metadata.llm_triage,null,2)));}card.append(expanded);$('findings').append(card);}
}
$('ai-button').addEventListener('click',async()=>{try{if(!$('ai-consent').checked)throw new Error('请先同意发送脱敏代码片段');await api(`/api/tasks/${activeTask}/ai`,{consent:true});message('AI 分析已请求；模型不可用时保留静态报告。');await refresh();}catch(error){message(error.message,true);}});
$('severity-filter').addEventListener('change',renderFindings);
$('refresh-button').addEventListener('click',()=>refresh().catch(error=>message(error.message,true)));
(async()=>{try{token=(await api('/api/session')).token;await refresh();}catch(error){message(error.message,true);}})();
