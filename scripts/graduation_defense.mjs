/* global process, console */
// Build an editable local deck with the Codex artifact runtime. No product dependency.
import fs from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const [workspaceDir, modulesDir, skillDir, runtimePython] = process.argv.slice(2);
if (!runtimePython) throw new Error('Usage: node graduation_defense.mjs workspace modules skill python');
process.env.RUNTIME_NODE_MODULES = modulesDir;
process.env.RUNTIME_NODE = process.execPath;
const { Presentation, PresentationFile } = await import(pathToFileURL(path.join(modulesDir, '@oai/artifact-tool/dist/artifact_tool.mjs')).href);
const { finalizePresentation } = await import(pathToFileURL(path.join(skillDir, 'container_tools/artifact_tool_utils.mjs')).href);
const buildDir = path.join(workspaceDir, 'artifacts/graduation-20261009/materials-build-v5');
const outputDir = path.join(workspaceDir, 'artifacts/graduation-20261009/materials-output');
await fs.mkdir(buildDir, { recursive: true });
await fs.mkdir(outputDir, { recursive: true });
const p = Presentation.create({ slideSize: { width: 1280, height: 720 } });
const font = 'Microsoft YaHei';
const ink = '#172a3c';

function text(slide, value, x, y, w, h, size=30, bold=false, color=ink) {
  const s=slide.shapes.add({geometry:'textbox',position:{left:x,top:y,width:w,height:h},fill:'none',line:{fill:'none',width:0}});
  s.text=value;
  s.text.style={typeface:font,fontSize:size,bold,color};
  return s;
}
function slide(title, note='') {
  const s=p.slides.add(); s.background.fill='#ffffff';
  text(s,title,64,46,1152,90,43,true);
  text(s,String(p.slides.items.length).padStart(2,'0'),1160,660,56,30,18,false,'#6a7c8a');
  s.speakerNotes.text=note;
  return s;
}
function paragraphs(s, values, y=170) {
  for(let i=0;i<values.length;i++) text(s,values[i],70,y+i*108,1130,84,30);
}
function table(s, values, widths, top=174, height=360) {
  const t=s.tables.add({rows:values.length,columns:values[0].length,left:70,top,width:1135,height,columnWidths:widths,values});
  t.borders.assign({style:'solid',fill:'#d9e1e7',width:1});
  for(let r=0;r<values.length;r++) for(let c=0;c<values[0].length;c++){
    const cell=t.getCell(r,c);cell.fill=r===0?'#172a3c':r%2?'#ffffff':'#edf3f6';
    cell.text.style={typeface:font,fontSize:24,color:r===0?'#ffffff':ink,bold:r===0};
  }
  return t;
}
function node(s, value,x,y,w=245,h=85) {
  const n=s.shapes.add({geometry:'rect',position:{left:x,top:y,width:w,height:h},fill:'#edf3f6',line:{fill:'#728b9b',width:1}});
  n.text=value;n.text.style={typeface:font,fontSize:25,color:ink};n.text.alignment='center';n.text.verticalAlignment='middle';return n;
}
function connect(s,a,b,from='right',to='left') {
  s.shapes.connect(a,b,{kind:'elbow',fromSide:from,toSide:to,line:{fill:'#728b9b',width:2},tail:{type:'arrow',width:'med',length:'med'}});
}

let s=slide('源代码安全检测系统', '题目全称：基于 Python 与大语言模型的源代码安全检测系统设计与实现。学校模板和个人信息待补。材料依据 2026-10-09 实测编写。');
text(s,'基于 Python 与大语言模型的\n设计与实现',70,230,1110,180,57,true);
text(s,'计算机应用技术专业毕业设计通用答辩草稿\n2026 年 10 月 9 日',74,480,1090,105,28);

s=slide('需求与实现范围','来源：docs/audits/graduation-baseline.md、docs/graduation/system-design.md。保留既有 Python 包和 TypeScript CLI，没有新增生产框架。');
paragraphs(s,['已有命令行扫描，补齐文件导入、任务历史和可视化流程。','本版重点支持 Python、本地单用户和受控项目。','完整流程包含静态证据、可选模型复核和报告导出。','零发现不代表安全，发现需要人工结合业务确认。']);

s=slide('实际系统架构','来源：src/ai_code_audit/web 与 docs/graduation/system-design.md。图形和连接均可编辑。进程分离仅用于受限执行和超时，不是操作系统沙箱。');
const browser=node(s,'浏览器',75,190);
const http=node(s,'回环 HTTP 校验',405,190);
const service=node(s,'快照与任务服务',900,190);
const db=node(s,'SQLite\n静态发现与 AI 分表',75,415);
const worker=node(s,'可信工作进程\n扫描或 AI',405,415);
const engines=node(s,'AST 与原扫描器\n现有路由与本机模型',900,415);
connect(s,browser,http);connect(s,http,service);connect(s,service,worker,'bottom','top');
connect(s,worker,engines);connect(s,service,db,'bottom','top');
text(s,'扫描默认 60 秒，AI 默认 90 秒硬超时。用户明确同意后才发送有限脱敏片段。',75,575,1110,65,26);

s=slide('数据库与证据关联','来源：src/ai_code_audit/web/store.py。user_version=1；外键、参数绑定和写入事务。查询时合并 AI 元数据，原始 evidence 不覆盖。');
table(s,[['表','主键','保存内容'],['projects','id','项目、文件清单与摘要'],['tasks','id','状态、统计、时间与错误'],['findings','task_id + ordinal','完整静态发现 JSON'],['ai_results','task_id + ordinal','独立模型复核 JSON']],[245,385,505]);
text(s,'一个项目多个任务，一个任务多项发现，每项发现可关联一项 AI 结果。',75,585,1100,75,26);

s=slide('五类静态风险规则','来源：src/ai_code_audit/python_security.py。规则是潜在风险模式。AST 没有完整变量与跨文件数据流，别名遮蔽也可能误判。参考风险分类 https://cwe.mitre.org/。');
table(s,[['规则','类别','处理方向'],['CG-PY-001','命令注入','参数数组和限定命令'],['CG-PY-002','SQL 注入','数据库参数绑定'],['CG-PY-003','不安全反序列化','安全数据格式与 loader'],['CG-PY-004','动态代码执行','明确解析器'],['CG-PY-005','硬编码凭据','外部管理与必要轮换']],[295,395,445],162,400);
text(s,'每项发现包含文件位置、依据、风险等级和建议，默认尚未验证。',75,586,1100,75,26);

s=slide('真实界面与本机模型','来源：docs/tests/screenshots/graduation-ai-detail.jpg（真实浏览器原生截图）；完整流程见 graduation-real-ai-flow.jpg。实际浏览器任务 aa9fdcdc56f74cc8ab6248505cf3e857，calculator.py:6。本机模型已成功，静态证据保持不变。');
const bytes=await fs.readFile(path.join(workspaceDir,'docs/tests/screenshots/graduation-ai-detail.jpg'));
s.images.add({blob:bytes.buffer.slice(bytes.byteOffset,bytes.byteOffset+bytes.byteLength),contentType:'image/jpeg',alt:'真实浏览器模型复核详情',fit:'contain',position:{left:65,top:185,width:430,height:390}});
text(s,'qwen2.5:3b-instruct-q4_K_M\nOllama 0.40.0',525,180,680,120,33,true);
text(s,'真实解释与修复建议成功保存。\nAI 判断属于推断。\n模型失败时静态报告仍可查看。',525,340,650,210,30);
text(s,'模型建议需要核对，系统没有执行修复代码的入口。',525,572,650,85,25);

s=slide('安全与故障处理','来源：tests/test_graduation_security.py、tests/test_graduation_workflow.py。本轮覆盖项通过，不是完整渗透测试。OWASP 提示注入说明：https://genai.owasp.org/llmrisk/llm01-prompt-injection/。');
paragraphs(s,['上传前完整验证路径、文件大小、数量与 ZIP 元数据。','限制 HTTP 并发、任务队列和工作进程超时。','界面文本和 HTML 报告转义，不执行源码或模型输出。','数据库插入失败回滚新快照，重启恢复中断任务。']);

s=slide('同样本静态与 AI 对照','来源：benchmarks/graduation/labels.json、docs/tests/graduation-evaluation.json、graduation-ai-evaluation.json。目标规则样例级口径。模型 digest 357c53fb659c5076de1d65ccb0b397446227b71a42be9d1603d46168015c9e4b，温度0、最大500tokens、无重试。');
text(s,'20 个手工标注合成样例，10 阳性和 10 阴性，各重复三次。',75,154,1130,65,29);
table(s,[['方式','TP','FP','FN','TN','Precision','Recall'],['静态','8','2','2','8','80%','80%'],['静态 + AI','8','2','2','8','80%','80%']],[325,85,85,85,85,235,235],255,205);
text(s,'30 次真实复核成功，0 次调用失败。\n本次没有观察到准确率提升。',75,520,1095,110,32,true);

s=slide('误报 漏报与模型局限','来源：两份评价 JSON 及 real-ai-proof.json。过滤仅用于实验，产品保留全部静态发现。标签未经独立复核，样本不能代表真实项目总体准确率。');
paragraphs(s,['误报：固定 os.system 命令、常量 eval。','漏报：SQL 经变量传递、字典中的硬编码凭据。','AI 仅复核已有候选，不能补回静态漏报。','模型曾把参数化查询作为 eval 修复建议，需人工识别。']);

s=slide('测试与独立部署','来源：docs/tests/graduation-test-report.md 和最终交付清单。Python427 passed，TS593 passed/2 skipped。版本与哈希锁定30包，从 Git 导出快照进行安装，不依赖开发 PYTHONPATH。Linux/Docker/远程CI未实测。');
text(s,'427 项 Python 集成测试通过',75,185,1110,80,44,true);
text(s,'593 项 TypeScript 测试通过，2 项跳过',75,295,1110,75,35);
text(s,'30 包离线依赖锁定与哈希校验\n安装版验证真实 HTTP、持久化、导出和重启',75,410,1100,125,32);
text(s,'适用范围为本机回环演示，尚无公网账号与多用户权限。',75,580,1100,70,27);

s=slide('演示与后续工作','来源：docs/graduation/defense-outline.md。学校模板、本人信息和独立标签复核由学生补充。现场模型不可用时展示真实降级证据，不能伪装成功。');
paragraphs(s,['导入受控样例，扫描并展示位置、证据和建议。','明确同意后请求本机模型，导出 HTML 并查询历史。','比较修复样例，解释零发现与安全结论的区别。','后续优先扩展独立语料、变量追踪和模型评价。']);

for(const [i,item] of p.slides.items.entries()){
  const blob=await p.export({slide:item,format:'png',scale:1});
  await fs.writeFile(path.join(buildDir,`slide-${String(i+1).padStart(2,'0')}.png`),new Uint8Array(await blob.arrayBuffer()));
}
const candidatePath=path.join(buildDir,'candidate.pptx');
await (await PresentationFile.exportPptx(p)).save(candidatePath);
const result=await finalizePresentation({workspaceDir,candidatePath,finalPath:path.join(outputDir,'毕业设计答辩通用草稿-v5.pptx'),pythonExecutable:runtimePython,
  integrityValidatorPath:path.join(skillDir,'container_tools/inspect_presentation_package_integrity.py'),
  layoutValidatorPath:path.join(skillDir,'container_tools/inspect_presentation_layout_geometry.py'),
  layoutArgs:['--expected-slide-size-emu','12192000,6858000','--validate-heading-fit',
    ...[4,5,8].flatMap(number=>['--require-native-table-slide',String(number)])],
  explicitTotalSlideCount:11,requiredNativeTableOwnerSlides:[4,5,8],fontPolicy:{basis:'design',families:[font]},verifyArtifactToolImport:true,
  receiptPath:path.join(buildDir,'validation.json')});
console.log(JSON.stringify(result));
