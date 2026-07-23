import { createServer } from 'node:http';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

const tempDir = await mkdtemp(join(tmpdir(), 'codeguard-router-smoke-'));
const sourcePath = join(tempDir, 'smoke.py');
const configPath = join(tempDir, 'router.yml');

const server = createServer((request, response) => {
  request.resume();
  request.once('end', () => {
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify({
      id: 'router-smoke',
      object: 'chat.completion',
      created: 0,
      model: 'smoke-model',
      choices: [{
        index: 0,
        message: {
          role: 'assistant',
          content: JSON.stringify({
            confirmed: true,
            confidence: 0.99,
            reasoning: 'Local smoke router confirmed the finding.',
          }),
        },
        finish_reason: 'stop',
      }],
      usage: {
        prompt_tokens: 10,
        completion_tokens: 10,
        total_tokens: 20,
      },
    }));
  });
});

try {
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') {
    throw new Error('Unable to resolve local smoke server port.');
  }

  await writeFile(sourcePath, 'eval(user_input)\n', 'utf8');
  await writeFile(configPath, [
    'providers:',
    '  - name: local',
    `    base_url: http://127.0.0.1:${address.port}/v1`,
    '    api_key: smoke-only',
    '    default_model: smoke-model',
    'audit:',
    '  backend: noop',
    '',
  ].join('\n'), 'utf8');

  const result = await run(process.execPath, [
    join(process.cwd(), 'dist', 'index.js'),
    'scan',
    sourcePath,
    '--output',
    'json',
    '--fail-on',
    'none',
  ], {
    ...process.env,
    CODEGUARD_LLM_CONFIG: configPath,
    CODEGUARD_LLM_TIER: 'standard',
  });

  if (result.code !== 0) {
    throw new Error(`CLI exited ${result.code}: ${result.stderr}`);
  }
  const report = JSON.parse(result.stdout);
  if (report.scan.llmCalls < 1 || report.findings[0]?.llmAnalysis?.confirmed !== true) {
    throw new Error(`Unexpected smoke report: ${result.stdout}`);
  }

  console.log(`router smoke: ${report.scan.llmCalls} LLM call(s), finding confirmed`);
} finally {
  await new Promise(resolve => server.close(resolve));
  await rm(tempDir, { recursive: true, force: true });
}

function run(command, args, env) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command, args, {
      env,
      shell: false,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.on('data', chunk => { stderr += chunk; });
    child.once('error', reject);
    child.once('close', code => resolvePromise({ code, stdout, stderr }));
  });
}

