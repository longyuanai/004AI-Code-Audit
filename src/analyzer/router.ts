import { existsSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export type RouterTaskTier = 'cheap' | 'standard' | 'premium' | 'local';

export interface RouterChatMessage {
  role: 'system' | 'user' | 'assistant' | 'tool';
  content: string;
  name?: string;
  tool_call_id?: string;
}

export interface RouterChatRequest {
  model?: string;
  messages: RouterChatMessage[];
  temperature?: number;
  max_tokens?: number;
  top_p?: number;
  response_format?: Record<string, string>;
}

export interface RouterChatResponse {
  id: string;
  model: string;
  created: number;
  choices: Array<{
    index: number;
    message: RouterChatMessage;
    finish_reason?: string | null;
  }>;
  usage?: {
    prompt_tokens?: number;
    completion_tokens?: number;
    total_tokens?: number;
  };
}

/**
 * Structural port matching shared_llm_core.LLMRouter.chat().
 *
 * Unit and integration tests inject this port directly, so no test needs a
 * provider SDK, API key, network connection, or Python process.
 */
export interface LLMRouterPort {
  chat(tier: RouterTaskTier, request: RouterChatRequest): Promise<RouterChatResponse>;
}

export interface SharedLLMCoreRouterOptions {
  pythonCommand?: string;
  yamlPath?: string;
  sharedCorePath?: string;
  bridgePath?: string;
}

/**
 * Windows-safe adapter for the Python shared_llm_core package.
 *
 * It uses spawn() with an argv array (never a shell command), writes one JSON
 * request to stdin, and reads one JSON response from stdout.
 */
export class SharedLLMCoreRouter implements LLMRouterPort {
  private readonly pythonCommand: string;
  private readonly yamlPath?: string;
  private readonly sharedCorePath: string;
  private readonly bridgePath: string;

  constructor(options: SharedLLMCoreRouterOptions = {}) {
    this.pythonCommand = options.pythonCommand
      ?? process.env.CODEGUARD_PYTHON
      ?? (process.platform === 'win32' ? 'python' : 'python3');
    this.yamlPath = options.yamlPath ?? process.env.CODEGUARD_LLM_CONFIG;
    this.sharedCorePath = options.sharedCorePath
      ?? process.env.SHARED_LLM_CORE_PATH
      ?? findSharedCorePath();
    this.bridgePath = options.bridgePath ?? findBridgePath();
  }

  async chat(tier: RouterTaskTier, request: RouterChatRequest): Promise<RouterChatResponse> {
    return runBridge({
      pythonCommand: this.pythonCommand,
      bridgePath: this.bridgePath,
      sharedCorePath: this.sharedCorePath,
      payload: {
        tier,
        request,
        yaml_path: this.yamlPath,
      },
    });
  }
}

interface BridgeCall {
  pythonCommand: string;
  bridgePath: string;
  sharedCorePath: string;
  payload: Record<string, unknown>;
}

function runBridge(call: BridgeCall): Promise<RouterChatResponse> {
  return new Promise((resolvePromise, reject) => {
    const sharedSrc = join(call.sharedCorePath, 'src');
    const existingPythonPath = process.env.PYTHONPATH;
    const pythonPath = existingPythonPath
      ? `${sharedSrc}${process.platform === 'win32' ? ';' : ':'}${existingPythonPath}`
      : sharedSrc;
    const child = spawn(call.pythonCommand, [call.bridgePath], {
      env: { ...process.env, PYTHONPATH: pythonPath },
      shell: false,
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
    });

    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.on('data', chunk => { stderr += chunk; });

    child.once('error', error => {
      reject(new Error(`Unable to start shared LLM router bridge: ${error.message}`));
    });
    child.once('close', code => {
      if (code !== 0) {
        reject(new Error(
          `shared_llm_core bridge exited with code ${code}: ${stderr.trim() || 'no error output'}`,
        ));
        return;
      }

      try {
        resolvePromise(JSON.parse(stdout) as RouterChatResponse);
      } catch (error) {
        reject(new Error(
          `shared_llm_core bridge returned invalid JSON: ${
            error instanceof Error ? error.message : String(error)
          }`,
        ));
      }
    });

    child.stdin.end(JSON.stringify(call.payload), 'utf8');
  });
}

function findBridgePath(): string {
  const packageRoot = findPackageRoot(dirname(fileURLToPath(import.meta.url)));
  const bundled = join(packageRoot, 'dist', 'shared-llm-bridge.py');
  if (existsSync(bundled)) {
    return bundled;
  }

  const source = join(packageRoot, 'src', 'analyzer', 'shared_llm_bridge.py');
  if (existsSync(source)) {
    return source;
  }

  throw new Error('Unable to locate shared_llm_core bridge script.');
}

function findSharedCorePath(): string {
  const starts = [
    resolve(process.cwd()),
    dirname(fileURLToPath(import.meta.url)),
  ];

  for (const start of starts) {
    let current = start;
    while (true) {
      const candidate = join(current, '000shared-llm-core');
      if (existsSync(join(candidate, 'src', 'shared_llm_core', '__init__.py'))) {
        return candidate;
      }
      const parent = dirname(current);
      if (parent === current) break;
      current = parent;
    }
  }

  throw new Error(
    'Unable to locate 000shared-llm-core. Set SHARED_LLM_CORE_PATH to its project directory.',
  );
}

function findPackageRoot(startDir: string): string {
  let current = startDir;
  while (true) {
    if (existsSync(join(current, 'package.json'))) {
      return current;
    }
    const parent = dirname(current);
    if (parent === current) {
      throw new Error('Unable to locate AI-CodeGuard package root.');
    }
    current = parent;
  }
}

