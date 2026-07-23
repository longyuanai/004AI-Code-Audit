
export type OutputFormat = 'sarif' | 'json' | 'text' | 'github';
/** @deprecated Provider selection is owned by shared_llm_core.LLMRouter. */
export type LLMProvider = 'claude' | 'openai';
export type LLMTaskTier = 'cheap' | 'standard' | 'premium' | 'local';

export interface ScanConfig {
  include: string[];
  exclude: string[];
}

export interface RulesConfig {
  preset: 'owasp-top-10' | 'all' | 'none';
  custom?: string;
  disable: string[];
}

export interface LLMConfig {
  tier?: LLMTaskTier;
  routerConfig?: string;
  pythonCommand?: string;
  /** @deprecated Kept only so existing v0.4 config files continue to parse. */
  provider: LLMProvider;
  /** @deprecated LLMRouter resolves the model from the configured task tier. */
  model: string;
  /** @deprecated Provider credentials are read by shared_llm_core. */
  apiKey?: string;
  maxConcurrency: number;
  maxCostUSD?: number;
}

export interface OutputConfig {
  format: OutputFormat;
  file?: string;
}

export interface CacheConfig {
  enabled: boolean;
  directory: string;
  ttl: number;
}

export interface CodeGuardConfig {
  scan: ScanConfig;
  rules: RulesConfig;
  llm: LLMConfig;
  output: OutputConfig;
  cache: CacheConfig;
}
