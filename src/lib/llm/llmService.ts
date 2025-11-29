/**
 * LLM Service
 * 
 * Main service for interacting with LLM providers
 * Supports multiple providers with extensible architecture
 */

import { LLMProvider as LLMProviderInterface, LLMRequest, LLMResponse, LLMProviderConfig } from './providers/types';
import { LLMProvider } from '../../types';

// Provider registry with lazy loading - providers are only loaded when first used
const providerInstances: Map<LLMProvider, LLMProviderInterface> = new Map();

// Dynamic provider loading functions
const providerLoaders: Map<LLMProvider, () => Promise<LLMProviderInterface>> = new Map([
  ['openai', async () => {
    const { OpenAIProvider } = await import('./providers/openai');
    return new OpenAIProvider();
  }],
  ['anthropic', async () => {
    const { AnthropicProvider } = await import('./providers/anthropic');
    return new AnthropicProvider();
  }],
  ['google', async () => {
    const { GoogleProvider } = await import('./providers/google');
    return new GoogleProvider();
  }],
  ['ollama', async () => {
    const { OllamaProvider } = await import('./providers/ollama');
    return new OllamaProvider();
  }],
]);

/**
 * Provider metadata for UI display
 */
export interface ProviderMetadata {
  id: LLMProvider;
  name: string;
  description: string;
  requiresApiKey: boolean;
  requiresEndpoint?: boolean;
  defaultModel: string;
  models: string[];
  apiKeyUrl?: string;
  docsUrl?: string;
}

export const providerMetadata: Map<LLMProvider, ProviderMetadata> = new Map([
  ['openai', {
    id: 'openai',
    name: 'OpenAI',
    description: '',
    requiresApiKey: true,
    defaultModel: 'gpt-5.1',
    models: ['gpt-5.1'],
    apiKeyUrl: 'https://platform.openai.com/api-keys',
    docsUrl: 'https://platform.openai.com/docs',
  }],
  ['anthropic', {
    id: 'anthropic',
    name: 'Anthropic',
    description: '',
    requiresApiKey: true,
    defaultModel: 'claude-sonnet-4-5',
    models: [
      'claude-sonnet-4-5',
      'claude-haiku-4-5',
      'claude-opus-4-5',
      'claude-opus-4-1',
    ],
    apiKeyUrl: 'https://console.anthropic.com/',
    docsUrl: 'https://docs.anthropic.com/',
  }],
  ['google', {
    id: 'google',
    name: 'Google Gemini',
    description: '',
    requiresApiKey: true,
    defaultModel: 'gemini-2.0-flash-exp',
    models: ['gemini-2.0-flash-exp', 'gemini-1.5-pro', 'gemini-1.5-flash'],
    apiKeyUrl: 'https://aistudio.google.com/app/apikey',
    docsUrl: 'https://ai.google.dev/docs',
  }],
  ['ollama', {
    id: 'ollama',
    name: 'Ollama (Local)',
    description: 'Local LLM server running on your machine',
    requiresApiKey: false,
    requiresEndpoint: true,
    defaultModel: 'llama2',
    models: [],
    docsUrl: 'https://ollama.ai/library',
  }],
]);

/**
 * Get provider instance (lazy-loaded on first use)
 */
export async function getProvider(provider: LLMProvider): Promise<LLMProviderInterface | null> {
  // Return cached instance if already loaded
  if (providerInstances.has(provider)) {
    return providerInstances.get(provider)!;
  }

  // Load provider dynamically
  const loader = providerLoaders.get(provider);
  if (!loader) {
    return null;
  }

  try {
    const instance = await loader();
    providerInstances.set(provider, instance);
    return instance;
  } catch (error) {
    return null;
  }
}

/**
 * Send analysis request to LLM
 */
export async function sendAnalysisRequest(
  provider: LLMProvider,
  config: LLMProviderConfig,
  systemPrompt: string,
  userPrompt: string
): Promise<LLMResponse> {
  const providerInstance = await getProvider(provider);

  if (!providerInstance) {
    throw new Error(`Unsupported provider: ${provider}`);
  }

  const metadata = providerMetadata.get(provider);
  if (metadata?.requiresApiKey && (!config.apiKey || config.apiKey.trim().length === 0)) {
    throw new Error('API key is required for this provider');
  }

  const request: LLMRequest = {
    messages: [
      {
        role: 'system',
        content: systemPrompt,
      },
      {
        role: 'user',
        content: userPrompt,
      },
    ],
    model: config.model,
    temperature: config.temperature ?? 0.7,
    maxTokens: config.maxTokens ?? 4000,
  };

  const response = await providerInstance.sendRequest(request, config);

  if (response.error) {
    throw new Error(response.error);
  }

  return response;
}

/**
 * Validate API key for a provider
 */
export async function validateAPIKey(
  provider: LLMProvider,
  apiKey: string
): Promise<boolean> {
  const providerInstance = await getProvider(provider);

  if (!providerInstance) {
    return false;
  }

  // For providers that don't require API keys (like Ollama), validate endpoint instead
  const metadata = providerMetadata.get(provider);
  if (!metadata?.requiresApiKey) {
    // For Ollama, we still call validateAPIKey to check server connectivity
    try {
      return await providerInstance.validateAPIKey(apiKey || '');
    } catch {
      return false;
    }
  }

  if (!apiKey || apiKey.trim().length === 0) {
    return false;
  }

  try {
    return await providerInstance.validateAPIKey(apiKey);
  } catch {
    return false;
  }
}

/**
 * Fetch live model list from provider if supported, otherwise fall back to metadata
 */
export async function fetchAvailableModels(
  provider: LLMProvider,
  config: LLMProviderConfig
): Promise<string[]> {
  const providerInstance = await getProvider(provider);
  if (providerInstance?.listModels) {
    const models = await providerInstance.listModels(config);
    if (models.length > 0) return models;
  }
  return getAvailableModels(provider);
}

/**
 * Get provider metadata
 */
export function getProviderMetadata(provider: LLMProvider): ProviderMetadata | undefined {
  return providerMetadata.get(provider);
}

/**
 * Get all available providers
 */
export function getAllProviders(): LLMProvider[] {
  return Array.from(providerLoaders.keys());
}

/**
 * Get all provider metadata
 */
export function getAllProviderMetadata(): ProviderMetadata[] {
  return Array.from(providerMetadata.values());
}

/**
 * Get available models for a provider (metadata only; prefer fetchAvailableModels for live)
 */
export function getAvailableModels(provider: LLMProvider): string[] {
  const metadata = providerMetadata.get(provider);
  return metadata?.models || [];
}

/**
 * Send analysis request with file attachments
 * @param provider LLM provider (supports: openai, anthropic, google)
 * @param config Provider configuration
 * @param files Array of files to upload
 * @param systemPrompt System prompt text
 * @param userPrompt User prompt text
 */
export async function sendAnalysisRequestWithFiles(
  provider: LLMProvider,
  config: LLMProviderConfig,
  files: Array<{ name: string; content: string }>,
  systemPrompt: string,
  userPrompt: string
): Promise<LLMResponse> {
  const providerInstance = await getProvider(provider);

  if (!providerInstance) {
    throw new Error(`Unsupported provider: ${provider}`);
  }

  const metadata = providerMetadata.get(provider);
  if (metadata?.requiresApiKey && (!config.apiKey || config.apiKey.trim().length === 0)) {
    throw new Error('API key is required for this provider');
  }

  // Check if provider has sendRequestWithFiles method
  const fileProvider = providerInstance as any;
  if (!fileProvider.sendRequestWithFiles) {
    throw new Error('This provider does not support file attachments');
  }

  const request: LLMRequest = {
    messages: [
      {
        role: 'system',
        content: systemPrompt,
      },
      {
        role: 'user',
        content: userPrompt,
      },
    ],
    model: config.model,
    temperature: config.temperature ?? 0.7,
    maxTokens: config.maxTokens ?? 4000,
  };

  const response = await fileProvider.sendRequestWithFiles(files, request, config);

  if (response.error) {
    throw new Error(response.error);
  }

  return response;
}
