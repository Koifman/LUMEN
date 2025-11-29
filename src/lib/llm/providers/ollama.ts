/**
 * Ollama Provider (Local LLM Server)
 * Connects to locally hosted Ollama server for privacy-focused LLM inference
 */

import { LLMProvider, LLMRequest, LLMResponse, LLMProviderConfig } from './types';

export class OllamaProvider implements LLMProvider {
  name = 'Ollama';

  async sendRequest(request: LLMRequest, config: LLMProviderConfig): Promise<LLMResponse> {
    const endpoint = config.endpoint || 'http://localhost:11434';
    const model = config.model || request.model || 'llama2';

    try {
      // Use Ollama's chat API endpoint
      const response = await fetch(`${endpoint}/api/chat`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          model,
          messages: request.messages.map(m => ({
            role: m.role,
            content: m.content,
          })),
          stream: false, // Use non-streaming for simpler implementation
          options: {
            temperature: config.temperature ?? request.temperature ?? 0.7,
            num_predict: config.maxTokens ?? request.maxTokens ?? 4000,
            // Additional Ollama options for better output
            num_ctx: 8192, // Increase context window
            repeat_penalty: 1.1, // Prevent repetition
            top_k: 40,
            top_p: 0.9,
          },
        }),
      });

      if (!response.ok) {
        const errorText = await response.text();
        let errorMessage = `Ollama server error (${response.status})`;

        try {
          const errorJson = JSON.parse(errorText);
          errorMessage = errorJson.error || errorMessage;
        } catch {
          errorMessage = errorText || errorMessage;
        }

        return {
          content: '',
          model,
          error: errorMessage,
        };
      }

      const data = await response.json();

      // Ollama response format
      const content = data.message?.content || '';

      if (!content) {
        return {
          content: '',
          model: data.model || model,
          error: 'Ollama returned no content. Check if the model is loaded and try again.',
        };
      }

      return {
        content,
        model: data.model || model,
        usage: {
          promptTokens: data.prompt_eval_count || 0,
          completionTokens: data.eval_count || 0,
          totalTokens: (data.prompt_eval_count || 0) + (data.eval_count || 0),
        },
      };
    } catch (error: any) {
      let errorMessage = 'Failed to connect to Ollama server';

      if (error instanceof Error) {
        errorMessage = error.message;
      }

      // Provide helpful error messages for common issues
      if (errorMessage.includes('Failed to fetch') || errorMessage.includes('NetworkError')) {
        errorMessage = `Cannot connect to Ollama server at ${endpoint}. Make sure Ollama is running and accessible.`;
      } else if (errorMessage.includes('CORS')) {
        errorMessage = `CORS error connecting to Ollama. You may need to configure CORS headers on your Ollama server.`;
      }

      return {
        content: '',
        model,
        error: errorMessage,
      };
    }
  }

  async validateAPIKey(apiKey: string): Promise<boolean> {
    // Ollama doesn't require an API key, but we use this method to check
    // if the Ollama server is running and accessible

    // If an endpoint is provided in the "API key" field, use it
    // Otherwise, use the default endpoint
    const endpoint = apiKey && apiKey.trim().length > 0 && apiKey.includes('http')
      ? apiKey.trim()
      : 'http://localhost:11434';

    try {
      // Try to list models to check if server is accessible
      const response = await fetch(`${endpoint}/api/tags`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      return response.ok;
    } catch (error) {
      // Server is not accessible
      return false;
    }
  }

  async listModels(config: LLMProviderConfig): Promise<string[]> {
    const endpoint = config.endpoint || 'http://localhost:11434';

    try {
      const response = await fetch(`${endpoint}/api/tags`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        return [];
      }

      const data = await response.json();

      // Ollama returns { models: [ { name: "llama2", ... }, ... ] }
      if (data.models && Array.isArray(data.models)) {
        return data.models.map((model: any) => model.name || model.model).filter(Boolean);
      }

      return [];
    } catch (error) {
      // If we can't list models, return empty array
      return [];
    }
  }
}
