#!/usr/bin/env node

/**
 * Metabase MCP Server (HTTP transport)
 * Exposes MCP endpoints over HTTP for SSE or REST clients
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { HttpServerTransport } from "@modelcontextprotocol/sdk/server/http.js";
import {
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
  CallToolRequestSchema
} from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";

// --- All original constants, enums, interfaces stay unchanged ---

// Custom error enum
enum ErrorCode {
  InternalError = "internal_error",
  InvalidRequest = "invalid_request",
  InvalidParams = "invalid_params",
  MethodNotFound = "method_not_found"
}

// Custom error class
class McpError extends Error {
  code: ErrorCode;

  constructor(code: ErrorCode, message: string) {
    super(message);
    this.code = code;
    this.name = "McpError";
  }
}

// API error type definition
interface ApiError {
  status?: number;
  message?: string;
  data?: { message?: string };
}

// Get Metabase configuration from environment variables
const METABASE_URL = process.env.METABASE_URL;
const METABASE_USER_EMAIL = process.env.METABASE_USER_EMAIL;
const METABASE_PASSWORD = process.env.METABASE_PASSWORD;
const METABASE_API_KEY = process.env.METABASE_API_KEY;

if (!METABASE_URL || (!METABASE_API_KEY && (!METABASE_USER_EMAIL || !METABASE_PASSWORD))) {
  throw new Error("METABASE_URL is required, and either METABASE_API_KEY or both METABASE_USER_EMAIL and METABASE_PASSWORD must be provided");
}

// Create custom Schema object using z.object
const ListResourceTemplatesRequestSchema = z.object({
  method: z.literal("resources/list_templates")
});

const ListToolsRequestSchema = z.object({
  method: z.literal("tools/list")
});

// Logger level enum
enum LogLevel {
  DEBUG = 'debug',
  INFO = 'info',
  WARN = 'warn',
  ERROR = 'error',
  FATAL = 'fatal'
}

// Authentication method enum
enum AuthMethod {
  SESSION = 'session',
  API_KEY = 'api_key'
}

class MetabaseServer {
  private server: Server;
  private baseUrl: string;
  private sessionToken: string | null = null;
  private apiKey: string | null = null;
  private authMethod: AuthMethod = METABASE_API_KEY ? AuthMethod.API_KEY : AuthMethod.SESSION;
  private headers: Record<string, string> = {
    "Content-Type": "application/json",
  };

  constructor() {
    this.server = new Server(
      {
        name: "metabase-mcp-server",
        version: "0.1.0",
      },
      {
        capabilities: {
          resources: {},
          tools: {},
        },
      }
    );

    this.baseUrl = METABASE_URL!;
    if (METABASE_API_KEY) {
      this.apiKey = METABASE_API_KEY;
      this.logInfo('Using API Key authentication method');
    } else {
      this.logInfo('Using Session Token authentication method');
    }

    this.setupResourceHandlers();
    this.setupToolHandlers();

    this.server.onerror = (error: Error) => {
      this.logError('Unexpected server error occurred', error);
    };

    process.on('SIGINT', async () => {
      this.logInfo('Gracefully shutting down server');
      await this.server.close();
      process.exit(0);
    });
  }

  private log(level: LogLevel, message: string, data?: unknown, error?: Error) {
    const timestamp = new Date().toISOString();
    const logMessage: Record<string, unknown> = { timestamp, level, message };
    if (data !== undefined) logMessage.data = data;
    if (error) {
      logMessage.error = error.message || 'Unknown error';
      logMessage.stack = error.stack;
    }
    console.error(JSON.stringify(logMessage));
    try {
      console.error(`[${timestamp}] ${level.toUpperCase()}: ${message}${error ? ` - ${error.message}` : ''}`);
    } catch {}
  }

  private logDebug(message: string, data?: unknown) {
    this.log(LogLevel.DEBUG, message, data);
  }
  private logInfo(message: string, data?: unknown) {
    this.log(LogLevel.INFO, message, data);
  }
  private logWarn(message: string, data?: unknown, error?: Error) {
    this.log(LogLevel.WARN, message, data, error);
  }
  private logError(message: string, error: unknown) {
    this.log(LogLevel.ERROR, message, undefined, error instanceof Error ? error : new Error(String(error)));
  }
  private logFatal(message: string, error: unknown) {
    this.log(LogLevel.FATAL, message, undefined, error instanceof Error ? error : new Error(String(error)));
  }

  private async request<T>(path: string, options: RequestInit = {}): Promise<T> {
    const url = new URL(path, this.baseUrl);
    const headers = { ...this.headers };
    if (this.authMethod === AuthMethod.API_KEY && this.apiKey) {
      headers['X-API-KEY'] = this.apiKey;
    } else if (this.authMethod === AuthMethod.SESSION && this.sessionToken) {
      headers['X-Metabase-Session'] = this.sessionToken;
    }
    this.logDebug(`Making request to ${url.toString()}`);
    const response = await fetch(url.toString(), { ...options, headers });
    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw {
        status: response.status,
        message: response.statusText,
        data: errorData
      };
    }
    return response.json() as Promise<T>;
  }

  private async getSessionToken(): Promise<string> {
    if (this.authMethod === AuthMethod.API_KEY && this.apiKey) return this.apiKey;
    if (this.sessionToken) return this.sessionToken;
    const response = await this.request<{ id: string }>('/api/session', {
      method: 'POST',
      body: JSON.stringify({
        username: METABASE_USER_EMAIL,
        password: METABASE_PASSWORD,
      }),
    });
    this.sessionToken = response.id;
    return this.sessionToken;
  }

  private setupResourceHandlers() {
    this.server.setRequestHandler(ListResourcesRequestSchema, async (_request) => {
      await this.getSessionToken();
      const dashboardsResponse = await this.request<any[]>('/api/dashboard');
      return {
        resources: dashboardsResponse.map((dashboard: any) => ({
          uri: `metabase://dashboard/${dashboard.id}`,
          mimeType: "application/json",
          name: dashboard.name,
          description: `Metabase dashboard: ${dashboard.name}`
        }))
      };
    });

    this.server.setRequestHandler(ListResourceTemplatesRequestSchema, async () => ({
      resourceTemplates: [
        { uriTemplate: 'metabase://dashboard/{id}', name: 'Dashboard by ID', mimeType: 'application/json', description: 'Get a Metabase dashboard by its ID' },
        { uriTemplate: 'metabase://card/{id}', name: 'Card by ID', mimeType: 'application/json', description: 'Get a Metabase question/card by its ID' },
        { uriTemplate: 'metabase://database/{id}', name: 'Database by ID', mimeType: 'application/json', description: 'Get a Metabase database by its ID' },
      ]
    }));

    this.server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
      const uri = request.params?.uri;
      await this.getSessionToken();
      if (!uri) throw new McpError(ErrorCode.InvalidParams, "URI parameter is required");

      const match = uri.match(/^metabase:\/\/(dashboard|card|database)\/(\d+)$/);
      if (!match) throw new McpError(ErrorCode.InvalidRequest, `Invalid URI format: ${uri}`);

      const [_, type, id] = match;
      const response = await this.request<any>(`/api/${type}/${id}`);
      return {
        contents: [{
          uri,
          mimeType: "application/json",
          text: JSON.stringify(response, null, 2)
        }]
      };
    });
  }

  private setupToolHandlers() {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [
        { name: "list_dashboards", description: "List all dashboards in Metabase", inputSchema: { type: "object", properties: {} } },
        { name: "list_cards", description: "List all questions/cards in Metabase", inputSchema: { type: "object", properties: {} } },
        { name: "list_databases", description: "List all databases in Metabase", inputSchema: { type: "object", properties: {} } },
        {
          name: "execute_card", description: "Execute a Metabase question/card and get results",
          inputSchema: {
            type: "object",
            properties: {
              card_id: { type: "number", description: "ID of the card/question to execute" },
              parameters: { type: "object", description: "Optional parameters for the query" }
            },
            required: ["card_id"]
          }
        },
        {
          name: "get_dashboard_cards", description: "Get all cards in a dashboard",
          inputSchema: {
            type: "object",
            properties: { dashboard_id: { type: "number", description: "ID of the dashboard" } },
            required: ["dashboard_id"]
          }
        },
        {
          name: "execute_query", description: "Execute a SQL query against a Metabase database",
          inputSchema: {
            type: "object",
            properties: {
              database_id: { type: "number", description: "ID of the database to query" },
              query: { type: "string", description: "SQL query to execute" },
              native_parameters: { type: "array", items: { type: "object" }, description: "Optional query params" }
            },
            required: ["database_id", "query"]
          }
        }
      ]
    }));

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      await this.getSessionToken();
      const { name, arguments: args } = request.params || {};
      switch (name) {
        case "list_dashboards":
          return { content: [{ type: "text", text: JSON.stringify(await this.request('/api/dashboard'), null, 2) }] };
        case "list_cards":
          return { content: [{ type: "text", text: JSON.stringify(await this.request('/api/card'), null, 2) }] };
        case "list_databases":
          return { content: [{ type: "text", text: JSON.stringify(await this.request('/api/database'), null, 2) }] };
        case "execute_card":
          return {
            content: [{
              type: "text",
              text: JSON.stringify(await this.request(`/api/card/${args?.card_id}/query`, {
                method: 'POST',
                body: JSON.stringify({ parameters: args?.parameters || {} })
              }), null, 2)
            }]
          };
        case "get_dashboard_cards":
          const dashboard = await this.request<any>(`/api/dashboard/${args?.dashboard_id}`);
          return {
            content: [{
              type: "text",
              text: JSON.stringify(dashboard.cards || [], null, 2)
            }]
          };
        case "execute_query":
          return {
            content: [{
              type: "text",
              text: JSON.stringify(await this.request(`/api/dataset`, {
                method: 'POST',
                body: JSON.stringify({
                  type: "native",
                  native: { query: args?.query, template_tags: {} },
                  parameters: args?.native_parameters || [],
                  database: args?.database_id
                })
              }), null, 2)
            }]
          };
        default:
          return { isError: true, content: [{ type: "text", text: `Unknown tool: ${name}` }] };
      }
    });
  }

  async run() {
    try {
      const port = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;
      const transport = new HttpServerTransport({ port });
      await this.server.connect(transport);
      this.logInfo(`Metabase MCP server listening on HTTP port ${port}`);
    } catch (error) {
      this.logFatal('Failed to start Metabase MCP server', error);
      throw error;
    }
  }
}

// Error handling
process.on('uncaughtException', (error: Error) => {
  console.error(JSON.stringify({ timestamp: new Date().toISOString(), level: 'fatal', message: 'Uncaught exception', error: error.message, stack: error.stack }));
  process.exit(1);
});
process.on('unhandledRejection', (reason: unknown) => {
  console.error(JSON.stringify({ timestamp: new Date().toISOString(), level: 'fatal', message: 'Unhandled rejection', error: reason instanceof Error ? reason.message : String(reason) }));
});

const server = new MetabaseServer();
server.run().catch(error => {
  console.error(JSON.stringify({ timestamp: new Date().toISOString(), level: 'fatal', message: 'Fatal startup error', error: error instanceof Error ? error.message : String(error) }));
  process.exit(1);
});
