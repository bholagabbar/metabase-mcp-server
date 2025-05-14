#!/usr/bin/env node

/**
 * Metabase MCP Server (HTTP transport)
 * Implements interaction with Metabase API over SSE/HTTP
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { HttpServerTransport } from "@modelcontextprotocol/sdk/server/http.js";
import {
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
  CallToolRequestSchema
} from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";

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
const ListResourceTemplatesRequestSchema = z.object({ method: z.literal("resources/list_templates") });
const ListToolsRequestSchema             = z.object({ method: z.literal("tools/list") });

// Logger level enum
enum LogLevel   { DEBUG = 'debug', INFO = 'info', WARN = 'warn', ERROR = 'error', FATAL = 'fatal' }
// Authentication method enum
enum AuthMethod { SESSION = 'session', API_KEY = 'api_key' }

class MetabaseServer {
  private server: Server;
  private baseUrl: string;
  private sessionToken: string | null = null;
  private apiKey: string | null       = null;
  private authMethod: AuthMethod      = METABASE_API_KEY ? AuthMethod.API_KEY : AuthMethod.SESSION;
  private headers: Record<string, string> = { "Content-Type": "application/json" };

  constructor() {
    this.server = new Server(
      { name: "metabase-mcp-server", version: "0.1.0" },
      { capabilities: { resources: {}, tools: {} } }
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
    this.server.onerror = (error: Error) => this.logError('Unexpected server error occurred', error);

    process.on('SIGINT', async () => {
      this.logInfo('Gracefully shutting down server');
      await this.server.close();
      process.exit(0);
    });
  }

  // Logging utilities
  private log(level: LogLevel, message: string, data?: unknown, error?: Error) {
    const timestamp = new Date().toISOString();
    const logMessage: any = { timestamp, level, message };
    if (data !== undefined) logMessage.data = data;
    if (error) {
      logMessage.error = error.message;
      logMessage.stack = error.stack;
    }
    console.error(JSON.stringify(logMessage));
    console.error(`[${timestamp}] ${level.toUpperCase()}: ${message}${error ? ` - ${error.message}` : ''}`);
  }
  private logDebug(msg:string, d?:unknown){this.log(LogLevel.DEBUG,msg,d)}
  private logInfo(msg:string, d?:unknown){this.log(LogLevel.INFO,msg,d)}
  private logWarn(msg:string, d?:unknown,e?:Error){this.log(LogLevel.WARN,msg,d,e)}
  private logError(msg:string,e:unknown){this.log(LogLevel.ERROR,msg,undefined,e instanceof Error?e:new Error(String(e)))}
  private logFatal(msg:string,e:unknown){this.log(LogLevel.FATAL,msg,undefined,e instanceof Error?e:new Error(String(e)))}

  /** HTTP request helper */
  private async request<T>(path:string,opts:RequestInit={}) { 
    const url = new URL(path,this.baseUrl);
    const headers = {...this.headers};
    if(this.authMethod===AuthMethod.API_KEY&&this.apiKey)headers['X-API-KEY']=this.apiKey;
    else if(this.authMethod===AuthMethod.SESSION&&this.sessionToken)headers['X-Metabase-Session']=this.sessionToken;
    this.logDebug(`Request to ${url}`,headers);
    const res = await fetch(url.toString(),{...opts,headers});
    if(!res.ok){const e=await res.json().catch(()=>({}));throw{status:res.status,message:res.statusText,data:e}};
    return res.json() as Promise<T>;
  }

  private async getSessionToken():Promise<string> {
    if(this.authMethod===AuthMethod.API_KEY&&this.apiKey)return this.apiKey;
    if(this.sessionToken)return this.sessionToken;
    const r=await this.request<{id:string}>('/api/session',{method:'POST',body:JSON.stringify({username:METABASE_USER_EMAIL,password:METABASE_PASSWORD})});
    this.sessionToken=r.id;return this.sessionToken;
  }

  private setupResourceHandlers(){
    this.server.setRequestHandler(ListResourcesRequestSchema,async()=>{
      await this.getSessionToken();
      const d=await this.request<any[]>('/api/dashboard');
      return{resources:d.map(x=>({uri:`metabase://dashboard/${x.id}`,mimeType:'application/json',name:x.name,description:`Metabase dashboard: ${x.name}`}))};
    });

    this.server.setRequestHandler(ListResourceTemplatesRequestSchema,async()=>({resourceTemplates:[
      {uriTemplate:'metabase://dashboard/{id}',name:'Dashboard by ID',mimeType:'application/json',description:'Get a Metabase dashboard by ID'},
      {uriTemplate:'metabase://card/{id}',name:'Card by ID',mimeType:'application/json',description:'Get a Metabase card by ID'},
      {uriTemplate:'metabase://database/{id}',name:'Database by ID',mimeType:'application/json',description:'Get a Metabase database by ID'},
    ]}));

    this.server.setRequestHandler(ReadResourceRequestSchema,async(req)=>{
      const uri=req.params?.uri!;await this.getSessionToken();
      const m=uri.match(/^metabase:\/\/(dashboard|card|database)\/(\d+)$/);
      if(!m)throw new McpError(ErrorCode.InvalidRequest,`Invalid URI: ${uri}`);
      const[_,t,i]=m;const data=await this.request<any>(`/api/${t}/${i}`);
      return{contents:[{uri,mimeType:'application/json',text:JSON.stringify(data,null,2)}]};
    });
  }

  private setupToolHandlers(){
    this.server.setRequestHandler(ListToolsRequestSchema,async()=>({tools:[
      {name:'list_dashboards',description:'List dashboards',inputSchema:{type:'object',properties:{}}},
      {name:'list_cards',description:'List cards',inputSchema:{type:'object',properties:{}}},
      {name:'list_databases',description:'List databases',inputSchema:{type:'object',properties:{}}},
      {name:'execute_card',description:'Execute card',inputSchema:{type:'object',properties:{card_id:{type:'number'}},required:['card_id']}},
      {name:'get_dashboard_cards',description:'Get dashboard cards',inputSchema:{type:'object',properties:{dashboard_id:{type:'number'}},required:['dashboard_id']}},
      {name:'execute_query',description:'Execute SQL query',inputSchema:{type:'object',properties:{database_id:{type:'number'},query:{type:'string'}},required:['database_id','query']}},
    ]}));

    this.server.setRequestHandler(CallToolRequestSchema,async(req)=>{
      await this.getSessionToken();const{name,args}=req.params!;
      switch(name){
        case'list_dashboards':return{content:[{type:'text',text:JSON.stringify(await this.request<any[]>('/api/dashboard'),null,2)}]};
        case'list_cards':return{content:[{type:'text',text:JSON.stringify(await this.request<any[]>('/api/card'),null,2)}]};
        case'list_databases':return{content:[{type:'text',text:JSON.stringify(await this.request<any[]>('/api/database'),null,2)}]};
        case'execute_card':{
          const r=await this.request<any>(`/api/card/${args.card_id}/query`,{method:'POST',body:JSON.stringify({parameters:args.parameters||{}})});
          return{content:[{type:'text',text:JSON.stringify(r,null,2)}]};
        }
        case'get_dashboard_cards':{
          const d=await this.request<any>(`/api/dashboard/${args.dashboard_id}`);
          return{content:[{type:'text',text:JSON.stringify(d.cards||[],null,2)}]};
        }
        case'execute_query':{
          const q=await this.request<any>('/api/dataset',{method:'POST',body:JSON.stringify({type:'native',native:{query:args.query,template_tags:{}},parameters:args.native_parameters||[],database:args.database_id})});
          return{content:[{type:'text',text:JSON.stringify(q,null,2)}]};
        }
        default:return{isError:true,content:[{type:'text',text:`Unknown tool: ${name}`}]}  
      }
    });
  }

  async run(){
    const port=process.env.PORT?parseInt(process.env.PORT,10):3000;
    const transport=new HttpServerTransport({port});
    await this.server.connect(transport);
    this.logInfo(`MCP server listening on port ${port}`);
  }
}

// Global error handlers
process.on('uncaughtException',err=>{console.error('Fatal:',err);process.exit(1);});
process.on('unhandledRejection',reason=>{console.error('Unhandled Rejection:',reason);process.exit(1);});

const srv=new MetabaseServer();
srv.run().catch(err=>{console.error('Startup error:',err);process.exit(1);});
