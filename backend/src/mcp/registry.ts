/**
 * MCP tool registry: the deferral gate. Tools stay deferred until a skill
 * that gates them loads; calling a deferred tool throws. In-memory and
 * process-wide, so a restart re-defers everything until the skill loads
 * again. Re-registering a server keeps its unlock state.
 */
import type { McpToolSchema, McpTransport } from './client.js';

/** A tool schema that is still gated behind its skill. */
export interface DeferredMcpTool extends McpToolSchema {
  serverId: string;
  deferred: true;
  unlocked: false;
}

/** A tool schema a loaded skill has made available to the agent. */
export interface AvailableMcpTool extends McpToolSchema {
  serverId: string;
  deferred: false;
  unlocked: true;
  /** The skill that unlocked this server's tools. */
  unlockedBy: string;
}

export interface McpRegistryServerStatus {
  serverId: string;
  /** 'http' | 'sse' only, stdio servers are rejected before they reach this registry. */
  transport: McpTransport;
  toolCount: number;
  deferredCount: number;
  unlocked: boolean;
  unlockedBy: string | null;
}

interface RegisteredServer {
  tools: McpToolSchema[];
  transport: McpTransport;
  unlockedBy: string | null;
}

function cleanTools(tools: McpToolSchema[]): McpToolSchema[] {
  if (!Array.isArray(tools)) throw new Error('mcp_invalid_tools: tools must be an array');
  return tools.map((tool) => {
    if (!tool || typeof tool.name !== 'string' || !tool.name) {
      throw new Error('mcp_invalid_tool: tool without a name');
    }
    return {
      name: tool.name,
      description: tool.description,
      inputSchema:
        tool.inputSchema && typeof tool.inputSchema === 'object' ? tool.inputSchema : {},
    };
  });
}

export class McpToolRegistry {
  private servers = new Map<string, RegisteredServer>();

  /**
   * Register a server's tools as deferred. `transport` records which
   * wire the server speaks ('http' | 'sse'); it defaults to 'http'
   * and is only used for status reporting.
   */
  registerMcpServer(
    serverId: string,
    tools: McpToolSchema[],
    transport: McpTransport = 'http',
  ): void {
    if (!serverId) throw new Error('mcp_server_id_required');
    const clean = cleanTools(tools);
    const existing = this.servers.get(serverId);
    this.servers.set(serverId, {
      tools: clean,
      transport,
      unlockedBy: existing?.unlockedBy ?? null,
    });
  }

  /** Drop a server and all its tools (e.g. when the server config is deleted). */
  unregisterMcpServer(serverId: string): void {
    this.servers.delete(serverId);
  }

  /** This server's tools, still deferred, what the agent may NOT call yet. */
  deferredTools(serverId: string): DeferredMcpTool[] {
    const server = this.servers.get(serverId);
    if (!server) return [];
    return server.tools.map((tool) => ({
      ...tool,
      serverId,
      deferred: true as const,
      unlocked: false as const,
    }));
  }

  /**
   * Mark a server's tools available, recording the skill that gates
   * them. Throws `mcp_unknown_server` when the server was never
   * registered. Returns the newly available tools.
   */
  unlockTools(serverId: string, skillName: string): McpToolSchema[] {
    const server = this.servers.get(serverId);
    if (!server) throw new Error(`mcp_unknown_server: ${serverId}`);
    if (!skillName || !skillName.trim()) {
      throw new Error(
        'mcp_skill_required: unlockTools needs the name of the skill that gates these tools',
      );
    }
    server.unlockedBy = skillName.trim();
    return server.tools.map((tool) => ({ ...tool }));
  }

  /** Only unlocked tools, the full set the agent may call right now. */
  availableTools(): AvailableMcpTool[] {
    const out: AvailableMcpTool[] = [];
    for (const [serverId, server] of this.servers) {
      if (!server.unlockedBy) continue;
      for (const tool of server.tools) {
        out.push({
          ...tool,
          serverId,
          deferred: false,
          unlocked: true,
          unlockedBy: server.unlockedBy,
        });
      }
    }
    return out;
  }

  isToolAvailable(serverId: string, toolName: string): boolean {
    const server = this.servers.get(serverId);
    if (!server || !server.unlockedBy) return false;
    return server.tools.some((tool) => tool.name === toolName);
  }

  /**
   * The gate. Throws `mcp_unknown_server` (never registered),
   * `mcp_tool_deferred` (registered but its skill has not loaded) or
   * `mcp_unknown_tool` (unlocked server, no such tool).
   */
  assertToolAvailable(serverId: string, toolName: string): void {
    const server = this.servers.get(serverId);
    if (!server) throw new Error(`mcp_unknown_server: ${serverId}`);
    if (!server.unlockedBy) {
      throw new Error(
        `mcp_tool_deferred: tool ${toolName} on server ${serverId} is deferred — ` +
          'load the skill that gates this server before calling it',
      );
    }
    if (!server.tools.some((tool) => tool.name === toolName)) {
      throw new Error(`mcp_unknown_tool: server ${serverId} has no tool ${toolName}`);
    }
  }

  /** Per-server status: transport, counts, and whether a skill unlocked it. */
  listServers(): McpRegistryServerStatus[] {
    return [...this.servers.entries()].map(([serverId, server]) => ({
      serverId,
      transport: server.transport,
      toolCount: server.tools.length,
      deferredCount: server.unlockedBy ? 0 : server.tools.length,
      unlocked: server.unlockedBy !== null,
      unlockedBy: server.unlockedBy,
    }));
  }
}

/**
 * Shared process-wide registry. The skills worker and the routes use
 * this one instance, so an unlock in one place is visible in the other.
 */
export const mcpRegistry = new McpToolRegistry();
