/**
 * OpenClaw OVID Plugin — Agent identity tools
 */

import { exportJWK, importJWK } from 'jose';
import {
  generateKeypair,
  exportPublicKeyBase64,
  createOvid,
  verifyOvid,
  type KeyPair,
  type OvidResult,
} from '@clawdreyhepburn/ovid';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';

export const id = 'openclaw-ovid';
export const name = 'OVID';

interface PluginConfig {
  keyDir?: string;
  defaultTtl?: number;
  maxTtl?: number;
  maxChainDepth?: number;
  /** Auto-mint OVID tokens for spawned sub-agents (default: true) */
  autoMint?: boolean;
  /** Default Cedar mandate for auto-minted tokens */
  defaultMandate?: string;
}

interface OpenClawPluginApi {
  pluginConfig: any;
  logger: {
    info(msg: string, ...args: any[]): void;
    warn(msg: string, ...args: any[]): void;
    error(msg: string, ...args: any[]): void;
  };
  registerService(service: { id: string; start(): Promise<void> | void; stop(): Promise<void> | void }): void;
  registerTool(
    tool: {
      name: string;
      label?: string;
      description: string;
      parameters: Record<string, any>;
      execute(toolCallId: string, params: any): Promise<any>;
    },
    opts?: { optional?: boolean },
  ): void;
  registerCli?(fn: (ctx: { program: any }) => void, opts?: { commands: string[] }): void;
  on?(hookName: string, handler: (...args: any[]) => any, opts?: { name?: string; description?: string }): void;
}

function resolveKeyDir(keyDir: string): string {
  return keyDir.replace(/^~/, os.homedir());
}

function fingerprint(publicKeyBase64: string): string {
  const hash = crypto.createHash('sha256').update(publicKeyBase64).digest('hex');
  return hash.slice(0, 16);
}

let keypair: KeyPair | null = null;
let publicKeyBase64: string = '';
let mintCount = 0;

async function loadOrGenerateKeypair(keyDir: string, logger: OpenClawPluginApi['logger']): Promise<void> {
  const dir = resolveKeyDir(keyDir);
  const privPath = path.join(dir, 'orchestrator.jwk');
  const pubPath = path.join(dir, 'orchestrator.pub');

  if (fs.existsSync(privPath) && fs.existsSync(pubPath)) {
    // Load existing keypair from JWK
    const jwk = JSON.parse(fs.readFileSync(privPath, 'utf-8'));
    const privateKey = await importJWK(jwk, 'EdDSA') as any;
    const { d: _, ...pubJwk } = jwk;
    const publicKey = await importJWK(pubJwk, 'EdDSA') as any;
    keypair = { privateKey, publicKey };
    publicKeyBase64 = fs.readFileSync(pubPath, 'utf-8').trim();
    logger.info(`OVID identity ready (key: ${fingerprint(publicKeyBase64)})`);
  } else {
    await generateAndSave(dir, logger);
  }
}

async function generateAndSave(dir: string, logger: OpenClawPluginApi['logger']): Promise<void> {
  fs.mkdirSync(dir, { recursive: true });
  keypair = await generateKeypair();
  publicKeyBase64 = await exportPublicKeyBase64(keypair.publicKey);

  // Export private key as JWK for persistence
  const jwk = await exportJWK(keypair.privateKey);
  fs.writeFileSync(path.join(dir, 'orchestrator.jwk'), JSON.stringify(jwk, null, 2), { mode: 0o600 });
  fs.writeFileSync(path.join(dir, 'orchestrator.pub'), publicKeyBase64 + '\n', { mode: 0o644 });

  logger.info(`OVID identity ready (key: ${fingerprint(publicKeyBase64)}) [newly generated]`);
}

export default function register(api: OpenClawPluginApi) {
  const config: PluginConfig = api.pluginConfig ?? {};
  const keyDir = config.keyDir ?? '~/.ovid/keys/';
  const defaultTtl = config.defaultTtl ?? 1800;
  const maxTtl = config.maxTtl ?? 86400;
  const maxChainDepth = config.maxChainDepth ?? 5;
  const logger = api.logger;

  const autoMint = config.autoMint !== false; // default: true
  const defaultMandate = config.defaultMandate ?? `permit(
  principal,
  action in [Ovid::Action::"read", Ovid::Action::"search", Ovid::Action::"summarize"],
  resource
);`;

  api.registerService({
    id: 'ovid',
    async start() {
      await loadOrGenerateKeypair(keyDir, logger);
      if (autoMint) {
        logger.info('OVID auto-mint enabled — sub-agents will receive identity tokens on spawn');
      }
      logger.warn('OVID identity active but no mandate evaluation found. Install @clawdreyhepburn/openclaw-ovid-me for enforcement.');
    },
    stop() {},
  });

  // --- Auto-mint OVID tokens for spawned sub-agents ---
  if (autoMint && api.on) {
    api.on("before_tool_call", async (event: any) => {
      const toolName: string = event.toolName ?? event.tool ?? event.name ?? "";
      if (toolName !== "sessions_spawn") return {};

      if (!keypair) {
        logger.warn("[OVID] Cannot auto-mint: keypair not loaded");
        return {};
      }

      const params = event.params ?? {};
      const task: string = (params.task as string) ?? "";
      const label: string = (params.label as string) ?? "";
      const agentId = label || `subagent-${crypto.randomUUID().slice(0, 8)}`;

      try {
        const ttl = Math.min(defaultTtl, maxTtl);
        const result = await createOvid({
          issuerKeys: keypair,
          agentId,
          mandate: { rarFormat: 'cedar', policySet: defaultMandate } as any,
          ttlSeconds: ttl,
        });

        mintCount++;

        const ovidBlock = [
          `[OVID_IDENTITY]`,
          `You have been issued a cryptographic identity token (OVID).`,
          `Your agent ID: ${agentId}`,
          `Your mandate (Cedar policy) defines what you are authorized to do.`,
          `Token (JWT): ${result.jwt}`,
          `Issuer public key: ${publicKeyBase64}`,
          `Expires in: ${ttl}s`,
          `[/OVID_IDENTITY]`,
        ].join('\n');

        const newTask = `${ovidBlock}\n\n${task}`;
        logger.info(`[OVID] Auto-minted token for sub-agent "${agentId}" (ttl=${ttl}s)`);

        return { params: { ...params, task: newTask } };
      } catch (err: any) {
        logger.error(`[OVID] Auto-mint failed: ${err.message}`);
        return {}; // Don't block the spawn
      }
    }, {
      name: "ovid.auto-mint-spawn",
      description: "Auto-mint OVID identity tokens for spawned sub-agents",
    });
    logger.info("Registered before_tool_call hook for OVID auto-mint on sessions_spawn");
  }

  // --- Tool: ovid_mint ---
  api.registerTool(
    {
      name: 'ovid_mint',
      label: 'OVID Mint',
      description: 'Mint an OVID token for a sub-agent. Returns the signed JWT, public key, and claims summary.',
      parameters: {
        type: 'object',
        required: ['mandate'],
        properties: {
          mandate: { type: 'string', description: 'Cedar policy text for the mandate' },
          agentId: { type: 'string', description: 'Agent identifier (optional, generated if omitted)' },
          ttlSeconds: { type: 'number', description: `Token TTL in seconds (default: ${defaultTtl}, max: ${maxTtl})` },
        },
      },
      async execute(_toolCallId: string, params: { mandate: string; agentId?: string; ttlSeconds?: number }) {
        if (!keypair) {
          return { content: [{ type: 'text', text: 'ERROR: OVID keypair not loaded.' }], isError: true };
        }

        const ttl = Math.min(params.ttlSeconds ?? defaultTtl, maxTtl);
        const agentId = params.agentId ?? `agent-${crypto.randomUUID().slice(0, 8)}`;

        try {
          const result = await createOvid({
            issuerKeys: keypair,
            agentId,
            mandate: { rarFormat: 'cedar', policySet: params.mandate } as any,
            ttlSeconds: ttl,
          });

          mintCount++;

          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                jwt: result.jwt,
                agentId: result.claims.sub,
                publicKey: publicKeyBase64,
                expiresIn: `${ttl}s`,
                mandate: params.mandate.slice(0, 200) + (params.mandate.length > 200 ? '...' : ''),
              }, null, 2),
            }],
          };
        } catch (err: any) {
          return { content: [{ type: 'text', text: `Mint failed: ${err.message}` }], isError: true };
        }
      },
    },
    { optional: true },
  );

  // --- Tool: ovid_verify ---
  api.registerTool(
    {
      name: 'ovid_verify',
      label: 'OVID Verify',
      description: 'Verify an OVID token. Returns validity, principal, mandate, chain, and expiry.',
      parameters: {
        type: 'object',
        required: ['jwt'],
        properties: {
          jwt: { type: 'string', description: 'The OVID JWT to verify' },
        },
      },
      async execute(_toolCallId: string, params: { jwt: string }) {
        if (!keypair) {
          return { content: [{ type: 'text', text: 'ERROR: OVID keypair not loaded.' }], isError: true };
        }

        try {
          const result: OvidResult = await verifyOvid(params.jwt, keypair.publicKey, { trustedRoots: [keypair.publicKey], maxChainDepth });

          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                valid: result.valid,
                principal: result.principal,
                mandate: result.mandate?.policySet?.slice(0, 300),
                chain: result.chain,
                expiresIn: `${result.expiresIn}s`,
              }, null, 2),
            }],
          };
        } catch (err: any) {
          return { content: [{ type: 'text', text: `Verify failed: ${err.message}` }], isError: true };
        }
      },
    },
    { optional: true },
  );

  // --- Tool: ovid_inspect ---
  api.registerTool(
    {
      name: 'ovid_inspect',
      label: 'OVID Inspect',
      description: 'Decode and pretty-print an OVID token without verification.',
      parameters: {
        type: 'object',
        required: ['jwt'],
        properties: {
          jwt: { type: 'string', description: 'The OVID JWT to inspect' },
        },
      },
      async execute(_toolCallId: string, params: { jwt: string }) {
        try {
          const parts = params.jwt.split('.');
          if (parts.length !== 3) {
            return { content: [{ type: 'text', text: 'Invalid JWT format (expected 3 parts)' }], isError: true };
          }

          const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
          const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());

          const now = Math.floor(Date.now() / 1000);
          const expired = payload.exp ? payload.exp < now : false;
          const expiresIn = payload.exp ? payload.exp - now : null;

          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                header,
                payload,
                mandate: payload.mandate?.policySet ?? '(none)',
                expiry: {
                  expired,
                  expiresIn: expiresIn !== null ? `${expiresIn}s` : 'no expiry',
                  expiresAt: payload.exp ? new Date(payload.exp * 1000).toISOString() : null,
                },
              }, null, 2),
            }],
          };
        } catch (err: any) {
          return { content: [{ type: 'text', text: `Inspect failed: ${err.message}` }], isError: true };
        }
      },
    },
    { optional: true },
  );

  // --- CLI ---
  api.registerCli?.(
    ({ program }) => {
      const cmd = program.command('ovid').description('OVID agent identity');

      cmd.command('status').action(async () => {
        const dir = resolveKeyDir(keyDir);
        const pubPath = path.join(dir, 'orchestrator.pub');
        const hasKey = fs.existsSync(pubPath);

        console.log('\n🔑 OVID Identity Status\n');
        if (hasKey) {
          const pubB64 = fs.readFileSync(pubPath, 'utf-8').trim();
          console.log(`  Key:     ${fingerprint(pubB64)}`);
          console.log(`  Dir:     ${dir}`);
        } else {
          console.log('  No keypair found.');
          console.log(`  Dir:     ${dir}`);
          console.log('  Run "openclaw ovid keygen" to generate.');
        }
        console.log(`  Minted:  ${mintCount} tokens this session`);
        console.log(`  TTL:     ${defaultTtl}s default, ${maxTtl}s max`);
        console.log(`  Depth:   ${maxChainDepth} max chain depth`);
        console.log();
      });

      cmd.command('keygen').action(async () => {
        const dir = resolveKeyDir(keyDir);
        console.log(`\nGenerating Ed25519 keypair in ${dir}...`);
        await generateAndSave(dir, logger);
        console.log(`Done. Fingerprint: ${fingerprint(publicKeyBase64)}\n`);
      });
    },
    { commands: ['ovid'] },
  );
}
