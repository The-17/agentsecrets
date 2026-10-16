/**
 * Backend mode resolution.
 *
 * - `local`: delegate privileged operations to the installed CLI via
 *   `agentsecrets mcp bridge`. Full capability (keychain, proxy session,
 *   refresh, E2EE), zero credentials in bridge config.
 * - `cloud`: direct HTTPS — control-plane API for management (user JWT),
 *   cloud resolver /v1/resolve for credentialed calls (workload token =
 *   agent identity). The zero-install distribution path.
 *
 * Selection: AGENTSECRETS_MCP_MODE=local|cloud|auto (default auto).
 * AGENTSECRETS_USE_CLOUD=true forces cloud. auto: working binary -> local,
 * otherwise cloud (npx installs without the CLI land on cloud with no
 * configuration — the default distribution experience).
 */

import { findBinary, pingBinary, type PingInfo } from './local/binary.js';
import type { ModeResolution } from './resolver/types.js';

export function resolveMode(): ModeResolution {
  const explicit = (process.env['AGENTSECRETS_MCP_MODE'] ?? 'auto').trim().toLowerCase();
  if (process.env['AGENTSECRETS_USE_CLOUD']?.toLowerCase() === 'true' || explicit === 'cloud') {
    return {
      mode: 'cloud',
      binary: null,
      bridgeVersion: null,
      reason: process.env['AGENTSECRETS_USE_CLOUD']?.toLowerCase() === 'true' ? 'AGENTSECRETS_USE_CLOUD=true' : 'AGENTSECRETS_MCP_MODE=cloud',
    };
  }
  if (explicit === 'local') {
    const bin = findBinary();
    const info: PingInfo | null = bin ? pingBinary(bin) : null;
    if (!info) {
      throw new Error(
        'AGENTSECRETS_MCP_MODE=local but no working `agentsecrets` binary was found. ' +
          'Install the CLI (https://agentsecrets.tech) or switch to cloud mode.'
      );
    }
    return { mode: 'local', binary: info.binary, bridgeVersion: info.version, reason: 'AGENTSECRETS_MCP_MODE=local' };
  }
  if (explicit !== 'auto') {
    throw new Error(`AGENTSECRETS_MCP_MODE must be local|cloud|auto, got ${JSON.stringify(explicit)}.`);
  }
  const bin = findBinary();
  const info = bin ? pingBinary(bin) : null;
  if (info) {
    return { mode: 'local', binary: info.binary, bridgeVersion: info.version, reason: 'local binary detected' };
  }
  return { mode: 'cloud', binary: null, bridgeVersion: null, reason: 'no local binary; cloud default' };
}
