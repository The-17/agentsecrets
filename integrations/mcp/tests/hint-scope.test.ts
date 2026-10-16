import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { hintScope } from '../src/tools/proxy.js';
import type { CallCtx } from '../src/resolver/index.js';

type Echo = Parameters<typeof hintScope>[2];
type Args = Parameters<typeof hintScope>[1];

function call(
  project: { workspaceId?: string; projectId?: string } | null,
  env = 'development'
): CallCtx {
  return { ctx: { project, env: { name: env } } } as unknown as CallCtx;
}

function echo(over: Partial<Echo> = {}): Echo {
  return {
    source: 'pinned-identity',
    workspace_id: null,
    project_id: null,
    environment: null,
    matches_request: true,
    ...over,
  };
}

const args = { environment: 'development' } as Args;

describe('workload-posture scope hint (workspace-wide resolution)', () => {
  it('narrows a workspace-wide identity to the project the call targets', () => {
    const s = hintScope(
      call({ workspaceId: 'ws1', projectId: 'proj_b' }),
      args,
      echo({ workspace_id: 'ws1', project_id: null })
    );
    assert.deepEqual(s, { environment: 'development', workspace_id: 'ws1', project_id: 'proj_b' });
  });

  it('the pinned echo wins over local context, so the hint cannot disagree with the enforced identity', () => {
    const s = hintScope(
      call({ workspaceId: 'ws1', projectId: 'ctx_proj' }),
      args,
      echo({ workspace_id: 'ws1', project_id: 'pin_proj' })
    );
    assert.equal(s.project_id, 'pin_proj');
  });

  it('sends only what is known when nothing is bound', () => {
    const s = hintScope(call(null), args, echo());
    assert.deepEqual(s, { environment: 'development' });
  });

  it('environment falls back to the active context when the call omits it', () => {
    const s = hintScope(call({ workspaceId: 'ws1' }, 'staging'), {} as Args, echo({ workspace_id: 'ws1' }));
    assert.equal(s.environment, 'staging');
  });
});
