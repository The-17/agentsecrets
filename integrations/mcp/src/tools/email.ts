/**
 * Email verification tools.
 *   email_verify  prove control of the account address with the six-digit code
 *   email_resend  request a fresh code
 *
 * Verification is what unlocks the metered surface: cloud mode, a second
 * project, more than a handful of secrets, and inviting people. Without it an
 * account still works, but the server refuses those actions with a message
 * naming this command.
 */

import { z } from 'zod';
import type { CallCtx } from '../resolver/index.js';
import { callControl } from '../resolver/index.js';
import { fail, type ToolResult } from '../resolver/types.js';
import { dispatch, withContext } from './common.js';
import { needJwt } from '../resolver/guards.js';

export const emailVerifySchema = z.object({
  code: z
    .string()
    .describe('The six-digit code from the verification email'),
  email: z
    .string()
    .optional()
    .describe('Account email. Optional in local mode (taken from the CLI session); required in cloud mode.'),
});
export type EmailVerifyArgs = z.infer<typeof emailVerifySchema>;

export const emailResendSchema = z.object({
  email: z
    .string()
    .optional()
    .describe('Account email. Optional in local mode (taken from the CLI session); required in cloud mode.'),
});
export type EmailResendArgs = z.infer<typeof emailResendSchema>;

export async function emailVerify(call: CallCtx, args: EmailVerifyArgs): Promise<ToolResult> {
  const code = (args.code ?? '').trim();
  if (!code) return fail('A six-digit verification code is required.');
  return dispatch(call, 'email.verify', { code }, async () => {
    needJwt(call.creds);
    const email = (args.email ?? '').trim();
    if (!email) throw new Error('Pass the account email in cloud mode; it is not derivable from the token.');
    await callControl(call).post('auth.verify_email', { email, otp: Number(code) });
    return withContext(call, { verified: true, email });
  });
}

export async function emailResend(call: CallCtx, args: EmailResendArgs): Promise<ToolResult> {
  return dispatch(call, 'email.resend', { ...args }, async () => {
    needJwt(call.creds);
    const email = (args.email ?? '').trim();
    if (!email) throw new Error('Pass the account email in cloud mode; it is not derivable from the token.');
    await callControl(call).post('auth.resend_otp', { email });
    return withContext(call, { sent: true, email });
  });
}

export const emailDescriptions = {
  email_verify:
    'Verify the account email address with the six-digit code that was sent to it. ' +
    'WHEN: the server refuses an action with "verify your email", or the human pastes a code.',
  email_resend:
    'Send a fresh six-digit verification code to the account address. ' +
    'WHEN: the code expired or never arrived.',
};
