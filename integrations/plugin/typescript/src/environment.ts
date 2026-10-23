/**
 * Environment names accepted by the resolver.
 *
 * The rule is the control plane's rule, kept identical on purpose: a name the
 * server would reject must fail here, before a request is built. Custom names
 * are as valid as the standard three. Whether a custom name may *resolve* is
 * the resolver's decision, never this plugin's.
 */

import { InvalidRequest } from "./errors.js";

export const STANDARD_ENVIRONMENTS = ["development", "staging", "production"] as const;
export type StandardEnvironment = (typeof STANDARD_ENVIRONMENTS)[number];

export const RESERVED_ENVIRONMENTS = ["root", "admin", "api", "internal", "default"] as const;

export const MAX_ENVIRONMENT_LENGTH = 32;

export const NAME_PATTERN = "^[a-z][a-z0-9-]{1,31}$";

export const NAME_RULE =
  "lowercase letters, numbers and hyphens, starting with a letter, 2 to 32 characters";

const NAME = new RegExp(NAME_PATTERN);

/** Normalize and validate an environment name, or throw InvalidRequest. */
export function parseEnvironment(value: unknown): string {
  if (typeof value !== "string") {
    throw new InvalidRequest("environment must be a string");
  }
  const name = value.trim().toLowerCase();
  if (!name) {
    throw new InvalidRequest(`environment name is required: use ${NAME_RULE}`);
  }
  if (name.length > MAX_ENVIRONMENT_LENGTH) {
    throw new InvalidRequest(
      `environment name must be at most ${MAX_ENVIRONMENT_LENGTH} characters`,
    );
  }
  if ((RESERVED_ENVIRONMENTS as readonly string[]).includes(name)) {
    throw new InvalidRequest(`"${name}" is a reserved environment name; choose another name`);
  }
  if (!NAME.test(name)) {
    throw new InvalidRequest(`invalid environment name "${value}": use ${NAME_RULE}`);
  }
  return name;
}
