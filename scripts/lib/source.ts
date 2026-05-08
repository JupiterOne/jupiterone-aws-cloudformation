/**
 * Parses an `ingestion-sources-configs/{definitionId}.json` payload (the same
 * shape published to the `jupiterone-prod-us-jupiter-integrations` S3 bucket
 * and exposed via `/integrations-public/v1/ingestion-sources/definitions/:id`)
 * and extracts the IAM permissions JupiterOne needs to ingest AWS resources.
 *
 * Per-step authorization is declared in graph-aws as:
 *   authorization: {
 *     permissions: ['ec2:DescribeVpcs', 'apigateway:GET arn:aws:apigateway:*::/restapis'],
 *     roles:       ['ec2:Describe*'],
 *   }
 * The build pipeline flattens that into each `childIngestionSourcesMetadata`
 * entry, exposing `permissions[]` (exact actions, possibly with a resource ARN
 * suffix) and `roles[]` (wildcard form). We tolerate either shape.
 */
export interface RawIngestionSource {
  permissions?: string[];
  roles?: string[];
  childIngestionSourcesMetadata?: RawIngestionSource[];
  authorization?: {
    permissions?: string[];
    roles?: string[];
  };
}

export interface RawIngestionSourcesPayload {
  ingestionSourcesConfig?: RawIngestionSource[];
  /**
   * Aggregated authorization for the whole integration. The upstream pipeline
   * publishes this alongside the per-step blocks; reading it ensures we
   * capture permissions/roles even when individual steps don't declare them.
   */
  authorization?: {
    permissions?: string[];
    roles?: string[];
  };
}

export interface ResourcePermission {
  action: string;
  resources: string[];
}

export interface ExtractedPermissions {
  /** Exact IAM actions, e.g. `ec2:DescribeVpcs`. Sorted, deduplicated. */
  exactActions: string[];
  /** Wildcard IAM actions, e.g. `ec2:Describe*`. Sorted, deduplicated. */
  wildcardActions: string[];
  /**
   * Resource-scoped permissions sourced from the per-step `permissions[]`
   * array. These enumerate every specific ARN the integration touches and
   * feed the *detailed* template.
   */
  resourcePermissions: ResourcePermission[];
  /**
   * Resource-scoped permissions sourced from the per-step `roles[]` array.
   * These are the broad ARN form (e.g. `arn:aws:apigateway:*::/*`) intended
   * for the *wildcard* templates (`iam-cloudformation`, GovCloud).
   */
  wildcardResourcePermissions: ResourcePermission[];
}

function collectSources(payload: RawIngestionSourcesPayload): RawIngestionSource[] {
  const out: RawIngestionSource[] = [];
  // Root-level aggregated authorization (set by the upstream build pipeline).
  if (payload.authorization) {
    out.push({ authorization: payload.authorization });
  }
  const visit = (source: RawIngestionSource | undefined) => {
    if (!source) return;
    out.push(source);
    for (const child of source.childIngestionSourcesMetadata ?? []) {
      visit(child);
    }
  };
  for (const root of payload.ingestionSourcesConfig ?? []) {
    visit(root);
  }
  return out;
}

function getPermissions(source: RawIngestionSource): string[] {
  return source.authorization?.permissions ?? source.permissions ?? [];
}

function getRoles(source: RawIngestionSource): string[] {
  return source.authorization?.roles ?? source.roles ?? [];
}

/**
 * `apigateway:GET arn:aws:apigateway:*::/apis` -> action + resource.
 * Plain `ec2:DescribeVpcs` -> action only.
 */
function splitActionResource(
  raw: string,
): { action: string; resource: string | null } {
  const trimmed = raw.trim();
  const space = trimmed.indexOf(' ');
  if (space === -1) {
    return { action: trimmed, resource: null };
  }
  return {
    action: trimmed.slice(0, space).trim(),
    resource: trimmed.slice(space + 1).trim(),
  };
}

function isWildcard(action: string): boolean {
  return action.includes('*');
}

function sortedUnique(values: Iterable<string>): string[] {
  return Array.from(new Set(values)).sort((a, b) => a.localeCompare(b));
}

function collapseResourceMap(
  map: Map<string, Set<string>>,
): ResourcePermission[] {
  return Array.from(map)
    .map(([action, resources]) => ({
      action,
      resources: sortedUnique(resources),
    }))
    .sort((a, b) => a.action.localeCompare(b.action));
}

export function extractPermissions(
  payload: RawIngestionSourcesPayload,
): ExtractedPermissions {
  const exactActions = new Set<string>();
  const wildcardActions = new Set<string>();
  const resourceMap = new Map<string, Set<string>>();
  const wildcardResourceMap = new Map<string, Set<string>>();

  for (const source of collectSources(payload)) {
    for (const raw of getPermissions(source)) {
      if (!raw) continue;
      const { action, resource } = splitActionResource(raw);
      if (!action) continue;
      if (resource) {
        if (!resourceMap.has(action)) resourceMap.set(action, new Set());
        resourceMap.get(action)!.add(resource);
      } else if (isWildcard(action)) {
        wildcardActions.add(action);
      } else {
        exactActions.add(action);
      }
    }
    for (const raw of getRoles(source)) {
      if (!raw) continue;
      const { action, resource } = splitActionResource(raw);
      if (!action) continue;
      if (resource) {
        // `roles[]` resource form is the broad-ARN catch-all used by the
        // wildcard templates (e.g. `apigateway:GET arn:aws:apigateway:*::/*`).
        if (!wildcardResourceMap.has(action)) {
          wildcardResourceMap.set(action, new Set());
        }
        wildcardResourceMap.get(action)!.add(resource);
      } else if (isWildcard(action)) {
        wildcardActions.add(action);
      } else {
        // `roles` is supposed to be the wildcard form, but accept exact actions
        // too in case a step only declares non-wildcardable actions.
        exactActions.add(action);
      }
    }
  }

  return {
    exactActions: sortedUnique(exactActions),
    wildcardActions: sortedUnique(wildcardActions),
    resourcePermissions: collapseResourceMap(resourceMap),
    wildcardResourcePermissions: collapseResourceMap(wildcardResourceMap),
  };
}
