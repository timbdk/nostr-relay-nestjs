import { Environment } from './environment';

// Pinned size limits audited in PQE Signing Phase 2 (§4)
export const MAX_WS_PAYLOAD_BYTES = 256 * 1024; // 256 KB (WebSocket gateway frame limit)
export const MAX_NIP11_MESSAGE_BYTES = 128 * 1024; // 128 KB (NIP-11 info document message length limit)
export const MAX_PROXY_BODY_BYTES = 16 * 1024 * 1024; // 16 MB (Nginx client_max_body_size)

export function limitConfig(env: Environment) {
  return {
    createdAtLowerLimit: env.CREATED_AT_LOWER_LIMIT,
    createdAtUpperLimit: env.CREATED_AT_UPPER_LIMIT,
    minPowDifficulty: env.MIN_POW_DIFFICULTY ?? 0,
    maxSubscriptionsPerClient: env.MAX_SUBSCRIPTIONS_PER_CLIENT ?? 20,
    blacklist: env.BLACKLIST,
    whitelist: env.WHITELIST,
    maxPayloadBytes: MAX_WS_PAYLOAD_BYTES,
    maxMessageBytes: MAX_NIP11_MESSAGE_BYTES,
    maxProxyBodyBytes: MAX_PROXY_BODY_BYTES,
  };
}
export type LimitConfig = ReturnType<typeof limitConfig>;

