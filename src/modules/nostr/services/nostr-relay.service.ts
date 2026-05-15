import { Injectable, OnApplicationShutdown, Optional } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  Event,
  Filter,
  createOutgoingNoticeMessage,
  EventUtils,
} from '@nostr-relay/common';
import { randomUUID } from 'crypto';
import {
  type ValidationContext,
} from 'verity-event-validation-module';
import { NostrRelay } from '@nostr-relay/core';
import { CreatedAtLimitGuard } from '@nostr-relay/created-at-limit-guard';
import { OrGuard } from '@nostr-relay/or-guard';
import { PowGuard } from '@nostr-relay/pow-guard';
import { Throttler } from '@nostr-relay/throttler';
import { VerityValidator } from './verity-validator';
import { verifyVerityEventSync } from './verity-crypto-validator';
import { InjectPinoLogger, PinoLogger } from 'nestjs-pino';
import { Config } from 'src/config';
import { MessageHandlingConfig } from 'src/config/message-handling.config';
import { WebSocket } from 'ws';
import { ValidationError } from 'zod-validation-error';
import { WotService } from '../../../modules/wot/wot.service';
import { MetricService } from '../../metric/metric.service';
import { EventRepository } from '../../repositories/event.repository';
import { NostrRelayLogger } from '../../share/nostr-relay-logger.service';
import { TestingCheckpointService } from '../../testing/testing-checkpoint.service';
import { BlacklistGuardPlugin, WhitelistGuardPlugin } from '../plugins';

@Injectable()
export class NostrRelayService implements OnApplicationShutdown {
  private readonly relay: NostrRelay;
  private readonly messageHandlingConfig: MessageHandlingConfig;
  private readonly validator: VerityValidator;
  private readonly throttler: Throttler;
  private readonly trustedSignerPubkey: string[] | undefined;

  constructor(
    @InjectPinoLogger(NostrRelayService.name)
    private readonly logger: PinoLogger,
    private readonly metricService: MetricService,
    nostrRelayLogger: NostrRelayLogger,
    private readonly eventRepository: EventRepository,
    private readonly configService: ConfigService<Config, true>,
    wotService: WotService,
    @Optional() private readonly checkpointService?: TestingCheckpointService,
  ) {
    const hostname = configService.get('hostname');
    const relayUrl = configService.get('relayUrl');
    const trustedSignerPubkey = configService.get('trustedSignerPubkey');
    this.trustedSignerPubkey = trustedSignerPubkey;
    const serializationPrefix = configService.get('serializationPrefix');
    const {
      createdAtLowerLimit,
      createdAtUpperLimit,
      minPowDifficulty,
      maxSubscriptionsPerClient,
      blacklist,
      whitelist,
    } = configService.get('limit', { infer: true });
    const cacheConfig = configService.get('cache', { infer: true });
    const throttlerConfig = configService.get('throttler.ws', { infer: true });
    this.messageHandlingConfig = configService.get('messageHandling', {
      infer: true,
    });
    let relayHostname = hostname;
    if (relayUrl) {
      try {
        const url = new URL(relayUrl);
        relayHostname = url.hostname; // Must be hostname only (no port) for EventUtils validation
        this.logger.info(`[DEBUG] Configured NostrRelay with RELAY_URL=${relayUrl} -> hostname=${relayHostname}`);
      } catch (error) {
        this.logger.warn(`Invalid RELAY_URL: ${relayUrl}`);
      }
    }

    this.relay = new NostrRelay(eventRepository, {
      hostname: relayHostname,
      logger: nostrRelayLogger,
      maxSubscriptionsPerClient,
      ...cacheConfig,
      // WORKAROUND: @nostr-relay/core has a race condition in LazyCache that randomly returns undefined
      // and crashes handleEventMessage. We disable the event handling cache to bypass it.
      eventHandlingResultCacheTtl: 0,
    });
    this.validator = new VerityValidator(serializationPrefix);

/**
 * SAFE PLUGIN WRAPPING
 *
 * STRUCTURAL DESIGN NOTE:
 * This wrapper is a defensive measure against a structural flaw in the @nostr-relay ecosystem
 * where return type conventions (success vs canHandle) are inconsistent and guards frequently
 * return undefined on success, causing crashes in @nostr-relay/core.
 *
 * TODO: This entire approach of monkey-patching EventUtils and wrapping third-party plugins
 * should be refactored into a clean adapter pattern or by contributing robustness fixes upstream.
 */
const wrapInSafety = (plugin: any): any => {
  if (!plugin || typeof plugin.beforeHandleEvent !== 'function') {
    return plugin;
  }
  const target = plugin;
  const originalBefore = target.beforeHandleEvent.bind(target);
  target.beforeHandleEvent = async (event: any, client?: any): Promise<any> => {
    const result = await originalBefore(event, client);
    // Ensure we always return an object with both potential success keys to satisfy
    // different versions/packages of the core library and the OrGuard plugin.
    if (result === undefined || result === null) {
      return { canHandle: true, success: true };
    }
    // If result is already an object, ensure it has both keys if they match success state
    if (typeof result === 'object') {
      if (result.success && !('canHandle' in result)) result.canHandle = true;
      if (result.canHandle && !('success' in result)) result.success = true;
    }
    return result;
  };
  return plugin;
};

    this.throttler = new Throttler(throttlerConfig);
    this.relay.register(wrapInSafety(this.throttler));

    const createdAtLimitGuardPlugin = new CreatedAtLimitGuard({
      lowerLimit: createdAtLowerLimit,
      upperLimit: createdAtUpperLimit,
    });
    const wotGuard = wotService.getWotGuardPlugin();
    const orGuardPlugin = new OrGuard();
    let hasOrGuards = false;

    if (wotGuard && wotGuard.getEnabled()) {
      orGuardPlugin.addGuard(wrapInSafety(wotGuard));
      hasOrGuards = true;
    }

    if (minPowDifficulty > 0) {
      const powGuardPlugin = new PowGuard(minPowDifficulty);
      orGuardPlugin.addGuard(wrapInSafety(powGuardPlugin));
      hasOrGuards = true;
    }

    if (blacklist?.length) {
      const blacklistGuardPlugin = new BlacklistGuardPlugin(blacklist);
      this.relay.register(wrapInSafety(blacklistGuardPlugin));
    }

    if (whitelist?.length) {
      const whitelistGuardPlugin = new WhitelistGuardPlugin(whitelist);
      orGuardPlugin.addGuard(wrapInSafety(whitelistGuardPlugin));
      hasOrGuards = true;
    }

    if (hasOrGuards) {
      this.relay.register(wrapInSafety(orGuardPlugin));
    }

    // Monkey-patch EventUtils.validate to use our extracted crypto function.
    // This is required because NostrRelay's EventService uses EventUtils.validate internally
    // and we cannot inject a custom validator into it.
    //
    // WARNING: This is a global side effect and highly brittle.
    // The actual logic lives in verity-crypto-validator.ts for testability.
    (EventUtils as any).validate = (event: Event) => {
      return verifyVerityEventSync(event, serializationPrefix);
    };

    this.relay.register(wrapInSafety(createdAtLimitGuardPlugin));
  }

  onApplicationShutdown() {
    this.throttler.destroy();
  }

  private readonly authenticatedSigners = new WeakMap<WebSocket, string>();
  private readonly authChallenges = new WeakMap<WebSocket, string>();

  /**
   * Check if a pubkey is a trusted signer (signing-service, auth-hooks, or test registrar).
   * Returns false for undefined/null pubkeys.
   */
  private isTrustedSigner(pubkey: string | undefined): boolean {
    if (!pubkey) return false;
    const trustedSigners = this.trustedSignerPubkey;
    if (!trustedSigners) return false;
    return trustedSigners.includes(pubkey);
  }

  handleConnection(client: WebSocket, ip = 'unknown') {
    // Intercept the core's AUTH challenge to capture it for our verification layer.
    // The @nostr-relay/core sends ["AUTH", ctx.id] (a UUID) when hostname is configured.
    // We must NOT send a second challenge — the NDK client uses the first one it receives.
    const originalSend = client.send.bind(client);
    client.send = (data: string | Buffer, ...args: any[]) => {
      try {
        const parsed = JSON.parse(typeof data === 'string' ? data : data.toString());
        if (Array.isArray(parsed) && parsed[0] === 'AUTH' && typeof parsed[1] === 'string') {
          this.authChallenges.set(client, parsed[1]);
          this.checkpointService?.broadcast('relay.auth.challenge_sent', {
            challenge: parsed[1].substring(0, 16),
          });
        }
      } catch { /* not JSON, ignore */ }
      return originalSend(data, ...args);
    };

    this.relay.handleConnection(client, ip);
    this.metricService.incrementConnectionCount();
  }

  handleDisconnect(client: WebSocket) {
    this.relay.handleDisconnect(client);
    this.metricService.decrementConnectionCount();
  }

  async handleMessage(client: WebSocket, data: Array<any>): Promise<void> {
    let msg: any;
    try {
      const start = Date.now();
      msg = await this.validator.validateIncomingMessage(data);
      if (!this.messageHandlingConfig[msg[0].toLowerCase()]) {
        return;
      }

      // Checkpoint Broadcasting & Debug Logging (testing/development only)
      if (
        process.env.NODE_ENV === 'testing' ||
        process.env.NODE_ENV === 'development'
      ) {
        const msgType = msg[0];
        if (msgType === 'EVENT' && msg[1]) {
          const event = msg[1];
          const kind = event.kind;
          const tags = Array.isArray(event.tags) ? event.tags : [];
          const pTags = tags
            .filter((t: string[]) => t[0] === 'p')
            .map((t: string[]) => t[1]);

          // Broadcast checkpoint for ALL event kinds so the test runner can
          // trace any publish (e.g., kind 30598 config events from the browser).
          this.checkpointService?.broadcast('relay.event.received', {
            kind,
            pubkey: event.pubkey?.substring(0, 16),
            id: event.id?.substring(0, 16),
            pTags: pTags.map((p: string) => p?.substring(0, 16)),
          });

          // NIP-46 detailed logging (kinds 24133/24134)
          if (kind === 24133 || kind === 24134) {
            this.logger.info(
              `[NIP46-EVENT] Received kind=${kind} id=${event.id?.substring(
                0,
                8,
              )} from=${event.pubkey?.substring(0, 8)} to=[${pTags
                .map((p: string) => p?.substring(0, 8))
                .join(',')}]`,
            );
          }
        } else if (msgType === 'REQ' && msg.length > 2) {
          // Log subscriptions that might be for NIP-46
          const subscriptionId = msg[1];
          const filters = msg.slice(2);
          const hasNip46Kinds = filters.some(
            (f: any) =>
              f.kinds && (f.kinds.includes(24133) || f.kinds.includes(24134)),
          );
          if (hasNip46Kinds) {
            const pFilters = filters.map((f: any) => f['#p'] || []);
            this.logger.info(
              `[NIP46-SUB] REQ id=${subscriptionId} #p=${JSON.stringify(
                pFilters.flat().map((p: string) => p?.substring(0, 8)),
              )}`,
            );
          }
        }
      }

      // Enforce Trusted Signer if configured
      // NIP-42 AUTH handling
      if (msg[0] === 'AUTH') {
        const authEvent = msg[1];

        this.checkpointService?.broadcast('relay.auth.received', {
          pubkey: authEvent.pubkey?.substring(0, 16),
          isTrusted: this.isTrustedSigner(authEvent.pubkey),
        });
        
        // 1. Verify challenge
        const expectedChallenge = this.authChallenges.get(client);
        const challengeInEvent = authEvent.tags?.find((t: string[]) => t[0] === 'challenge')?.[1];
        
        if (!expectedChallenge || challengeInEvent !== expectedChallenge) {
          this.logger.warn(`[AUTH] Challenge mismatch for ${authEvent.pubkey}`);
          this.checkpointService?.broadcast('relay.auth.rejected', {
            pubkey: authEvent.pubkey?.substring(0, 16),
            reason: 'challenge_mismatch',
          });
          client.send(JSON.stringify(['OK', authEvent.id, false, 'auth: challenge mismatch']));
          return;
        }

        // 2. Complete cryptographic validation
        const validationError = EventUtils.validate(authEvent);
        if (validationError) {
          this.logger.warn(`[AUTH] Event validation failed for ${authEvent.pubkey}: ${validationError}`);
          this.checkpointService?.broadcast('relay.auth.rejected', {
            pubkey: authEvent.pubkey?.substring(0, 16),
            reason: 'validation_failed',
            detail: validationError,
          });
          client.send(JSON.stringify(['OK', authEvent.id, false, validationError]));
          return;
        }

        // 3. Success (ANY PUBKEY ALLOWED to authenticate their connection)
        this.authenticatedSigners.set(client, authEvent.pubkey);

        this.checkpointService?.broadcast('relay.auth.success', {
          pubkey: authEvent.pubkey?.substring(0, 16),
          isTrusted: this.isTrustedSigner(authEvent.pubkey),
        });

        if (this.isTrustedSigner(authEvent.pubkey)) {
          this.logger.info(`[AUTH] Successfully authenticated as trusted signer: ${authEvent.pubkey.substring(0, 16)}`);
        } else {
          this.logger.info(`[AUTH] Successfully authenticated as client: ${authEvent.pubkey.substring(0, 16)}`);
        }
        client.send(JSON.stringify(['OK', authEvent.id, true, 'auth: success']));
        // Do not pass AUTH to core — its handleAuthMessage uses EventUtils.isSignedEventValid
        // which validates with standard serialization prefix (0), not our custom prefix.
        // Without this return, clients receive contradictory OK responses (true then false),
        // causing NDK signer confusion and downstream TypeErrors under load.
        return;
      }

      // EVENT Write Authorization Pipeline
      // Security ordering: NIP-42 → crypto → connection policies → registry.check → core
      //
      // No identity lock (event.pubkey === authenticated_pubkey) is enforced because:
      //   - NIP-46 remote signing means the web-client authenticates as client.keypair but publishes
      //     events signed by the user's key (session.pubkey). These are different keys by design.
      //   - Cryptographic validation ensures nobody can forge events for keys they don't control.
      if (msg[0] === 'EVENT' && msg[1]) {
        const event = msg[1];

        const authenticatedPubkey = this.authenticatedSigners.get(client);
        const isTrustedConnection = this.isTrustedSigner(authenticatedPubkey);

        const buildRejectionMessage = (reason: string) => {
          return JSON.stringify(['OK', event.id, false, reason]);
        };

        // Step 1: NIP-42 gate (cheapest check — no DB, no crypto)
        if (!authenticatedPubkey) {
          this.logger.warn(
            `[EVENT] Rejected event from unauthenticated connection. Event pubkey: ${event.pubkey?.substring(0, 16)}`,
          );

          // Crucial for NDK: Send the AUTH challenge alongside the auth-required rejection
          // so that the client's connectivity layer immediately triggers its authentication flow.
          const challenge = this.authChallenges.get(client) || randomUUID();
          this.authChallenges.set(client, challenge);
          client.send(JSON.stringify(['AUTH', challenge]));

          return client.send(buildRejectionMessage(
            'auth-required: backend authentication required',
          ));
        }

        // Step 2: Crypto verification (before any content inspection)
        // Uses the extracted sync function — same logic as the EventUtils monkey-patch.
        // We verify explicitly here so we can reject BEFORE registry.check() runs
        // (which would otherwise leak registration status via error codes).
        const cryptoError = verifyVerityEventSync(event, this.configService.get('serializationPrefix'));
        if (cryptoError) {
          return client.send(buildRejectionMessage(cryptoError));
        }

        // Step 3: Connection-level policies (Kind 415, NIP-46)
        // These are relay-specific rules that depend on connection identity, NOT event content.

        // Kind 415 (username registration) can only be published by the signer daemon
        // over a trusted connection. The event's pubkey is the user's key, but only
        // trusted connections may transmit these events.
        if (event.kind === 415 && !isTrustedConnection) {
          return client.send(buildRejectionMessage(
            'restricted: Kind 415 requires trusted connection',
          ));
        }

        // NIP-46 events (24133/24134) require an authenticated connection.
        // The NIP-42 gate above already ensures authentication.
        // The signer's ACL engine handles fine-grained authorization for NIP-46 commands;
        // the relay's job is only ensuring the transport is authenticated.
        // NOTE: p-tag targets cannot be validated here because NIP-46 is bidirectional —
        // clients target user pubkeys (not the signer's admin identity), and the relay
        // has no way to know which user pubkeys the signer manages.
        if (event.kind === 24133 || event.kind === 24134) {
          // All NIP-46 events pass through if the connection is authenticated.
          // No registration lookup needed — the signer ACL handles authorization.
        }

        // Step 4: Framework-driven validation (structural + publisher + context)
        const self = this;
        const validationContext: ValidationContext = {
          async checkUserIsRegistered(pubkey) {
            // Retry loop to handle race conditions with DB writes
            const maxAttempts = 3;
            for (let attempt = 0; attempt < maxAttempts; attempt++) {
              const events = await self.findEvents(
                [{ kinds: [415], authors: [pubkey], limit: 1 }],
              );
              if (events.length > 0) return true;
              if (attempt < maxAttempts - 1) {
                await new Promise((resolve) => setTimeout(resolve, 100));
              }
            }
            return false;
          },
          async checkParentEventExists(eventId) {
            const events = await self.findEvents(
              [{ ids: [eventId], limit: 1 }],
            );
            return events.length > 0;
          },
        };

        const checkResult = await this.validator.registry.check(event, {
          context: validationContext,
          trustedSigners: this.trustedSignerPubkey,
          skipPublisherCheck: isTrustedConnection,
          skipContextCheck: false,
        });

        if (!checkResult.ok) {
          const firstError = checkResult.errors[0];
          const reason = `invalid: [${firstError.code}]: ${firstError.message}`;
          return client.send(buildRejectionMessage(reason));
        }
      }

      await this.relay.handleMessage(client, msg as any);
      this.metricService.pushProcessingTime(msg[0] as any, Date.now() - start);

      // Post-processing checkpoint for ALL events so the test runner can verify
      // that any publish (e.g., kind 30598 config events) was actually stored.
      if (this.checkpointService && (msg as any)[0] === 'EVENT' && (msg as any)[1]) {
        const event = (msg as any)[1];
        this.checkpointService.broadcast('relay.event.processed', {
          kind: event.kind,
          pubkey: event.pubkey?.substring(0, 16),
          id: event.id?.substring(0, 16),
        });
      }
    } catch (error) {
      if (error instanceof ValidationError) {
        client.send(JSON.stringify(createOutgoingNoticeMessage(error.message)));
        return;
      }
      this.logger.error(error);
      client.send(JSON.stringify(createOutgoingNoticeMessage((error as Error).message)));
    }
  }

  async handleEvent(event: Event) {
    return await this.relay.handleEvent(event);
  }

  async findEvents(filters: Filter[], pubkey?: string) {
    return await this.relay.findEvents(filters, pubkey);
  }

  async validateEvent(data: any) {
    const result = await this.validator.validateAndResolve(data);
    return result.event;
  }

  async validateFilter(data: any) {
    return await this.validator.validateFilter(data);
  }

  async validateFilters(data: any) {
    return await this.validator.validateFilters(data);
  }
}
