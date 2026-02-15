import { Injectable, OnApplicationShutdown } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  Event,
  Filter,
  createOutgoingNoticeMessage,
  EventUtils,
} from '@nostr-relay/common';
import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import { NostrRelay } from '@nostr-relay/core';
import { CreatedAtLimitGuard } from '@nostr-relay/created-at-limit-guard';
import { OrGuard } from '@nostr-relay/or-guard';
import { PowGuard } from '@nostr-relay/pow-guard';
import { Throttler } from '@nostr-relay/throttler';
import { VerityValidator } from './verity-validator';
import { InjectPinoLogger, PinoLogger } from 'nestjs-pino';
import { Config } from 'src/config';
import { MessageHandlingConfig } from 'src/config/message-handling.config';
import { WebSocket } from 'ws';
import { ValidationError } from 'zod-validation-error';
import { WotService } from '../../../modules/wot/wot.service';
import { MetricService } from '../../metric/metric.service';
import { EventRepository } from '../../repositories/event.repository';
import { NostrRelayLogger } from '../../share/nostr-relay-logger.service';
import { BlacklistGuardPlugin, WhitelistGuardPlugin } from '../plugins';

@Injectable()
export class NostrRelayService implements OnApplicationShutdown {
  private readonly relay: NostrRelay;
  private readonly messageHandlingConfig: MessageHandlingConfig;
  private readonly validator: VerityValidator;
  private readonly throttler: Throttler;

  constructor(
    @InjectPinoLogger(NostrRelayService.name)
    private readonly logger: PinoLogger,
    private readonly metricService: MetricService,
    nostrRelayLogger: NostrRelayLogger,
    eventRepository: EventRepository,
    private readonly configService: ConfigService<Config, true>,
    wotService: WotService,
  ) {
    const hostname = configService.get('hostname');
    const relayUrl = configService.get('relayUrl');
    const trustedSignerPubkey = configService.get('trustedSignerPubkey');
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
    });
    this.validator = new VerityValidator(serializationPrefix);

    this.throttler = new Throttler(throttlerConfig);
    this.relay.register(this.throttler);

    const createdAtLimitGuardPlugin = new CreatedAtLimitGuard({
      lowerLimit: createdAtLowerLimit,
      upperLimit: createdAtUpperLimit,
    });
    const orGuardPlugin = new OrGuard(wotService.getWotGuardPlugin());

    if (minPowDifficulty > 0) {
      const powGuardPlugin = new PowGuard(minPowDifficulty);
      orGuardPlugin.addGuard(powGuardPlugin);
    }
    if (blacklist?.length) {
      const blacklistGuardPlugin = new BlacklistGuardPlugin(blacklist);
      this.relay.register(blacklistGuardPlugin);
    }
    if (whitelist?.length) {
      const whitelistGuardPlugin = new WhitelistGuardPlugin(whitelist);
      orGuardPlugin.addGuard(whitelistGuardPlugin);
    }

    // Monkey-patch EventUtils.validate to support custom serialization prefix
    // This is required because NostrRelay's EventService uses EventUtils.validate internally
    // and we cannot inject a custom validator into it.
    EventUtils.validate = (event: Event) => {
      // 1. Basic field validation (same as original)
      if (!event.id || !/^[0-9a-f]{64}$/.test(event.id)) return 'invalid: id is wrong';
      if (!event.pubkey || !/^[0-9a-f]{64}$/.test(event.pubkey)) return 'invalid: pubkey is wrong';
      if (!event.sig || !/^[0-9a-f]{128}$/.test(event.sig)) return 'invalid: signature is wrong';

      // 2. Custom ID Validation
      try {
        const serialized = JSON.stringify([
          serializationPrefix,
          event.pubkey,
          event.created_at,
          event.kind,
          event.tags,
          event.content,
        ]);
        const hash = sha256(new TextEncoder().encode(serialized));
        const computedId = bytesToHex(hash);

        if (event.id !== computedId) {
          // Check if it matches standard serialization (0) for backward compatibility?
          // Or just enforce prefix. Enforce for now.
          return `invalid: id is wrong. Expected ${computedId}, got ${event.id}, prefix=${serializationPrefix}`;
        }
      } catch (e) {
        return `invalid: id calculation failed: ${e.message}`;
      }

      // 3. Signature Verification
      try {
        if (!schnorr.verify(event.sig, event.id, event.pubkey)) {
          return 'invalid: signature is wrong';
        }
      } catch (error) {
        return 'invalid: signature verification failed';
      }

      return undefined; // Valid
    };

    this.relay.register(orGuardPlugin);
    this.relay.register(createdAtLimitGuardPlugin);
  }

  onApplicationShutdown() {
    this.throttler.destroy();
  }

  handleConnection(client: WebSocket, ip = 'unknown') {
    this.relay.handleConnection(client, ip);
    this.metricService.incrementConnectionCount();
  }

  handleDisconnect(client: WebSocket) {
    this.relay.handleDisconnect(client);
    this.metricService.decrementConnectionCount();
  }

  async handleMessage(client: WebSocket, data: Array<any>) {
    try {
      const start = Date.now();
      const msg = await this.validator.validateIncomingMessage(data);
      if (!this.messageHandlingConfig[msg[0].toLowerCase()]) {
        return;
      }

      // NIP-46 Debug Logging: Track kind 24133/24134 events (testing/development only)
      if (process.env.NODE_ENV === 'testing' || process.env.NODE_ENV === 'development') {
        const msgType = msg[0];
        if (msgType === 'EVENT' && msg[1]) {
          const event = msg[1];
          const kind = event.kind;
          // NIP-46 kinds: 24133 (NostrConnect request/response)
          if (kind === 24133 || kind === 24134) {
            const pTags = (event.tags || []).filter((t: string[]) => t[0] === 'p').map((t: string[]) => t[1]);
            this.logger.info(`[NIP46-EVENT] Received kind=${kind} id=${event.id?.substring(0, 8)} from=${event.pubkey?.substring(0, 8)} to=[${pTags.map((p: string) => p?.substring(0, 8)).join(',')}]`);
          }
        } else if (msgType === 'REQ' && msg.length > 2) {
          // Log subscriptions that might be for NIP-46
          const subscriptionId = msg[1];
          const filters = msg.slice(2);
          const hasNip46Kinds = filters.some((f: any) =>
            f.kinds && (f.kinds.includes(24133) || f.kinds.includes(24134))
          );
          if (hasNip46Kinds) {
            const pFilters = filters.map((f: any) => f['#p'] || []);
            this.logger.info(`[NIP46-SUB] REQ id=${subscriptionId} #p=${JSON.stringify(pFilters.flat().map((p: string) => p?.substring(0, 8)))}`);
          }
        }
      }

      // Enforce Trusted Signer if configured
      if (msg[0] === 'AUTH') {
        const trustedSigner = this.configService.get('trustedSignerPubkey');
        if (trustedSigner) {
          const authEvent = msg[1];
          if (authEvent.pubkey !== trustedSigner) {
            this.logger.warn(`[AUTH] Rejected untrusted signer: ${authEvent.pubkey}`);
            return createOutgoingNoticeMessage('restricted: unknown signer');
          }
        }
      }

      await this.relay.handleMessage(client, msg);
      this.metricService.pushProcessingTime(msg[0], Date.now() - start);
    } catch (error) {
      if (error instanceof ValidationError) {
        return createOutgoingNoticeMessage(error.message);
      }
      this.logger.error(error);
      return createOutgoingNoticeMessage((error as Error).message);
    }
  }

  async handleEvent(event: Event) {
    return await this.relay.handleEvent(event);
  }

  async findEvents(filters: Filter[], pubkey?: string) {
    return await this.relay.findEvents(filters, pubkey);
  }

  async validateEvent(data: any) {
    return await this.validator.validateEvent(data);
  }

  async validateFilter(data: any) {
    return await this.validator.validateFilter(data);
  }

  async validateFilters(data: any) {
    return await this.validator.validateFilters(data);
  }
}
