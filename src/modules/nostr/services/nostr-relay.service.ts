/**
 * Purpose: Central Nostr Relay service coordinating event ingestion, validation, and broadcasting.
 * Behavior: Enforces NIP-42 authentication, uniform cryptographic verification against the chain cache,
 *           readiness gate, platform-chain trusted connection recognition, a created-at guard that
 *           exempts the trusted-channel kinds, read policy evaluation, and hold-until-first-use egress
 *           filtering.
 * Usage: Injected into NostrGateway and EventController.
 */

// ── Imports ──────────────────────────────────────────────────────────────────

import { Injectable, OnApplicationShutdown, Optional } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import {
  Event,
  Filter,
  createOutgoingNoticeMessage,
  EventUtils,
} from '@nostr-relay/common'
import { randomUUID } from 'crypto'
import {
  type ValidationContext,
  evaluateReadPolicy,
  type ReadPolicyContext,
  identityIdFromPublicKey,
} from 'verity-event-data-module'
import { NostrRelay } from '@nostr-relay/core'
import { CreatedAtLimitGuard } from '@nostr-relay/created-at-limit-guard'
import { OrGuard } from '@nostr-relay/or-guard'
import { PowGuard } from '@nostr-relay/pow-guard'
import { Throttler } from '@nostr-relay/throttler'
import { VerityValidator } from './verity-validator'
import { verifyVerityEventAsync, verifyVerityEventSync } from './verity-crypto-validator'
import { InjectPinoLogger, PinoLogger } from 'nestjs-pino'
import { Config } from 'src/config'
import { MessageHandlingConfig } from 'src/config/message-handling.config'
import { WebSocket } from 'ws'
import { ValidationError } from 'zod-validation-error'
import { WotService } from '../../../modules/wot/wot.service'
import { MetricService } from '../../metric/metric.service'
import { EventRepository } from '../../repositories/event.repository'
import { NostrRelayLogger } from '../../share/nostr-relay-logger.service'
import { TestingCheckpointService } from '../../testing/testing-checkpoint.service'
import { BlacklistGuardPlugin, WhitelistGuardPlugin } from '../plugins'
import { ChainCacheService } from './chain-cache.service'

// ── Service ──────────────────────────────────────────────────────────────────

@Injectable()
export class NostrRelayService implements OnApplicationShutdown {
  private readonly relay: NostrRelay
  private readonly messageHandlingConfig: MessageHandlingConfig
  private readonly validator: VerityValidator
  private readonly throttler: Throttler
  private readonly platformId: string
  private readonly relayHostname?: string
  private readonly createdAtLowerLimit?: number
  private readonly createdAtUpperLimit?: number

  constructor(
    @InjectPinoLogger(NostrRelayService.name)
    private readonly logger: PinoLogger,
    private readonly metricService: MetricService,
    nostrRelayLogger: NostrRelayLogger,
    private readonly eventRepository: EventRepository,
    private readonly configService: ConfigService<Config, true>,
    private readonly chainCacheService: ChainCacheService,
    wotService: WotService,
    @Optional() private readonly checkpointService?: TestingCheckpointService,
  ) {
    const hostname = configService.get('hostname')
    const relayUrl = configService.get('relayUrl')
    this.platformId = configService.get('platformId', { infer: true })
    const serializationPrefix = configService.get('serializationPrefix')

    const {
      createdAtLowerLimit,
      createdAtUpperLimit,
      minPowDifficulty,
      maxSubscriptionsPerClient,
      blacklist,
      whitelist,
    } = configService.get('limit', { infer: true })
    this.createdAtLowerLimit = createdAtLowerLimit
    this.createdAtUpperLimit = createdAtUpperLimit

    const cacheConfig = configService.get('cache', { infer: true })
    const throttlerConfig = configService.get('throttler.ws', { infer: true })
    this.messageHandlingConfig = configService.get('messageHandling', {
      infer: true,
    })

    let relayHostname = hostname
    if (relayUrl) {
      try {
        const url = new URL(relayUrl)
        relayHostname = url.hostname
        this.logger.info(`[DEBUG] Configured NostrRelay with RELAY_URL=${relayUrl} -> hostname=${relayHostname}`)
      } catch (error) {
        this.logger.warn(`Invalid RELAY_URL: ${relayUrl}`)
      }
    }
    this.relayHostname = relayHostname

    this.relay = new NostrRelay(eventRepository, {
      hostname: relayHostname,
      logger: nostrRelayLogger,
      maxSubscriptionsPerClient,
      ...cacheConfig,
      eventHandlingResultCacheTtl: 0,
    })
    this.validator = new VerityValidator(serializationPrefix)

    const wrapInSafety = (plugin: any): any => {
      if (!plugin || typeof plugin.beforeHandleEvent !== 'function') {
        return plugin
      }
      const target = plugin
      const originalBefore = target.beforeHandleEvent.bind(target)
      target.beforeHandleEvent = async (event: any, client?: any): Promise<any> => {
        const result = await originalBefore(event, client)
        if (result === undefined || result === null) {
          return { canHandle: true, success: true }
        }
        if (typeof result === 'object') {
          if (result.success && !('canHandle' in result)) result.canHandle = true
          if (result.canHandle && !('success' in result)) result.success = true
        }
        return result
      }
      return plugin
    }

    this.throttler = new Throttler(throttlerConfig)
    this.relay.register(wrapInSafety(this.throttler))

    // CreatedAtLimitGuard wrapper: exempt trusted-channel kinds 297 and 415.
    // Their chain entries are backdated to 00:00 UTC (up to 24 h old at
    // publication), and these kinds arrive only over the trusted connection,
    // which is the authority on their validity — the guard targets untrusted
    // writes and keeps covering content kinds and browser-origin traffic.
    const innerCreatedAtLimitGuard = new CreatedAtLimitGuard({
      lowerLimit: createdAtLowerLimit,
      upperLimit: createdAtUpperLimit,
    })
    const createdAtLimitGuardWrapper = {
      beforeHandleEvent: async (event: any) => {
        if (event.kind === 297 || event.kind === 415) {
          return { canHandle: true, success: true }
        }
        return innerCreatedAtLimitGuard.beforeHandleEvent(event)
      },
    }

    this.relay.register(wrapInSafety(createdAtLimitGuardWrapper))

    const wotGuard = wotService.getWotGuardPlugin()
    const orGuardPlugin = new OrGuard()
    let hasOrGuards = false

    if (wotGuard && wotGuard.getEnabled()) {
      orGuardPlugin.addGuard(wrapInSafety(wotGuard))
      hasOrGuards = true
    }

    if (minPowDifficulty > 0) {
      const powGuardPlugin = new PowGuard(minPowDifficulty)
      orGuardPlugin.addGuard(wrapInSafety(powGuardPlugin))
      hasOrGuards = true
    }

    if (blacklist?.length) {
      const blacklistGuardPlugin = new BlacklistGuardPlugin(blacklist)
      this.relay.register(wrapInSafety(blacklistGuardPlugin))
    }

    if (whitelist?.length) {
      const whitelistGuardPlugin = new WhitelistGuardPlugin(whitelist)
      orGuardPlugin.addGuard(wrapInSafety(whitelistGuardPlugin))
      hasOrGuards = true
    }

    if (hasOrGuards) {
      this.relay.register(wrapInSafety(orGuardPlugin))
    }

    // Monkey-patch EventUtils.validate to use uniform verification
    (EventUtils as any).validate = (event: Event) => {
      return verifyVerityEventSync(
        event,
        serializationPrefix,
        (kid) => this.chainCacheService.byId(kid),
        { platformId: this.platformId }
      )
    }
  }

  onApplicationShutdown() {
    this.throttler.destroy()
  }

  // ── Connection & Identity State ────────────────────────────────────────────

  private readonly authenticatedSigners = new WeakMap<WebSocket, string>()
  private readonly resolvedIdentities = new WeakMap<WebSocket, string>()
  /** Persistent device→user identity mapping (survives connection lifecycles). */
  private readonly deviceIdentities = new Map<string, string>()
  private readonly authChallenges = new WeakMap<WebSocket, string>()
  private readonly authenticatedConnections = new Map<string, Set<WebSocket>>()

  /**
   * Check if a connection uid corresponds to a trusted service.
   * Resolves connection uid against platform chain service delegate entries.
   */
  private isTrustedSigner(uid: string | undefined): boolean {
    if (!uid) return false
    return this.chainCacheService.isTrustedService(uid)
  }

  /**
   * Builds a ReadPolicyContext for a given client connection.
   */
  private buildReadContext(client: WebSocket): ReadPolicyContext {
    const devicePubkey = this.authenticatedSigners.get(client)
    let userPubkey = this.resolvedIdentities.get(client)
    if (!userPubkey && devicePubkey) {
      userPubkey = this.deviceIdentities.get(devicePubkey)
    }
    return { devicePubkey, userPubkey }
  }

  /**
   * Resolves the user identity for a device key connection.
   */
  private resolveIdentity(clientPubkey: string, userPubkey: string): void {
    const clientUid = /^[a-f0-9]{64}$/i.test(clientPubkey) ? identityIdFromPublicKey(clientPubkey) : clientPubkey
    const userUid = /^[a-f0-9]{64}$/i.test(userPubkey) ? identityIdFromPublicKey(userPubkey) : userPubkey

    this.deviceIdentities.set(clientPubkey, userUid)
    this.deviceIdentities.set(clientUid, userUid)

    const connections = this.authenticatedConnections.get(clientUid) || this.authenticatedConnections.get(clientPubkey)
    if (connections) {
      for (const ws of connections) {
        this.resolvedIdentities.set(ws, userUid)
      }
      this.logger.info(
        `[IDENTITY] Resolved identity: device=${clientPubkey.substring(0, 8)} (${clientUid.substring(0, 8)}) → user=${userPubkey.substring(0, 8)} (${userUid.substring(0, 8)}) (${connections.size} connection(s))`,
      )
      this.checkpointService?.broadcast('relay.identity.resolved', {
        devicePubkey: clientPubkey.substring(0, 16),
        userPubkey: userPubkey.substring(0, 16),
        connections: connections.size,
      })
    } else {
      this.logger.info(
        `[IDENTITY] Stored identity (no active connections): device=${clientPubkey.substring(0, 8)} (${clientUid.substring(0, 8)}) → user=${userPubkey.substring(0, 8)} (${userUid.substring(0, 8)})`,
      )
    }
  }

  // ── Connection Handling ────────────────────────────────────────────────────

  handleConnection(client: WebSocket, ip = 'unknown') {
    const originalSend = client.send.bind(client)
    client.send = (data: string | Buffer, ...args: any[]) => {
      try {
        const raw = typeof data === 'string' ? data : data.toString()
        const parsed = JSON.parse(raw)
        if (Array.isArray(parsed)) {
          // AUTH challenge capture
          if (parsed[0] === 'AUTH' && typeof parsed[1] === 'string') {
            this.authChallenges.set(client, parsed[1])
            this.checkpointService?.broadcast('relay.auth.challenge_sent', {
              challenge: parsed[1].substring(0, 16),
            })
          }

          // Read Policy & Held-entry egress filtering
          // Format: ["EVENT", subscriptionId, event]
          if (parsed[0] === 'EVENT' && parsed[2] && typeof parsed[2] === 'object') {
            const senderPubkey = this.authenticatedSigners.get(client)
            const isTrusted = senderPubkey && this.isTrustedSigner(senderPubkey)
            if (!isTrusted) {
              // Hold-until-first-use: withhold held Kind 297 delegate entries from public serving
              if (parsed[2].kind === 297 && this.chainCacheService.isHeld(parsed[2].id)) {
                return
              }
              const context = this.buildReadContext(client)
              if (!evaluateReadPolicy(parsed[2], context)) {
                return
              }
            }
          }
        }
      } catch {
        /* not JSON, ignore */
      }
      return originalSend(data, ...args)
    }

    this.relay.handleConnection(client, ip)
    this.metricService.incrementConnectionCount()
  }

  handleDisconnect(client: WebSocket) {
    const pubkey = this.authenticatedSigners.get(client)
    if (pubkey) {
      const connections = this.authenticatedConnections.get(pubkey)
      if (connections) {
        connections.delete(client)
        if (connections.size === 0) {
          this.authenticatedConnections.delete(pubkey)
        }
      }
    }
    this.relay.handleDisconnect(client)
    this.metricService.decrementConnectionCount()
  }

  // ── Message Processing ─────────────────────────────────────────────────────

  async handleMessage(client: WebSocket, data: Array<any>): Promise<void> {
    let msg: any
    try {
      const start = Date.now()
      msg = await this.validator.validateIncomingMessage(data)
      if (!this.messageHandlingConfig[msg[0].toLowerCase()]) {
        return
      }

      const msgType = msg[0]
      if (msgType === 'EVENT' && msg[1]) {
        const event = msg[1]
        const kind = event.kind
        const tags = Array.isArray(event.tags) ? event.tags : []
        const pTags = tags
          .filter((t: string[]) => t[0] === 'p')
          .map((t: string[]) => t[1])
        const eventUid = event.uid ?? event.pubkey

        if (
          process.env.NODE_ENV === 'testing' ||
          process.env.NODE_ENV === 'development'
        ) {
          this.checkpointService?.broadcast('relay.event.received', {
            kind,
            pubkey: eventUid?.substring(0, 16),
            id: event.id?.substring(0, 16),
            pTags: pTags.map((p: string) => p?.substring(0, 16)),
          })

          if (kind === 24133 || kind === 24134 || kind === 24135) {
            this.logger.info(
              `[NIP46-EVENT] Received kind=${kind} id=${event.id?.substring(
                0,
                8,
              )} from=${eventUid?.substring(0, 8)} to=[${pTags
                .map((p: string) => p?.substring(0, 8))
                .join(',')}]`,
            )
          }
        }

        // Production Gate Fix: Identity attestation consumption runs in all environments
        if (kind === 24135) {
          const clientTag = tags.find((t: string[]) => t[0] === 'client')?.[1]
          const userTag = tags.find((t: string[]) => t[0] === 'user')?.[1]
          if (clientTag && userTag) {
            this.resolveIdentity(clientTag, userTag)
          }
        }
      } else if (msgType === 'REQ' && msg.length > 2) {
        if (
          process.env.NODE_ENV === 'testing' ||
          process.env.NODE_ENV === 'development'
        ) {
          const subscriptionId = msg[1]
          const filters = msg.slice(2)
          const hasNip46Kinds = filters.some(
            (f: any) =>
              f.kinds && (f.kinds.includes(24133) || f.kinds.includes(24134) || f.kinds.includes(24135)),
          )
          if (hasNip46Kinds) {
            const pFilters = filters.map((f: any) => f['#p'] || [])
            this.logger.info(
              `[NIP46-SUB] REQ id=${subscriptionId} #p=${JSON.stringify(
                pFilters.flat().map((p: string) => p?.substring(0, 8)),
              )}`,
            )
          }
        }
      }

      // ── NIP-42 AUTH Handling ───────────────────────────────────────────────
      if (msg[0] === 'AUTH') {
        const authEvent = msg[1]
        const authUid = authEvent.uid ?? authEvent.pubkey

        // 1. Kind check: must be Kind 22242
        if (authEvent.kind !== 22242) {
          this.logger.warn(`[AUTH] Invalid kind ${authEvent.kind} for AUTH event`)
          this.checkpointService?.broadcast('relay.auth.rejected', {
            pubkey: authUid?.substring(0, 16),
            reason: 'invalid_kind',
          })
          client.send(JSON.stringify(['OK', authEvent.id, false, 'auth: kind must be 22242']))
          return
        }

        // 2. Challenge check
        const expectedChallenge = this.authChallenges.get(client)
        const challengeInEvent = authEvent.tags?.find((t: string[]) => t[0] === 'challenge')?.[1]

        if (!expectedChallenge || challengeInEvent !== expectedChallenge) {
          this.logger.warn(`[AUTH] Challenge mismatch for ${authUid}`)
          this.checkpointService?.broadcast('relay.auth.rejected', {
            pubkey: authUid?.substring(0, 16),
            reason: 'challenge_mismatch',
          })
          client.send(JSON.stringify(['OK', authEvent.id, false, 'auth: challenge mismatch']))
          return
        }

        // 3. Relay tag check (NIP-42 binding)
        const relayTag = authEvent.tags?.find((t: string[]) => t[0] === 'relay')?.[1]
        if (relayTag && this.relayHostname) {
          let tagMatches = false
          try {
            const parsedUrl = new URL(relayTag)
            tagMatches = parsedUrl.hostname === this.relayHostname
          } catch {
            tagMatches = false
          }
          if (!tagMatches) {
            this.logger.warn(`[AUTH] Relay tag mismatch for ${authUid}: expected ${this.relayHostname}, got ${relayTag}`)
            this.checkpointService?.broadcast('relay.auth.rejected', {
              pubkey: authUid?.substring(0, 16),
              reason: 'relay_mismatch',
            })
            client.send(JSON.stringify(['OK', authEvent.id, false, 'auth: relay tag mismatch']))
            return
          }
        }

        // 4. Created-at limits check
        const nowSec = Math.floor(Date.now() / 1000)
        if (this.createdAtLowerLimit && authEvent.created_at < nowSec - this.createdAtLowerLimit) {
          this.logger.warn(`[AUTH] Event created_at too old for ${authUid}`)
          this.checkpointService?.broadcast('relay.auth.rejected', {
            pubkey: authUid?.substring(0, 16),
            reason: 'created_at_out_of_range',
          })
          client.send(JSON.stringify(['OK', authEvent.id, false, 'auth: created_at out of range']))
          return
        }
        if (this.createdAtUpperLimit && authEvent.created_at > nowSec + this.createdAtUpperLimit) {
          this.logger.warn(`[AUTH] Event created_at in future for ${authUid}`)
          this.checkpointService?.broadcast('relay.auth.rejected', {
            pubkey: authUid?.substring(0, 16),
            reason: 'created_at_out_of_range',
          })
          client.send(JSON.stringify(['OK', authEvent.id, false, 'auth: created_at out of range']))
          return
        }

        // 5. Cryptographic validation (self-certifying verify: uid == H(key))
        const validationError = EventUtils.validate(authEvent)
        if (validationError) {
          this.logger.warn(`[AUTH] Event validation failed for ${authUid}: ${validationError}`)
          this.checkpointService?.broadcast('relay.auth.rejected', {
            pubkey: authUid?.substring(0, 16),
            reason: 'validation_failed',
            detail: validationError,
          })
          client.send(JSON.stringify(['OK', authEvent.id, false, validationError]))
          return
        }

        // 6. Tier resolution & Success
        const tier = this.chainCacheService.isTrustedService(authUid) ? 'trusted' : 'device'
        const isTrusted = tier === 'trusted'

        this.checkpointService?.broadcast('relay.auth.received', {
          pubkey: authUid?.substring(0, 16),
          isTrusted,
          tier,
        })

        this.authenticatedSigners.set(client, authUid)
        const existingConnections = this.authenticatedConnections.get(authUid)
        if (existingConnections) {
          existingConnections.add(client)
        } else {
          this.authenticatedConnections.set(authUid, new Set([client]))
        }

        const storedIdentity = this.deviceIdentities.get(authUid)
        if (storedIdentity) {
          this.resolvedIdentities.set(client, storedIdentity)
        }

        this.checkpointService?.broadcast('relay.auth.success', {
          pubkey: authUid?.substring(0, 16),
          isTrusted,
          tier,
        })

        if (isTrusted) {
          this.logger.info(`[AUTH] Successfully authenticated as trusted signer (${tier}): ${authUid.substring(0, 16)}`)
        } else {
          this.logger.info(`[AUTH] Successfully authenticated as client (${tier}): ${authUid.substring(0, 16)}`)
        }
        client.send(JSON.stringify(['OK', authEvent.id, true, 'auth: success']))
        return
      }

      // ── EVENT Write Authorization Pipeline ─────────────────────────────────
      if (msg[0] === 'EVENT' && msg[1]) {
        const event = msg[1]
        const eventUid = event.uid ?? event.pubkey

        const authenticatedPubkey = this.authenticatedSigners.get(client)
        const isTrustedConnection = this.isTrustedSigner(authenticatedPubkey)

        const buildRejectionMessage = (reason: string) => {
          return JSON.stringify(['OK', event.id, false, reason])
        }

        // Step 0: Cold-start readiness gate (blocks writes while backfilling)
        if (!this.chainCacheService.isReady()) {
          this.logger.warn(`[EVENT] Blocked event write during chain backfill: ${event.id}`)
          return client.send(buildRejectionMessage('blocked: [CHAIN_SYNCING]: relay is synchronizing, retry shortly'))
        }

        // Step 1: NIP-42 gate (cheapest check)
        if (!authenticatedPubkey) {
          this.logger.warn(
            `[EVENT] Rejected event from unauthenticated connection. Event uid: ${eventUid?.substring(0, 16)}`,
          )
          const challenge = this.authChallenges.get(client) || randomUUID()
          this.authChallenges.set(client, challenge)
          client.send(JSON.stringify(['AUTH', challenge]))

          return client.send(buildRejectionMessage(
            'auth-required: backend authentication required',
          ))
        }

        // Step 2: Crypto verification (uniform path via chain cache)
        const cryptoError = await verifyVerityEventAsync(
          event,
          this.configService.get('serializationPrefix'),
          (kid) => this.chainCacheService.byId(kid),
          { platformId: this.platformId }
        )
        if (cryptoError) {
          this.logger.warn(`[EVENT] Rejected event ${event.id} (kind ${event.kind}) due to cryptoError: ${cryptoError}`)
          return client.send(buildRejectionMessage(cryptoError))
        }

        // Step 3: Connection-level policies (Kind 297 and 415 trusted only)
        if ((event.kind === 297 || event.kind === 415) && !isTrustedConnection) {
          this.logger.warn(`[EVENT] Rejected Kind ${event.kind} from untrusted connection (auth: ${authenticatedPubkey})`)
          return client.send(buildRejectionMessage(
            `restricted: [TRUSTED_CONNECTION_REQUIRED]: Kind ${event.kind} requires trusted connection`,
          ))
        }

        // Step 4: Framework-driven validation (structural + publisher + context)
        const validationContext: ValidationContext = {
          checkUserIsRegistered: async (uid: string) => {
            return this.chainCacheService.isUserRegistered(uid)
          },
          checkParentEventExists: async (eventId: string) => {
            const events = await this.findEvents(
              [{ ids: [eventId], limit: 1 }],
            )
            return events.length > 0
          },
        }

        const checkResult = await this.validator.registry.check(event, {
          context: validationContext,
          trustedSigners: this.chainCacheService.getTrustedServiceUids(),
          skipPublisherCheck: isTrustedConnection,
          skipContextCheck: false,
        })

        if (!checkResult.ok) {
          const firstError = checkResult.errors[0]
          const reason = `invalid: [${firstError.code}]: ${firstError.message}`
          this.logger.warn(`[EVENT] Rejected event ${event.id} (kind ${event.kind}) due to validation: ${reason}`)
          return client.send(buildRejectionMessage(reason))
        }

        // Step 5: Release on first use if referencing a held entry
        if (event.kid) {
          this.chainCacheService.release(event.kid)
        }
      }

      await this.relay.handleMessage(client, msg as any)
      this.metricService.pushProcessingTime(msg[0] as any, Date.now() - start)

      if (this.checkpointService && (msg as any)[0] === 'EVENT' && (msg as any)[1]) {
        const event = (msg as any)[1]
        const eventUid = event.uid ?? event.pubkey
        this.checkpointService.broadcast('relay.event.processed', {
          kind: event.kind,
          pubkey: eventUid?.substring(0, 16),
          id: event.id?.substring(0, 16),
        })
      }
    } catch (error) {
      if (error instanceof ValidationError) {
        client.send(JSON.stringify(createOutgoingNoticeMessage(error.message)))
        return
      }
      this.logger.error(error)
      client.send(JSON.stringify(createOutgoingNoticeMessage((error as Error).message)))
    }
  }

  async handleEvent(event: Event) {
    return await this.relay.handleEvent(event)
  }

  async findEvents(filters: Filter[], pubkey?: string) {
    return await this.relay.findEvents(filters, pubkey)
  }

  async validateEvent(data: any) {
    const result = await this.validator.validateAndResolve(data)
    return result.event
  }

  async validateFilter(data: any) {
    return await this.validator.validateFilter(data)
  }

  async validateFilters(data: any) {
    return await this.validator.validateFilters(data)
  }
}
