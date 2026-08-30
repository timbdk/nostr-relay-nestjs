/**
 * Purpose: NestJS shell for the ChainCacheCore — registers the cache in the DI
 *          container, wires cron scheduling, and delegates all logic to the
 *          decorator-free core.
 * Behavior: See chain-cache-core.ts for the actual implementation.
 * Usage: Injected into NostrRelayService, EventController, and TestingController.
 */

// ── Imports ──────────────────────────────────────────────────────────────────

import { Injectable, OnApplicationBootstrap, OnModuleInit, Optional } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { Cron } from '@nestjs/schedule'
import { InjectPinoLogger, PinoLogger } from 'nestjs-pino'
import { Config } from '../../../config'
import { EventRepository } from '../../repositories/event.repository'
import { TestingCheckpointService } from '../../testing/testing-checkpoint.service'
import { ChainCacheCore, ChainEntry } from './chain-cache-core'

// ── Re-exports for consumers ─────────────────────────────────────────────────

export { ChainEntry } from './chain-cache-core'

// ── Service ──────────────────────────────────────────────────────────────────

@Injectable()
export class ChainCacheService implements OnModuleInit, OnApplicationBootstrap {
  private readonly core: ChainCacheCore

  constructor(
    @InjectPinoLogger(ChainCacheService.name)
    private readonly logger: PinoLogger,
    private readonly eventRepository: EventRepository,
    private readonly configService: ConfigService<Config, true>,
    @Optional() private readonly checkpointService?: TestingCheckpointService,
  ) {
    const platformId = this.configService.get('platformId', { infer: true })
    const limitConfig = this.configService.get('limit', { infer: true })
    this.core = new ChainCacheCore({
      logger: this.logger,
      eventRepository: this.eventRepository,
      platformId,
      createdAtLowerLimit: limitConfig?.createdAtLowerLimit ?? 86400,
      checkpointService: this.checkpointService,
    })
  }

  onModuleInit() {
    this.core.init()
  }

  async onApplicationBootstrap() {
    await this.core.backfill()
  }

  @Cron('0 * * * *')
  evictionSweep(): void {
    this.core.evictionSweep()
  }

  // ── Delegate all public API to the core ─────────────────────────────────────

  isReady(): boolean {
    return this.core.isReady()
  }

  applyEvent(event: any, isBackfill?: boolean): void {
    this.core.applyEvent(event, isBackfill)
  }

  isHeld(entryId: string): boolean {
    return this.core.isHeld(entryId)
  }

  release(entryId: string): void {
    this.core.release(entryId)
  }

  byId(entryId: string): ChainEntry | null {
    return this.core.byId(entryId)
  }

  byUid(uid: string): ChainEntry[] {
    return this.core.byUid(uid)
  }

  isUserRegistered(uid: string): boolean {
    return this.core.isUserRegistered(uid)
  }

  isTrustedService(uid: string): boolean {
    return this.core.isTrustedService(uid)
  }

  getTrustedServiceUids(): string[] {
    return this.core.getTrustedServiceUids()
  }

  setChainReady(ready: boolean): void {
    this.core.setChainReady(ready)
  }

  async reset(): Promise<void> {
    await this.core.reset()
  }
}
