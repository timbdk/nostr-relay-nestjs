import { Body, Controller, HttpCode, HttpStatus, Inject, Post, forwardRef } from '@nestjs/common'
import { ChainCacheService } from '../nostr/services/chain-cache.service'

@Controller('testing')
export class TestingController {
  constructor(
    @Inject(forwardRef(() => ChainCacheService))
    private readonly chainCacheService: ChainCacheService,
  ) {}

  @Post('reset-chain-cache')
  @HttpCode(HttpStatus.OK)
  async resetChainCache(): Promise<{ ok: boolean }> {
    await this.chainCacheService.reset()
    return { ok: true }
  }

  @Post('set-chain-ready')
  @HttpCode(HttpStatus.OK)
  async setChainReady(@Body() body: { ready?: boolean }): Promise<{ ok: boolean }> {
    const isReady = typeof body?.ready === 'boolean' ? body.ready : false
    this.chainCacheService.setChainReady(isReady)
    return { ok: true }
  }
}
