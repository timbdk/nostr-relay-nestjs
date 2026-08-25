import {
  BeforeHandleEventPlugin,
  BeforeHandleEventResult,
  Event,
} from '@nostr-relay/common'

export class WhitelistGuardPlugin implements BeforeHandleEventPlugin {
  private readonly whitelist: Set<string>

  constructor(whitelist: string[]) {
    this.whitelist = new Set(whitelist)
  }

  beforeHandleEvent(event: Event): BeforeHandleEventResult {
    const author = (event as any).uid ?? event.pubkey
    if (!this.whitelist.has(author)) {
      return {
        canHandle: false,
        message: 'blocked: you are banned from posting here',
      }
    }
    return { canHandle: true }
  }
}
