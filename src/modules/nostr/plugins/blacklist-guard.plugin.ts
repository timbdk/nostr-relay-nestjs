import {
  BeforeHandleEventPlugin,
  BeforeHandleEventResult,
  Event,
} from '@nostr-relay/common'

export class BlacklistGuardPlugin implements BeforeHandleEventPlugin {
  private readonly blacklist: Set<string>

  constructor(blacklist: string[]) {
    this.blacklist = new Set(blacklist)
  }

  beforeHandleEvent(event: Event): BeforeHandleEventResult {
    const author = (event as any).uid ?? event.pubkey
    if (this.blacklist.has(author)) {
      return {
        canHandle: false,
        message: 'blocked: you are banned from posting here',
      }
    }
    return { canHandle: true }
  }
}
