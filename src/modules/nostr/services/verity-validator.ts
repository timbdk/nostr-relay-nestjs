import { Validator } from '@nostr-relay/validator';
import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';

export class VerityValidator extends Validator {
    constructor(private readonly serializationPrefix: number) {
        super();
    }

    public async validateIncomingMessage(message: any): Promise<any> {
        if (!Array.isArray(message) || message.length === 0) {
            return super.validateIncomingMessage(message);
        }
        const type = message[0];
        if (type === 'EVENT') {
            if (message.length < 2) throw new Error('Invalid EVENT message');
            // Just return the event object for now; validateEvent is called separately by NostrRelay
            return ['EVENT', message[1]];
        }
        // For other messages (REQ, CLOSE, AUTH, etc.), delegate to super
        return super.validateIncomingMessage(message);
    }

    public async validateFilter(filter: any): Promise<any> {
        return super.validateFilter(filter);
    }

    public async validateFilters(filters: any): Promise<any> {
        return super.validateFilters(filters);
    }

    /**
     * SERIALIZATION:
     * [prefix, pubkey, created_at, kind, tags, content]
     */
    public async validateEvent(event: any): Promise<any> {
        console.log('[VerityValidator] validateEvent called', JSON.stringify(event));

        if (typeof event !== 'object' || event === null) {
            throw new Error('Event must be an object');
        }

        const { id, pubkey, created_at, kind, tags, content, sig } = event;

        if (typeof id !== 'string' || !/^[0-9a-f]{64}$/.test(id)) {
            throw new Error('invalid id');
        }
        if (typeof pubkey !== 'string' || !/^[0-9a-f]{64}$/.test(pubkey)) {
            throw new Error('invalid pubkey');
        }
        if (typeof created_at !== 'number') {
            throw new Error('invalid created_at');
        }
        if (typeof kind !== 'number') {
            throw new Error('invalid kind');
        }
        if (!Array.isArray(tags)) {
            throw new Error('invalid tags');
        }
        if (typeof content !== 'string') {
            throw new Error('invalid content');
        }
        if (typeof sig !== 'string' || !/^[0-9a-f]{128}$/.test(sig)) {
            throw new Error('invalid sig');
        }

        // 2. Calculate ID using Custom Serialization
        const serialized = JSON.stringify([
            this.serializationPrefix,
            pubkey,
            created_at,
            kind,
            tags,
            content,
        ]);
        const hash = sha256(new TextEncoder().encode(serialized));
        const computedId = bytesToHex(hash);

        if (id !== computedId) {
            const debugInfo = `Expected ${computedId}, got ${id}. Prefix: ${this.serializationPrefix}. Serialized: ${serialized}`;
            console.log(`[VerityValidator] ID MISMATCH: ${debugInfo}`); // Keep log just in case
            throw new Error(`invalid: id is wrong. ${debugInfo}`);
        }

        // 3. Verify Signature
        try {
            const isValid = await schnorr.verify(sig, id, pubkey);
            if (!isValid) {
                throw new Error('invalid signature');
            }
        } catch (e) {
            throw new Error('invalid signature');
        }

        return event;
    }
}
