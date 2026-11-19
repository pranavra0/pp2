import type { Reservation, StockState } from './state.js';

type Order = { id: string } & (
  { type: 'reserve'; item: string; quantity: number } | { type: 'release' }
);
type Update = { next: StockState; value: Reservation };

function key(id: string): string {
  if (typeof id !== 'string' || !/^[a-zA-Z0-9_-]{1,80}$/.test(id)) throw new TypeError('invalid ID');
  return '@' + id;
}

export default function write(state: StockState, order: Order): Update {
  const id = key(order.id);
  const { stock, reservations } = state;
  const existing = reservations[id];
  switch (order.type) {
    case 'reserve': {
      const item = key(order.item);
      if (!Number.isSafeInteger(order.quantity) || order.quantity <= 0) throw new TypeError('invalid quantity');
      if (existing) {
        if (existing.item !== order.item || existing.quantity !== order.quantity) throw new Error('reservation ID already in use');
        return { next: state, value: existing };
      }
      const available = stock[item] ?? 0;
      if (available < order.quantity) throw new Error('insufficient stock');
      stock[item] = available - order.quantity;
      const reservation: Reservation = { id: order.id, item: order.item, quantity: order.quantity, status: 'reserved' };
      reservations[id] = reservation;
      return { next: state, value: reservation };
    }
    case 'release':
      if (!existing) throw new Error('unknown reservation');
      if (existing.status === 'reserved') {
        const item = key(existing.item);
        const available = stock[item];
        if (available === undefined) throw new Error('reservation references missing stock');
        stock[item] = available + existing.quantity;
        existing.status = 'released';
      }
      return { next: state, value: existing };
    default: throw new TypeError('unknown stock operation');
  }
}
