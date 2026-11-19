import type { Reservation, StockState } from './state.js';

type Inventory = { available: Record<string, number>; reservations: Reservation[] };

export default function read({ stock, reservations }: StockState): Inventory {
  return {
    available: Object.fromEntries(Object.entries(stock).map(([item, amount]) => [item.slice(1), amount])),
    reservations: Object.values(reservations).map(({ id, item, quantity, status }) => ({ id, item, quantity, status })),
  };
}
