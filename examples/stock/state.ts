export interface Reservation {
  id: string;
  item: string;
  quantity: number;
  status: 'reserved' | 'released';
}

export interface StockState {
  stock: Record<string, number>;
  reservations: Record<string, Reservation>;
}
