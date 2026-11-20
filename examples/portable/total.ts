export function total(readings: number[]) {
    return readings.reduce((sum, reading) => sum + reading, 0);
}
