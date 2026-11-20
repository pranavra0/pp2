import {total} from './total.js';

export default async function summarize(_: unknown, readings: number[]) {
    return {count: readings.length, total: total(readings)};
}
