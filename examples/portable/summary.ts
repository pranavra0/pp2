import {total} from './total.js';

export default function summarize(state: {readings: number[]}, minimum: number) {
    const readings = state.readings.filter(value => value >= minimum);
    return {count: readings.length, total: total(readings)};
}
