export default function append(state: {readings: number[]}, reading: number) {
    if (!Number.isFinite(reading)) throw new Error("expected a reading");
    state.readings.push(reading);
    return {state, value: state.readings.length};
}
