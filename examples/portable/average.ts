export default function average(summary: {total: number, count: number}) {
    return summary.count ? summary.total / summary.count : null;
}
