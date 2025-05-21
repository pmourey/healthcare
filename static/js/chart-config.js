// static/js/chart-config.js
const chartColors = {
    main: 'rgb(75, 192, 192)',
    limits: 'rgba(255, 99, 132, 0.8)'
};

function createChartConfig(chartId, labels, markerInfo) {
    return {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: `${markerInfo.display_name} (${markerInfo.unit})`,
                data: markerInfo.values,
                borderColor: chartColors.main,
                tension: 0.1,
                fill: false
            },
            {
                label: 'Limite maximale',
                data: Array(labels.length).fill(markerInfo.limits.max),
                borderColor: chartColors.limits,
                borderDash: [5, 5],
                fill: false,
                pointRadius: 0
            },
            {
                label: 'Limite minimale',
                data: Array(labels.length).fill(markerInfo.limits.min),
                borderColor: chartColors.limits,
                borderDash: [5, 5],
                fill: false,
                pointRadius: 0
            }]
        },
        options: {
            responsive: true,
            plugins: {
                title: {
                    display: true,
                    text: markerInfo.display_name
                }
            },
            scales: {
                y: {
                    title: {
                        display: true,
                        text: markerInfo.unit
                    }
                }
            }
        }
    };
}

function initializeChart(chartType, markerId, markerInfo, dates) {
    const chartId = `${chartType}_${markerId}_chart`;
    const ctx = document.getElementById(chartId);
    if (ctx) {
        new Chart(ctx, createChartConfig(chartId, dates, markerInfo));
    }
}
