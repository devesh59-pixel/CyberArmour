/**
 * CyberGuard AI - Telemetry & Threat Metrics Visualizer
 */

class TelemetryCharts {
  constructor() {
    this.trafficChart = null;
    this.anomalyChart = null;
    this.distributionChart = null;
    
    this.trafficHistory = Array(20).fill(45);
    this.anomalyHistory = Array(20).fill(10);
    this.labels = Array(20).fill('');
    
    this.initCharts();
  }

  initCharts() {
    const trafficCtx = document.getElementById('trafficChart')?.getContext('2d');
    const anomalyCtx = document.getElementById('anomalyChart')?.getContext('2d');
    const distCtx = document.getElementById('distributionChart')?.getContext('2d');

    if (trafficCtx) {
      this.trafficChart = new Chart(trafficCtx, {
        type: 'line',
        data: {
          labels: this.labels,
          datasets: [{
            label: 'Packets / Sec',
            data: this.trafficHistory,
            borderColor: '#00f2fe',
            backgroundColor: 'rgba(0, 242, 254, 0.08)',
            borderWidth: 2,
            fill: true,
            tension: 0.4,
            pointRadius: 0
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          animation: false,
          plugins: { legend: { display: false } },
          scales: {
            x: { display: false },
            y: {
              grid: { color: 'rgba(56, 189, 248, 0.08)' },
              ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 } },
              suggestedMin: 0,
              suggestedMax: 150
            }
          }
        }
      });
    }

    if (anomalyCtx) {
      this.anomalyChart = new Chart(anomalyCtx, {
        type: 'line',
        data: {
          labels: this.labels,
          datasets: [{
            label: 'Threat Risk Score',
            data: this.anomalyHistory,
            borderColor: '#ff0055',
            backgroundColor: 'rgba(255, 0, 85, 0.08)',
            borderWidth: 2,
            fill: true,
            tension: 0.4,
            pointRadius: 0
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          animation: false,
          plugins: { legend: { display: false } },
          scales: {
            x: { display: false },
            y: {
              grid: { color: 'rgba(255, 0, 85, 0.08)' },
              ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 } },
              min: 0,
              max: 100
            }
          }
        }
      });
    }

    if (distCtx) {
      this.distributionChart = new Chart(distCtx, {
        type: 'doughnut',
        data: {
          labels: ['DDoS', 'Brute Force', 'SQL Injection', 'XSS', 'Port Scan', 'Zero-Day / Others'],
          datasets: [{
            data: [1, 1, 1, 1, 1, 1],
            backgroundColor: ['#ff0055', '#f59e0b', '#38bdf8', '#8b5cf6', '#ec4899', '#10b981'],
            borderColor: '#090d1f',
            borderWidth: 2
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              position: 'bottom',
              labels: { color: '#94a3b8', font: { family: 'Outfit', size: 11 }, boxWidth: 12 }
            }
          },
          cutout: '68%'
        }
      });
    }
  }

  updateMetrics(packetsPerSec, riskScore, threatDist) {
    // 1. Update Traffic Stream
    this.trafficHistory.push(packetsPerSec);
    this.trafficHistory.shift();
    if (this.trafficChart) {
      this.trafficChart.data.datasets[0].data = this.trafficHistory;
      this.trafficChart.update('none');
    }

    // 2. Update Risk Score Stream
    this.anomalyHistory.push(riskScore);
    this.anomalyHistory.shift();
    if (this.anomalyChart) {
      this.anomalyChart.data.datasets[0].data = this.anomalyHistory;
      this.anomalyChart.update('none');
    }

    // 3. Update Threat Breakdown Distribution
    if (this.distributionChart && threatDist) {
      const ddos = threatDist['DDoS'] || 0;
      const bf = threatDist['Brute Force'] || 0;
      const sqli = threatDist['SQL Injection'] || 0;
      const xss = threatDist['Cross-Site Scripting (XSS)'] || 0;
      const scan = threatDist['Port Scan'] || 0;
      const other = (threatDist['Zero-Day Anomaly'] || 0) + (threatDist['Path Traversal'] || 0) + (threatDist['Command Injection'] || 0) + (threatDist['Data Exfiltration'] || 0);

      const total = ddos + bf + sqli + xss + scan + other;
      if (total > 0) {
        this.distributionChart.data.datasets[0].data = [ddos, bf, sqli, xss, scan, other];
        this.distributionChart.update();
      }
    }
  }
}

window.TelemetryCharts = null;
