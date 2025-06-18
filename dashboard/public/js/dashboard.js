document.addEventListener('DOMContentLoaded', () => {
  // Socket.io connection
  const socket = io();
  
  // Session start time (when page loads)
  const sessionStartTime = Date.now();
  
  // Initialize dashboard data
  initializeDashboard();
  
  // Set up interval to refresh data (reduced since we have real-time updates)
  setInterval(fetchSystemStatus, 30000); // Refresh status every 30 seconds
  setInterval(fetchAlertStats, 60000);   // Refresh stats every 60 seconds (backup)
  setInterval(fetchAlerts, 45000);       // Refresh alerts every 45 seconds (backup)
  
  // Listen for new alerts via WebSocket
  socket.on('new-alerts', (alerts) => {
    updateAlertsTable(alerts, true);
    playAlertSound();
  });
  
  // Listen for real-time statistics updates
  socket.on('stats-update', (data) => {
    // For real-time updates, we need to fetch session-filtered data
    // Since the server sends all data, we fetch fresh session-filtered data
    fetchAlertStats();
  });
  
  // Listen for session start event from server
  socket.on('session-start', (data) => {
    // Server provides its own session start time, but we use client-side for consistency
    console.log('Session started at:', new Date(sessionStartTime).toLocaleString());
  });
  
  // Initialize charts
  let attackTypeChart;
  
  // Function to initialize dashboard
  function initializeDashboard() {
    fetchSystemStatus();
    fetchAlertStats();
    fetchAlerts();
  }
  
  // Function to fetch system status
  function fetchSystemStatus() {
    fetch('/api/system-status')
      .then(response => response.json())
      .then(data => {
        const statusLight = document.getElementById('status-light');
        const statusText = document.getElementById('status-text');
        const modeText = document.getElementById('mode-text');
        const lastUpdate = document.getElementById('last-update');
        
        // Update status light and text
        if (data.status === 'Running') {
          statusLight.className = 'status-light active';
          statusText.textContent = 'Status: Running';
        } else {
          statusLight.className = 'status-light inactive';
          statusText.textContent = `Status: ${data.status}`;
        }
        
        // Update mode text
        modeText.textContent = `Mode: ${data.mode}`;
        
        // Update last update time
        lastUpdate.textContent = moment(data.lastUpdate).format('YYYY-MM-DD HH:mm:ss');
      })
      .catch(error => {
        console.error('Error fetching system status:', error);
      });
  }
  
  // Function to fetch alert statistics
  function fetchAlertStats() {
    fetch(`/api/alert-stats?sessionStart=${sessionStartTime}`)
      .then(response => response.json())
      .then(data => {
        // Update total alerts
        document.getElementById('total-alerts').textContent = data.totalAlerts;
        
        // Update top sources table
        updateTopTable('top-sources', data.topSources, 'Source IP', 'ip', 'count');
        
        // Update top targets table
        updateTopTable('top-targets', data.topTargets, 'Target IP', 'ip', 'count');
        
        // Update attack type chart
        updateAttackTypeChart(data.attackStats);
      })
      .catch(error => {
        console.error('Error fetching alert stats:', error);
      });
  }
  
  // Function to fetch alerts
  function fetchAlerts() {
    fetch(`/api/alerts?sessionStart=${sessionStartTime}`)
      .then(response => response.json())
      .then(data => {
        updateAlertsTable(data.alerts, false);
      })
      .catch(error => {
        console.error('Error fetching alerts:', error);
      });
  }
  
  // Function to update the alerts table
  function updateAlertsTable(alerts, isNewAlert) {
    const alertsTable = document.getElementById('alerts-table').getElementsByTagName('tbody')[0];
    
    if (!alerts || alerts.length === 0) {
      alertsTable.innerHTML = '<tr><td colspan="7">No alerts found</td></tr>';
      return;
    }
    
    if (!isNewAlert) {
      // Clear existing rows if this is a full refresh
      alertsTable.innerHTML = '';
    }
    
    // Add new alerts to the table
    alerts.forEach(alert => {
      // Check if this alert is already in the table (avoid duplicates)
      const existingRow = document.getElementById(`alert-${alert.id}`);
      if (existingRow) {
        return;
      }
      
      const row = document.createElement('tr');
      row.id = `alert-${alert.id}`;
      
      if (isNewAlert) {
        row.className = 'new-alert';
      }
      
      // Determine severity class
      let severityClass = 'severity-low';
      if (alert.severity >= 3) {
        severityClass = 'severity-high';
      } else if (alert.severity >= 2) {
        severityClass = 'severity-medium';
      }
      
      row.innerHTML = `
        <td>${moment(alert.timestamp, 'YYYY-MM-DD HH:mm:ss').format('MM/DD HH:mm:ss')}</td>
        <td>${alert.id}</td>
        <td>${alert.message}</td>
        <td>${alert.source}</td>
        <td>${alert.destination}</td>
        <td>${alert.protocol}</td>
        <td class="${severityClass}">${alert.severity}</td>
      `;
      
      // Add row to the beginning of the table
      if (alertsTable.rows.length > 0) {
        alertsTable.insertBefore(row, alertsTable.firstChild);
      } else {
        alertsTable.appendChild(row);
      }
      
      // Limit to max 100 rows
      if (alertsTable.rows.length > 100) {
        alertsTable.removeChild(alertsTable.lastChild);
      }
    });
  }
  
  // Function to update top tables (sources or targets)
  function updateTopTable(tableId, data, labelText, keyField, valueField) {
    const table = document.getElementById(tableId).getElementsByTagName('tbody')[0];
    
    if (!data || data.length === 0) {
      table.innerHTML = `<tr><td colspan="2">No ${labelText.toLowerCase()} data</td></tr>`;
      return;
    }
    
    table.innerHTML = '';
    
    data.forEach(item => {
      const row = document.createElement('tr');
      row.innerHTML = `
        <td>${item[keyField]}</td>
        <td>${item[valueField]}</td>
      `;
      table.appendChild(row);
    });
  }
  
  // Function to update attack type chart
  function updateAttackTypeChart(chartData) {
    const ctx = document.getElementById('attack-type-chart').getContext('2d');
    
    // Destroy existing chart if it exists
    if (attackTypeChart) {
      attackTypeChart.destroy();
    }
    
    // Create colors array (one color per attack type) - Black and Gold theme
    const colors = [];
    for (let i = 0; i < chartData.labels.length; i++) {
      if (chartData.labels[i].includes('SQL') || chartData.labels[i].includes('XSS') || chartData.labels[i].includes('Path Traversal')) {
        colors.push('#ff5733'); // Bright red-orange for high severity
      } else if (chartData.labels[i].includes('SYN') || chartData.labels[i].includes('DNS')) {
        colors.push('#ffd700'); // Gold for medium severity
      } else {
        colors.push('#b8860b'); // Dark goldenrod for low severity
      }
    }
    
    // Create new chart
    attackTypeChart = new Chart(ctx, {
      type: 'pie',
      data: {
        labels: chartData.labels,
        datasets: [{
          data: chartData.data,
          backgroundColor: colors,
          borderWidth: 1
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'right',
            labels: {
              boxWidth: 15,
              color: '#ffffff', // White text for legend
              font: {
                weight: 'bold'
              }
            }
          },
          tooltip: {
            callbacks: {
              label: function(context) {
                const label = context.label || '';
                const value = context.parsed || 0;
                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                const percentage = Math.round((value / total) * 100);
                return `${label}: ${value} (${percentage}%)`;
              }
            }
          }
        }
      }
    });
  }
  
  // Function to play alert sound (can be implemented if needed)
  function playAlertSound() {
    // Could implement a subtle notification sound here
    // Example: new Audio('/sounds/alert.mp3').play();
  }
});
