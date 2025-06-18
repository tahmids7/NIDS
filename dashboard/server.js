const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const socketIo = require('socket.io');
const { exec } = require('child_process');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

// Express configuration
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

// Serve the main dashboard page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'index.html'));
});

// API endpoints
app.get('/api/alerts', (req, res) => {
  // Read alerts from the log file (session-based)
  const alertsPath = path.join(__dirname, '..', 'build', 'logs', 'alerts.log');
  const sessionStartTime = req.query.sessionStart; // Client sends session start time
  
  if (!fs.existsSync(alertsPath)) {
    return res.status(404).json({ error: 'Alerts log not found' });
  }
  
  try {
    // Use readline to process file efficiently with session filtering
    const readline = require('readline');
    const stream = fs.createReadStream(alertsPath, { 
      encoding: 'utf8'
    });
    
    const rl = readline.createInterface({
      input: stream,
      crlfDelay: Infinity
    });
    
    const alerts = [];
    
    rl.on('line', (line) => {
      if (line.trim() !== '') {
        // Filter by session start time if provided
        if (sessionStartTime) {
          const timestampMatch = line.match(/\[(.*?)\]/);
          if (timestampMatch) {
            const alertTime = new Date(timestampMatch[1]);
            const sessionStart = new Date(parseInt(sessionStartTime));
            if (alertTime < sessionStart) {
              return; // Skip alerts from before session start
            }
          }
        }
        
        // Parse alert log entries
        const parts = line.match(/\[(.*?)\] ALERT #(\d+) \(SID: (\d+)\): (.*?) \((.*?) -> (.*?)\) Protocol: (.*?) Severity: (\d+)/);
        
        if (parts) {
          alerts.push({
            timestamp: parts[1],
            id: parts[2],
            sid: parts[3],
            message: parts[4],
            source: parts[5],
            destination: parts[6],
            protocol: parts[7],
            severity: parts[8]
          });
        }
      }
    });
    
    rl.on('close', () => {
      // Return the most recent 50 alerts for display
      const recentAlerts = alerts.slice(-50).reverse();
      
      res.json({ alerts: recentAlerts });
    });
  } catch (err) {
    console.error(`Error processing alerts: ${err}`);
    res.status(500).json({ error: 'Server error processing alerts' });
  }
});

app.get('/api/system-status', (req, res) => {
  // Read the system log to get NIDS status
  const systemLogPath = path.join(__dirname, '..', 'build', 'logs', 'system.log');
  
  if (!fs.existsSync(systemLogPath)) {
    return res.status(404).json({ error: 'System log not found' });
  }
  
  try {
    // Get the last 20 lines of the system log
    exec(`tail -n 20 ${systemLogPath}`, (error, stdout, stderr) => {
      if (error) {
        console.error(`Error reading system log: ${error}`);
        return res.status(500).json({ error: 'Failed to read system log' });
      }
      
      // Basic status check 
      const running = stdout.includes('NIDS is running');
      const mode = stdout.includes('simulation mode') ? 'Simulation' : 'Live Capture';
      
      res.json({
        status: running ? 'Running' : 'Stopped',
        mode: mode,
        lastUpdate: new Date().toISOString()
      });
    });
  } catch (err) {
    console.error(`Error processing system status: ${err}`);
    res.status(500).json({ error: 'Server error processing system status' });
  }
});

// Get alert statistics (session-based - only alerts since session start)
app.get('/api/alert-stats', (req, res) => {
  const alertsPath = path.join(__dirname, '..', 'build', 'logs', 'alerts.log');
  const sessionStartTime = req.query.sessionStart; // Client sends session start time
  
  if (!fs.existsSync(alertsPath)) {
    return res.status(404).json({ error: 'Alerts log not found' });
  }
  
  try {
    // Use readline to process file line by line without loading everything into memory
    const readline = require('readline');
    
    // Read the entire file but filter by session start time
    const stream = fs.createReadStream(alertsPath, { 
      encoding: 'utf8'
    });
    
    const rl = readline.createInterface({
      input: stream,
      crlfDelay: Infinity
    });
    
    const attackStats = {};
    const sourceIPs = {};
    const destIPs = {};
    let totalAlerts = 0;
    const lines = [];
    
    rl.on('line', (line) => {
      if (line.trim() !== '') {
        lines.push(line);
      }
    });
    
    rl.on('close', () => {
      // Filter lines based on session start time if provided
      let filteredLines = lines;
      if (sessionStartTime) {
        const sessionStart = new Date(parseInt(sessionStartTime));
        filteredLines = lines.filter(line => {
          const timestampMatch = line.match(/\[(.*?)\]/);
          if (timestampMatch) {
            const alertTime = new Date(timestampMatch[1]);
            return alertTime >= sessionStart;
          }
          return false;
        });
      }
      
      // Process the filtered lines
      filteredLines.forEach(line => {
        const parts = line.match(/\[(.*?)\] ALERT #(\d+) \(SID: (\d+)\): (.*?) \((\d+\.\d+\.\d+\.\d+):(\d+) -> (\d+\.\d+\.\d+\.\d+):(\d+)\) Protocol: (.*?) Severity: (\d+)/);
        
        if (parts) {
          totalAlerts++;
          const attackType = parts[4];
          const sourceIP = parts[5]; // Direct IP extraction
          const destIP = parts[7];   // Direct IP extraction
          
          // Count attack types
          attackStats[attackType] = (attackStats[attackType] || 0) + 1;
          sourceIPs[sourceIP] = (sourceIPs[sourceIP] || 0) + 1;
          destIPs[destIP] = (destIPs[destIP] || 0) + 1;
        }
      });
      
      // Format for chart.js
      const attackLabels = Object.keys(attackStats);
      const attackData = Object.values(attackStats);
      
      res.json({
        totalAlerts,
        attackStats: {
          labels: attackLabels,
          data: attackData
        },
        topSources: Object.entries(sourceIPs)
          .sort((a, b) => b[1] - a[1])
          .slice(0, 5)
          .map(([ip, count]) => ({ ip, count })),
        topTargets: Object.entries(destIPs)
          .sort((a, b) => b[1] - a[1])
          .slice(0, 5)
          .map(([ip, count]) => ({ ip, count }))
      });
    });
    
    rl.on('error', (error) => {
      console.error(`Error reading alerts for stats: ${error}`);
      res.json({
        totalAlerts: 0,
        attackStats: {
          labels: ['SYN Scan', 'DNS Amplification', 'ICMP', 'SQL Injection', 'XSS'],
          data: [0, 0, 0, 0, 0]
        },
        topSources: [],
        topTargets: []
      });
    });
  } catch (err) {
    console.error(`Error processing stats: ${err}`);
    res.status(500).json({ error: 'Server error processing alert statistics' });
  }
});

// WebSocket for real-time updates
let lastAlertCount = 0;
let alertUpdateInterval;

io.on('connection', (socket) => {
  console.log('Client connected to dashboard');
  
  // Send initial session start time
  socket.emit('session-start', { timestamp: Date.now() });
  
  // Set up a timer to check for new alerts and statistics every 3 seconds
  alertUpdateInterval = setInterval(() => {
    const alertsPath = path.join(__dirname, '..', 'build', 'logs', 'alerts.log');
    
    if (!fs.existsSync(alertsPath)) {
      return;
    }
    
    // Check current alert count
    exec(`wc -l < ${alertsPath}`, (error, stdout) => {
      if (error) return;
      
      const currentCount = parseInt(stdout.trim());
      if (currentCount > lastAlertCount) {
        lastAlertCount = currentCount;
        
        // Emit both new alerts and updated statistics
        emitRecentAlerts(socket);
        emitUpdatedStatistics(socket, null); // Pass null to get all statistics for real-time updates
      }
    });
  }, 3000);
  
  socket.on('disconnect', () => {
    console.log('Client disconnected from dashboard');
    if (alertUpdateInterval) {
      clearInterval(alertUpdateInterval);
    }
  });
});

// Function to emit recent alerts
function emitRecentAlerts(socket) {
  const alertsPath = path.join(__dirname, '..', 'build', 'logs', 'alerts.log');
  
  // Get the last 5 alerts
  exec(`tail -n 5 ${alertsPath}`, (error, stdout, stderr) => {
    if (error) {
      console.error(`Error reading recent alerts: ${error}`);
      return;
    }
    
    const recentAlerts = stdout.split('\n')
      .filter(line => line.trim() !== '')
      .map(line => {
        const parts = line.match(/\[(.*?)\] ALERT #(\d+) \(SID: (\d+)\): (.*?) \((.*?) -> (.*?)\) Protocol: (.*?) Severity: (\d+)/);
        
        if (parts) {
          return {
            timestamp: parts[1],
            id: parts[2],
            sid: parts[3],
            message: parts[4],
            source: parts[5],
            destination: parts[6],
            protocol: parts[7],
            severity: parts[8]
          };
        }
        return null;
      })
      .filter(alert => alert !== null);
    
    if (recentAlerts.length > 0) {
      socket.emit('new-alerts', recentAlerts);
    }
  });
}

// Function to emit updated statistics
function emitUpdatedStatistics(socket) {
  const alertsPath = path.join(__dirname, '..', 'build', 'logs', 'alerts.log');
  
  if (!fs.existsSync(alertsPath)) {
    return;
  }
  
  // Use the same logic as the alert-stats endpoint but for real-time updates
  const readline = require('readline');
  const stream = fs.createReadStream(alertsPath, { 
    encoding: 'utf8'
  });
  
  const rl = readline.createInterface({
    input: stream,
    crlfDelay: Infinity
  });
  
  const attackStats = {};
  const sourceIPs = {};
  const destIPs = {};
  let totalAlerts = 0;
  const lines = [];
  
  rl.on('line', (line) => {
    if (line.trim() !== '') {
      lines.push(line);
    }
  });
  
  rl.on('close', () => {
    // Process all lines (session filtering will be done client-side for real-time updates)
    lines.forEach(line => {
      const parts = line.match(/\[(.*?)\] ALERT #(\d+) \(SID: (\d+)\): (.*?) \((\d+\.\d+\.\d+\.\d+):(\d+) -> (\d+\.\d+\.\d+\.\d+):(\d+)\) Protocol: (.*?) Severity: (\d+)/);
      
      if (parts) {
        totalAlerts++;
        const attackType = parts[4];
        const sourceIP = parts[5];
        const destIP = parts[7];
        
        // Count attack types
        attackStats[attackType] = (attackStats[attackType] || 0) + 1;
        sourceIPs[sourceIP] = (sourceIPs[sourceIP] || 0) + 1;
        destIPs[destIP] = (destIPs[destIP] || 0) + 1;
      }
    });
    
    // Format for chart.js
    const attackLabels = Object.keys(attackStats);
    const attackData = Object.values(attackStats);
    
    // Emit real-time statistics update
    socket.emit('stats-update', {
      totalAlerts,
      attackStats: {
        labels: attackLabels,
        data: attackData
      },
      topSources: Object.entries(sourceIPs)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5)
        .map(([ip, count]) => ({ ip, count })),
      topTargets: Object.entries(destIPs)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5)
        .map(([ip, count]) => ({ ip, count }))
    });
  });
}

// Start the server
const PORT = process.env.PORT || 5000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`NIDS Dashboard server running on port ${PORT}`);
});
