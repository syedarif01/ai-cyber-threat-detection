import { useEffect, useState } from 'react'

import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Legend
} from 'recharts'

import './App.css'

const API_URL = 'http://127.0.0.1:8000'

const COLORS = ['#ef4444', '#f59e0b', '#22c55e']

// Format alert timestamp
const formatTimestamp = (timestamp) => {
  if (!timestamp) return 'Not available'

  const date = new Date(timestamp)

  if (Number.isNaN(date.getTime())) {
    return 'Not available'
  }

  return date.toLocaleString('en-IN', {
    day: '2-digit',
    month: 'long',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    hour12: true
  })
}

function App() {
  const [alerts, setAlerts] = useState([])
  const [apiStatus, setApiStatus] = useState('Checking...')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [activePage, setActivePage] = useState('overview')

  // Alert history states
  const [historyAlerts, setHistoryAlerts] = useState([])
  const [historyLoading, setHistoryLoading] = useState(false)
  const [historyError, setHistoryError] = useState('')

  // Search and filter states
  const [searchTerm, setSearchTerm] = useState('')
  const [severityFilter, setSeverityFilter] = useState('All')

  // Alert details state
  const [selectedAlert, setSelectedAlert] = useState(null)

  // Fetch current alerts
  const fetchAlerts = async () => {
    setLoading(true)
    setError('')

    try {
      const response = await fetch(`${API_URL}/detect`)

      if (!response.ok) {
        throw new Error(`API error: ${response.status}`)
      }

      const data = await response.json()

      setAlerts(Array.isArray(data.alerts) ? data.alerts : [])
      setApiStatus('Online')
    } catch (err) {
      setApiStatus('Offline')
      setError('Unable to connect to the detection API.')
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  // Fetch historical alerts from PostgreSQL
  const fetchHistory = async () => {
    setHistoryLoading(true)
    setHistoryError('')

    try {
      const response = await fetch(`${API_URL}/history?limit=100`)

      if (!response.ok) {
        throw new Error(`API error: ${response.status}`)
      }

      const data = await response.json()

      setHistoryAlerts(
        Array.isArray(data.alerts) ? data.alerts : []
      )

    } catch (err) {
      setHistoryError('Unable to load alert history.')
      console.error(err)
    } finally {
      setHistoryLoading(false)
    }
  }

  // Check backend health
  const checkAPI = async () => {
    try {
      const response = await fetch(`${API_URL}/health`)

      if (!response.ok) {
        throw new Error('API unavailable')
      }

      setApiStatus('Online')
    } catch {
      setApiStatus('Offline')
    }
  }

  // Load data when application starts
  useEffect(() => {
    checkAPI()
    fetchAlerts()
  }, [])

  // Calculate statistics
  const highAlerts = alerts.filter(
    alert => alert.severity === 'High'
  ).length

  const mediumAlerts = alerts.filter(
    alert => alert.severity === 'Medium'
  ).length

  const lowAlerts = alerts.filter(
    alert => alert.severity === 'Low'
  ).length

  const suspiciousIPs = new Set(
    alerts.map(alert => alert.source_ip)
  ).size

  // Search and filter current alerts
  const filteredAlerts = alerts.filter(alert => {
    const search = searchTerm.toLowerCase().trim()

    const matchesSearch =
      String(alert.source_ip || '').toLowerCase().includes(search) ||
      String(alert.alert_type || '').toLowerCase().includes(search) ||
      String(alert.ml_prediction || '').toLowerCase().includes(search)

    const matchesSeverity =
      severityFilter === 'All' ||
      String(alert.severity || '').toLowerCase() ===
        severityFilter.toLowerCase()

    return matchesSearch && matchesSeverity
  })

  // Filter historical alerts
  const filteredHistory = historyAlerts.filter(alert => {
    const search = searchTerm.toLowerCase().trim()

    const matchesSearch =
      String(alert.source_ip || '').toLowerCase().includes(search) ||
      String(alert.alert_type || '').toLowerCase().includes(search) ||
      String(alert.description || '').toLowerCase().includes(search)

    const matchesSeverity =
      severityFilter === 'All' ||
      String(alert.severity || '').toLowerCase() ===
        severityFilter.toLowerCase()

    return matchesSearch && matchesSeverity
  })

  // Reset filters
  const resetFilters = () => {
    setSearchTerm('')
    setSeverityFilter('All')
  }

  // Chart data
  const chartData = [
    { severity: 'High', threats: highAlerts },
    { severity: 'Medium', threats: mediumAlerts },
    { severity: 'Low', threats: lowAlerts }
  ]

  const pieData = chartData.filter(
    item => item.threats > 0
  )

  // Page titles
  const pageTitles = {
    overview: 'Security Overview',
    alerts: 'Security Alerts',
    monitoring: 'Threat Monitoring',
    analytics: 'Security Analytics',
    history: 'Alert History'
  }

  // Statistics cards
  const renderStats = () => (
    <section className="stats-grid">

      <div className="stat-card">
        <span>Total Threat Alerts</span>
        <h2>{alerts.length}</h2>
        <small>Alerts returned by API</small>
      </div>

      <div className="stat-card">
        <span>High Severity</span>
        <h2 className="red-text">{highAlerts}</h2>
        <small>High-priority alerts</small>
      </div>

      <div className="stat-card">
        <span>Suspicious IPs</span>
        <h2>{suspiciousIPs}</h2>
        <small>Unique IPs in current results</small>
      </div>

      <div className="stat-card">
        <span>API Status</span>
        <h2 className={apiStatus === 'Online' ? 'green-text' : 'red-text'}>
          {apiStatus}
        </h2>
        <small>Backend connection</small>
      </div>

    </section>
  )

  // Detection engine
  const renderDetectionEngine = () => (
    <section className="info-grid">

      <div className="panel">
        <h3>Detection Engine</h3>

        <div className="method">
          <span>Rule-Based Detection</span>
          <strong>Active</strong>
        </div>

        <div className="method">
          <span>Machine Learning</span>
          <strong>Active</strong>
        </div>

        <div className="method">
          <span>ML Model</span>
          <strong>Random Forest</strong>
        </div>
      </div>

      <div className="panel">
        <h3>Threat Intelligence</h3>

        <div className="threat-summary">
          <span>Current detected alerts</span>
          <h2>{alerts.length}</h2>
          <p>Based on the latest API response</p>
        </div>
      </div>

    </section>
  )

  // Alert details popup
  const renderAlertDetails = () => {
    if (!selectedAlert) return null

    const detectionMethods = Array.isArray(
      selectedAlert.detection_methods
    )
      ? selectedAlert.detection_methods
      : []

    const timestamp =
      selectedAlert.created_at || selectedAlert.timestamp

    return (
      <div
        className="alert-modal-overlay"
        onClick={() => setSelectedAlert(null)}
      >
        <div
          className="alert-details-modal"
          onClick={event => event.stopPropagation()}
        >

          <div className="alert-modal-header">
            <div>
              <h2>Alert Details</h2>
              <p>Detailed security threat information</p>
            </div>

            <button
              className="close-modal-button"
              onClick={() => setSelectedAlert(null)}
              aria-label="Close alert details"
            >
              ×
            </button>
          </div>

          <div className="alert-details-content">

            {selectedAlert.id !== undefined && (
              <div className="detail-item">
                <span>Alert ID</span>
                <strong>{selectedAlert.id}</strong>
              </div>
            )}

            <div className="detail-item">
              <span>Source IP Address</span>
              <strong>{selectedAlert.source_ip || 'N/A'}</strong>
            </div>

            <div className="detail-item">
              <span>Alert Type</span>
              <strong>{selectedAlert.alert_type || 'N/A'}</strong>
            </div>

            <div className="detail-item">
              <span>Severity</span>
              <strong className={`severity ${String(
                selectedAlert.severity || ''
              ).toLowerCase()}`}>
                {selectedAlert.severity || 'N/A'}
              </strong>
            </div>

            <div className="detail-item">
              <span>Failed Login Attempts</span>
              <strong>{selectedAlert.failed_attempts ?? 'N/A'}</strong>
            </div>

            <div className="detail-item">
              <span>Machine Learning Prediction</span>
              <strong>{selectedAlert.ml_prediction || 'N/A'}</strong>
            </div>

            <div className="detail-item">
              <span>Detection Methods</span>
              <strong>
                {detectionMethods.length > 0
                  ? detectionMethods.join(', ')
                  : 'Not provided by API'}
              </strong>
            </div>

            <div className="detail-item">
              <span>Alert Description</span>
              <strong>
                {selectedAlert.description || 'No description provided'}
              </strong>
            </div>

            <div className="detail-item">
              <span>Created At</span>
              <strong>{formatTimestamp(timestamp)}</strong>
            </div>

          </div>

          <div className="alert-modal-footer">
            <button
              className="close-details-button"
              onClick={() => setSelectedAlert(null)}
            >
              Close Details
            </button>
          </div>

        </div>
      </div>
    )
  }

  // Security alerts table
  const renderAlerts = () => (
    <section className="panel alerts-panel">

      <div className="section-heading">
        <div>
          <h3>Security Alerts</h3>
          <p>Suspicious activity detected by the AI engine</p>
        </div>

        <span className="live-label">● LIVE API DATA</span>
      </div>

      {error && (
        <p className="error-message">{error}</p>
      )}

      <div className="alert-controls">

        <input
          type="text"
          className="search-input"
          placeholder="Search by IP, alert type or ML prediction..."
          value={searchTerm}
          onChange={event => setSearchTerm(event.target.value)}
        />

        <select
          className="severity-filter"
          value={severityFilter}
          onChange={event => setSeverityFilter(event.target.value)}
        >
          <option value="All">All Severities</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>

        <button
          className="reset-filter-button"
          onClick={resetFilters}
        >
          Reset
        </button>

      </div>

      <p className="filter-count">
        Showing {filteredAlerts.length} of {alerts.length} alerts
      </p>

      {loading && (
        <p>Loading security alerts...</p>
      )}

      {!loading && !error && alerts.length === 0 && (
        <p>No threat alerts returned by the API.</p>
      )}

      {!loading && alerts.length > 0 && filteredAlerts.length === 0 && (
        <p>No matching alerts found. Try changing your search or filter.</p>
      )}

      {!loading && filteredAlerts.length > 0 && (
        <div className="table-container">

          <table>
            <thead>
              <tr>
                <th>Source IP</th>
                <th>Alert Type</th>
                <th>Severity</th>
                <th>Failed Attempts</th>
                <th>ML Prediction</th>
                <th>Action</th>
              </tr>
            </thead>

            <tbody>
              {filteredAlerts.map((alert, index) => (
                <tr key={`${alert.source_ip}-${index}`}>

                  <td>{alert.source_ip}</td>
                  <td>{alert.alert_type}</td>

                  <td>
                    <span className={`severity ${String(
                      alert.severity || ''
                    ).toLowerCase()}`}>
                      {alert.severity}
                    </span>
                  </td>

                  <td>{alert.failed_attempts ?? 'N/A'}</td>
                  <td>{alert.ml_prediction || 'N/A'}</td>

                  <td>
                    <button
                      className="view-details-button"
                      onClick={() => setSelectedAlert(alert)}
                    >
                      View Details
                    </button>
                  </td>

                </tr>
              ))}
            </tbody>
          </table>

        </div>
      )}

    </section>
  )

  // Historical alerts page
  const renderHistory = () => (
    <section className="panel alerts-panel">

      <div className="section-heading">
        <div>
          <h3>Historical Security Alerts</h3>
          <p>Previously detected and stored threats from PostgreSQL</p>
        </div>

        <button
          className="refresh-button"
          onClick={fetchHistory}
          disabled={historyLoading}
        >
          {historyLoading ? 'Loading...' : '↻ Refresh History'}
        </button>
      </div>

      {historyError && (
        <p className="error-message">{historyError}</p>
      )}

      <div className="alert-controls">

        <input
          type="text"
          className="search-input"
          placeholder="Search history by IP, type or description..."
          value={searchTerm}
          onChange={event => setSearchTerm(event.target.value)}
        />

        <select
          className="severity-filter"
          value={severityFilter}
          onChange={event => setSeverityFilter(event.target.value)}
        >
          <option value="All">All Severities</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>

        <button
          className="reset-filter-button"
          onClick={resetFilters}
        >
          Reset
        </button>

      </div>

      <p className="filter-count">
        Showing {filteredHistory.length} of {historyAlerts.length} historical alerts
      </p>

      {historyLoading && (
        <p>Loading historical alerts from PostgreSQL...</p>
      )}

      {!historyLoading && !historyError && historyAlerts.length === 0 && (
        <p>No historical alerts found in the database.</p>
      )}

      {!historyLoading && historyAlerts.length > 0 && filteredHistory.length === 0 && (
        <p>No matching historical alerts found.</p>
      )}

      {!historyLoading && filteredHistory.length > 0 && (
        <div className="table-container">

          <table>
            <thead>
              <tr>
                <th>Alert ID</th>
                <th>Source IP</th>
                <th>Alert Type</th>
                <th>Severity</th>
                <th>Created At</th>
                <th>Action</th>
              </tr>
            </thead>

            <tbody>
              {filteredHistory.map(alert => (
                <tr key={alert.id}>

                  <td>#{alert.id}</td>

                  <td>{alert.source_ip}</td>

                  <td>{alert.alert_type}</td>

                  <td>
                    <span className={`severity ${String(
                      alert.severity || ''
                    ).toLowerCase()}`}>
                      {alert.severity}
                    </span>
                  </td>

                  <td>{formatTimestamp(alert.created_at)}</td>

                  <td>
                    <button
                      className="view-details-button"
                      onClick={() => setSelectedAlert(alert)}
                    >
                      View Details
                    </button>
                  </td>

                </tr>
              ))}
            </tbody>
          </table>

        </div>
      )}

    </section>
  )

  // Bar chart
  const renderBarChart = () => (
    <section className="panel chart-panel">

      <h3>Threat Severity Distribution</h3>

      <p>Number of threats detected at each severity level.</p>

      <div className="chart-container">

        <ResponsiveContainer width="100%" height={320}>
          <BarChart
            data={chartData}
            margin={{ top: 20, right: 20, left: 0, bottom: 10 }}
          >

            <CartesianGrid
              strokeDasharray="3 3"
              stroke="#475569"
            />

            <XAxis dataKey="severity" stroke="#cbd5e1" />

            <YAxis allowDecimals={false} stroke="#cbd5e1" />

            <Tooltip
              contentStyle={{
                backgroundColor: '#0f172a',
                border: '1px solid #475569',
                borderRadius: '8px',
                color: '#ffffff'
              }}
              formatter={value => [`${value}`, 'Threats']}
            />

            <Bar
              dataKey="threats"
              radius={[8, 8, 0, 0]}
              isAnimationActive
            >

              {chartData.map((entry, index) => (
                <Cell
                  key={`bar-${entry.severity}`}
                  fill={COLORS[index]}
                />
              ))}

            </Bar>

          </BarChart>
        </ResponsiveContainer>

      </div>

    </section>
  )

  // Pie chart
  const renderPieChart = () => (
    <section className="panel chart-panel">

      <h3>Threat Distribution</h3>

      <p>Percentage of detected threats by severity.</p>

      <div className="chart-container">

        {pieData.length === 0 ? (
          <p className="empty-chart">
            No threat data available for visualization.
          </p>
        ) : (

          <ResponsiveContainer width="100%" height={340}>
            <PieChart>

              <Pie
                data={pieData}
                dataKey="threats"
                nameKey="severity"
                cx="50%"
                cy="45%"
                outerRadius={105}
                innerRadius={45}
                paddingAngle={4}
                label={({ name, percent }) =>
                  `${name} ${(percent * 100).toFixed(0)}%`
                }
                labelLine={{ stroke: '#cbd5e1' }}
                isAnimationActive
              >

                {pieData.map(entry => {
                  const originalIndex = chartData.findIndex(
                    item => item.severity === entry.severity
                  )

                  return (
                    <Cell
                      key={`pie-${entry.severity}`}
                      fill={COLORS[originalIndex]}
                    />
                  )
                })}

              </Pie>

              <Tooltip
                contentStyle={{
                  backgroundColor: '#0f172a',
                  border: '1px solid #475569',
                  borderRadius: '8px',
                  color: '#ffffff'
                }}
                formatter={value => [`${value}`, 'Threats']}
              />

              <Legend />

            </PieChart>
          </ResponsiveContainer>

        )}

      </div>

    </section>
  )

  return (
    <div className="dashboard">

      {/* Sidebar */}
      <aside className="sidebar">

        <div className="brand">
          <span className="brand-icon">🛡</span>

          <div>
            <h2>CyberGuard AI</h2>
            <small>THREAT INTELLIGENCE</small>
          </div>
        </div>

        <div className="menu-title">
          MAIN MENU
        </div>

        <nav>

          <a
            href="#overview"
            className={activePage === 'overview' ? 'active' : ''}
            onClick={() => setActivePage('overview')}
          >
            ▦ Dashboard
          </a>

          <a
            href="#alerts"
            className={activePage === 'alerts' ? 'active' : ''}
            onClick={() => setActivePage('alerts')}
          >
            ⚠ Security Alerts
          </a>

          <a
            href="#monitoring"
            className={activePage === 'monitoring' ? 'active' : ''}
            onClick={() => setActivePage('monitoring')}
          >
            ◉ Threat Monitoring
          </a>

          <a
            href="#analytics"
            className={activePage === 'analytics' ? 'active' : ''}
            onClick={() => setActivePage('analytics')}
          >
            ▥ Analytics
          </a>

          <a
            href="#history"
            className={activePage === 'history' ? 'active' : ''}
            onClick={() => {
              setActivePage('history')
              resetFilters()
              fetchHistory()
            }}
          >
            ◷ Alert History
          </a>

        </nav>

        <div className="sidebar-bottom">

          <div className="system-label">
            SYSTEM STATUS
          </div>

          <p>
            <span
              className={
                apiStatus === 'Online'
                  ? 'green-dot'
                  : 'red-dot'
              }
            ></span>

            API {apiStatus}
          </p>

        </div>

      </aside>

      {/* Main Content */}
      <main className="main-content">

        <header className="topbar">

          <div>
            <h1>{pageTitles[activePage]}</h1>
            <p>AI-powered cyber threat detection and response</p>
          </div>

          {activePage !== 'history' && (
            <button
              className="refresh-button"
              onClick={fetchAlerts}
              disabled={loading}
            >
              {loading ? 'Refreshing...' : '↻ Refresh Data'}
            </button>
          )}

        </header>

        {/* Dashboard */}
        {activePage === 'overview' && (
          <>
            {renderStats()}
            {renderDetectionEngine()}
            {renderAlerts()}
          </>
        )}

        {/* Security Alerts */}
        {activePage === 'alerts' && (
          <>
            {renderStats()}
            {renderAlerts()}
          </>
        )}

        {/* Threat Monitoring */}
        {activePage === 'monitoring' && (
          <>
            {renderDetectionEngine()}

            <section className="panel">

              <h3>Monitoring Status</h3>

              <p>Rule-based detection: Active</p>
              <p>Machine learning detection: Active</p>
              <p>Backend API: {apiStatus}</p>
              <p>Currently detected threats: {alerts.length}</p>

            </section>
          </>
        )}

        {/* Analytics */}
        {activePage === 'analytics' && (
          <>
            {renderStats()}

            <section className="panel">

              <h3>Threat Analytics</h3>

              <div className="method">
                <span>Total detected threats</span>
                <strong>{alerts.length}</strong>
              </div>

              <div className="method">
                <span>High severity threats</span>
                <strong>{highAlerts}</strong>
              </div>

              <div className="method">
                <span>Medium severity threats</span>
                <strong>{mediumAlerts}</strong>
              </div>

              <div className="method">
                <span>Low severity threats</span>
                <strong>{lowAlerts}</strong>
              </div>

              <div className="method">
                <span>Unique suspicious IPs</span>
                <strong>{suspiciousIPs}</strong>
              </div>

              <div className="method">
                <span>Detection model</span>
                <strong>Random Forest</strong>
              </div>

            </section>

            {renderBarChart()}
            {renderPieChart()}
          </>
        )}

        {/* Alert History */}
        {activePage === 'history' && renderHistory()}

        {/* Footer */}
        <footer>
          AI Cyber Threat Detection & Response Platform
          <span>Development Version 1.0.0</span>
        </footer>

      </main>

      {/* Alert Details Popup */}
      {renderAlertDetails()}

    </div>
  )
}

export default App