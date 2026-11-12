import { useEffect, useState } from 'react'

import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer
} from 'recharts'

import './App.css'

const API_URL = 'http://127.0.0.1:8000'

const ACTIVE_STATUSES = [
  'New',
  'Acknowledged',
  'Investigating'
]

// --------------------------------------------------
// HELPER FUNCTIONS
// --------------------------------------------------

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

const formatOccurrences = (count) => {
  const value = Number(count ?? 1)

  return Number.isFinite(value) && value > 0
    ? value
    : 1
}

const parseDetectionMethods = (methods) => {
  if (!methods) return []

  if (Array.isArray(methods)) return methods

  try {
    const parsed = JSON.parse(methods)
    return Array.isArray(parsed) ? parsed : []
  } catch {
    return [methods]
  }
}

// --------------------------------------------------
// GET LATEST ACTIVE INCIDENT PER SOURCE IP
// --------------------------------------------------

const getLatestActiveIncidents = (records) => {
  if (!Array.isArray(records)) return []

  const latestByIP = new Map()

  records.forEach(alert => {
    if (!ACTIVE_STATUSES.includes(alert.status)) return

    const ip = alert.source_ip

    if (!ip) return

    const existing = latestByIP.get(ip)

    const alertTime = new Date(
      alert.last_seen_at || alert.created_at || 0
    ).getTime()

    const existingTime = existing
      ? new Date(
          existing.last_seen_at || existing.created_at || 0
        ).getTime()
      : -1

    if (
      !existing ||
      alertTime > existingTime ||
      (
        alertTime === existingTime &&
        Number(alert.id) > Number(existing.id)
      )
    ) {
      latestByIP.set(ip, alert)
    }
  })

  return Array.from(latestByIP.values())
}

// --------------------------------------------------
// MAIN APPLICATION
// --------------------------------------------------

function App() {

  // Main dashboard data
  const [alerts, setAlerts] = useState([])

  const [historyAlerts, setHistoryAlerts] = useState([])

  const [apiStatus, setApiStatus] = useState('Checking...')

  const [loading, setLoading] = useState(false)

  const [error, setError] = useState('')

  const [activePage, setActivePage] = useState('overview')

  // Search and filters
  const [alertSearch, setAlertSearch] = useState('')

  const [severityFilter, setSeverityFilter] = useState('All')

  const [statusFilter, setStatusFilter] = useState('All')

  const [alertTypeFilter, setAlertTypeFilter] = useState('All')

  // History
  const [historyLoading, setHistoryLoading] = useState(false)

  const [historyError, setHistoryError] = useState('')

  // Alert details
  const [selectedAlert, setSelectedAlert] = useState(null)

  const [detailsLoading, setDetailsLoading] = useState(false)

  const [detailsError, setDetailsError] = useState('')

  // Status management
  const [statusUpdating, setStatusUpdating] = useState(false)

  const [statusError, setStatusError] = useState('')

  const [statusSuccess, setStatusSuccess] = useState('')

  // Analyst notes
  const [newAnalystNote, setNewAnalystNote] = useState('')

  const [noteSaving, setNoteSaving] = useState(false)

  const [noteError, setNoteError] = useState('')

  const [noteSuccess, setNoteSuccess] = useState('')
  // --------------------------------------------------
// INCIDENT RESPONSE MANAGEMENT
// --------------------------------------------------

const [responseActions, setResponseActions] = useState([])

const [responseAuditLogs, setResponseAuditLogs] = useState([])

const [responseStatusFilter, setResponseStatusFilter] = useState('All')

const [responseLoading, setResponseLoading] = useState(false)

const [responseError, setResponseError] = useState('')

const [responseSuccess, setResponseSuccess] = useState('')

const [selectedResponseAction, setSelectedResponseAction] = useState(
  'Investigate Source IP'
)

const [responseDescription, setResponseDescription] = useState('')

const [analystName, setAnalystName] = useState('Security Analyst')

const [selectedResponseAlertId, setSelectedResponseAlertId] = useState('')


  // --------------------------------------------------
  // API HEALTH CHECK
  // --------------------------------------------------

  const checkAPI = async () => {

    try {

      const response = await fetch(`${API_URL}/health`)

      if (!response.ok) {
        throw new Error('API unavailable')
      }

      setApiStatus('Online')

    } catch (err) {

      setApiStatus('Offline')

      console.error(err)

    }
  }


  // --------------------------------------------------
  // FETCH HISTORY
  // READ-ONLY: DOES NOT EXECUTE DETECTION
  // --------------------------------------------------

  const fetchHistory = async () => {

    setHistoryLoading(true)

    setHistoryError('')

    try {

      const response = await fetch(
        `${API_URL}/history?limit=100`
      )

      if (!response.ok) {
        throw new Error(`API error: ${response.status}`)
      }

      const data = await response.json()

      const records = Array.isArray(data.alerts)
        ? data.alerts
        : []

      setHistoryAlerts(records)

      return records

    } catch (err) {

      setHistoryError('Unable to load alert history.')

      console.error(err)

      return null

    } finally {

      setHistoryLoading(false)

    }
  }
  // --------------------------------------------------
// FETCH RESPONSE ACTION HISTORY
// GET /response-actions
// --------------------------------------------------

const fetchResponseActions = async () => {
  setResponseLoading(true)
  setResponseError('')

  try {
    const [response, auditResponse] = await Promise.all([
      fetch(`${API_URL}/response-actions?limit=100`),
      fetch(`${API_URL}/audit-logs?entity_type=ResponseAction&limit=200`),
    ])

    if (!response.ok) {
      throw new Error(
        `Response API error: ${response.status}`
      )
    }

    const data = await response.json()

    const records = Array.isArray(data.response_actions)
      ? data.response_actions
      : []

    setResponseActions(records)

    if (auditResponse.ok) {
      const auditData = await auditResponse.json()
      setResponseAuditLogs(Array.isArray(auditData.audit_logs) ? auditData.audit_logs : [])
    } else {
      setResponseAuditLogs([])
    }

  } catch (err) {
    console.error(err)

    setResponseError(
      err.message || 'Unable to load response-action history.'
    )

  } finally {
    setResponseLoading(false)
  }
}


// --------------------------------------------------
// CREATE INCIDENT RESPONSE ACTION
// POST /alerts/{alert_id}/response-actions
// --------------------------------------------------

const createResponseAction = async () => {
  if (!selectedResponseAlertId) {
    setResponseError('Please select a security incident.')
    return
  }

  setResponseLoading(true)
  setResponseError('')
  setResponseSuccess('')

  try {
    const response = await fetch(
      `${API_URL}/alerts/${selectedResponseAlertId}/response-actions`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action_type: selectedResponseAction,
          description: responseDescription.trim() || null,
        }),
      }
    )

    const data = await response.json()
    if (!response.ok) {
      throw new Error(data.detail || 'Unable to create response action.')
    }

    setResponseSuccess('Response action created successfully.')
    setResponseDescription('')
    await fetchResponseActions()
  } catch (err) {
    console.error(err)
    setResponseError(err.message || 'Unable to create response action.')
  } finally {
    setResponseLoading(false)
  }
}


// --------------------------------------------------
// APPROVE OR REJECT RESPONSE ACTION
// PATCH /response-actions/{action_id}/decision
// --------------------------------------------------

const decideResponseAction = async (actionId, decision) => {
  setResponseLoading(true)
  setResponseError('')
  setResponseSuccess('')

  try {
    const response = await fetch(
      `${API_URL}/response-actions/${actionId}/decision`,
      {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          decision,
          analyst_name: analystName.trim() || 'Security Analyst',
        }),
      }
    )

    const data = await response.json()
    if (!response.ok) {
      throw new Error(data.detail || `Unable to ${decision.toLowerCase()} action.`)
    }

    setResponseSuccess(`Response action ${decision.toLowerCase()} successfully.`)
    await fetchResponseActions()
  } catch (err) {
    console.error(err)
    setResponseError(err.message || 'Unable to update response action.')
  } finally {
    setResponseLoading(false)
  }
}


// --------------------------------------------------
// SIMULATE APPROVED RESPONSE ACTION
// POST /response-actions/{action_id}/simulate
// --------------------------------------------------

const simulateResponseAction = async (actionId) => {
  setResponseLoading(true)
  setResponseError('')
  setResponseSuccess('')

  try {
    const response = await fetch(
      `${API_URL}/response-actions/${actionId}/simulate`,
      { method: 'POST' }
    )

    const data = await response.json()
    if (!response.ok) {
      throw new Error(data.detail || 'Unable to simulate response action.')
    }

    setResponseSuccess(
      'Response action simulated successfully. No real network changes were made.'
    )
    await fetchResponseActions()
  } catch (err) {
    console.error(err)
    setResponseError(err.message || 'Unable to simulate response action.')
  } finally {
    setResponseLoading(false)
  }
}


  // --------------------------------------------------
  // FETCH ACTIVE INCIDENTS
  // READ-ONLY: DOES NOT EXECUTE DETECTION
  // --------------------------------------------------

  const fetchAlerts = async () => {

    setLoading(true)

    setError('')

    try {

      const response = await fetch(
        `${API_URL}/history?limit=100`
      )

      if (!response.ok) {
        throw new Error(`API error: ${response.status}`)
      }

      const data = await response.json()

      const records = Array.isArray(data.alerts)
        ? data.alerts
        : []

      // Preserve every database record in history.
      setHistoryAlerts(records)

      // Display only the latest active incident per IP.
      const activeAlerts = getLatestActiveIncidents(records)

      setAlerts(activeAlerts)

      setApiStatus('Online')

    } catch (err) {

      setApiStatus('Offline')

      setError('Unable to load saved security incidents.')

      console.error(err)

    } finally {

      setLoading(false)

    }
  }
    // --------------------------------------------------
  // MANUAL THREAT DETECTION
  // POST /detect
  // --------------------------------------------------

  const runDetection = async () => {

    if (loading) return

    setLoading(true)

    setError('')

    try {

      const response = await fetch(
        `${API_URL}/detect`,
        {
          method: 'POST'
        }
      )

      const data = await response.json()

      if (!response.ok) {

        throw new Error(
          data.detail || 'Threat detection failed.'
        )

      }

      const detectedAlerts = Array.isArray(data.alerts)
        ? data.alerts
        : []

      // Display only the latest active incident per IP.
      const activeAlerts = getLatestActiveIncidents(
        detectedAlerts
      )

      setAlerts(activeAlerts)

      setApiStatus('Online')

      // Refresh complete incident history.
      await fetchHistory()

      console.log(
        'Detection completed successfully:',
        data
      )

    } catch (err) {

      setError(
        err.message || 'Unable to execute threat detection.'
      )

      console.error(err)

    } finally {

      setLoading(false)

    }
  }


  // --------------------------------------------------
  // FIND STORED INCIDENT
  // --------------------------------------------------

  const getStoredIncident = (
    alert,
    history = historyAlerts
  ) => {

    if (!alert || !Array.isArray(history)) {
      return null
    }

    // First match using database ID.
    if (alert.id != null) {

      const matchedById = history.find(
        item => Number(item.id) === Number(alert.id)
      )

      if (matchedById) {
        return matchedById
      }
    }

    // Fallback: match using source IP.
    const matchingIncidents = history.filter(item => {

      if (item.source_ip !== alert.source_ip) {
        return false
      }

      if (!ACTIVE_STATUSES.includes(item.status)) {
        return false
      }

      return true

    })

    matchingIncidents.sort((a, b) => {

      const timeA = new Date(
        a.last_seen_at || a.created_at
      ).getTime()

      const timeB = new Date(
        b.last_seen_at || b.created_at
      ).getTime()

      return timeB - timeA

    })

    return matchingIncidents[0] || null
  }


  // --------------------------------------------------
  // ALERT DISPLAY DATA
  // DATABASE VALUES TAKE PRIORITY
  // --------------------------------------------------

  const getAlertDisplay = (alert) => {

    const incident = getStoredIncident(alert)

    return {

      ...alert,

      ...(incident || {}),

      severity:
        incident?.severity ||
        alert?.severity ||
        'Low',

      occurrence_count:
        incident?.occurrence_count ??
        alert?.occurrence_count ??
        1,

      last_seen_at:
        incident?.last_seen_at ||
        alert?.last_seen_at ||
        null,

      created_at:
        incident?.created_at ||
        alert?.created_at ||
        alert?.timestamp ||
        null,

      status:
        incident?.status ||
        alert?.status ||
        'New'

    }
  }


  // --------------------------------------------------
  // OPEN ALERT DETAILS
  // --------------------------------------------------

  const openAlertDetails = async (alert) => {

    setDetailsError('')

    setDetailsLoading(false)

    setStatusError('')

    setStatusSuccess('')

    setNoteError('')

    setNoteSuccess('')

    setNewAnalystNote('')

    const incident = getStoredIncident(alert)

    const displayAlert = {
      ...alert,
      ...(incident || {})
    }

    setSelectedAlert(displayAlert)

    const incidentId = displayAlert.id

    if (!incidentId) {

      setDetailsError(
        'No matching database incident was found.'
      )

      return
    }

    setDetailsLoading(true)

    try {

      const response = await fetch(
        `${API_URL}/alerts/${incidentId}`
      )

      if (!response.ok) {

        throw new Error(
          `Details API error: ${response.status}`
        )

      }

      const data = await response.json()

      const fullAlert = data.alert || data

      setSelectedAlert(previous => ({
        ...previous,
        ...fullAlert
      }))

    } catch (err) {

      console.error(err)

      setDetailsError(
        'Could not retrieve additional incident details.'
      )

    } finally {

      setDetailsLoading(false)

    }
  }
    // --------------------------------------------------
  // UPDATE INCIDENT STATUS
  // --------------------------------------------------

  const updateIncidentStatus = async (newStatus) => {

    if (!selectedAlert?.id || statusUpdating) {
      return
    }

    setStatusUpdating(true)

    setStatusError('')

    setStatusSuccess('')

    try {

      const response = await fetch(
        `${API_URL}/alerts/${selectedAlert.id}/status`,
        {
          method: 'PATCH',

          headers: {
            'Content-Type': 'application/json'
          },

          body: JSON.stringify({
            status: newStatus
          })
        }
      )

      const data = await response.json()

      if (!response.ok) {
        throw new Error(
          data.detail || 'Unable to update incident status.'
        )
      }

      const updatedAlert = data.alert || data

      setSelectedAlert(updatedAlert)

      setStatusSuccess(
        `Incident status successfully changed to ${newStatus}.`
      )

      // Refresh history only. Do not run detection.
      await fetchHistory()

    } catch (err) {

      console.error(err)

      setStatusError(
        err.message || 'Incident status update failed.'
      )

    } finally {

      setStatusUpdating(false)

    }
  }


  // --------------------------------------------------
  // SAVE ANALYST NOTES
  // --------------------------------------------------

  const saveAnalystNote = async () => {

    if (
      !selectedAlert?.id ||
      !newAnalystNote.trim() ||
      noteSaving
    ) {
      return
    }

    setNoteSaving(true)

    setNoteError('')

    setNoteSuccess('')

    let noteWasSaved = false

    try {

      const response = await fetch(
        `${API_URL}/alerts/${selectedAlert.id}/notes`,
        {
          method: 'PATCH',

          headers: {
            'Content-Type': 'application/json'
          },

          body: JSON.stringify({
            note: newAnalystNote.trim()
          })
        }
      )

      const data = await response.json()

      if (!response.ok) {
        throw new Error(
          data.detail || 'Unable to save analyst note.'
        )
      }

      noteWasSaved = true

      const detailsResponse = await fetch(
        `${API_URL}/alerts/${selectedAlert.id}`
      )

      if (!detailsResponse.ok) {
        throw new Error(
          'Note saved, but refreshing details failed.'
        )
      }

      const updatedAlert = await detailsResponse.json()

      setSelectedAlert(
        updatedAlert.alert || updatedAlert
      )

      setNewAnalystNote('')

      setNoteSuccess(
        'Analyst note saved successfully!'
      )

      await fetchHistory()

    } catch (err) {

      console.error(err)

      if (noteWasSaved) {

        setNewAnalystNote('')

        setNoteSuccess(
          'Note saved successfully. Reopen the alert to refresh its details.'
        )

      } else {

        setNoteError(
          err.message || 'Unable to save analyst note.'
        )

      }

    } finally {

      setNoteSaving(false)

    }
  }


  // --------------------------------------------------
  // APPLICATION STARTUP
  // READ DATABASE ONLY
  // --------------------------------------------------

  useEffect(() => {

    checkAPI()

    fetchAlerts()

    fetchResponseActions()

  }, [])


  // --------------------------------------------------
  // STATISTICS
  // --------------------------------------------------

  const criticalAlerts = alerts.filter(
    alert => getAlertDisplay(alert).severity === 'Critical'
  ).length

  const highAlerts = alerts.filter(
    alert => getAlertDisplay(alert).severity === 'High'
  ).length

  const mediumAlerts = alerts.filter(
    alert => getAlertDisplay(alert).severity === 'Medium'
  ).length

  const lowAlerts = alerts.filter(
    alert => getAlertDisplay(alert).severity === 'Low'
  ).length

  const suspiciousIPs = new Set(
    alerts.map(alert => alert.source_ip)
  ).size

  const chartData = [

    {
      severity: 'Critical',
      threats: criticalAlerts
    },

    {
      severity: 'High',
      threats: highAlerts
    },

    {
      severity: 'Medium',
      threats: mediumAlerts
    },

    {
      severity: 'Low',
      threats: lowAlerts
    }

  ]


  // --------------------------------------------------
  // PAGE TITLES
  // --------------------------------------------------

  const pageTitles = {

    overview: 'Security Overview',

    alerts: 'Security Alerts',

    monitoring: 'Threat Monitoring',

    analytics: 'Security Analytics',

    history: 'Alert History',

    response: 'Incident Response Management'

  }


  // --------------------------------------------------
  // ALERT TYPES
  // --------------------------------------------------

  const availableAlertTypes = [

    ...new Set(

      alerts
        .map(alert => alert.alert_type)
        .filter(Boolean)

    )

  ].sort()


  // --------------------------------------------------
  // FILTER ALERTS
  // --------------------------------------------------

  const filteredAlerts = alerts.filter(alert => {

    const displayAlert = getAlertDisplay(alert)

    const search = alertSearch.trim().toLowerCase()

    const sourceIP = String(
      displayAlert.source_ip || ''
    ).toLowerCase()

    const alertType = String(
      displayAlert.alert_type || ''
    ).toLowerCase()

    const severity = String(
      displayAlert.severity || ''
    ).toLowerCase()

    const status = String(
      displayAlert.status || ''
    ).toLowerCase()

    const matchesSearch =
      !search ||
      sourceIP.includes(search) ||
      alertType.includes(search)

    const matchesSeverity =
      severityFilter === 'All' ||
      severity === severityFilter.toLowerCase()

    const matchesStatus =
      statusFilter === 'All' ||
      status === statusFilter.toLowerCase()

    const matchesAlertType =
      alertTypeFilter === 'All' ||
      displayAlert.alert_type === alertTypeFilter

    return (
      matchesSearch &&
      matchesSeverity &&
      matchesStatus &&
      matchesAlertType
    )

  })


  // --------------------------------------------------
  // RESET FILTERS
  // --------------------------------------------------

  const resetAlertFilters = () => {

    setAlertSearch('')

    setSeverityFilter('All')

    setStatusFilter('All')

    setAlertTypeFilter('All')

  }
    // --------------------------------------------------
  // STATISTICS CARDS
  // --------------------------------------------------

  const renderStats = () => (

    <section className="stats-grid">

      <div className="stat-card">
        <span>Active Threat Alerts</span>
        <h2>{alerts.length}</h2>
        <small>Saved active incidents</small>
      </div>

      <div className="stat-card">
        <span>High / Critical Severity</span>
        <h2 className="red-text">
          {highAlerts + criticalAlerts}
        </h2>
        <small>High-priority and critical alerts</small>
      </div>

      <div className="stat-card">
        <span>Suspicious IPs</span>
        <h2>{suspiciousIPs}</h2>
        <small>Unique suspicious IP addresses</small>
      </div>

      <div className="stat-card">
        <span>API Status</span>
        <h2 className={
          apiStatus === 'Online'
            ? 'green-text'
            : 'red-text'
        }>
          {apiStatus}
        </h2>
        <small>Backend connection</small>
      </div>

    </section>

  )


  // --------------------------------------------------
  // DETECTION ENGINE PANEL
  // --------------------------------------------------

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
          <span>Current active incidents</span>
          <h2>{alerts.length}</h2>
          <p>Based on saved database incidents</p>
        </div>

      </div>

    </section>

  )


  // --------------------------------------------------
  // ALERT DETAILS MODAL
  // --------------------------------------------------

  const renderAlertDetails = () => {

    if (!selectedAlert) {
      return null
    }

    const detectionMethods = parseDetectionMethods(
      selectedAlert.detection_methods
    )

    const status = selectedAlert.status || 'New'

    const occurrenceCount = formatOccurrences(
      selectedAlert.occurrence_count
    )

    const statusOptions = [
      'New',
      'Acknowledged',
      'Investigating',
      'Resolved'
    ]

    return (

      <div
        className="alert-modal-overlay"
        onClick={() => {

          if (!statusUpdating && !noteSaving) {
            setSelectedAlert(null)
          }

        }}
      >

        <div
          className="alert-details-modal"
          onClick={event => event.stopPropagation()}
        >

          <div className="alert-modal-header">

            <div>
              <h2>Alert Details</h2>
              <p>Security threat and incident information</p>
            </div>

            <button
              className="close-modal-button"
              onClick={() => setSelectedAlert(null)}
              aria-label="Close alert details"
              disabled={statusUpdating || noteSaving}
            >
              ×
            </button>

          </div>


          <div className="alert-details-content">

            <div className="detail-item">
              <span>Alert ID</span>
              <strong>{selectedAlert.id ?? 'N/A'}</strong>
            </div>

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
              <strong>
                {selectedAlert.failed_attempts ?? 'N/A'}
              </strong>
            </div>

            <div className="detail-item">
              <span>Machine Learning Prediction</span>
              <strong>
                {selectedAlert.ml_prediction || 'N/A'}
              </strong>
            </div>

            <div className="detail-item">
              <span>Detection Methods</span>
              <strong>
                {detectionMethods.length
                  ? detectionMethods.join(', ')
                  : 'Not provided by API'}
              </strong>
            </div>

            <div className="detail-item">
              <span>Incident Status</span>
              <strong className={`severity ${String(
                status
              ).toLowerCase()}`}>
                {status}
              </strong>
            </div>

            <div className="detail-item">
              <span>Occurrence Count</span>
              <strong>{occurrenceCount}</strong>
            </div>

            <div className="detail-item">
              <span>First Seen</span>
              <strong>
                {formatTimestamp(selectedAlert.created_at)}
              </strong>
            </div>

            <div className="detail-item">
              <span>Last Seen</span>
              <strong>
                {formatTimestamp(selectedAlert.last_seen_at)}
              </strong>
            </div>

            <div className="detail-item">
              <span>Created At</span>
              <strong>
                {formatTimestamp(selectedAlert.created_at)}
              </strong>
            </div>

            <div className="detail-item">
              <span>Resolved At</span>
              <strong>
                {formatTimestamp(selectedAlert.resolved_at)}
              </strong>
            </div>

            <div className="detail-item detail-description">
              <span>Description</span>
              <p>
                {selectedAlert.description || 'No description available.'}
              </p>
            </div>

          </div>


          {/* INCIDENT STATUS MANAGEMENT */}

          <div className="incident-management response-create-form">

            <h3>Incident Status Management</h3>

            <p>Update the current investigation status:</p>

            <div className="status-options">

              {statusOptions.map(option => (

                <button
                  key={option}
                  type="button"
                  className={
                    status === option
                      ? 'view-details-button active-status-button'
                      : 'view-details-button'
                  }
                  onClick={() => updateIncidentStatus(option)}
                  disabled={statusUpdating || status === option}
                >
                  {option}
                </button>

              ))}

            </div>

            {statusUpdating && (
              <p className="loading-message">
                Updating incident status...
              </p>
            )}

            {statusError && (
              <p className="error-message">
                {statusError}
              </p>
            )}

            {statusSuccess && (
              <p className="success-message">
                {statusSuccess}
              </p>
            )}

          </div>


          {/* ANALYST NOTES */}

          <div className="incident-management analyst-notes-management">

            <h3>Analyst Notes Management</h3>

            <p>
              Add investigation findings or response observations:
            </p>

            {selectedAlert.analyst_notes && (

              <div className="existing-analyst-notes">

                <h4>Previous Analyst Notes</h4>

                <pre>{selectedAlert.analyst_notes}</pre>

              </div>

            )}

            <textarea
              className="analyst-note-input"
              value={newAnalystNote}
              onChange={event =>
                setNewAnalystNote(event.target.value)
              }
              placeholder="Write your investigation notes here..."
              rows={5}
              maxLength={5000}
              disabled={noteSaving}
            />

            <div className="note-character-count">
              {newAnalystNote.length}/5000 characters
            </div>

            <button
              type="button"
              className="view-details-button save-note-button"
              onClick={saveAnalystNote}
              disabled={noteSaving || !newAnalystNote.trim()}
            >
              {noteSaving
                ? 'Saving Note...'
                : 'Save Analyst Note'}
            </button>

            {noteSaving && (
              <p className="loading-message">
                Saving analyst note to database...
              </p>
            )}

            {noteError && (
              <p className="error-message">
                {noteError}
              </p>
            )}

            {noteSuccess && (
              <p className="success-message">
                {noteSuccess}
              </p>
            )}

          </div>


          {detailsLoading && (
            <p>Loading latest incident details...</p>
          )}

          {detailsError && (
            <p className="error-message">
              {detailsError}
            </p>
          )}

          <div className="alert-modal-footer">

            <button
              className="close-details-button"
              onClick={() => setSelectedAlert(null)}
              disabled={statusUpdating || noteSaving}
            >
              Close Details
            </button>

          </div>

        </div>

      </div>

    )
  }
  // --------------------------------------------------
  // SECURITY ALERTS TABLE
  // --------------------------------------------------

  const renderAlerts = () => (

    <section className="panel alerts-panel">

      <div className="section-heading">

        <div>
          <h3>Security Alerts</h3>
          <p>
            Latest active incident for each suspicious IP address
          </p>
        </div>

        <span className="live-label">
          ● DATABASE INCIDENTS
        </span>

      </div>


      {error && (
        <p className="error-message">
          {error}
        </p>
      )}


      {/* SEARCH AND FILTERS */}

      <div className="alert-filter-panel">

        <div className="alert-filter-heading">

          <div>
            <h4>Search &amp; Filter Alerts</h4>
            <p>
              Find alerts by IP address, alert type, severity or incident status.
            </p>
          </div>

          <button
            type="button"
            className="reset-filter-button"
            onClick={resetAlertFilters}
          >
            Reset Filters
          </button>

        </div>


        <div className="alert-controls">

          <input
            type="text"
            className="search-input"
            placeholder="Search source IP or alert type..."
            value={alertSearch}
            onChange={event =>
              setAlertSearch(event.target.value)
            }
            aria-label="Search source IP or alert type"
          />


          <select
            className="severity-filter"
            value={severityFilter}
            onChange={event =>
              setSeverityFilter(event.target.value)
            }
            aria-label="Filter by severity"
          >
            <option value="All">All Severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>


          <select
            className="severity-filter"
            value={statusFilter}
            onChange={event =>
              setStatusFilter(event.target.value)
            }
            aria-label="Filter by incident status"
          >
            <option value="All">All Statuses</option>
            <option value="New">New</option>
            <option value="Acknowledged">Acknowledged</option>
            <option value="Investigating">Investigating</option>
            <option value="Resolved">Resolved</option>
          </select>


          <select
            className="severity-filter"
            value={alertTypeFilter}
            onChange={event =>
              setAlertTypeFilter(event.target.value)
            }
            aria-label="Filter by alert type"
          >
            <option value="All">All Alert Types</option>

            {availableAlertTypes.map(type => (
              <option key={type} value={type}>
                {type}
              </option>
            ))}

          </select>

        </div>


        <p className="filter-count">
          Showing {filteredAlerts.length} of {alerts.length} alerts
        </p>

      </div>


      {loading && (
        <p>Loading security alerts...</p>
      )}


      {!loading && !error && alerts.length === 0 && (
        <p>
          No active threat incidents found. Use Run Detection to scan the available logs.
        </p>
      )}


      {!loading && alerts.length > 0 && filteredAlerts.length === 0 && (

        <div className="no-filter-results">

          <p>No alerts match your search or selected filters.</p>

          <button
            type="button"
            className="reset-filter-button"
            onClick={resetAlertFilters}
          >
            Clear Filters
          </button>

        </div>

      )}


      {!loading && filteredAlerts.length > 0 && (

        <div className="table-container">

          <table>

            <thead>
              <tr>
                <th>Source IP</th>
                <th>Alert Type</th>
                <th>Severity</th>
                <th>Status</th>
                <th>Occurrences</th>
                <th>Failed Attempts</th>
                <th>ML Prediction</th>
                <th>Action</th>
              </tr>
            </thead>


            <tbody>

              {filteredAlerts.map((alert, index) => {

                const displayAlert = getAlertDisplay(alert)

                const currentStatus = displayAlert.status

                return (

                  <tr
                    key={
                      alert.id ??
                      `${alert.source_ip}-${alert.alert_type}-${index}`
                    }
                  >

                    <td>
                      {displayAlert.source_ip || 'N/A'}
                    </td>

                    <td>
                      {displayAlert.alert_type || 'N/A'}
                    </td>

                    <td>
                      <span className={`severity ${String(
                        displayAlert.severity || ''
                      ).toLowerCase()}`}>
                        {displayAlert.severity || 'N/A'}
                      </span>
                    </td>

                    <td>
                      <span className={`incident-status-badge ${String(
                        currentStatus
                      ).toLowerCase()}`}>
                        {currentStatus}
                      </span>
                    </td>

                    <td>
                      {formatOccurrences(
                        displayAlert.occurrence_count
                      )}
                    </td>

                    <td>
                      {displayAlert.failed_attempts ?? 'N/A'}
                    </td>

                    <td>
                      {displayAlert.ml_prediction || 'N/A'}
                    </td>

                    <td>
                      <button
                        className="view-details-button"
                        onClick={() => openAlertDetails(displayAlert)}
                      >
                        View Details
                      </button>
                    </td>

                  </tr>

                )

              })}

            </tbody>

          </table>

        </div>

      )}

    </section>

  )
  // INCIDENT RESPONSE MANAGEMENT PAGE

  const renderResponseManagement = () => (
    <section className="panel alerts-panel">
    {(() => {
      const pendingCount = responseActions.filter(action => action.approval_status === 'Pending').length
      const approvedCount = responseActions.filter(action => action.approval_status === 'Approved').length
      const rejectedCount = responseActions.filter(action => action.approval_status === 'Rejected').length
      const simulatedCount = responseActions.filter(action => action.execution_status === 'Simulated').length
      const visibleActions = responseStatusFilter === 'All'
        ? responseActions
        : responseActions.filter(action => responseStatusFilter === 'Simulated'
          ? action.execution_status === 'Simulated'
          : action.approval_status === responseStatusFilter)
      return (
        <>
      <div className="section-heading">
        <div>
          <h3>Incident Response Management</h3>
          <p>Create, review, approve and simulate security response actions.</p>
        </div>
        <button
          type="button"
          className="refresh-button"
          onClick={fetchResponseActions}
          disabled={responseLoading}
        >
          {responseLoading ? 'Loading...' : '↻ Refresh Actions'}
        </button>
      </div>

      <div className="response-summary" aria-label="Response action summary">
        <div><span>Total actions</span><strong>{responseActions.length}</strong></div>
        <div><span>Pending</span><strong>{pendingCount}</strong></div>
        <div><span>Approved</span><strong>{approvedCount}</strong></div>
        <div><span>Rejected</span><strong>{rejectedCount}</strong></div>
        <div><span>Simulated</span><strong>{simulatedCount}</strong></div>
      </div>

      <div className="incident-management response-create-form">
        <h3>Create Response Action</h3>
        <p>Select a saved security incident and choose an action.</p>

        <label htmlFor="response-incident">Security Incident</label>
        <select
          id="response-incident"
          className="severity-filter"
          value={selectedResponseAlertId}
          onChange={event => setSelectedResponseAlertId(event.target.value)}
          disabled={responseLoading}
        >
          <option value="">Select an incident</option>
          {historyAlerts.map(alert => (
            <option key={alert.id} value={alert.id}>
              #{alert.id} — {alert.source_ip} — {alert.severity}
            </option>
          ))}
        </select>

        <label htmlFor="response-action-type">Response Action</label>
        <select
          id="response-action-type"
          className="severity-filter"
          value={selectedResponseAction}
          onChange={event => setSelectedResponseAction(event.target.value)}
          disabled={responseLoading}
        >
          <option value="Investigate Source IP">Investigate Source IP</option>
          <option value="Review Authentication Logs">Review Authentication Logs</option>
          <option value="Monitor Suspicious Activity">Monitor Suspicious Activity</option>
          <option value="Temporarily Block IP">Temporarily Block IP</option>
          <option value="Require Password Reset">Require Password Reset</option>
        </select>

        <label htmlFor="response-analyst-name">Analyst Name</label>
        <input
          id="response-analyst-name"
          className="search-input"
          type="text"
          value={analystName}
          onChange={event => setAnalystName(event.target.value)}
          placeholder="Enter analyst name"
          maxLength={100}
          disabled={responseLoading}
        />

        <label htmlFor="response-description">Action Description</label>
        <textarea
          id="response-description"
          className="analyst-note-input"
          value={responseDescription}
          onChange={event => setResponseDescription(event.target.value)}
          placeholder="Describe why this response action is required..."
          rows={4}
          maxLength={2000}
          disabled={responseLoading}
        />

        <button
          type="button"
          className="view-details-button"
          onClick={createResponseAction}
          disabled={responseLoading || !selectedResponseAlertId}
        >
          {responseLoading ? 'Processing...' : 'Create Response Action'}
        </button>
      </div>

      {responseError && <p className="error-message">{responseError}</p>}
      {responseSuccess && <p className="success-message">{responseSuccess}</p>}

      <div className="section-heading">
        <div>
          <h3>Response Action History</h3>
          <p>Previously created and saved response actions.</p>
        </div>
        <label className="response-filter-label" htmlFor="response-status-filter">
          Status
          <select id="response-status-filter" className="severity-filter" value={responseStatusFilter}
            onChange={event => setResponseStatusFilter(event.target.value)}>
            <option>All</option><option>Pending</option><option>Approved</option>
            <option>Rejected</option><option>Simulated</option>
          </select>
        </label>
      </div>

      {responseLoading && responseActions.length === 0 && (
        <p>Loading response actions...</p>
      )}

      {!responseLoading && responseActions.length === 0 && (
        <p>No response actions have been created yet.</p>
      )}

      {responseActions.length > 0 && visibleActions.length === 0 && <p>No actions match this status.</p>}
      {visibleActions.length > 0 && (
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Action ID</th>
                <th>Incident</th>
                <th>Source IP</th>
                <th>Action</th>
                <th>Approval</th>
                <th>Execution</th>
                <th>Mode</th>
                <th>Analyst</th>
                <th>Created At</th>
                <th>Controls</th>
              </tr>
            </thead>
            <tbody>
              {visibleActions.map(action => (
                <tr key={action.id}>
                  <td>#{action.id}</td>
                  <td>#{action.alert_id}</td>
                  <td>{action.source_ip || 'N/A'}</td>
                  <td>
                    <strong>{action.action_type}</strong>
                    {action.description && <p>{action.description}</p>}
                  </td>
                  <td>{action.approval_status}</td>
                  <td>{action.execution_status}</td>
                  <td>{action.execution_mode}</td>
                  <td>{action.analyst_name || 'N/A'}</td>
                  <td>{formatTimestamp(action.created_at)}</td>
                  <td>
                    {action.approval_status === 'Pending' && (
                      <div className="status-options">
                        <button
                          type="button"
                          className="view-details-button"
                          onClick={() => decideResponseAction(action.id, 'Approved')}
                          disabled={responseLoading}
                        >Approve</button>
                        <button
                          type="button"
                          className="view-details-button"
                          onClick={() => decideResponseAction(action.id, 'Rejected')}
                          disabled={responseLoading}
                        >Reject</button>
                      </div>
                    )}

                    {action.approval_status === 'Approved' &&
                      action.execution_status === 'Not Executed' && (
                        <button
                          type="button"
                          className="view-details-button"
                          onClick={() => simulateResponseAction(action.id)}
                          disabled={responseLoading}
                        >Simulate</button>
                      )}

                    {action.execution_status === 'Simulated' && (
                      <span className="success-message">Simulation Complete</span>
                    )}
                    {action.execution_status === 'Rejected' && (
                      <span className="error-message">Rejected</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <p className="loading-message">
        <strong>Safety:</strong> All execution is simulation-only. This dashboard
        does not actually block IP addresses or modify network settings.
      </p>
      <div className="section-heading response-audit-heading">
        <div><h3>Audit History</h3><p>Recorded response action events, newest first.</p></div>
      </div>
      {responseAuditLogs.length === 0 ? <p>No response audit records are available.</p> : (
        <div className="table-container">
          <table>
            <thead><tr><th>Action</th><th>Entity ID</th><th>Analyst</th><th>Details</th><th>Timestamp</th></tr></thead>
            <tbody>{responseAuditLogs.map(log => (
              <tr key={log.id}><td>{log.action}</td><td>{log.entity_type} #{log.entity_id ?? '—'}</td>
                <td>{log.analyst_name || 'N/A'}</td><td>{log.details || '—'}</td>
                <td>{formatTimestamp(log.created_at)}</td></tr>
            ))}</tbody>
          </table>
        </div>
      )}
        </>
      )
    })()}
    </section>
  )


    // ALERT HISTORY TABLE
  // --------------------------------------------------

  const renderHistory = () => (

    <section className="panel alerts-panel">

      <div className="section-heading">

        <div>
          <h3>Historical Security Alerts</h3>
          <p>
            Previously detected and stored threats from PostgreSQL
          </p>
        </div>

        <button
          className="refresh-button"
          onClick={fetchHistory}
          disabled={historyLoading}
        >
          {historyLoading
            ? 'Loading...'
            : '↻ Refresh History'}
        </button>

      </div>


      {historyError && (
        <p className="error-message">
          {historyError}
        </p>
      )}


      {historyLoading && (
        <p>Loading historical alerts...</p>
      )}


      {!historyLoading && historyAlerts.length === 0 && (
        <p>No historical alerts found.</p>
      )}


      {!historyLoading && historyAlerts.length > 0 && (

        <div className="table-container">

          <table>

            <thead>
              <tr>
                <th>Alert ID</th>
                <th>Source IP</th>
                <th>Alert Type</th>
                <th>Severity</th>
                <th>Occurrences</th>
                <th>Created At</th>
                <th>Last Seen</th>
                <th>Status</th>
                <th>Action</th>
              </tr>
            </thead>


            <tbody>

              {historyAlerts.map(alert => (

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

                  <td>
                    {formatOccurrences(
                      alert.occurrence_count
                    )}
                  </td>

                  <td>
                    {formatTimestamp(alert.created_at)}
                  </td>

                  <td>
                    {formatTimestamp(alert.last_seen_at)}
                  </td>

                  <td>
                    <span className={`incident-status-badge ${String(
                      alert.status || ''
                    ).toLowerCase()}`}>
                      {alert.status || 'New'}
                    </span>
                  </td>

                  <td>
                    <button
                      className="view-details-button"
                      onClick={() => openAlertDetails(alert)}
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


  // --------------------------------------------------
  // MAIN DASHBOARD
  // --------------------------------------------------

  return (

    <div className="dashboard">


      {/* SIDEBAR */}

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

              fetchHistory()

            }}
          >
            ▤ Alert History
          </a>

          <a
            href="#response"
            className={activePage === 'response' ? 'active' : ''}
            onClick={() => {
              setActivePage('response')
              fetchResponseActions()
              fetchHistory()
            }}
          >
            🛡 Incident Response
          </a>

        </nav>


        <div className="sidebar-bottom">

          <div className="system-label">
            SYSTEM STATUS
          </div>

          <p>

            <span className={
              apiStatus === 'Online'
                ? 'green-dot'
                : 'red-dot'
            }></span>

            API {apiStatus}

          </p>

        </div>

      </aside>


      {/* MAIN CONTENT */}

      <main className="main-content">


        {/* TOPBAR */}

        <header className="topbar">

          <div>
            <h1>{pageTitles[activePage]}</h1>

            <p>
              AI-powered cyber threat detection and response
            </p>
          </div>


          <div style={{
            display: 'flex',
            gap: '10px',
            flexWrap: 'wrap'
          }}>


            {/* REFRESH BUTTON */}

            <button
              className="refresh-button"
              onClick={() => {

                if (activePage === 'history') {
                  fetchHistory()
                } else {
                  fetchAlerts()
                }

              }}
              disabled={loading || historyLoading}
            >
              {loading || historyLoading
                ? 'Refreshing...'
                : '↻ Refresh Data'}
            </button>


            {/* MANUAL DETECTION BUTTON */}

            <button
              className="refresh-button"
              onClick={runDetection}
              disabled={loading}
              style={{
                backgroundColor: '#2563eb',
                color: '#ffffff'
              }}
            >
              {loading
                ? 'Detecting...'
                : '▶ Run Detection'}
            </button>

          </div>

        </header>


        {/* OVERVIEW PAGE */}

        {activePage === 'overview' && (

          <>
            {renderStats()}

            {renderDetectionEngine()}

            {renderAlerts()}
          </>

        )}


        {/* SECURITY ALERTS PAGE */}

        {activePage === 'alerts' && (

          <>
            {renderStats()}

            {renderAlerts()}
          </>

        )}


        {/* MONITORING PAGE */}

        {activePage === 'monitoring' && (

          <>

            {renderDetectionEngine()}

            <section className="panel">

              <h3>Monitoring Status</h3>

              <p>Rule-based detection: Active</p>

              <p>Machine learning detection: Active</p>

              <p>Backend API: {apiStatus}</p>

              <p>Currently active incidents: {alerts.length}</p>

            </section>

          </>

        )}


        {/* ANALYTICS PAGE */}

        {activePage === 'analytics' && (

          <>

            {renderStats()}


            <section className="panel">

              <h3>Threat Analytics</h3>


              <div className="method">
                <span>Total active incidents</span>
                <strong>{alerts.length}</strong>
              </div>


              <div className="method">
                <span>Critical severity threats</span>
                <strong>{criticalAlerts}</strong>
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


            {/* SEVERITY CHART */}

            <section className="panel chart-panel">

              <h3>Threat Severity Distribution</h3>

              <p>
                Number of active incidents grouped by severity
              </p>

              <div className="chart-container">

                <ResponsiveContainer width="100%" height={300}>

                  <BarChart data={chartData}>

                    <CartesianGrid
                      strokeDasharray="3 3"
                      stroke="#263449"
                    />

                    <XAxis
                      dataKey="severity"
                      stroke="#94a3b8"
                    />

                    <YAxis
                      allowDecimals={false}
                      stroke="#94a3b8"
                    />

                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#111b2e',
                        border: '1px solid #263449',
                        borderRadius: '8px',
                        color: '#ffffff'
                      }}
                    />

                    <Bar
                      dataKey="threats"
                      fill="#3b82f6"
                      radius={[6, 6, 0, 0]}
                    />

                  </BarChart>

                </ResponsiveContainer>

              </div>

            </section>

          </>

        )}


        {/* HISTORY PAGE */}

        {activePage === 'history' && renderHistory()}

        {/* INCIDENT RESPONSE MANAGEMENT PAGE */}

        {activePage === 'response' && renderResponseManagement()}


        {/* FOOTER */}

        <footer>

          AI Cyber Threat Detection & Response Platform

          <span>Development Version 1.5.0</span>

        </footer>

      </main>


      {/* ALERT DETAILS MODAL */}

      {renderAlertDetails()}

    </div>

  )

}

export default App
