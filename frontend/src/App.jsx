import React, { useState, useEffect, useRef } from 'react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer
} from 'recharts';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Activity,
  Cpu,
  Search,
  RefreshCw,
  CheckCircle,
  Brain,
  Sliders,
  TrendingUp,
  Inbox
} from 'lucide-react';
import AlertDetails from './components/AlertDetails';
import { mockAlerts } from './mock_data';

const API_BASE_URL = '';

// Compute campaigns if working offline
function deriveCampaignsOffline(alertList) {
  const map = {};
  const CAMP_NAMES = {
    camp_bec_wire_01: 'Executive Impersonation (Wire Transfer)',
    camp_m365_harvest_02: 'Office 365 Credential Harvesting (Moscow IP)',
    camp_dhl_delivery_03: 'DHL / FedEx Customs Delivery Scam'
  };
  const CAMP_DESCRIPTIONS = {
    camp_bec_wire_01: 'BEC campaigns targeting finance departments asking for urgent wire transfer.',
    camp_m365_harvest_02: 'Spoofed Microsoft Office 365 security warnings directing users to malicious sign-in portals.',
    camp_dhl_delivery_03: 'Shipping package delivery notice asking for small customs fees to resolve delivery failures.'
  };

  alertList.forEach((a) => {
    const cid = a.campaign_id;
    if (cid) {
      if (!map[cid]) {
        map[cid] = {
          id: cid,
          name: CAMP_NAMES[cid] || cid,
          count: 0,
          max_score: 0.0,
          category: a.threat_category || 'unknown',
          description: CAMP_DESCRIPTIONS[cid] || 'Active campaign cluster.'
        };
      }
      map[cid].count++;
      if (a.confidence_score > map[cid].max_score) {
        map[cid].max_score = a.confidence_score;
      }
    }
  });

  return Object.values(map).sort((a, b) => b.count - a.count);
}

export default function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [alerts, setAlerts] = useState([]);
  const [campaigns, setCampaigns] = useState([]);
  const [thresholds, setThresholds] = useState({
    Executive: 0.6,
    Finance: 0.65,
    'General Employee': 0.75,
    Default: 0.7
  });
  const [modelMetrics, setModelMetrics] = useState({
    model_version: 'deberta-v3-phish-v1.4',
    last_retrained: '2026-05-22T14:30:00Z',
    training_samples: 492000,
    metrics: {
      precision: 0.972,
      recall: 0.958,
      f1_score: 0.965,
      false_positive_rate: 0.012
    },
    active_learning: {
      unlabeled_uncertain_samples: 3,
      accumulated_feedback_count: 852,
      drift_indicator: 'stable'
    }
  });

  const [selectedAlert, setSelectedAlert] = useState(null);
  const [apiOnline, setApiOnline] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [verdictFilter, setVerdictFilter] = useState('all');
  const [loading, setLoading] = useState(true);
  const [retraining, setRetraining] = useState(false);
  const [toastMessage, setToastMessage] = useState(null);

  // Scan Email Form State
  const [scanEmailText, setScanEmailText] = useState('');
  const [scanRecipient, setScanRecipient] = useState('');
  const [scanRecipientGroup, setScanRecipientGroup] = useState('Default');
  const [scanResult, setScanResult] = useState(null);
  const [isScanning, setIsScanning] = useState(false);
  const resultRef = useRef(null);

  // Helper to trigger temporary toast alerts
  const triggerToast = (msg, type = 'success') => {
    setToastMessage({ text: msg, type });
    setTimeout(() => setToastMessage(null), 4000);
  };

  // Check backend availability & fetch initial data
  const loadData = async () => {
    setLoading(true);
    try {
      // 1. Ping an API endpoint to verify API connectivity
      const rootRes = await fetch(`${API_BASE_URL}/api/v1/settings/thresholds`).catch(() => null);
      if (rootRes && rootRes.ok) {
        setApiOnline(true);

        // 2. Fetch live data
        const alertsRes = await fetch(`${API_BASE_URL}/api/v1/alerts`);
        const fetchedAlerts = await alertsRes.json();
        setAlerts(fetchedAlerts);

        const campaignsRes = await fetch(`${API_BASE_URL}/api/v1/campaigns`);
        const fetchedCampaigns = await campaignsRes.json();
        setCampaigns(fetchedCampaigns);

        const thresholdsRes = await fetch(`${API_BASE_URL}/api/v1/settings/thresholds`);
        const fetchedThresholds = await thresholdsRes.json();
        if (fetchedThresholds?.thresholds) {
          setThresholds(fetchedThresholds.thresholds);
        }

        const metricsRes = await fetch(`${API_BASE_URL}/api/v1/model/metrics`);
        const fetchedMetrics = await metricsRes.json();
        if (fetchedMetrics) {
          setModelMetrics(fetchedMetrics);
        }
      } else {
        throw new Error('API Offline');
      }
    } catch (e) {
      console.warn('Backend API offline. Falling back to offline client-side simulation.', e);
      setApiOnline(false);

      // Load mock fallback data
      setAlerts(mockAlerts);

      // Derive campaign clusters offline
      const derivedCampaigns = deriveCampaignsOffline(mockAlerts);
      setCampaigns(derivedCampaigns);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    Promise.resolve().then(() => {
      loadData();
    });
  }, []);


  // Dynamic statistics calculation
  const stats = React.useMemo(() => {
    const total = alerts.length;
    const phishing = alerts.filter((a) => a.verdict === 'phishing').length;
    const suspicious = alerts.filter((a) => a.verdict === 'suspicious').length;
    const benign = alerts.filter((a) => a.verdict === 'benign').length;
    const pending = alerts.filter((a) => a.analyst_action === 'pending').length;
    const rate = total > 0 ? Math.round((phishing / total) * 100) : 0;

    // Daily volume grouping
    const dailyMap = {};
    alerts.forEach((a) => {
      const dateStr = a.timestamp.slice(0, 10);
      if (!dailyMap[dateStr]) {
        dailyMap[dateStr] = { date: dateStr, phishing: 0, benign: 0, suspicious: 0 };
      }
      if (a.verdict === 'phishing') dailyMap[dateStr].phishing++;
      else if (a.verdict === 'benign') dailyMap[dateStr].benign++;
      else dailyMap[dateStr].suspicious++;
    });

    const dailyVolume = Object.values(dailyMap)
      .sort((a, b) => a.date.localeCompare(b.date))
      .slice(-7);

    return { total, phishing, suspicious, benign, pending, rate, dailyVolume };
  }, [alerts]);

  // Submit SOC feedback/override
  const handleTriageAction = async (alertId, action, notes) => {
    try {
      if (apiOnline) {
        const res = await fetch(`${API_BASE_URL}/api/v1/alerts/${alertId}/feedback`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ action, notes })
        });
        if (res.ok) {
          await res.json();
          // Update local state alert record
          setAlerts((prev) =>
            prev.map((a) => (a.id === alertId ? { ...a, analyst_action: action, analyst_notes: notes } : a))
          );
          if (selectedAlert?.id === alertId) {
            setSelectedAlert((prev) => ({ ...prev, analyst_action: action, analyst_notes: notes }));
          }
          triggerToast(`Alert ${alertId} successfully triaged as ${action.replace('_', ' ')}.`);
        } else {
          throw new Error('Triage endpoint failed');
        }
      } else {
        // Offline state update
        setAlerts((prev) =>
          prev.map((a) => (a.id === alertId ? { ...a, analyst_action: action, analyst_notes: notes } : a))
        );
        if (selectedAlert?.id === alertId) {
          setSelectedAlert((prev) => ({ ...prev, analyst_action: action, analyst_notes: notes }));
        }
        triggerToast(`Local Simulation: Triaged ${alertId} as ${action.replace('_', ' ')}.`);
      }
    } catch (e) {
      console.error('Failed to triage alert', e);
      triggerToast('Failed to submit triage feedback to API.', 'error');
    }
  };

  // Submit updated sensitivity threshold policies
  const handleUpdateThresholds = async (e) => {
    e.preventDefault();
    try {
      if (apiOnline) {
        const res = await fetch(`${API_BASE_URL}/api/v1/settings/thresholds`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ thresholds })
        });
        if (res.ok) {
          triggerToast('Sensitivity threshold policies updated successfully.');
        } else {
          throw new Error('Threshold save failed');
        }
      } else {
        triggerToast('Local Simulation: Sensitivity thresholds updated locally.');
      }
    } catch (e) {
      console.error(e);
      triggerToast('Failed to update sensitivity policies on backend.', 'error');
    }
  };

  // Trigger retraining simulation
  const handleRetrainModel = async () => {
    setRetraining(true);
    try {
      if (apiOnline) {
        const res = await fetch(`${API_BASE_URL}/api/v1/model/retrain`, { method: 'POST' });
        if (res.ok) {
          triggerToast('Model retrained successfully. Metrics re-calibrated.');
          // Update retrained timestamp
          setModelMetrics((prev) => ({
            ...prev,
            last_retrained: new Date().toISOString()
          }));
        } else {
          throw new Error('Retraining call failed');
        }
      } else {
        await new Promise((resolve) => setTimeout(resolve, 3000));
        triggerToast('Local Simulation: Model retrained successfully.');
        setModelMetrics((prev) => ({
          ...prev,
          last_retrained: new Date().toISOString(),
          active_learning: {
            ...prev.active_learning,
            unlabeled_uncertain_samples: 0,
            accumulated_feedback_count: prev.active_learning.accumulated_feedback_count + 12
          }
        }));
      }
    } catch (e) {
      console.error(e);
      triggerToast('Model retraining trigger failed.', 'error');
    } finally {
      setRetraining(false);
    }
  };

  // Update slider/input thresholds
  const handleSliderChange = (group, val) => {
    setThresholds((prev) => ({
      ...prev,
      [group]: parseFloat(val)
    }));
  };

  // Submit Raw Email to Score
  const handleScanEmail = async (e) => {
    e.preventDefault();
    if (!scanEmailText || !scanRecipient) {
      triggerToast('Please provide both the email text and recipient.', 'error');
      return;
    }
    
    setIsScanning(true);
    setScanResult(null);
    try {
      if (apiOnline) {
        const res = await fetch(`${API_BASE_URL}/api/v1/score`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            raw_email: scanEmailText,
            recipient: scanRecipient,
            recipient_group: scanRecipientGroup
          })
        });
        if (res.ok) {
          const data = await res.json();
          setScanResult(data);
          // Removed loadData() to prevent the page from unmounting and losing scroll position
          triggerToast('Email scanned successfully.');
          setTimeout(() => resultRef.current?.scrollIntoView({ behavior: 'smooth' }), 100);
        } else {
          throw new Error('Scan failed');
        }
      } else {
        triggerToast('API Offline: Cannot scan live email currently.', 'error');
      }
    } catch (error) {
      console.error(error);
      triggerToast('Failed to connect to scoring engine.', 'error');
    } finally {
      setIsScanning(false);
    }
  };

  // Filter alerts based on search and selected filter status
  const filteredAlerts = React.useMemo(() => {
    return alerts.filter((a) => {
      // 1. Search filter
      const matchesSearch =
        searchQuery === '' ||
        a.subject?.toLowerCase().includes(searchQuery.toLowerCase()) ||
        a.sender?.toLowerCase().includes(searchQuery.toLowerCase()) ||
        a.recipient?.toLowerCase().includes(searchQuery.toLowerCase()) ||
        a.id.toLowerCase().includes(searchQuery.toLowerCase());

      // 2. Verdict / Review Status filter
      let matchesFilter = true;
      if (verdictFilter === 'phishing') {
        matchesFilter = a.verdict === 'phishing';
      } else if (verdictFilter === 'suspicious') {
        matchesFilter = a.verdict === 'suspicious';
      } else if (verdictFilter === 'benign') {
        matchesFilter = a.verdict === 'benign';
      } else if (verdictFilter === 'pending') {
        matchesFilter = a.analyst_action === 'pending';
      }

      return matchesSearch && matchesFilter;
    });
  }, [alerts, searchQuery, verdictFilter]);

  // Active learning borderline labeling alerts (confidence between 40% and 80% and pending)
  const labelingQueueAlerts = React.useMemo(() => {
    return alerts.filter(
      (a) => a.confidence_score >= 0.4 && a.confidence_score <= 0.8 && a.analyst_action === 'pending'
    );
  }, [alerts]);

  return (
    <div className="app-layout">
      {/* Toast Notification Banner */}
      {toastMessage && (
        <div
          style={{
            position: 'fixed',
            top: '20px',
            right: '20px',
            zIndex: '9999',
            backgroundColor: toastMessage.type === 'error' ? 'var(--danger)' : 'var(--success)',
            color: 'white',
            padding: '12px 20px',
            borderRadius: 'var(--radius-md)',
            boxShadow: 'var(--shadow-lg)',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            fontSize: '13px',
            fontWeight: '600',
            animation: 'slideInRight 0.2s var(--ease)'
          }}
        >
          <CheckCircle size={16} />
          {toastMessage.text}
        </div>
      )}

      {/* Sidebar Navigation */}
      <nav className="sidebar">
        <div className="sidebar-logo">
          <div className="sidebar-logo-icon">
            <Shield size={16} color="white" />
          </div>
          <div className="sidebar-logo-text">
            <span className="sidebar-logo-title">APDS</span>
            <span className="sidebar-logo-sub">Threat Intel</span>
          </div>
        </div>

        <div className="sidebar-nav">
          <div className="sidebar-section-label">Operations</div>
          <div
            className={`nav-item ${activeTab === 'overview' ? 'active' : ''}`}
            onClick={() => setActiveTab('overview')}
          >
            <Activity className="nav-item-icon" size={16} />
            <span>SOC Dashboard</span>
          </div>
          <div
            className={`nav-item ${activeTab === 'alerts' ? 'active' : ''}`}
            onClick={() => setActiveTab('alerts')}
          >
            <Inbox className="nav-item-icon" size={16} />
            <span>Alerts Queue</span>
            {stats.pending > 0 && <span className="nav-item-badge">{stats.pending}</span>}
          </div>
          <div
            className={`nav-item ${activeTab === 'scan' ? 'active' : ''}`}
            onClick={() => setActiveTab('scan')}
          >
            <Search className="nav-item-icon" size={16} />
            <span>Scan Email</span>
          </div>

          <div className="sidebar-section-label">Active Learning</div>
          <div
            className={`nav-item ${activeTab === 'labeling' ? 'active' : ''}`}
            onClick={() => setActiveTab('labeling')}
          >
            <Brain className="nav-item-icon" size={16} />
            <span>Labeling Queue</span>
            {labelingQueueAlerts.length > 0 && (
              <span
                className="nav-item-badge"
                style={{ backgroundColor: 'var(--warning)', color: 'var(--bg-base)' }}
              >
                {labelingQueueAlerts.length}
              </span>
            )}
          </div>

          <div className="sidebar-section-label">Settings</div>
          <div
            className={`nav-item ${activeTab === 'policy' ? 'active' : ''}`}
            onClick={() => setActiveTab('policy')}
          >
            <Sliders className="nav-item-icon" size={16} />
            <span>Sensitivity Policies</span>
          </div>
          <div
            className={`nav-item ${activeTab === 'metrics' ? 'active' : ''}`}
            onClick={() => setActiveTab('metrics')}
          >
            <Cpu className="nav-item-icon" size={16} />
            <span>Model Intelligence</span>
          </div>
        </div>

        <div className="sidebar-status">
          <div className="api-status">
            <div className={`status-dot ${apiOnline ? '' : 'offline'}`} />
            <span>{apiOnline ? 'Live: API Connected' : 'Simulation Fallback'}</span>
          </div>
        </div>
      </nav>

      {/* Main Content Area */}
      <main className="main-content">
        <header className="main-header">
          <span className="main-header-title">
            {activeTab === 'overview' && 'SOC Operations Dashboard'}
            {activeTab === 'alerts' && 'Email Threat Alerts Queue'}
            {activeTab === 'labeling' && 'Active Learning Borderline Queue'}
            {activeTab === 'policy' && 'Sensitivity Threshold Settings'}
            {activeTab === 'metrics' && 'Language Model Intelligence & Performance'}
            {activeTab === 'scan' && 'Manual Email Scanning Engine'}
          </span>
          <button
            className="filter-btn"
            style={{ display: 'flex', alignItems: 'center', gap: '5px' }}
            onClick={loadData}
          >
            <RefreshCw size={12} /> Sync Data
          </button>
        </header>

        {loading ? (
          <div className="loading-spinner">
            <div className="spinner" />
            <span>Synchronizing security log database...</span>
          </div>
        ) : (
          <div className="main-body">
            {/* TAB 1: OVERVIEW */}
            {activeTab === 'overview' && (
              <>
                {/* Stats Widgets */}
                <div className="stats-grid">
                  <div className="stat-card danger fade-up">
                    <span className="stat-card-label">Blocked Phishing</span>
                    <span className="stat-card-value">{stats.phishing}</span>
                    <span className="stat-card-sub">
                      <ShieldAlert size={12} /> Threat alerts verified
                    </span>
                  </div>
                  <div className="stat-card warning fade-up">
                    <span className="stat-card-label">Suspicious Queue</span>
                    <span className="stat-card-value">{stats.suspicious}</span>
                    <span className="stat-card-sub">
                      <AlertTriangle size={12} /> Under automated watch
                    </span>
                  </div>
                  <div className="stat-card success fade-up">
                    <span className="stat-card-label">Safe Emails</span>
                    <span className="stat-card-value">{stats.benign}</span>
                    <span className="stat-card-sub">
                      <ShieldCheck size={12} /> Decrypted & route passed
                    </span>
                  </div>
                  <div className="stat-card accent fade-up">
                    <span className="stat-card-label">Detection Rate</span>
                    <span className="stat-card-value">{stats.rate}%</span>
                    <span className="stat-card-sub">
                      <TrendingUp size={12} /> Phishing-to-alert volume ratio
                    </span>
                  </div>
                </div>

                {/* Dashboard Plots */}
                <div className="two-col">
                  {/* Recharts Area Plot */}
                  <div className="card" style={{ display: 'flex', flexDirection: 'column' }}>
                    <div className="card-header">
                      <span className="card-title">Weekly Threat Volume Timeline</span>
                    </div>
                    <div className="card-body" style={{ flex: 1, minHeight: '260px' }}>
                      <ResponsiveContainer width="100%" height={240}>
                        <AreaChart data={stats.dailyVolume} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                          <defs>
                            <linearGradient id="colorPhish" x1="0" y1="0" x2="0" y2="1">
                              <stop offset="5%" stopColor="var(--danger)" stopOpacity={0.4} />
                              <stop offset="95%" stopColor="var(--danger)" stopOpacity={0.0} />
                            </linearGradient>
                            <linearGradient id="colorBenign" x1="0" y1="0" x2="0" y2="1">
                              <stop offset="5%" stopColor="var(--success)" stopOpacity={0.3} />
                              <stop offset="95%" stopColor="var(--success)" stopOpacity={0.0} />
                            </linearGradient>
                          </defs>
                          <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
                          <XAxis dataKey="date" stroke="var(--text-secondary)" fontSize={11} tickLine={false} />
                          <YAxis stroke="var(--text-secondary)" fontSize={11} tickLine={false} />
                          <Tooltip
                            contentStyle={{
                              backgroundColor: 'var(--bg-card)',
                              borderColor: 'var(--border-light)',
                              color: 'var(--text-primary)'
                            }}
                          />
                          <Area
                            type="monotone"
                            dataKey="phishing"
                            name="Phishing Threats"
                            stroke="var(--danger)"
                            fillOpacity={1}
                            fill="url(#colorPhish)"
                            strokeWidth={2}
                          />
                          <Area
                            type="monotone"
                            dataKey="benign"
                            name="Safe Traffic"
                            stroke="var(--success)"
                            fillOpacity={1}
                            fill="url(#colorBenign)"
                            strokeWidth={2}
                          />
                        </AreaChart>
                      </ResponsiveContainer>
                    </div>
                  </div>

                  {/* Active Campaigns Tracking */}
                  <div className="card">
                    <div className="card-header">
                      <span className="card-title">Targeted Phishing Campaigns Cluster</span>
                    </div>
                    <div className="card-body">
                      {campaigns.length === 0 ? (
                        <div className="empty-state">
                          <Inbox className="empty-state-icon" />
                          <div className="empty-state-text">No active campaigns tracked in database.</div>
                        </div>
                      ) : (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                          {campaigns.map((camp) => (
                            <div key={camp.id} className="campaign-item" style={{ borderBottom: '1px solid var(--border)', paddingBottom: '12px' }}>
                              <div style={{ flex: 1, minWidth: 0 }}>
                                <div className="campaign-name" style={{ fontSize: '13px', fontWeight: '600', color: 'var(--text-heading)' }}>
                                  {camp.name}
                                </div>
                                <div style={{ fontSize: '11.5px', color: 'var(--text-secondary)', marginTop: '2px', textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }}>
                                  {camp.description}
                                </div>
                              </div>
                              <div style={{ display: 'flex', alignItems: 'center', gap: '16px', marginLeft: '16px' }}>
                                <div style={{ textAlign: 'right' }}>
                                  <span className="campaign-count">{camp.count} hit{camp.count > 1 ? 's' : ''}</span>
                                  <div style={{ fontSize: '10px', color: 'var(--text-muted)' }}>Max Risk: {Math.round(camp.max_score * 100)}%</div>
                                </div>
                                <div className="campaign-bar-track">
                                  <div
                                    className="campaign-bar-fill"
                                    style={{ width: `${Math.min((camp.count / stats.total) * 100, 100)}%` }}
                                  />
                                </div>
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              </>
            )}

            {/* TAB 2: ALERTS QUEUE */}
            {activeTab === 'alerts' && (
              <div className="card" style={{ display: 'flex', flexDirection: 'column', height: '100%', border: 'none' }}>
                {/* Search / Filters toolbar */}
                <div className="alerts-toolbar" style={{ marginBottom: '16px' }}>
                  <div className="search-box">
                    <Search className="search-icon" size={14} />
                    <input
                      type="text"
                      placeholder="Search alert by ID, subject, sender, or recipient..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                    />
                  </div>

                  <button
                    className={`filter-btn ${verdictFilter === 'all' ? 'active-all' : ''}`}
                    onClick={() => setVerdictFilter('all')}
                  >
                    All Alerts ({alerts.length})
                  </button>
                  <button
                    className={`filter-btn ${verdictFilter === 'phishing' ? 'active-phishing' : ''}`}
                    onClick={() => setVerdictFilter('phishing')}
                  >
                    Phishing ({alerts.filter((a) => a.verdict === 'phishing').length})
                  </button>
                  <button
                    className={`filter-btn ${verdictFilter === 'suspicious' ? 'active-phishing' : ''}`}
                    style={{
                      borderColor: 'var(--warning-border)',
                      color: 'var(--warning)'
                    }}
                    onClick={() => setVerdictFilter('suspicious')}
                  >
                    Suspicious ({alerts.filter((a) => a.verdict === 'suspicious').length})
                  </button>
                  <button
                    className={`filter-btn ${verdictFilter === 'benign' ? 'active-benign' : ''}`}
                    onClick={() => setVerdictFilter('benign')}
                  >
                    Safe ({alerts.filter((a) => a.verdict === 'benign').length})
                  </button>
                  <button
                    className={`filter-btn ${verdictFilter === 'pending' ? 'active-all' : ''}`}
                    onClick={() => setVerdictFilter('pending')}
                  >
                    Pending SOC Triage ({stats.pending})
                  </button>
                </div>

                {/* Queue list structure */}
                <div style={{ display: 'flex', flex: 1, gap: '16px', overflow: 'hidden' }}>
                  <div className="alert-list" style={{ flex: 1, overflowY: 'auto', paddingRight: '4px' }}>
                    {filteredAlerts.length === 0 ? (
                      <div className="empty-state">
                        <Inbox className="empty-state-icon" />
                        <div className="empty-state-text">No alerts matching the selected search query or filters.</div>
                      </div>
                    ) : (
                      filteredAlerts.map((alert) => {
                        const isSelected = selectedAlert?.id === alert.id;
                        const formattedTime = new Date(alert.timestamp).toLocaleTimeString([], {
                          hour: '2-digit',
                          minute: '2-digit'
                        });

                        return (
                          <div
                            key={alert.id}
                            className={`alert-row ${isSelected ? 'selected' : ''} ${
                              alert.verdict === 'phishing' ? 'phishing-row' : ''
                            } ${alert.verdict === 'benign' ? 'benign-row' : ''}`}
                            onClick={() => setSelectedAlert(alert)}
                          >
                            <div
                              className={`alert-row-icon ${alert.verdict === 'phishing' ? 'phishing' : 'benign'}`}
                              style={{
                                backgroundColor:
                                  alert.verdict === 'suspicious'
                                    ? 'var(--warning-soft)'
                                    : alert.verdict === 'phishing'
                                    ? 'var(--danger-soft)'
                                    : 'var(--success-soft)',
                                color:
                                  alert.verdict === 'suspicious'
                                    ? 'var(--warning)'
                                    : alert.verdict === 'phishing'
                                    ? 'var(--danger)'
                                    : 'var(--success)'
                              }}
                            >
                              {alert.verdict === 'phishing' ? (
                                <ShieldAlert size={16} />
                              ) : alert.verdict === 'suspicious' ? (
                                <AlertTriangle size={16} />
                              ) : (
                                <ShieldCheck size={16} />
                              )}
                            </div>

                            <div className="alert-row-body">
                              <div className="alert-row-subject">{alert.subject}</div>
                              <div className="alert-row-meta">
                                From: {alert.sender} &bull; To: {alert.recipient}
                              </div>
                            </div>

                            <div className="alert-row-right">
                              <span className="alert-row-time">{formattedTime}</span>
                              <div className="confidence-bar-wrap">
                                <span
                                  className={`confidence-label ${
                                    alert.confidence_score >= 0.7
                                      ? 'high'
                                      : alert.confidence_score >= 0.4
                                      ? 'mid'
                                      : 'low'
                                  }`}
                                >
                                  {Math.round(alert.confidence_score * 100)}%
                                </span>
                              </div>
                            </div>
                          </div>
                        );
                      })
                    )}
                  </div>

                  {/* Sidebar Forensic Details */}
                  <AlertDetails
                    key={selectedAlert?.id || 'empty'}
                    alert={selectedAlert}
                    onAction={handleTriageAction}
                    onClose={() => setSelectedAlert(null)}
                  />
                </div>
              </div>
            )}

            {/* TAB 3: ACTIVE LEARNING LABELING QUEUE */}
            {activeTab === 'labeling' && (
              <div className="card">
                <div className="card-header">
                  <span className="card-title">High-Entropy Uncertainty Queue (Active Learning)</span>
                </div>
                <div className="card-body">
                  <div
                    style={{
                      backgroundColor: 'rgba(245, 158, 11, 0.08)',
                      border: '1px solid rgba(245, 158, 11, 0.25)',
                      borderRadius: 'var(--radius-md)',
                      padding: '16px',
                      color: 'var(--text-secondary)',
                      fontSize: '13px',
                      marginBottom: '20px',
                      lineHeight: '1.5'
                    }}
                  >
                    <strong style={{ color: 'var(--warning)', display: 'block', marginBottom: '4px' }}>
                      About Active Learning Ingestion
                    </strong>
                    These email alerts are flagged with borderline confidence scores (between 40% and 80%) where the
                    DeBERTa classifier pipeline is mathematically uncertain. Reviewing and confirming these samples
                    generates highly valuable human-in-the-loop labels to retrain the neural model and eliminate decision drift.
                  </div>

                  {labelingQueueAlerts.length === 0 ? (
                    <div className="empty-state">
                      <Brain className="empty-state-icon" style={{ color: 'var(--success)' }} />
                      <div className="empty-state-text">
                        Excellent! The Active Learning Queue is fully cleared. No high-entropy uncertainty alerts pending.
                      </div>
                    </div>
                  ) : (
                    <div style={{ display: 'flex', gap: '16px' }}>
                      <div className="alert-list" style={{ flex: 1 }}>
                        {labelingQueueAlerts.map((alert) => (
                          <div
                            key={alert.id}
                            className={`alert-row ${selectedAlert?.id === alert.id ? 'selected' : ''}`}
                            style={{ borderLeft: '3px solid var(--warning)' }}
                            onClick={() => setSelectedAlert(alert)}
                          >
                            <div
                              className="alert-row-icon"
                              style={{ backgroundColor: 'var(--warning-soft)', color: 'var(--warning)' }}
                            >
                              <Brain size={16} />
                            </div>
                            <div className="alert-row-body">
                              <div className="alert-row-subject">{alert.subject}</div>
                              <div className="alert-row-meta">
                                Target Group: <span className="tag">{alert.recipient_group}</span> &bull; Score:{' '}
                                <strong>{Math.round(alert.confidence_score * 100)}%</strong>
                              </div>
                            </div>
                            <div className="alert-row-right" style={{ justifyContent: 'center' }}>
                              <button
                                className="filter-btn"
                                style={{
                                  padding: '4px 8px',
                                  fontSize: '11.5px',
                                  borderColor: 'var(--warning-border)',
                                  color: 'var(--warning)'
                                }}
                              >
                                Triage Forensic &rarr;
                              </button>
                            </div>
                          </div>
                        ))}
                      </div>

                      <AlertDetails
                        key={selectedAlert?.id || 'empty'}
                        alert={selectedAlert}
                        onAction={handleTriageAction}
                        onClose={() => setSelectedAlert(null)}
                      />
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* TAB 4: SENSITIVITY THRESHOLD POLICIES */}
            {activeTab === 'policy' && (
              <div className="card" style={{ maxWidth: '680px' }}>
                <div className="card-header">
                  <span className="card-title">Group-Based Sensitivity Policy Thresholds</span>
                </div>
                <div className="card-body">
                  <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '24px', lineHeight: '1.5' }}>
                    Adjust the risk tolerance thresholds dynamically per user recipient group. A lower threshold increases
                    security posture by blocking mails with lower threat scores (higher false positives), whereas a higher threshold
                    ensures less disruption to business flow for lower-risk accounts.
                  </p>

                  <form onSubmit={handleUpdateThresholds}>
                    {Object.entries(thresholds).map(([group, val]) => (
                      <div
                        key={group}
                        style={{
                          marginBottom: '24px',
                          display: 'flex',
                          flexDirection: 'column',
                          gap: '8px'
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <label style={{ fontWeight: '600', fontSize: '13.5px', color: 'var(--text-heading)' }}>
                            {group} Policy Threshold
                          </label>
                          <span
                            style={{
                              fontFamily: 'var(--font-mono)',
                              fontWeight: '700',
                              fontSize: '13.5px',
                              color: val < 0.65 ? 'var(--danger)' : 'var(--accent-hover)',
                              padding: '2px 8px',
                              background: 'var(--bg-card-alt)',
                              borderRadius: 'var(--radius-sm)',
                              border: '1px solid var(--border)'
                            }}
                          >
                            {val.toFixed(2)}
                          </span>
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
                          <input
                            type="range"
                            min="0.10"
                            max="0.95"
                            step="0.05"
                            value={val}
                            onChange={(e) => handleSliderChange(group, e.target.value)}
                            style={{
                              flex: 1,
                              accentColor: 'var(--accent)',
                              height: '5px',
                              background: 'var(--border)',
                              borderRadius: '5px',
                              outline: 'none',
                              cursor: 'pointer'
                            }}
                          />
                          <div style={{ display: 'flex', justifyContent: 'space-between', width: '90px', fontSize: '11px', color: 'var(--text-muted)' }}>
                            <span>High Alert</span>
                            <span>Safe Mode</span>
                          </div>
                        </div>
                      </div>
                    ))}

                    <div style={{ borderTop: '1px solid var(--border)', paddingTop: '20px', display: 'flex', justifyContent: 'flex-end' }}>
                      <button type="submit" className="action-btn dismiss" style={{ flex: 'none', padding: '10px 24px' }}>
                        Save Threshold Policies
                      </button>
                    </div>
                  </form>
                </div>
              </div>
            )}

            {/* TAB 5: MODEL INTELLIGENCE */}
            {activeTab === 'metrics' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                {/* Stats row */}
                <div className="stats-grid">
                  <div className="stat-card accent">
                    <span className="stat-card-label">Precision Rate</span>
                    <span className="stat-card-value">{Math.round(modelMetrics.metrics.precision * 1000) / 10}%</span>
                    <span className="stat-card-sub">False Positive Ratio: {Math.round(modelMetrics.metrics.false_positive_rate * 1000) / 10}%</span>
                  </div>
                  <div className="stat-card accent">
                    <span className="stat-card-label">Recall Rate</span>
                    <span className="stat-card-value">{Math.round(modelMetrics.metrics.recall * 1000) / 10}%</span>
                    <span className="stat-card-sub">Blocked threat detection efficiency</span>
                  </div>
                  <div className="stat-card success">
                    <span className="stat-card-label">Neural F1-Score</span>
                    <span className="stat-card-value">{modelMetrics.metrics.f1_score.toFixed(3)}</span>
                    <span className="stat-card-sub">Harmonic mean of precision and recall</span>
                  </div>
                  <div className="stat-card warning">
                    <span className="stat-card-label">Uncertain Feedback</span>
                    <span className="stat-card-value">{labelingQueueAlerts.length}</span>
                    <span className="stat-card-sub">High entropy queue sample count</span>
                  </div>
                </div>

                <div className="two-col">
                  {/* Model specifications */}
                  <div className="card">
                    <div className="card-header">
                      <span className="card-title">Network Architecture Details</span>
                    </div>
                    <div className="card-body">
                      <div className="info-row">
                        <span className="info-label">Base Model</span>
                        <span className="info-value">DeBERTa-v3-Base (Fine-tuned on PhishCorpus)</span>
                      </div>
                      <div className="info-row">
                        <span className="info-label">Version</span>
                        <span className="info-value mono">{modelMetrics.model_version}</span>
                      </div>
                      <div className="info-row">
                        <span className="info-label">Last Retrained</span>
                        <span className="info-value">{new Date(modelMetrics.last_retrained).toLocaleString()}</span>
                      </div>
                      <div className="info-row">
                        <span className="info-label">Training Corpus</span>
                        <span className="info-value">{modelMetrics.training_samples.toLocaleString()} labeled messages</span>
                      </div>
                      <div className="info-row">
                        <span className="info-label">Feedback Ingestion</span>
                        <span className="info-value">{modelMetrics.active_learning.accumulated_feedback_count} SOC responses ingested</span>
                      </div>
                      <div className="info-row">
                        <span className="info-label">Drift Status</span>
                        <span className="info-value">
                          <span className="tag" style={{ backgroundColor: 'var(--success-soft)', color: 'var(--success)', borderColor: 'var(--success-border)' }}>
                            {modelMetrics.active_learning.drift_indicator}
                          </span>
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Active learning retraining trigger */}
                  <div className="card" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center', padding: '30px' }}>
                    <Brain size={48} style={{ color: retraining ? 'var(--warning)' : 'var(--accent)', marginBottom: '16px', animation: retraining ? 'spin 1.5s linear infinite' : 'none' }} />
                    <span style={{ fontSize: '15px', fontWeight: '700', color: 'var(--text-heading)', marginBottom: '8px' }}>
                      Model Fine-Tuning & Ingestion
                    </span>
                    <p style={{ fontSize: '12px', color: 'var(--text-muted)', textAlign: 'center', marginBottom: '20px', maxWidth: '320px', lineHeight: '1.4' }}>
                      Trigger active learning feedback ingestion. This collects all triaged analyst decisions and fine-tunes the base semantic token weights to adapt to brand-new zero-day campaigns.
                    </p>
                    <button
                      className="action-btn confirm"
                      style={{
                        backgroundColor: retraining ? 'var(--bg-hover)' : 'var(--accent-soft)',
                        color: retraining ? 'var(--text-muted)' : 'var(--accent-hover)',
                        borderColor: retraining ? 'var(--border)' : 'var(--accent-glow)',
                        padding: '10px 24px',
                        flex: 'none'
                      }}
                      disabled={retraining}
                      onClick={handleRetrainModel}
                    >
                      {retraining ? (
                        <>
                          <div className="spinner" style={{ width: '12px', height: '12px', marginRight: '6px' }} />
                          Fine-tuning network...
                        </>
                      ) : (
                        'Trigger Model Retraining'
                      )}
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* TAB 6: MANUAL SCAN EMAIL */}
            {activeTab === 'scan' && (
              <div className="card" style={{ maxWidth: '800px' }}>
                <div className="card-header">
                  <span className="card-title">Real-time Email Analysis Engine</span>
                </div>
                <div className="card-body">
                  <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '24px', lineHeight: '1.5' }}>
                    Paste full raw email headers and body below to run them through the APDS detection pipeline instantly.
                  </p>

                  <form onSubmit={handleScanEmail} style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                    <div style={{ display: 'flex', gap: '20px' }}>
                      <div style={{ flex: 1 }}>
                        <label style={{ display: 'block', marginBottom: '6px', fontSize: '12px', fontWeight: '600', color: 'var(--text-heading)' }}>Recipient Email</label>
                        <input
                          type="text"
                          value={scanRecipient}
                          onChange={(e) => setScanRecipient(e.target.value)}
                          placeholder="user@company.com"
                          style={{ width: '100%', padding: '10px 12px', borderRadius: '6px', border: '1px solid var(--border)', background: 'var(--bg-input)', color: 'var(--text-primary)' }}
                          required
                        />
                      </div>
                      <div style={{ flex: 1 }}>
                        <label style={{ display: 'block', marginBottom: '6px', fontSize: '12px', fontWeight: '600', color: 'var(--text-heading)' }}>Recipient Policy Group</label>
                        <select
                          value={scanRecipientGroup}
                          onChange={(e) => setScanRecipientGroup(e.target.value)}
                          style={{ width: '100%', padding: '10px 12px', borderRadius: '6px', border: '1px solid var(--border)', background: 'var(--bg-input)', color: 'var(--text-primary)' }}
                        >
                          <option value="Default">Default</option>
                          <option value="Executive">Executive</option>
                          <option value="Finance">Finance</option>
                          <option value="General Employee">General Employee</option>
                        </select>
                      </div>
                    </div>

                    <div>
                      <label style={{ display: 'block', marginBottom: '6px', fontSize: '12px', fontWeight: '600', color: 'var(--text-heading)' }}>Raw Email Content</label>
                      <textarea
                        value={scanEmailText}
                        onChange={(e) => setScanEmailText(e.target.value)}
                        placeholder="From: spoofed@evil.com&#10;To: target@company.com&#10;Subject: Urgent Request&#10;&#10;Please wire funds immediately..."
                        style={{ width: '100%', minHeight: '200px', padding: '12px', borderRadius: '6px', border: '1px solid var(--border)', background: 'var(--bg-input)', color: 'var(--text-primary)', fontFamily: 'monospace', fontSize: '12px' }}
                        required
                      />
                    </div>

                    <div style={{ borderTop: '1px solid var(--border)', paddingTop: '20px', display: 'flex', justifyContent: 'flex-end' }}>
                      <button type="submit" className="action-btn confirm" style={{ flex: 'none', padding: '10px 24px' }} disabled={isScanning}>
                        {isScanning ? 'Scanning Pipeline...' : 'Run Analysis'}
                      </button>
                    </div>
                  </form>

                  {/* SCAN RESULT DISPLAY */}
                  {scanResult && (
                    <div ref={resultRef} style={{ marginTop: '30px', borderTop: '1px solid var(--border)', paddingTop: '20px' }}>
                      <h4 style={{ color: 'var(--text-heading)', marginBottom: '16px' }}>Analysis Results</h4>
                      
                      <div className={`stat-card ${scanResult?.threat_category === 'benign' ? 'success' : 'danger'}`} style={{ marginBottom: '20px' }}>
                        <span className="stat-card-label">Final Verdict</span>
                        <span className="stat-card-value" style={{ textTransform: 'capitalize' }}>{scanResult?.fusion_result?.verdict || 'Unknown'}</span>
                        <span className="stat-card-sub">Confidence Score: {scanResult?.fusion_result?.confidence_score ? Math.round(scanResult.fusion_result.confidence_score * 100) : 0}%</span>
                      </div>

                      <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                        <div className="info-row">
                          <span className="info-label">Threat Category</span>
                          <span className="info-value" style={{ textTransform: 'capitalize' }}>{scanResult?.threat_category ? scanResult.threat_category.replace('_', ' ') : 'None'}</span>
                        </div>
                        <div className="info-row">
                          <span className="info-label">Flags Detected</span>
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                            {scanResult.fusion_result.explanations && scanResult.fusion_result.explanations.length > 0 ? (
                              scanResult.fusion_result.explanations.map((flag, idx) => (
                                <span key={idx} style={{ color: 'var(--danger)', fontSize: '12px' }}>• {flag}</span>
                              ))
                            ) : (
                              <span style={{ color: 'var(--success)', fontSize: '12px' }}>No malicious flags detected</span>
                            )}
                          </div>
                        </div>
                      </div>
                    </div>
                  )}

                </div>
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  );
}
