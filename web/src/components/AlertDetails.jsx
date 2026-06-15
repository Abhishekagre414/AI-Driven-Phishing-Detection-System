import { useState } from 'react';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  Mail,
  AlertTriangle,
  ExternalLink,
  Paperclip,
  TrendingUp,
  FileText,
  Activity,
  Layers
} from 'lucide-react';

export default function AlertDetails({ alert, onAction, onClose }) {
  const [notes, setNotes] = useState(alert?.analyst_notes || '');

  if (!alert) {
    return (
      <div className="empty-state">
        <Shield className="empty-state-icon" style={{ opacity: 0.15, fontSize: '48px' }} />
        <div className="empty-state-text">Select an alert from the queue to view deep forensics.</div>
      </div>
    );
  }

  const {
    id,
    timestamp,
    sender,
    recipient,
    recipient_group,
    subject,
    verdict,
    threat_category,
    confidence_score,
    raw_email,
    parsed_details = {},
    nlp_analysis = {},
    url_analysis = {},
    fusion_result = {},
    analyst_action = 'pending'
  } = alert;

  // Format date nicely
  const formatDate = (dateStr) => {
    try {
      const d = new Date(dateStr);
      return d.toLocaleString();
    } catch {
      return dateStr;
    }
  };

  const getVerdictIcon = (v) => {
    switch (v) {
      case 'phishing':
        return <ShieldAlert className="verdict-banner-icon" style={{ color: 'var(--danger)' }} />;
      case 'suspicious':
        return <AlertTriangle className="verdict-banner-icon" style={{ color: 'var(--warning)' }} />;
      case 'benign':
      default:
        return <ShieldCheck className="verdict-banner-icon" style={{ color: 'var(--success)' }} />;
    }
  };

  const getAuthBadgeClass = (status) => {
    const s = (status || 'none').toLowerCase();
    if (s === 'pass') return 'auth-badge pass';
    if (s === 'fail') return 'auth-badge fail';
    if (s === 'softfail') return 'auth-badge softfail';
    return 'auth-badge none';
  };

  const formatByteSize = (bytes) => {
    if (!bytes) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  };

  // Extract SHAP contributions as an array for rendering
  const shapList = Object.entries(fusion_result.shap_contributions || {}).map(([key, val]) => ({
    name: key,
    value: val
  })).sort((a, b) => b.value - a.value);

  // Compute maximum absolute value for SHAP scaling
  const maxShapAbs = Math.max(...shapList.map(s => Math.abs(s.value)), 0.1);

  return (
    <aside className="detail-panel">
      {/* Detail Header */}
      <div className="detail-header">
        <button className="detail-close-btn" onClick={onClose} title="Close Panel">
          &times;
        </button>
        <span className="detail-header-title">Forensic Analysis: {id}</span>
        <span className={`badge ${verdict}`}>{verdict}</span>
      </div>

      <div className="detail-body">
        {/* Verdict Banner */}
        <div className="detail-section" style={{ paddingBottom: '10px' }}>
          <div className={`verdict-banner ${verdict}`}>
            {getVerdictIcon(verdict)}
            <div className="verdict-banner-text">
              <div className="verdict-banner-label">{verdict} threat</div>
              <div className="verdict-banner-sub">
                Category: <strong style={{ textTransform: 'capitalize' }}>{threat_category.replace('_', ' ')}</strong>
              </div>
            </div>
            <div className="confidence-gauge">
              <span className="confidence-pct">{Math.round(confidence_score * 100)}%</span>
              <span className="confidence-gauge-label">Score</span>
            </div>
          </div>
        </div>

        {/* Action Form */}
        <div className="detail-section">
          <div className="detail-section-title">
            <Activity size={12} /> SOC Analyst Action
          </div>
          <div style={{ marginBottom: '10px' }}>
            <textarea
              className="search-box"
              style={{
                width: '100%',
                minHeight: '60px',
                padding: '8px 12px',
                background: 'var(--bg-input)',
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius)',
                color: 'var(--text-primary)',
                fontFamily: 'var(--font-sans)',
                fontSize: '12.5px',
                outline: 'none',
                resize: 'vertical'
              }}
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              placeholder="Add analyst triage findings or notes..."
            />
          </div>
          <div className="analyst-actions" style={{ padding: 0, border: 'none' }}>
            <button
              className="action-btn confirm"
              onClick={() => onAction(id, 'confirmed', notes)}
              title="Confirm Phishing"
            >
              Confirm Phishing
            </button>
            <button
              className="action-btn dismiss"
              onClick={() => onAction(id, 'overridden_benign', notes)}
              title="Dismiss (Mark Safe)"
            >
              Dismiss (Safe)
            </button>
            <button
              className="action-btn escalate"
              style={{ flex: '0.8' }}
              onClick={() => onAction(id, 'escalated', notes)}
              title="Escalate Alert"
            >
              Escalate
            </button>
          </div>
          {analyst_action && analyst_action !== 'pending' && (
            <div style={{ marginTop: '8px', fontSize: '11px', color: 'var(--text-secondary)' }}>
              Current Status: <strong style={{ color: analyst_action.includes('benign') ? 'var(--success)' : 'var(--danger)' }}>{analyst_action.toUpperCase()}</strong>
            </div>
          )}
        </div>

        {/* Email Header Forensics */}
        <div className="detail-section">
          <div className="detail-section-title">
            <Layers size={12} /> Header Forensics & Auth
          </div>
          <div className="info-row">
            <span className="info-label">Sender</span>
            <span className="info-value mono">{sender}</span>
          </div>
          {parsed_details.reply_to && (
            <div className="info-row">
              <span className="info-label">Reply-To</span>
              <span className="info-value mono" style={{ color: parsed_details.reply_to_mismatch ? 'var(--warning)' : 'var(--text-secondary)' }}>
                {parsed_details.reply_to}
              </span>
            </div>
          )}
          <div className="info-row">
            <span className="info-label">Recipient</span>
            <span className="info-value mono">{recipient}</span>
          </div>
          <div className="info-row">
            <span className="info-label">Target Group</span>
            <span className="info-value">
              <span className="tag">{recipient_group}</span>
            </span>
          </div>
          <div className="info-row">
            <span className="info-label">Timestamp</span>
            <span className="info-value">{formatDate(timestamp)}</span>
          </div>
          <div className="info-row">
            <span className="info-label">Hop Hops</span>
            <span className="info-value mono">{parsed_details.hop_count || 0} server relays</span>
          </div>

          <div style={{ marginTop: '12px' }}>
            <span className="info-label" style={{ display: 'block', marginBottom: '6px' }}>Authentication Records</span>
            <div className="auth-row">
              <div className="auth-badge-wrap">
                <span style={{ fontSize: '10.5px', color: 'var(--text-muted)', marginRight: '4px', fontWeight: '600' }}>SPF:</span>
                <span className={getAuthBadgeClass(parsed_details.spf_status)}>{parsed_details.spf_status || 'none'}</span>
              </div>
              <div className="auth-badge-wrap">
                <span style={{ fontSize: '10.5px', color: 'var(--text-muted)', marginRight: '4px', fontWeight: '600' }}>DKIM:</span>
                <span className={getAuthBadgeClass(parsed_details.dkim_status)}>{parsed_details.dkim_status || 'none'}</span>
              </div>
              <div className="auth-badge-wrap">
                <span style={{ fontSize: '10.5px', color: 'var(--text-muted)', marginRight: '4px', fontWeight: '600' }}>DMARC:</span>
                <span className={getAuthBadgeClass(parsed_details.dmarc_status)}>{parsed_details.dmarc_status || 'none'}</span>
              </div>
            </div>
          </div>
        </div>

        {/* Email Content Body */}
        <div className="detail-section">
          <div className="detail-section-title">
            <Mail size={12} /> Message Content
          </div>
          <div style={{ marginBottom: '8px' }}>
            <span className="info-label">Subject:</span>
            <span style={{ fontSize: '12.5px', fontWeight: '600', color: 'var(--text-heading)', marginLeft: '4px' }}>
              {subject}
            </span>
          </div>
          <div className="body-preview">
            {parsed_details.body_text || raw_email}
          </div>
        </div>

        {/* Dangerous Attachments */}
        {parsed_details.attachments && parsed_details.attachments.length > 0 && (
          <div className="detail-section">
            <div className="detail-section-title">
              <Paperclip size={12} /> Attachments ({parsed_details.attachments.length})
            </div>
            {parsed_details.attachments.map((att, index) => (
              <div key={index} className="url-card" style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <FileText size={20} style={{ color: att.is_high_risk ? 'var(--danger)' : 'var(--text-secondary)' }} />
                <div style={{ flex: '1', minWidth: 0 }}>
                  <div style={{ fontSize: '12px', fontWeight: '600', color: 'var(--text-primary)', wordBreak: 'break-all' }}>
                    {att.filename}
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', display: 'flex', gap: '8px' }}>
                    <span>{formatByteSize(att.size_bytes)}</span>
                    <span>&bull;</span>
                    <span>{att.content_type.split('/')[1] || att.content_type}</span>
                  </div>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '3px', alignItems: 'flex-end' }}>
                  {att.is_high_risk && <span className="tag" style={{ background: 'var(--danger-soft)', color: 'var(--danger)', borderColor: 'var(--danger-border)' }}>High Risk</span>}
                  {att.has_macros && <span className="tag" style={{ background: 'var(--warning-soft)', color: 'var(--warning)', borderColor: 'var(--warning-border)' }}>Macros</span>}
                </div>
              </div>
            ))}
          </div>
        )}

        {/* NLP Semantic Breakdown */}
        {nlp_analysis && nlp_analysis.categories && (
          <div className="detail-section">
            <div className="detail-section-title">
              <TrendingUp size={12} /> Semantic Threat Cues
            </div>
            {Object.entries(nlp_analysis.categories).map(([cat, val]) => {
              const valPct = Math.round(val * 100);
              let barColor = 'var(--accent)';
              if (cat === 'credential_harvesting') barColor = 'var(--danger)';
              if (cat === 'bec') barColor = 'var(--bec)';

              return (
                <div key={cat} className="nlp-bar">
                  <span className="nlp-bar-label">{cat.replace('_', ' ')}</span>
                  <div className="nlp-bar-track">
                    <div
                      className="nlp-bar-fill"
                      style={{ width: `${valPct}%`, backgroundColor: barColor }}
                    />
                  </div>
                  <span className="nlp-bar-val">{valPct}%</span>
                </div>
              );
            })}

            {nlp_analysis.linguistic_signals && nlp_analysis.linguistic_signals.length > 0 && (
              <div style={{ marginTop: '12px', display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                {nlp_analysis.linguistic_signals.map((sig, i) => (
                  <span key={i} className="tag">
                    {sig.signal.replace(/_/g, ' ')} ({Math.round(sig.weight * 100)}%)
                  </span>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Embedded URLs */}
        {url_analysis && url_analysis.details && url_analysis.details.length > 0 && (
          <div className="detail-section">
            <div className="detail-section-title">
              <ExternalLink size={12} /> Embedded URLs ({url_analysis.details.length})
            </div>
            {url_analysis.details.map((detail, index) => {
              let scoreClass = 'low';
              if (detail.score >= 0.7) scoreClass = 'high';
              else if (detail.score >= 0.4) scoreClass = 'mid';

              return (
                <div key={index} className="url-card">
                  <div className="url-string">{detail.url}</div>
                  <div className="url-meta">
                    <span className="url-domain">{detail.domain}</span>
                    <span className={`url-score-chip ${scoreClass}`}>
                      Risk: {Math.round(detail.score * 100)}%
                    </span>
                    {detail.indicators && detail.indicators.map((ind, k) => (
                      <span key={k} className="url-indicator">
                        {ind.replace(/_/g, ' ')}
                      </span>
                    ))}
                    {!detail.ssl_valid && (
                      <span className="url-indicator" style={{ color: 'var(--danger)', background: 'var(--danger-soft)' }}>
                        Insecure HTTP
                      </span>
                    )}
                    {detail.domain_age_days < 90 && (
                      <span className="url-indicator" style={{ color: 'var(--warning)', background: 'var(--warning-soft)' }}>
                        New Domain ({detail.domain_age_days}d)
                      </span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {/* SHAP Explanations Chart */}
        {shapList.length > 0 && (
          <div className="detail-section">
            <div className="detail-section-title">
              <Layers size={12} /> Explainable ML (SHAP Weights)
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '8px' }}>
              {shapList.map((shap, index) => {
                const isPositive = shap.value > 0;
                const absVal = Math.abs(shap.value);
                const percent = Math.min((absVal / maxShapAbs) * 50, 50); // scale max to 50% width

                return (
                  <div key={index} style={{ display: 'flex', flexDirection: 'column', gap: '3px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', color: 'var(--text-secondary)' }}>
                      <span>{shap.name}</span>
                      <span style={{ fontFamily: 'var(--font-mono)', fontWeight: '600', color: isPositive ? 'var(--danger)' : 'var(--success)' }}>
                        {isPositive ? '+' : ''}{shap.value.toFixed(3)}
                      </span>
                    </div>
                    {/* Horizontal split bar container */}
                    <div style={{ height: '8px', background: 'var(--bg-base)', borderRadius: '4px', overflow: 'hidden', position: 'relative', display: 'flex' }}>
                      {/* Left half (Negative contribution) */}
                      <div style={{ flex: '1', display: 'flex', justifyContent: 'flex-end', borderRight: '1px solid var(--border)' }}>
                        {!isPositive && (
                          <div
                            style={{
                              width: `${percent * 2}%`,
                              height: '100%',
                              backgroundColor: 'var(--success)',
                              borderTopLeftRadius: '3px',
                              borderBottomLeftRadius: '3px'
                            }}
                          />
                        )}
                      </div>
                      {/* Right half (Positive contribution) */}
                      <div style={{ flex: '1', display: 'flex', justifyContent: 'flex-start' }}>
                        {isPositive && (
                          <div
                            style={{
                              width: `${percent * 2}%`,
                              height: '100%',
                              backgroundColor: 'var(--danger)',
                              borderTopRightRadius: '3px',
                              borderBottomRightRadius: '3px'
                            }}
                          />
                        )}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '9px', color: 'var(--text-muted)', marginTop: '4px', fontWeight: '500' }}>
              <span>&larr; REDUCES RISK (SAFE)</span>
              <span>INCREASES RISK (THREAT) &rarr;</span>
            </div>
          </div>
        )}

        {/* AI Explanations List */}
        {fusion_result.explanations && fusion_result.explanations.length > 0 && (
          <div className="detail-section" style={{ borderBottom: 'none' }}>
            <div className="detail-section-title">
              <Shield size={12} /> AI Threat Reasoning
            </div>
            <div style={{ marginTop: '8px' }}>
              {fusion_result.explanations.map((exp, index) => (
                <div key={index} className="explanation-item">
                  <div className="explanation-dot" style={{ backgroundColor: verdict === 'phishing' ? 'var(--danger)' : 'var(--warning)' }} />
                  <div>{exp}</div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </aside>
  );
}
