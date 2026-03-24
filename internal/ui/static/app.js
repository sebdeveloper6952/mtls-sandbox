(function () {
  'use strict';

  var startedAt = null;
  var selectedRequestId = null;
  var pollTimer = null;

  // --- Router ---
  document.addEventListener('DOMContentLoaded', function () {
    fetchStatus();
    setInterval(updateUptime, 1000);
    window.addEventListener('hashchange', route);
    route();
  });

  function route() {
    clearPoll();
    var hash = location.hash || '#/';
    var app = document.getElementById('app');

    if (hash === '#/' || hash === '#') {
      renderLanding(app);
    } else if (hash.indexOf('#/session/') === 0) {
      var id = hash.replace('#/session/', '');
      renderSession(app, id);
    } else if (hash === '#/monitor') {
      renderMonitor(app);
    } else {
      app.innerHTML = '<div class="page"><h2>Not Found</h2></div>';
    }
  }

  function clearPoll() {
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
  }

  // --- Landing Page ---
  function renderLanding(app) {
    app.innerHTML =
      '<div class="page landing">' +
        '<div class="hero">' +
          '<h2>Test Your mTLS Configuration</h2>' +
          '<p>Create a session to get a unique client certificate. Use it to validate your outgoing mTLS setup, or let us call your server to validate your incoming mTLS enforcement.</p>' +
          '<button class="btn btn-primary btn-large" id="btn-create-session">Create Session</button>' +
        '</div>' +
        '<div class="use-cases">' +
          '<div class="use-case">' +
            '<div class="use-case-icon">→</div>' +
            '<h3>Client Auth</h3>' +
            '<p class="use-case-desc">Your app connects to an mTLS server. Verify it presents client certs correctly.</p>' +
            '<ol class="use-case-steps">' +
              '<li>Download your session cert &amp; key</li>' +
              '<li>Configure your HTTP client to use them</li>' +
              '<li>Point your app at our mTLS endpoint</li>' +
              '<li>Watch the handshake result live</li>' +
            '</ol>' +
          '</div>' +
          '<div class="use-case-divider"></div>' +
          '<div class="use-case">' +
            '<div class="use-case-icon">←</div>' +
            '<h3>Server Auth</h3>' +
            '<p class="use-case-desc">Your server receives connections. Verify it correctly demands and verifies client certs.</p>' +
            '<ol class="use-case-steps">' +
              '<li>Trust our CA on your server</li>' +
              '<li>Set your server\'s HTTPS URL</li>' +
              '<li>We call you with our client cert</li>' +
              '<li>See whether the handshake passed or failed</li>' +
            '</ol>' +
          '</div>' +
        '</div>' +
      '</div>';

    document.getElementById('btn-create-session').addEventListener('click', function () {
      var btn = this;
      btn.disabled = true;
      btn.textContent = 'Creating...';
      fetch('/api/sessions', { method: 'POST' })
        .then(function (r) { return r.json(); })
        .then(function (sess) { location.hash = '#/session/' + sess.id; })
        .catch(function () {
          btn.disabled = false;
          btn.textContent = 'Create Session';
          alert('Failed to create session');
        });
    });
  }

  // --- Session Page ---
  function renderSession(app, id) {
    app.innerHTML =
      '<div class="page session-page">' +
        '<div class="session-loading">Loading session...</div>' +
      '</div>';

    fetch('/api/sessions/' + id)
      .then(function (r) {
        if (!r.ok) throw new Error('not found');
        return r.json();
      })
      .then(function (sess) { renderSessionContent(app, sess); })
      .catch(function () {
        app.innerHTML =
          '<div class="page"><div class="error-box">Session not found or expired. <a href="#/">Create a new one</a>.</div></div>';
      });
  }

  function renderSessionContent(app, sess) {
    var host = window.location.hostname;
    var isLocal = (host === 'localhost' || host === '127.0.0.1');
    var mtlsBase = 'https://' + host + ':8443';
    var curlCmd = 'curl --cert session.crt --key session.key' +
      (isLocal ? ' \\\n     --cacert ca.crt' : '') +
      ' \\\n     ' + mtlsBase + '/';

    var html =
      '<div class="page session-page">' +
        '<div class="session-header">' +
          '<div>' +
            '<h2>Session <code>' + esc(sess.id) + '</code></h2>' +
            '<div class="session-meta">' +
              '<span>CN: <strong>' + esc(sess.cert_cn) + '</strong></span>' +
              '<span>Expires: ' + esc(new Date(sess.expires_at).toLocaleString()) + '</span>' +
            '</div>' +
          '</div>' +
        '</div>' +

        '<div class="main-tabs">' +
          '<button class="main-tab-btn main-tab-active" id="main-tab-client">' +
            '<span class="tab-arrow">→</span> Client Auth' +
            ' <span id="inbound-count" class="count-badge">0</span>' +
          '</button>' +
          '<button class="main-tab-btn" id="main-tab-server">' +
            '<span class="tab-arrow">←</span> Server Auth' +
            ' <span id="call-count" class="count-badge">0</span>' +
          '</button>' +
        '</div>' +

        // ── Client Auth panel ──────────────────────────────────────
        '<div id="main-panel-client">' +
          '<p class="tab-intro">Test that your app correctly presents a client certificate when connecting to an mTLS server. ' +
            'Download your credentials, configure your HTTP client, point it at our endpoint, and watch the handshake result appear below.</p>' +

          '<section class="panel">' +
            '<h2>Your Credentials</h2>' +
            '<p class="help-text">Your app needs both files. Keep the private key secure — it never leaves this session.</p>' +
            '<div class="cred-grid">' +
              '<div class="cred-block">' +
                '<div class="cred-label">Certificate</div>' +
                '<pre class="pem-pre">' + esc(sess.client_cert_pem || '') + '</pre>' +
                '<div class="cred-actions">' +
                  '<button class="btn btn-copy" id="btn-copy-cert">Copy</button>' +
                  '<button class="btn" id="btn-dl-cert">Download .crt</button>' +
                '</div>' +
              '</div>' +
              '<div class="cred-block">' +
                '<div class="cred-label">Private Key</div>' +
                '<pre class="pem-pre pem-key">' + esc(sess.client_key_pem || '') + '</pre>' +
                '<div class="cred-actions">' +
                  '<button class="btn btn-copy" id="btn-copy-key">Copy</button>' +
                  '<button class="btn" id="btn-dl-key">Download .key</button>' +
                '</div>' +
              '</div>' +
            '</div>' +
          '</section>' +

          '<section class="panel">' +
            '<h2>Try It Now</h2>' +
            '<p class="help-text">Save the files above as <code>session.crt</code> and <code>session.key</code>, then run:</p>' +
            '<div class="curl-block">' +
              '<pre class="curl-cmd">' + esc(curlCmd) + '</pre>' +
              '<button class="btn btn-copy" id="btn-copy-curl">Copy</button>' +
            '</div>' +
            (isLocal
              ? '<p class="help-text">Running locally: also download <a href="/api/certs/ca" download="ca.crt">ca.crt</a> to verify our server cert, or replace <code>--cacert ca.crt</code> with <code>-k</code>.</p>'
              : '') +
          '</section>' +

          '<section class="panel">' +
            '<h2>Request Log <span id="inbound-log-count" class="count-badge">0</span></h2>' +
            '<div id="inbound-container"></div>' +
          '</section>' +
        '</div>' +

        // ── Server Auth panel ──────────────────────────────────────
        '<div id="main-panel-server" class="hidden">' +
          '<p class="tab-intro">Test that your server correctly demands and verifies client certificates from callers. ' +
            'Follow the steps below — we\'ll call your server using this session\'s client cert and show you exactly what happened.</p>' +

          '<section class="panel">' +
            '<h2>Step 1 — Trust Our CA</h2>' +
            '<p class="help-text">Add this certificate to your server\'s trusted <em>client</em> CA list (not the regular server trust store).</p>' +
            '<div class="pem-block">' +
              '<pre>' + esc(sess.ca_cert_pem || '') + '</pre>' +
              '<div class="pem-actions">' +
                '<button class="btn btn-copy" id="btn-copy-ca">Copy</button>' +
                '<button class="btn" id="btn-dl-ca">Download .crt</button>' +
              '</div>' +
            '</div>' +
            '<details class="code-snippets">' +
              '<summary>Configuration examples</summary>' +
              '<div class="snippet-grid">' +
                '<div class="snippet"><div class="snippet-label">nginx</div>' +
                  '<pre>ssl_client_certificate /etc/nginx/sandbox-ca.crt;\nssl_verify_client on;</pre>' +
                '</div>' +
                '<div class="snippet"><div class="snippet-label">Go</div>' +
                  '<pre>caPool := x509.NewCertPool()\ncaPool.AppendCertsFromPEM(caPEM)\ntlsCfg := &tls.Config{\n    ClientCAs:  caPool,\n    ClientAuth: tls.RequireAndVerifyClientCert,\n}</pre>' +
                '</div>' +
              '</div>' +
            '</details>' +
          '</section>' +

          '<section class="panel">' +
            '<h2>Step 2 — Your Server URL</h2>' +
            '<p class="help-text">The HTTPS URL we\'ll call. Must be publicly reachable — no private IPs.</p>' +
            '<div class="url-form">' +
              '<input type="url" id="callback-url" placeholder="https://your-server.example.com" value="' + attr(sess.callback_url || '') + '">' +
              '<button class="btn btn-primary" id="btn-save-url">Save</button>' +
            '</div>' +
            '<div id="url-feedback" class="feedback"></div>' +
          '</section>' +

          '<section class="panel">' +
            '<h2>Step 3 — Run Tests</h2>' +
            '<div class="test-grid">' +
              '<div class="test-option">' +
                '<button class="btn btn-primary" id="btn-test" data-mode="normal">Run mTLS Test</button>' +
                '<p class="test-desc">Sends our session cert.<br><strong class="result-ok">Should pass.</strong></p>' +
              '</div>' +
              '<div class="test-option">' +
                '<button class="btn btn-danger" id="btn-test-nocert" data-mode="no_cert">No Client Cert</button>' +
                '<p class="test-desc">Sends no cert at all.<br><strong class="result-fail">Should be rejected.</strong></p>' +
              '</div>' +
              '<div class="test-option">' +
                '<button class="btn btn-danger" id="btn-test-wrongca" data-mode="wrong_ca">Wrong CA</button>' +
                '<p class="test-desc">Cert from untrusted CA.<br><strong class="result-fail">Should be rejected.</strong></p>' +
              '</div>' +
            '</div>' +
            '<div id="test-feedback" class="feedback"></div>' +
          '</section>' +

          '<section class="panel">' +
            '<h2>Test Results <span id="call-log-count" class="count-badge">0</span></h2>' +
            '<div id="calls-container"></div>' +
          '</section>' +
        '</div>' +
      '</div>';

    app.innerHTML = html;

    // Main tab switching
    function showTab(tab) {
      var isClient = tab === 'client';
      document.getElementById('main-tab-client').classList.toggle('main-tab-active', isClient);
      document.getElementById('main-tab-server').classList.toggle('main-tab-active', !isClient);
      document.getElementById('main-panel-client').classList.toggle('hidden', !isClient);
      document.getElementById('main-panel-server').classList.toggle('hidden', isClient);
    }
    document.getElementById('main-tab-client').addEventListener('click', function () { showTab('client'); });
    document.getElementById('main-tab-server').addEventListener('click', function () { showTab('server'); });

    // Credentials
    document.getElementById('btn-copy-cert').addEventListener('click', function () { copyText(sess.client_cert_pem, this); });
    document.getElementById('btn-copy-key').addEventListener('click', function () { copyText(sess.client_key_pem, this); });
    document.getElementById('btn-dl-cert').addEventListener('click', function () { downloadText('session.crt', sess.client_cert_pem); });
    document.getElementById('btn-dl-key').addEventListener('click', function () { downloadText('session.key', sess.client_key_pem); });
    document.getElementById('btn-copy-curl').addEventListener('click', function () { copyText(curlCmd, this); });

    // CA cert
    document.getElementById('btn-copy-ca').addEventListener('click', function () { copyText(sess.ca_cert_pem, this); });
    document.getElementById('btn-dl-ca').addEventListener('click', function () { downloadText('sandbox-ca.crt', sess.ca_cert_pem); });

    // Save URL
    document.getElementById('btn-save-url').addEventListener('click', function () {
      var url = document.getElementById('callback-url').value.trim();
      var feedback = document.getElementById('url-feedback');
      fetch('/api/sessions/' + sess.id, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ callback_url: url })
      })
        .then(function (r) {
          if (!r.ok) return r.json().then(function (d) { throw new Error(d.error); });
          return r.json();
        })
        .then(function () {
          sess.callback_url = url;
          feedback.className = 'feedback feedback-ok';
          feedback.textContent = 'Saved!';
        })
        .catch(function (err) {
          feedback.className = 'feedback feedback-err';
          feedback.textContent = err.message || 'Failed to save';
        });
    });

    // Test buttons
    ['btn-test', 'btn-test-nocert', 'btn-test-wrongca'].forEach(function (btnId) {
      document.getElementById(btnId).addEventListener('click', function () {
        var btn = this;
        var origText = btn.textContent;
        var mode = btn.getAttribute('data-mode');
        var feedback = document.getElementById('test-feedback');
        btn.disabled = true;
        btn.textContent = 'Testing...';
        feedback.textContent = '';

        fetch('/api/sessions/' + sess.id + '/test', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ test_mode: mode })
        })
          .then(function (r) {
            if (!r.ok) return r.json().then(function (d) { throw new Error(d.error); });
            return r.json();
          })
          .then(function (result) {
            btn.disabled = false;
            btn.textContent = origText;
            if (!result.error) {
              feedback.className = 'feedback feedback-ok';
              feedback.textContent = 'HTTP ' + result.status_code + ' in ' + result.duration_ms + 'ms';
            } else {
              feedback.className = 'feedback feedback-err';
              feedback.textContent = result.error;
            }
            fetchCalls(sess.id);
          })
          .catch(function (err) {
            btn.disabled = false;
            btn.textContent = origText;
            feedback.className = 'feedback feedback-err';
            feedback.textContent = err.message || 'Test failed';
          });
      });
    });

    fetchCalls(sess.id);
    fetchInbound(sess.id);
    pollTimer = setInterval(function () {
      fetchCalls(sess.id);
      fetchInbound(sess.id);
    }, 5000);
  }

  function fetchCalls(sessionId) {
    fetch('/api/sessions/' + sessionId + '/calls?limit=50')
      .then(function (r) { return r.json(); })
      .then(function (data) {
        var badge = document.getElementById('call-count');
        if (badge) badge.textContent = data.total;
        var badge2 = document.getElementById('call-log-count');
        if (badge2) badge2.textContent = data.total;
        renderCalls(data.calls || []);
      })
      .catch(noop);
  }

  function renderCalls(calls) {
    var container = document.getElementById('calls-container');
    if (calls.length === 0) {
      container.innerHTML = '<div class="empty-state">No test calls yet. Run a test above!</div>';
      return;
    }

    var html = '<table><thead><tr><th>Time</th><th>Mode</th><th>Status</th><th>Result</th><th>Latency</th></tr></thead><tbody>';
    for (var i = 0; i < calls.length; i++) {
      var c = calls[i];
      var ok = c.probe_result && c.probe_result.inspection && c.probe_result.inspection.handshake_ok;
      var resultClass = c.error ? 'result-fail' : (ok ? 'result-ok' : 'result-fail');
      var resultText = c.error ? 'ERROR' : (ok ? 'PASS' : 'FAIL');
      var modeLabel = c.test_mode || 'normal';
      var modeClass = modeLabel === 'normal' ? 'mode-normal' : 'mode-negative';

      html += '<tr class="clickable call-row" data-idx="' + i + '">' +
        '<td>' + esc(timeAgo(c.created_at)) + '</td>' +
        '<td class="' + modeClass + '">' + esc(modeLabel) + '</td>' +
        '<td>' + (c.status_code || '--') + '</td>' +
        '<td class="' + resultClass + '">' + resultText + '</td>' +
        '<td>' + c.duration_ms + 'ms</td>' +
      '</tr>';

      // Expandable detail row
      html += '<tr class="call-detail hidden" id="call-detail-' + i + '"><td colspan="5">';
      if (c.error) {
        html += '<div class="detail-section"><span class="label">Error:</span> <span class="result-fail">' + esc(c.error) + '</span></div>';
      }
      if (c.probe_result && c.probe_result.inspection) {
        var insp = c.probe_result.inspection;
        html += '<div class="detail-section">';
        html += '<div class="detail-grid">';
        html += '<span class="label">Handshake</span><span class="' + (insp.handshake_ok ? 'result-ok' : 'result-fail') + '">' + (insp.handshake_ok ? 'OK' : 'FAILED') + '</span>';
        if (insp.failure_code) {
          html += '<span class="label">Failure</span><span class="result-fail">' + esc(insp.failure_code) + '</span>';
          html += '<span class="label">Reason</span><span>' + esc(insp.failure_reason) + '</span>';
        }
        if (insp.presented) {
          html += '<span class="label">TLS Version</span><span>' + esc(insp.presented.tls_version || '--') + '</span>';
          html += '<span class="label">Cipher</span><span>' + esc(insp.presented.cipher_suite || '--') + '</span>';
          if (insp.presented.cert_chain && insp.presented.cert_chain.length > 0) {
            var cert = insp.presented.cert_chain[0];
            html += '<span class="label">Server CN</span><span>' + esc(cert.subject) + '</span>';
          }
        }
        html += '</div>';
        if (insp.hints && insp.hints.length > 0) {
          html += '<ul class="hints-list">';
          for (var h = 0; h < insp.hints.length; h++) {
            html += '<li>' + esc(insp.hints[h]) + '</li>';
          }
          html += '</ul>';
        }
        html += '</div>';
      }
      html += '</td></tr>';
    }
    html += '</tbody></table>';
    container.innerHTML = html;

    // Toggle detail rows
    container.querySelectorAll('.call-row').forEach(function (row) {
      row.addEventListener('click', function () {
        var idx = row.getAttribute('data-idx');
        var detail = document.getElementById('call-detail-' + idx);
        detail.classList.toggle('hidden');
      });
    });
  }

  function fetchInbound(sessionId) {
    fetch('/api/sessions/' + sessionId + '/inbound?limit=50')
      .then(function (r) { return r.json(); })
      .then(function (data) {
        var badge = document.getElementById('inbound-count');
        if (badge) badge.textContent = data.total;
        var badge2 = document.getElementById('inbound-log-count');
        if (badge2) badge2.textContent = data.total;
        renderInbound(data.requests || []);
      })
      .catch(noop);
  }

  function renderInbound(requests) {
    var container = document.getElementById('inbound-container');
    if (requests.length === 0) {
      container.innerHTML = '<div class="empty-state">No inbound requests yet. Make a request to <code>mtls.apps.sebdev.io:8443</code> using this session\'s client cert.</div>';
      return;
    }

    var html = '<table><thead><tr><th>Time</th><th>Method</th><th>Path</th><th>Status</th><th>Handshake</th><th>Latency</th></tr></thead><tbody>';
    for (var i = 0; i < requests.length; i++) {
      var r = requests[i];
      var okClass = r.handshake_ok ? 'result-ok' : 'result-fail';
      var okText = r.handshake_ok ? 'PASS' : 'FAIL';

      html += '<tr class="clickable inbound-row" data-idx="' + i + '">' +
        '<td>' + esc(timeAgo(r.created_at)) + '</td>' +
        '<td>' + esc(r.method) + '</td>' +
        '<td>' + esc(r.path) + '</td>' +
        '<td>' + (r.status_code || '--') + '</td>' +
        '<td class="' + okClass + '">' + okText + '</td>' +
        '<td>' + r.latency_ms + 'ms</td>' +
      '</tr>';

      html += '<tr class="call-detail hidden" id="inbound-detail-' + i + '"><td colspan="6">';
      html += '<div class="detail-section"><div class="detail-grid">';
      html += '<span class="label">Handshake</span><span class="' + okClass + '">' + (r.handshake_ok ? 'OK' : 'FAILED') + '</span>';
      if (r.failure_code) {
        html += '<span class="label">Failure</span><span class="result-fail">' + esc(r.failure_code) + '</span>';
        html += '<span class="label">Reason</span><span>' + esc(r.failure_reason) + '</span>';
      }
      if (r.report && r.report.presented) {
        html += '<span class="label">TLS Version</span><span>' + esc(r.report.presented.tls_version || '--') + '</span>';
        html += '<span class="label">Cipher</span><span>' + esc(r.report.presented.cipher_suite || '--') + '</span>';
        if (r.report.presented.cert_chain && r.report.presented.cert_chain.length > 0) {
          html += '<span class="label">Client CN</span><span>' + esc(r.report.presented.cert_chain[0].subject) + '</span>';
        }
      }
      html += '</div>';
      if (r.report && r.report.hints && r.report.hints.length > 0) {
        html += '<ul class="hints-list">';
        for (var h = 0; h < r.report.hints.length; h++) {
          html += '<li>' + esc(r.report.hints[h]) + '</li>';
        }
        html += '</ul>';
      }
      html += '</div></td></tr>';
    }
    html += '</tbody></table>';
    container.innerHTML = html;

    container.querySelectorAll('.inbound-row').forEach(function (row) {
      row.addEventListener('click', function () {
        var idx = row.getAttribute('data-idx');
        document.getElementById('inbound-detail-' + idx).classList.toggle('hidden');
      });
    });
  }

  // --- Monitor Page (existing dashboard) ---
  function renderMonitor(app) {
    app.innerHTML =
      '<div class="page">' +
        '<section id="certs-panel" class="panel">' +
          '<h2 class="panel-header" data-toggle="certs-content">Certificates</h2>' +
          '<div id="certs-content" class="panel-body">' +
            '<div class="cert-cards" id="cert-cards"></div>' +
          '</div>' +
        '</section>' +

        '<section id="quick-test" class="panel">' +
          '<h2 class="panel-header" data-toggle="quick-test-content">Quick Test</h2>' +
          '<div id="quick-test-content" class="panel-body">' +
            '<div class="curl-commands" id="curl-commands"></div>' +
          '</div>' +
        '</section>' +

        '<div class="split-view">' +
          '<section id="request-log" class="panel">' +
            '<h2>Request Log <span id="request-count" class="count-badge">0</span></h2>' +
            '<table id="requests-table">' +
              '<thead><tr><th>Time</th><th>Method</th><th>Path</th><th>Cert CN</th><th>Result</th><th>Latency</th></tr></thead>' +
              '<tbody id="requests-body"></tbody>' +
            '</table>' +
          '</section>' +
          '<section id="detail-panel" class="panel hidden">' +
            '<h2>Inspection Detail</h2>' +
            '<div id="detail-content"></div>' +
          '</section>' +
        '</div>' +
      '</div>';

    // Toggle panels
    app.querySelectorAll('.panel-header').forEach(function (el) {
      el.addEventListener('click', function () {
        var targetId = el.getAttribute('data-toggle');
        if (targetId) document.getElementById(targetId).classList.toggle('collapsed');
      });
    });

    fetchCerts();
    fetchMonitorStatus();
    fetchRequests();
    pollTimer = setInterval(fetchRequests, 2000);
  }

  function fetchMonitorStatus() {
    fetch('/api/status')
      .then(function (r) { return r.json(); })
      .then(function (data) { updateCurlCommands(data); })
      .catch(noop);
  }

  // --- Status ---
  function fetchStatus() {
    fetch('/api/status')
      .then(function (r) { return r.json(); })
      .then(function (data) {
        startedAt = new Date(data.started_at);
        var badge = document.getElementById('mode-badge');
        if (badge) {
          badge.textContent = data.mode;
          badge.className = 'badge badge-' + data.mode;
        }
      })
      .catch(noop);
  }

  function updateUptime() {
    if (!startedAt) return;
    var secs = Math.floor((Date.now() - startedAt.getTime()) / 1000);
    var h = Math.floor(secs / 3600);
    var m = Math.floor((secs % 3600) / 60);
    var s = secs % 60;
    document.getElementById('uptime').textContent =
      'Uptime: ' + pad(h) + ':' + pad(m) + ':' + pad(s);
  }

  // --- Certificates ---
  function fetchCerts() {
    fetch('/api/certs')
      .then(function (r) { return r.json(); })
      .then(renderCertCards)
      .catch(noop);
  }

  function renderCertCards(data) {
    var container = document.getElementById('cert-cards');
    if (!container) return;
    container.innerHTML = '';
    var roles = ['ca', 'server', 'client'];
    for (var i = 0; i < roles.length; i++) {
      var role = roles[i];
      var cert = data[role];
      if (!cert) continue;
      var card = document.createElement('div');
      card.className = 'cert-card';

      var expDate = cert.not_after ? new Date(cert.not_after).toLocaleDateString() : '--';
      card.innerHTML =
        '<h3>' + esc(role) + '</h3>' +
        '<div class="field"><span class="label">CN</span><span>' + esc(cert.cn || '--') + '</span></div>' +
        '<div class="field"><span class="label">Issuer</span><span>' + esc(cert.issuer || '--') + '</span></div>' +
        '<div class="field"><span class="label">Expires</span><span>' + esc(expDate) + '</span></div>' +
        (cert.dns_names && cert.dns_names.length
          ? '<div class="field"><span class="label">SANs</span><span>' + esc(cert.dns_names.join(', ')) + '</span></div>'
          : '') +
        '<div class="actions">' +
          '<button class="btn btn-copy-pem" data-pem="' + attr(cert.pem || '') + '">Copy PEM</button>' +
          '<a class="btn" href="/api/certs/' + role + '" download>Download</a>' +
          (cert.key_pem
            ? '<button class="btn btn-copy-pem" data-pem="' + attr(cert.key_pem) + '">Copy Key</button>' +
              '<a class="btn" href="/api/certs/client-key" download>Download Key</a>'
            : '') +
        '</div>';

      container.appendChild(card);
    }

    container.querySelectorAll('.btn-copy-pem').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var pem = btn.getAttribute('data-pem');
        copyText(pem, btn);
      });
    });
  }

  // --- Curl Commands ---
  function updateCurlCommands(status) {
    var container = document.getElementById('curl-commands');
    if (!container) return;
    var p = status.persist_path || './certs';
    var port = status.mtls_port || 8443;
    var host = window.location.hostname;
    var base = 'https://' + host + ':' + port;
    var commands = [
      {
        label: 'Test mTLS handshake (strict mode)',
        cmd: 'curl --cert ' + p + '/client.crt --key ' + p + '/client.key \\\n  --cacert ' + p + '/ca.crt \\\n  ' + base + '/'
      },
      {
        label: 'Without client cert (should fail in strict mode)',
        cmd: 'curl --cacert ' + p + '/ca.crt ' + base + '/'
      },
      {
        label: 'Debug endpoint',
        cmd: 'curl --cert ' + p + '/client.crt --key ' + p + '/client.key \\\n  --cacert ' + p + '/ca.crt \\\n  ' + base + '/debug'
      }
    ];

    container.innerHTML = '';
    for (var i = 0; i < commands.length; i++) {
      var c = commands[i];
      var block = document.createElement('div');
      block.className = 'curl-block';
      block.innerHTML =
        '<div class="label">' + esc(c.label) + '</div>' +
        '<code>' + esc(c.cmd) + '</code>' +
        '<button class="btn btn-copy" data-cmd="' + attr(c.cmd) + '">Copy</button>';
      container.appendChild(block);
    }

    container.querySelectorAll('.btn-copy').forEach(function (btn) {
      btn.addEventListener('click', function () {
        navigator.clipboard.writeText(btn.getAttribute('data-cmd')).then(function () {
          btn.textContent = 'Copied!';
          setTimeout(function () { btn.textContent = 'Copy'; }, 1500);
        });
      });
    });
  }

  // --- Request Log ---
  function fetchRequests() {
    fetch('/api/requests?limit=100')
      .then(function (r) { return r.json(); })
      .then(renderRequests)
      .catch(noop);
  }

  function renderRequests(entries) {
    var countEl = document.getElementById('request-count');
    if (countEl) countEl.textContent = entries.length;
    var tbody = document.getElementById('requests-body');
    if (!tbody) return;
    tbody.innerHTML = '';

    for (var i = 0; i < entries.length; i++) {
      var e = entries[i];
      var tr = document.createElement('tr');
      tr.className = 'clickable' + (e.id === selectedRequestId ? ' selected' : '');
      tr.setAttribute('data-id', e.id);

      var ok = e.inspection && e.inspection.handshake_ok;
      var resultClass = ok ? 'result-ok' : 'result-fail';
      var resultText = ok ? 'PASS' : 'FAIL';

      tr.innerHTML =
        '<td>' + esc(timeAgo(e.timestamp)) + '</td>' +
        '<td>' + esc(e.method) + '</td>' +
        '<td>' + esc(e.path) + '</td>' +
        '<td>' + esc(e.cert_cn || 'none') + '</td>' +
        '<td class="' + resultClass + '">' + resultText + '</td>' +
        '<td>' + e.latency_ms + 'ms</td>';

      tr.addEventListener('click', onRowClick);
      tbody.appendChild(tr);
    }
  }

  function onRowClick(ev) {
    var tr = ev.currentTarget;
    var id = tr.getAttribute('data-id');
    selectedRequestId = id;

    document.querySelectorAll('#requests-body tr').forEach(function (r) {
      r.classList.remove('selected');
    });
    tr.classList.add('selected');

    fetch('/api/requests/' + id)
      .then(function (r) { return r.json(); })
      .then(renderDetail)
      .catch(noop);
  }

  function renderDetail(entry) {
    var panel = document.getElementById('detail-panel');
    if (!panel) return;
    panel.classList.remove('hidden');
    panel.classList.add('visible');
    var content = document.getElementById('detail-content');

    var report = entry.inspection || {};
    var ok = report.handshake_ok;

    var html = '';
    html += '<div class="detail-section"><h3>Summary</h3><div class="detail-grid">';
    html += '<span class="label">Result</span><span class="' + (ok ? 'result-ok' : 'result-fail') + '">' + (ok ? 'PASS' : 'FAIL') + '</span>';
    html += '<span class="label">Request</span><span>' + esc(entry.method + ' ' + entry.path) + '</span>';
    html += '<span class="label">Status</span><span>' + entry.status + '</span>';
    html += '<span class="label">Latency</span><span>' + entry.latency_ms + 'ms</span>';
    if (entry.cert_cn) {
      html += '<span class="label">Client CN</span><span>' + esc(entry.cert_cn) + '</span>';
    }
    if (report.failure_code) {
      html += '<span class="label">Failure</span><span class="result-fail">' + esc(report.failure_code) + '</span>';
      html += '<span class="label">Reason</span><span>' + esc(report.failure_reason) + '</span>';
    }
    html += '</div></div>';

    if (report.expected) {
      html += '<div class="detail-section"><h3>Expected</h3><div class="detail-grid">';
      html += '<span class="label">Client Auth</span><span>' + esc(report.expected.client_auth || '--') + '</span>';
      html += '<span class="label">Trusted CA</span><span>' + esc(report.expected.trusted_ca || '--') + '</span>';
      html += '</div></div>';
    }

    if (report.presented) {
      html += '<div class="detail-section"><h3>Presented</h3><div class="detail-grid">';
      html += '<span class="label">TLS Version</span><span>' + esc(report.presented.tls_version || '--') + '</span>';
      html += '<span class="label">Cipher Suite</span><span>' + esc(report.presented.cipher_suite || '--') + '</span>';
      if (report.presented.cert_chain && report.presented.cert_chain.length > 0) {
        var c = report.presented.cert_chain[0];
        html += '<span class="label">Subject</span><span>' + esc(c.subject) + '</span>';
        html += '<span class="label">Issuer</span><span>' + esc(c.issuer) + '</span>';
        html += '<span class="label">Expires</span><span>' + esc(c.not_after) + '</span>';
        html += '<span class="label">Key</span><span>' + esc(c.key_type + ' ' + c.key_bits + '-bit') + '</span>';
      }
      html += '</div></div>';
    }

    if (report.hints && report.hints.length > 0) {
      html += '<div class="detail-section"><h3>Hints</h3><ul class="hints-list">';
      for (var i = 0; i < report.hints.length; i++) {
        html += '<li>' + esc(report.hints[i]) + '</li>';
      }
      html += '</ul></div>';
    }

    content.innerHTML = html;
  }

  // --- Helpers ---
  function timeAgo(ts) {
    var diff = Math.floor((Date.now() - new Date(ts).getTime()) / 1000);
    if (diff < 60) return diff + 's ago';
    if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
    return Math.floor(diff / 3600) + 'h ago';
  }

  function pad(n) { return n < 10 ? '0' + n : '' + n; }

  function esc(s) {
    if (!s) return '';
    var d = document.createElement('div');
    d.appendChild(document.createTextNode(String(s)));
    return d.innerHTML;
  }

  function attr(s) {
    return String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;');
  }

  function downloadText(filename, content) {
    var a = document.createElement('a');
    a.href = 'data:text/plain;charset=utf-8,' + encodeURIComponent(content);
    a.download = filename;
    a.click();
  }

  function copyText(text, btn) {
    navigator.clipboard.writeText(text).then(function () {
      var orig = btn.textContent;
      btn.textContent = 'Copied!';
      btn.classList.add('copied');
      setTimeout(function () {
        btn.textContent = orig;
        btn.classList.remove('copied');
      }, 1500);
    });
  }

  function noop() {}
})();
