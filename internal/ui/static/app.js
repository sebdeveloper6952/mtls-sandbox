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
          '<p>Create a session to get a unique client certificate. Configure your server to trust our CA, ' +
             'then let us call your server to verify the mTLS handshake works.</p>' +
          '<button class="btn btn-primary" id="btn-create-session">Create Session</button>' +
        '</div>' +
        '<div class="steps">' +
          '<div class="step"><span class="step-num">1</span><div><strong>Create a session</strong><p>Get a unique client certificate and our CA cert.</p></div></div>' +
          '<div class="step"><span class="step-num">2</span><div><strong>Configure your server</strong><p>Add our CA certificate to your server\'s trusted client CAs.</p></div></div>' +
          '<div class="step"><span class="step-num">3</span><div><strong>Set your callback URL</strong><p>Tell us the HTTPS endpoint to test.</p></div></div>' +
          '<div class="step"><span class="step-num">4</span><div><strong>Run the test</strong><p>We\'ll call your server with our client cert and show the results.</p></div></div>' +
        '</div>' +
      '</div>';

    document.getElementById('btn-create-session').addEventListener('click', function () {
      var btn = this;
      btn.disabled = true;
      btn.textContent = 'Creating...';
      fetch('/api/sessions', { method: 'POST' })
        .then(function (r) { return r.json(); })
        .then(function (sess) {
          location.hash = '#/session/' + sess.id;
        })
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
    var html =
      '<div class="page session-page">' +
        '<div class="session-header">' +
          '<h2>Session <code>' + esc(sess.id) + '</code></h2>' +
          '<div class="session-meta">' +
            '<span>CN: <strong>' + esc(sess.cert_cn) + '</strong></span>' +
            '<span>Expires: ' + esc(new Date(sess.expires_at).toLocaleString()) + '</span>' +
          '</div>' +
        '</div>' +

        // CA cert download
        '<section class="panel">' +
          '<h2>Step 1: Trust Our CA</h2>' +
          '<div class="panel-body">' +
            '<p class="help-text">Add this CA certificate to your server\'s trusted client CAs.</p>' +
            '<div class="pem-block">' +
              '<pre id="ca-pem">' + esc(sess.ca_cert_pem || '') + '</pre>' +
              '<button class="btn btn-copy" id="btn-copy-ca">Copy CA Cert</button>' +
            '</div>' +
          '</div>' +
        '</section>' +

        // Client cert (for reference)
        (sess.client_cert_pem ?
          '<section class="panel">' +
            '<h2 class="panel-header" data-toggle="client-cert-body">Client Certificate (Reference)</h2>' +
            '<div id="client-cert-body" class="panel-body collapsed">' +
              '<p class="help-text">This is the client certificate we\'ll present to your server. You don\'t need to download this &mdash; we use it automatically.</p>' +
              '<div class="pem-block">' +
                '<pre>' + esc(sess.client_cert_pem) + '</pre>' +
                '<button class="btn btn-copy" data-copy="client-cert">Copy Cert</button>' +
              '</div>' +
            '</div>' +
          '</section>' : '') +

        // Callback URL
        '<section class="panel">' +
          '<h2>Step 2: Set Callback URL</h2>' +
          '<div class="panel-body">' +
            '<p class="help-text">Enter the HTTPS URL of your server that we should call with our client certificate.</p>' +
            '<div class="url-form">' +
              '<input type="url" id="callback-url" placeholder="https://your-server.com:8443/health" value="' + attr(sess.callback_url || '') + '">' +
              '<button class="btn btn-primary" id="btn-save-url">Save</button>' +
            '</div>' +
            '<div id="url-feedback" class="feedback"></div>' +
          '</div>' +
        '</section>' +

        // Test
        '<section class="panel">' +
          '<h2>Step 3: Test</h2>' +
          '<div class="panel-body">' +
            '<button class="btn btn-primary btn-large" id="btn-test">Run mTLS Test</button>' +
            '<div id="test-feedback" class="feedback"></div>' +
          '</div>' +
        '</section>' +

        // Call history
        '<section class="panel">' +
          '<h2>Test Results <span id="call-count" class="count-badge">0</span></h2>' +
          '<div id="calls-container"></div>' +
        '</section>' +
      '</div>';

    app.innerHTML = html;

    // Toggle panels
    app.querySelectorAll('.panel-header').forEach(function (el) {
      el.addEventListener('click', function () {
        var targetId = el.getAttribute('data-toggle');
        if (targetId) document.getElementById(targetId).classList.toggle('collapsed');
      });
    });

    // Copy CA
    document.getElementById('btn-copy-ca').addEventListener('click', function () {
      copyText(sess.ca_cert_pem, this);
    });

    // Copy client cert
    var copyClientBtn = app.querySelector('[data-copy="client-cert"]');
    if (copyClientBtn) {
      copyClientBtn.addEventListener('click', function () {
        copyText(sess.client_cert_pem, this);
      });
    }

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

    // Test
    document.getElementById('btn-test').addEventListener('click', function () {
      var btn = this;
      var feedback = document.getElementById('test-feedback');
      btn.disabled = true;
      btn.textContent = 'Testing...';
      feedback.textContent = '';

      fetch('/api/sessions/' + sess.id + '/test', { method: 'POST' })
        .then(function (r) {
          if (!r.ok) return r.json().then(function (d) { throw new Error(d.error); });
          return r.json();
        })
        .then(function (result) {
          btn.disabled = false;
          btn.textContent = 'Run mTLS Test';
          if (!result.error) {
            feedback.className = 'feedback feedback-ok';
            feedback.textContent = 'OK! Status ' + result.status_code + ' in ' + result.duration_ms + 'ms';
          } else {
            feedback.className = 'feedback feedback-err';
            feedback.textContent = result.error;
          }
          fetchCalls(sess.id);
        })
        .catch(function (err) {
          btn.disabled = false;
          btn.textContent = 'Run mTLS Test';
          feedback.className = 'feedback feedback-err';
          feedback.textContent = err.message || 'Test failed';
        });
    });

    // Load calls
    fetchCalls(sess.id);
    pollTimer = setInterval(function () { fetchCalls(sess.id); }, 5000);
  }

  function fetchCalls(sessionId) {
    fetch('/api/sessions/' + sessionId + '/calls?limit=50')
      .then(function (r) { return r.json(); })
      .then(function (data) {
        document.getElementById('call-count').textContent = data.total;
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

    var html = '<table><thead><tr><th>Time</th><th>URL</th><th>Status</th><th>Result</th><th>Latency</th></tr></thead><tbody>';
    for (var i = 0; i < calls.length; i++) {
      var c = calls[i];
      var ok = c.probe_result && c.probe_result.inspection && c.probe_result.inspection.handshake_ok;
      var resultClass = c.error ? 'result-fail' : (ok ? 'result-ok' : 'result-fail');
      var resultText = c.error ? 'ERROR' : (ok ? 'PASS' : 'FAIL');

      html += '<tr class="clickable call-row" data-idx="' + i + '">' +
        '<td>' + esc(timeAgo(c.created_at)) + '</td>' +
        '<td class="url-cell">' + esc(c.callback_url) + '</td>' +
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
