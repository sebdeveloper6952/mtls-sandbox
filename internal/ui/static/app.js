(function () {
  'use strict';

  let startedAt = null;
  let selectedRequestId = null;

  // --- Init ---
  document.addEventListener('DOMContentLoaded', function () {
    fetchStatus();
    fetchCerts();
    fetchRequests();
    setInterval(fetchRequests, 2000);
    setInterval(updateUptime, 1000);

    // Toggle collapsible panels
    document.querySelectorAll('.panel-header').forEach(function (el) {
      el.addEventListener('click', function () {
        const targetId = el.getAttribute('data-toggle');
        if (targetId) {
          document.getElementById(targetId).classList.toggle('collapsed');
        }
      });
    });
  });

  // --- Status ---
  function fetchStatus() {
    fetch('/api/status')
      .then(function (r) { return r.json(); })
      .then(function (data) {
        startedAt = new Date(data.started_at);
        const badge = document.getElementById('mode-badge');
        badge.textContent = data.mode;
        badge.className = 'badge badge-' + data.mode;
        updateCurlCommands(data);
      })
      .catch(noop);
  }

  function updateUptime() {
    if (!startedAt) return;
    const secs = Math.floor((Date.now() - startedAt.getTime()) / 1000);
    const h = Math.floor(secs / 3600);
    const m = Math.floor((secs % 3600) / 60);
    const s = secs % 60;
    document.getElementById('uptime').textContent =
      'Uptime: ' + pad(h) + ':' + pad(m) + ':' + pad(s);
  }

  // --- Certificates ---
  function fetchCerts() {
    fetch('/api/certs')
      .then(function (r) { return r.json(); })
      .then(function (data) {
        renderCertCards(data);
        if (data.client && data.client.not_after) {
          const exp = new Date(data.client.not_after);
          const days = Math.floor((exp - Date.now()) / 86400000);
          document.getElementById('cert-expiry').textContent =
            'Client cert expires: ' + days + 'd';
        }
      })
      .catch(noop);
  }

  function renderCertCards(data) {
    const container = document.getElementById('cert-cards');
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
          '<a class="btn" href="/api/certs/' + (role === 'ca' ? 'ca' : role) + '" download>Download</a>' +
          (cert.key_pem
            ? '<button class="btn btn-copy-pem" data-pem="' + attr(cert.key_pem) + '">Copy Key</button>' +
              '<a class="btn" href="/api/certs/client-key" download>Download Key</a>'
            : '') +
        '</div>';

      container.appendChild(card);
    }

    // Copy PEM buttons
    container.querySelectorAll('.btn-copy-pem').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var pem = btn.getAttribute('data-pem');
        navigator.clipboard.writeText(pem).then(function () {
          btn.classList.add('copied');
          btn.textContent = 'Copied!';
          setTimeout(function () {
            btn.classList.remove('copied');
            btn.textContent = btn.getAttribute('data-pem').includes('KEY') ? 'Copy Key' : 'Copy PEM';
          }, 1500);
        });
      });
    });
  }

  // --- Curl Commands ---
  function updateCurlCommands(status) {
    var container = document.getElementById('curl-commands');
    var p = status.persist_path || './certs';
    var port = status.mtls_port || 8443;
    var commands = [
      {
        label: 'Test mTLS handshake (strict mode)',
        cmd: 'curl --cert ' + p + '/client.crt --key ' + p + '/client.key \\\n  --cacert ' + p + '/ca.crt \\\n  https://localhost:' + port + '/'
      },
      {
        label: 'Without client cert (should fail in strict mode)',
        cmd: 'curl --cacert ' + p + '/ca.crt https://localhost:' + port + '/'
      },
      {
        label: 'Debug endpoint',
        cmd: 'curl --cert ' + p + '/client.crt --key ' + p + '/client.key \\\n  --cacert ' + p + '/ca.crt \\\n  https://localhost:' + port + '/debug'
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
    document.getElementById('request-count').textContent = entries.length;
    var tbody = document.getElementById('requests-body');
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

    // Highlight
    document.querySelectorAll('#requests-body tr').forEach(function (r) {
      r.classList.remove('selected');
    });
    tr.classList.add('selected');

    fetch('/api/requests/' + id)
      .then(function (r) { return r.json(); })
      .then(renderDetail)
      .catch(noop);
  }

  // --- Inspection Detail ---
  function renderDetail(entry) {
    var panel = document.getElementById('detail-panel');
    panel.classList.remove('hidden');
    panel.classList.add('visible');
    var content = document.getElementById('detail-content');

    var report = entry.inspection || {};
    var ok = report.handshake_ok;

    var html = '';

    // Summary
    html += '<div class="detail-section">';
    html += '<h3>Summary</h3>';
    html += '<div class="detail-grid">';
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

    // Expected vs Presented
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

    // Hints
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

  function noop() {}
})();
