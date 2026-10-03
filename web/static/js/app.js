/**
 * CodePulse AI - Interactive Frontend Controller
 * With Enhanced Custom Code Pasting, File Upload, Line Counting, and Tab Indentation
 */

document.addEventListener('DOMContentLoaded', () => {
  const codeEditor = document.getElementById('code-editor');
  const targetFilename = document.getElementById('target-filename');
  const providerSelect = document.getElementById('provider-select');
  const btnRunScan = document.getElementById('btn-run-scan');
  const presetsContainer = document.getElementById('presets-container');
  const statusText = document.getElementById('status-text');

  // New Editor Tool Buttons
  const btnClearCode = document.getElementById('btn-clear-code');
  const btnPasteCode = document.getElementById('btn-paste-code');
  const fileUploader = document.getElementById('file-uploader');
  const btnToggleWrap = document.getElementById('btn-toggle-wrap');
  const btnToggleSize = document.getElementById('btn-toggle-size');
  const editorContainer = document.querySelector('.editor-container');
  const editorModeBadge = document.getElementById('editor-mode-badge');
  const statLines = document.getElementById('stat-lines');
  const statChars = document.getElementById('stat-chars');

  // Stepper Elements
  const stepAst = document.getElementById('step-ast');
  const stepHunter = document.getElementById('step-hunter');
  const stepAuditor = document.getElementById('step-auditor');
  const stepPatcher = document.getElementById('step-patcher');

  // Result Containers
  const findingsContainer = document.getElementById('findings-container');
  const patchesContainer = document.getElementById('patches-container');
  const astContainer = document.getElementById('ast-container');
  const telemetryContainer = document.getElementById('telemetry-container');

  // Modals
  const modalBenchmark = document.getElementById('modal-benchmark');
  const modalPrompts = document.getElementById('modal-prompts');
  const btnOpenBenchmark = document.getElementById('btn-open-benchmark-modal');
  const btnOpenPrompts = document.getElementById('btn-open-prompts-modal');
  const btnCloseBenchmark = document.getElementById('btn-close-benchmark');
  const btnClosePrompts = document.getElementById('btn-close-prompts');
  const benchmarkModalContent = document.getElementById('benchmark-modal-content');
  const promptsModalContent = document.getElementById('prompts-modal-content');

  // Initialize
  initApp();

  async function initApp() {
    setupTabs();
    setupModals();
    setupEditorEnhancements();
    await checkHealth();
    await loadPresets();
    updateEditorStats();
  }

  function setupEditorEnhancements() {
    // 1. Clear / New Code
    btnClearCode.addEventListener('click', () => {
      codeEditor.value = '';
      targetFilename.value = 'custom_snippet.py';
      unhighlightPresets();
      setEditorBadge('Custom Code (Empty)');
      updateEditorStats();
      codeEditor.focus();
    });

    // 2. Paste from Clipboard
    btnPasteCode.addEventListener('click', async () => {
      try {
        if (navigator.clipboard && navigator.clipboard.readText) {
          const text = await navigator.clipboard.readText();
          if (text) {
            codeEditor.value = text;
            unhighlightPresets();
            setEditorBadge('Pasted from Clipboard');
            updateEditorStats();
            return;
          }
        }
      } catch (e) {
        // Fallback if browser clipboard permission prompt is denied
      }
      codeEditor.focus();
      codeEditor.select();
      alert('Press Cmd+V (Mac) or Ctrl+V (Windows) to paste your code into the editor.');
    });

    // 3. File Upload
    fileUploader.addEventListener('change', (e) => {
      const file = e.target.files[0];
      if (!file) return;

      const reader = new FileReader();
      reader.onload = (event) => {
        codeEditor.value = event.target.result;
        targetFilename.value = file.name;
        unhighlightPresets();
        setEditorBadge(`File: ${file.name}`);
        updateEditorStats();
      };
      reader.readAsText(file);
    });

    // 4. Toggle Wrap Lines (Soft wrap vs Horizontal Scroll)
    let isWrapped = false;
    btnToggleWrap.addEventListener('click', () => {
      isWrapped = !isWrapped;
      if (isWrapped) {
        codeEditor.classList.add('wrapped');
        btnToggleWrap.querySelector('span').textContent = 'Wrap: ON';
        btnToggleWrap.classList.add('active');
      } else {
        codeEditor.classList.remove('wrapped');
        btnToggleWrap.querySelector('span').textContent = 'Wrap: OFF';
        btnToggleWrap.classList.remove('active');
      }
    });

    // 5. Expand Editor Height
    let isExpanded = false;
    btnToggleSize.addEventListener('click', () => {
      isExpanded = !isExpanded;
      if (isExpanded) {
        editorContainer.classList.add('expanded');
        btnToggleSize.querySelector('span').textContent = '⛶ Shrink';
        btnToggleSize.classList.add('active');
      } else {
        editorContainer.classList.remove('expanded');
        btnToggleSize.querySelector('span').textContent = '⛶ Expand';
        btnToggleSize.classList.remove('active');
      }
    });

    // 6. Live Stats (Lines & Chars) on typing
    codeEditor.addEventListener('input', () => {
      updateEditorStats();
      unhighlightPresets();
      setEditorBadge('Custom Code');
    });

    // 7. Tab key support (Insert 4 spaces instead of defocusing)
    codeEditor.addEventListener('keydown', (e) => {
      if (e.key === 'Tab') {
        e.preventDefault();
        const start = codeEditor.selectionStart;
        const end = codeEditor.selectionEnd;
        codeEditor.value = codeEditor.value.substring(0, start) + '    ' + codeEditor.value.substring(end);
        codeEditor.selectionStart = codeEditor.selectionEnd = start + 4;
        updateEditorStats();
      }
    });
  }

  function updateEditorStats() {
    const text = codeEditor.value || '';
    const lines = text.length === 0 ? 0 : text.split('\n').length;
    const chars = text.length;
    statLines.textContent = `${lines} ${lines === 1 ? 'line' : 'lines'}`;
    statChars.textContent = `${chars.toLocaleString()} chars`;
  }

  function unhighlightPresets() {
    document.querySelectorAll('.preset-btn').forEach(b => b.classList.remove('active'));
  }

  function setEditorBadge(text) {
    if (editorModeBadge) {
      editorModeBadge.textContent = text;
    }
  }

  async function checkHealth() {
    try {
      const res = await fetch('/api/health');
      const data = await res.json();
      if (data.status === 'online') {
        const hasKey = data.gemini_api_key_configured;
        statusText.textContent = hasKey ? 'Gemini 3.8 Flash Active' : 'Offline Mock Engine Ready';
        if (hasKey) {
          providerSelect.value = 'gemini';
        } else {
          providerSelect.value = 'mock';
        }
      }
    } catch (err) {
      statusText.textContent = 'Server Offline';
    }
  }

  async function loadPresets() {
    try {
      const res = await fetch('/api/presets');
      const presets = await res.json();
      presetsContainer.innerHTML = '';

      presets.forEach((preset, index) => {
        const btn = document.createElement('button');
        btn.className = 'preset-btn';
        
        let badgeClass = 'badge-critical';
        if (preset.severity === 'HIGH') badgeClass = 'badge-high';
        if (preset.severity === 'SAFE') badgeClass = 'badge-safe';

        btn.innerHTML = `
          <span>${preset.title.split(':')[0]}</span>
          <span class="badge-micro ${badgeClass}">${preset.severity}</span>
        `;

        btn.addEventListener('click', () => {
          unhighlightPresets();
          btn.classList.add('active');
          loadPresetIntoEditor(preset);
        });

        presetsContainer.appendChild(btn);
      });

      // Default: leave editor clean with helpful placeholder OR load first preset if user clicks
      // Load first preset by default for instant showcase
      if (presets.length > 0) {
        presetsContainer.children[0].classList.add('active');
        loadPresetIntoEditor(presets[0]);
      }
    } catch (err) {
      console.error('Failed to load presets:', err);
    }
  }

  function loadPresetIntoEditor(preset) {
    codeEditor.value = preset.code;
    targetFilename.value = preset.id;
    setEditorBadge(`Preset: ${preset.title.split(':')[0]}`);
    updateEditorStats();
  }

  function setupTabs() {
    const tabBtns = document.querySelectorAll('.tab-btn');
    tabBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        tabBtns.forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

        btn.classList.add('active');
        const targetId = btn.getAttribute('data-tab');
        const targetTab = document.getElementById(targetId);
        if (targetTab) targetTab.classList.add('active');
      });
    });
  }

  function setupModals() {
    btnOpenBenchmark.addEventListener('click', async () => {
      modalBenchmark.style.display = 'flex';
      await loadBenchmarkModal();
    });
    btnCloseBenchmark.addEventListener('click', () => modalBenchmark.style.display = 'none');

    btnOpenPrompts.addEventListener('click', async () => {
      modalPrompts.style.display = 'flex';
      await loadPromptsModal();
    });
    btnClosePrompts.addEventListener('click', () => modalPrompts.style.display = 'none');
  }

  // Scan Execution
  btnRunScan.addEventListener('click', async () => {
    const code = codeEditor.value.trim();
    if (!code) {
      alert('Please enter or paste some code to audit.');
      codeEditor.focus();
      return;
    }

    btnRunScan.disabled = true;
    btnRunScan.innerHTML = `<span class="spinner"></span> Running Multi-Agent Pipeline...`;

    resetStepper();
    setStepState(stepAst, 'active', 'Analyzing AST...');

    const payload = {
      code: code,
      filename: targetFilename.value || 'snippet.py',
      provider: providerSelect.value,
      force_refresh: true
    };

    try {
      setTimeout(() => setStepState(stepHunter, 'active', 'Hunting Candidates...'), 250);
      setTimeout(() => setStepState(stepAuditor, 'active', 'Devil\'s Advocate...'), 600);

      const res = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      if (!res.ok) {
        throw new Error(await res.text());
      }

      const report = await res.json();

      // Finalize Stepper
      setStepState(stepAst, 'done', 'Analyzed');
      setStepState(stepHunter, 'done', `${report.hunter_candidates.length} Flagged`);
      const confirmed = report.audited_findings.filter(f => f.verdict === 'CONFIRMED').length;
      const fpCount = report.audited_findings.filter(f => f.verdict === 'REJECTED_FALSE_POSITIVE').length;
      setStepState(stepAuditor, 'done', `${confirmed} Real / ${fpCount} FP`);
      setStepState(stepPatcher, 'done', `${report.patches.length} Patches`);

      // Render Outputs
      renderFindings(report);
      renderPatches(report);
      renderAST(report);
      renderTelemetry(report);

      // Auto switch to Findings tab if not active
      const findingsTabBtn = document.querySelector('[data-tab="tab-findings"]');
      if (findingsTabBtn) findingsTabBtn.click();

    } catch (err) {
      alert('Audit failed: ' + err.message);
      resetStepper();
    } finally {
      btnRunScan.disabled = false;
      btnRunScan.innerHTML = `
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
          <polygon points="5 3 19 12 5 21 5 3"></polygon>
        </svg>
        <span>Execute Multi-Agent Audit</span>
      `;
    }
  });

  function resetStepper() {
    [stepAst, stepHunter, stepAuditor, stepPatcher].forEach(step => {
      step.className = 'step-card';
      step.querySelector('.step-status').textContent = 'Idle';
    });
  }

  function setStepState(element, state, text) {
    element.className = `step-card ${state}`;
    element.querySelector('.step-status').textContent = text;
  }

  function renderFindings(report) {
    if (!report.audited_findings || report.audited_findings.length === 0) {
      findingsContainer.innerHTML = `
        <div class="empty-state">
          <div style="color: var(--accent-emerald); font-size: 2.2rem; margin-bottom: 0.5rem;">✓</div>
          <h3>Clean Codebase</h3>
          <p>No vulnerabilities or dangerous unescaped data flows detected by Hunter or Auditor.</p>
        </div>
      `;
      return;
    }

    let html = '';
    report.audited_findings.forEach(finding => {
      const isConfirmed = finding.verdict === 'CONFIRMED';
      const isFP = finding.verdict === 'REJECTED_FALSE_POSITIVE';
      const badgeClass = isConfirmed ? 'badge-critical' : (isFP ? 'badge-safe' : 'badge-high');
      const meterColor = isConfirmed ? 'var(--accent-rose)' : 'var(--accent-emerald)';

      // Match hunter candidate details
      const cand = report.hunter_candidates.find(c => c.candidate_id === finding.candidate_id) || {};

      html += `
        <div class="finding-card" style="border-left: 4px solid ${isConfirmed ? 'var(--accent-rose)' : 'var(--accent-emerald)'};">
          <div class="finding-header">
            <div class="finding-cwe">
              <span class="cwe-tag">${finding.cwe_id}</span>
              <span class="cwe-name">${cand.cwe_name || 'Vulnerability Finding'}</span>
              <span class="badge-micro ${badgeClass}">${finding.verdict}</span>
            </div>
            <div class="confidence-meter">
              <span>Confidence: ${Math.round(finding.calibrated_confidence * 100)}%</span>
              <div class="meter-bar">
                <div class="meter-fill" style="width: ${finding.calibrated_confidence * 100}%; background: ${meterColor};"></div>
              </div>
            </div>
          </div>

          <div class="finding-body">
            ${cand.taint_path ? `
              <div>
                <strong style="color:var(--text-muted); font-size:0.75rem; text-transform:uppercase;">Dataflow Taint Path:</strong>
                <div class="taint-flow-box">${cand.taint_path}</div>
              </div>
            ` : ''}

            <div>
              <strong style="color:var(--text-muted); font-size:0.75rem; text-transform:uppercase;">Auditor Devil's Advocate Rationale:</strong>
              <p class="rationale-text">${finding.audit_rationale}</p>
            </div>

            ${finding.defense_mechanisms_found.length > 0 ? `
              <div>
                <strong style="color:var(--accent-emerald); font-size:0.75rem; text-transform:uppercase;">Defensive Controls Detected:</strong>
                <ul style="margin-left: 1.25rem; font-size: 0.8rem; color: #a7f3d0; margin-top: 0.25rem;">
                  ${finding.defense_mechanisms_found.map(d => `<li>${d}</li>`).join('')}
                </ul>
              </div>
            ` : ''}
          </div>
        </div>
      `;
    });

    findingsContainer.innerHTML = html;
  }

  function renderPatches(report) {
    if (!report.patches || report.patches.length === 0) {
      patchesContainer.innerHTML = `
        <div class="empty-state">
          <p>No actionable patches required. (Codebase verified clean or false positives suppressed).</p>
        </div>
      `;
      return;
    }

    let html = '';
    report.patches.forEach(patch => {
      const diffLines = patch.unified_diff.split('\n').map(line => {
        if (line.startsWith('+') && !line.startsWith('+++')) return `<div class="diff-line add">${escapeHtml(line)}</div>`;
        if (line.startsWith('-') && !line.startsWith('---')) return `<div class="diff-line del">${escapeHtml(line)}</div>`;
        if (line.startsWith('@@') || line.startsWith('---') || line.startsWith('+++')) return `<div class="diff-line info">${escapeHtml(line)}</div>`;
        return `<div class="diff-line">${escapeHtml(line)}</div>`;
      }).join('');

      html += `
        <div style="margin-bottom: 2rem;">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.75rem; flex-wrap:wrap; gap:0.5rem;">
            <div>
              <h3 style="font-size:1.05rem; font-weight:700; color:var(--text-main);">${patch.patch_summary}</h3>
              <p style="font-size:0.8rem; color:var(--text-muted);">${patch.security_rationale}</p>
            </div>
            <button class="preset-btn" onclick="navigator.clipboard.writeText(\`${escapeHtml(patch.unified_diff)}\`); alert('Unified diff copied to clipboard!');">
              Copy Patch
            </button>
          </div>

          <div class="diff-container">
            <div class="diff-header">
              <span>Unified Diff (git apply compatible)</span>
              <span style="font-size:0.75rem; color:var(--text-dim);">${patch.file_path}</span>
            </div>
            <div style="padding: 0.5rem 0;">${diffLines}</div>
          </div>

          ${patch.regression_test_code ? `
            <div style="margin-top: 1rem;">
              <h4 style="font-size:0.85rem; font-weight:700; color:var(--accent-cyan); margin-bottom:0.5rem;">Automated Pytest Regression Unit Test</h4>
              <div class="diff-container" style="padding: 1rem; color: #cbd5e1;">
                <pre><code>${escapeHtml(patch.regression_test_code)}</code></pre>
              </div>
            </div>
          ` : ''}
        </div>
      `;
    });

    patchesContainer.innerHTML = html;
  }

  function renderAST(report) {
    const ast = report.ast_metadata || {};
    const sinks = ast.dangerous_sinks || [];
    const sanitizers = ast.sanitizers || [];
    const funcs = Object.keys(ast.functions || {});

    astContainer.innerHTML = `
      <div style="display:flex; flex-direction:column; gap:1.25rem;">
        <div>
          <h4 style="font-size:0.85rem; font-weight:700; color:var(--accent-cyan); margin-bottom:0.4rem;">Functions Extracted (${funcs.length})</h4>
          <div style="display:flex; flex-wrap:wrap; gap:0.5rem;">
            ${funcs.length ? funcs.map(f => `<span class="badge-micro" style="background:rgba(255,255,255,0.08);">${f}()</span>`).join('') : '<span style="color:var(--text-dim); font-size:0.8rem;">None</span>'}
          </div>
        </div>

        <div>
          <h4 style="font-size:0.85rem; font-weight:700; color:var(--accent-rose); margin-bottom:0.4rem;">Potentially Dangerous Sinks (${sinks.length})</h4>
          <ul style="margin-left:1.25rem; font-size:0.85rem; color:#fca5a5;">
            ${sinks.length ? sinks.map(s => `<li>${s}</li>`).join('') : '<li style="color:var(--text-dim);">No dangerous execution sinks detected.</li>'}
          </ul>
        </div>

        <div>
          <h4 style="font-size:0.85rem; font-weight:700; color:var(--accent-emerald); margin-bottom:0.4rem;">Sanitizers & Typecast Guards (${sanitizers.length})</h4>
          <ul style="margin-left:1.25rem; font-size:0.85rem; color:#6ee7b7;">
            ${sanitizers.length ? sanitizers.map(s => `<li>${s}</li>`).join('') : '<li style="color:var(--text-dim);">No explicit sanitizers found in file.</li>'}
          </ul>
        </div>
      </div>
    `;
  }

  function renderTelemetry(report) {
    const stats = report.summary_statistics || {};
    const telemetry = report.telemetry || [];

    let stagesHtml = telemetry.map(t => `
      <div style="background:rgba(0,0,0,0.3); border:1px solid var(--border-color); border-radius:var(--radius-sm); padding:0.75rem; margin-bottom:0.5rem; display:flex; justify-content:space-between; align-items:center;">
        <div>
          <strong style="font-size:0.85rem; color:#fff;">${t.stage_name}</strong>
          <div style="font-size:0.75rem; color:var(--text-dim);">Model: ${t.model} | Cache: ${t.cached ? 'HIT' : 'MISS'}</div>
        </div>
        <div style="text-align:right;">
          <div style="font-size:0.85rem; font-weight:700; color:var(--accent-cyan);">${t.duration_ms}ms</div>
          <div style="font-size:0.75rem; color:var(--text-dim);">${t.total_tokens} tokens ($${t.estimated_cost_usd.toFixed(6)})</div>
        </div>
      </div>
    `).join('');

    telemetryContainer.innerHTML = `
      <div class="telemetry-grid">
        <div class="stat-box">
          <div class="stat-label">Pipeline Latency</div>
          <div class="stat-val" style="color:var(--accent-cyan);">${stats.pipeline_latency_ms || 0}ms</div>
        </div>
        <div class="stat-box">
          <div class="stat-label">Tokens Consumed</div>
          <div class="stat-val">${(stats.total_tokens_consumed || 0).toLocaleString()}</div>
        </div>
        <div class="stat-box">
          <div class="stat-label">Estimated Cost</div>
          <div class="stat-val" style="color:var(--accent-emerald);">$${(stats.total_cost_usd || 0).toFixed(5)}</div>
        </div>
        <div class="stat-box">
          <div class="stat-label">FP Reduction</div>
          <div class="stat-val" style="color:var(--accent-amber);">${stats.false_positive_reduction_pct || 0}%</div>
        </div>
      </div>

      <h4 style="font-size:0.85rem; font-weight:700; color:var(--text-main); margin-bottom:0.75rem;">Stage Execution Breakdown</h4>
      ${stagesHtml}
    `;
  }

  async function loadBenchmarkModal() {
    try {
      const res = await fetch('/api/benchmark');
      const data = await res.json();
      const m = data.aggregate_metrics || {};

      benchmarkModalContent.innerHTML = `
        <div class="telemetry-grid" style="margin-bottom:1.5rem;">
          <div class="stat-box">
            <div class="stat-label">Precision</div>
            <div class="stat-val" style="color:var(--accent-emerald);">${(m.precision * 100).toFixed(1)}%</div>
          </div>
          <div class="stat-box">
            <div class="stat-label">Recall</div>
            <div class="stat-val" style="color:var(--accent-cyan);">${(m.recall * 100).toFixed(1)}%</div>
          </div>
          <div class="stat-box">
            <div class="stat-label">F1-Score</div>
            <div class="stat-val" style="color:#a78bfa;">${(m.f1_score * 100).toFixed(1)}%</div>
          </div>
          <div class="stat-box">
            <div class="stat-label">False Positive Rate</div>
            <div class="stat-val" style="color:var(--accent-rose);">${(m.false_positive_rate * 100).toFixed(1)}%</div>
          </div>
        </div>

        <h3 style="font-size:0.95rem; font-weight:700; margin-bottom:0.75rem;">Corpus Test Cases (${data.total_files_evaluated})</h3>
        <table style="width:100%; border-collapse:collapse; font-size:0.82rem;">
          <thead>
            <tr style="border-bottom:1px solid var(--border-color); text-align:left; color:var(--text-muted);">
              <th style="padding:0.5rem;">File</th>
              <th style="padding:0.5rem;">Hunter Flags</th>
              <th style="padding:0.5rem;">Auditor Verdict</th>
              <th style="padding:0.5rem;">Latency</th>
            </tr>
          </thead>
          <tbody>
            ${(data.predictions || []).map(p => `
              <tr style="border-bottom:1px solid rgba(255,255,255,0.04);">
                <td style="padding:0.5rem; font-family:var(--font-mono); color:var(--accent-cyan);">${p.file_path.split('/').pop()}</td>
                <td style="padding:0.5rem;">${p.hunter_candidates.length} candidate(s)</td>
                <td style="padding:0.5rem;">
                  <span class="badge-micro ${p.overall_status === 'VULNERABILITIES_CONFIRMED' ? 'badge-critical' : 'badge-safe'}">
                    ${p.overall_status}
                  </span>
                </td>
                <td style="padding:0.5rem;">${p.summary_statistics.pipeline_latency_ms}ms</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      `;
    } catch (err) {
      benchmarkModalContent.innerHTML = `<p style="color:var(--accent-rose);">Failed to load benchmark data: ${err.message}</p>`;
    }
  }

  async function loadPromptsModal() {
    try {
      const res = await fetch('/api/prompts');
      const data = await res.json();

      let html = '';
      for (const [key, p] of Object.entries(data)) {
        html += `
          <div style="background:rgba(0,0,0,0.3); border:1px solid var(--border-color); border-radius:var(--radius-md); padding:1.25rem; margin-bottom:1.5rem;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.5rem;">
              <h3 style="font-size:1rem; font-weight:700; color:var(--accent-cyan);">${p.agent_name}</h3>
              <span class="badge-micro" style="background:rgba(255,255,255,0.1);">Version: ${p.version} | ${p.few_shot_count} Few-Shot Examples</span>
            </div>
            <p style="font-size:0.8rem; color:var(--text-dim); margin-bottom:0.75rem;">${p.description}</p>
            <div style="background:#090d16; border-radius:var(--radius-sm); padding:1rem; font-family:var(--font-mono); font-size:0.78rem; line-height:1.5; color:#cbd5e1; max-height:200px; overflow-y:auto; white-space:pre-wrap;">${escapeHtml(p.system_prompt)}</div>
          </div>
        `;
      }

      promptsModalContent.innerHTML = html;
    } catch (err) {
      promptsModalContent.innerHTML = `<p style="color:var(--accent-rose);">Failed to load prompts: ${err.message}</p>`;
    }
  }

  function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }
});
