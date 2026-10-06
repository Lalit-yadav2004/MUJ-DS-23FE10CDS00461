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
  const stepValidator = document.getElementById('step-validator');

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
  const btnThemeToggle = document.getElementById('btn-theme-toggle');

  // Initialize
  initApp();

  async function initApp() {
    setupTheme();
    setupTabs();
    setupModals();
    setupEditorEnhancements();
    await checkHealth();
    await loadPresets();
    updateEditorStats();
  }

  function setupTheme() {
    const saved = localStorage.getItem('codepulse-theme');
    // Default to light if user prefers light or saved as light, otherwise default to dark or saved
    const initialTheme = saved || 'dark';
    applyTheme(initialTheme);

    if (btnThemeToggle) {
      btnThemeToggle.addEventListener('click', () => {
        const current = document.documentElement.getAttribute('data-theme') || 'dark';
        const next = current === 'dark' ? 'light' : 'dark';
        applyTheme(next);
      });
    }
  }

  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('codepulse-theme', theme);

    if (btnThemeToggle) {
      if (theme === 'light') {
        btnThemeToggle.innerHTML = `
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>
          </svg>
          <span id="theme-toggle-label">Dark</span>
        `;
        btnThemeToggle.setAttribute('title', 'Switch to Dark Studio Theme');
      } else {
        btnThemeToggle.innerHTML = `
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="5"></circle>
            <line x1="12" y1="1" x2="12" y2="3"></line>
            <line x1="12" y1="21" x2="12" y2="23"></line>
            <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line>
            <line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line>
            <line x1="1" y1="12" x2="3" y2="12"></line>
            <line x1="21" y1="12" x2="23" y2="12"></line>
            <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line>
            <line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line>
          </svg>
          <span id="theme-toggle-label">Light</span>
        `;
        btnThemeToggle.setAttribute('title', 'Switch to Light Studio Theme');
      }
    }
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
        const hasGemini = data.gemini_api_key_configured;
        const hasNvidia = data.nvidia_api_key_configured;

        if (data.default_provider === 'nvidia' && hasNvidia) {
          statusText.textContent = 'NVIDIA NIM (Llama 3.3 70B) Active';
          providerSelect.value = 'nvidia';
        } else if (hasGemini) {
          statusText.textContent = 'Gemini 3.8 Flash Active';
          providerSelect.value = 'gemini';
        } else if (hasNvidia) {
          statusText.textContent = 'NVIDIA NIM Ready';
          providerSelect.value = 'nvidia';
        } else {
          statusText.textContent = 'Offline Mock Engine Ready';
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
      setTimeout(() => setStepState(stepAuditor, 'active', "Devil's Advocate..."), 600);
      setTimeout(() => setStepState(stepPatcher, 'active', 'Synthesizing Patches...'), 950);
      setTimeout(() => setStepState(stepValidator, 'active', 'Validating Patches...'), 1250);

      const res = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      if (!res.ok) {
        throw new Error(await res.text());
      }

      const report = await res.json();
      const stats = report.summary_statistics || {};

      // Finalize Stepper
      setStepState(stepAst, 'done',
        `${stats.ast_sinks_detected ?? report.ast_metadata?.dangerous_sinks?.length ?? 0} Sinks`);
      setStepState(stepHunter, 'done', `${report.hunter_candidates.length} Flagged`);
      const confirmed = report.audited_findings.filter(f => f.verdict === 'CONFIRMED').length;
      const fpCount = report.audited_findings.filter(f => f.verdict === 'REJECTED_FALSE_POSITIVE').length;
      setStepState(stepAuditor, 'done', `${confirmed} Real / ${fpCount} FP`);
      setStepState(stepPatcher, 'done', `${report.patches.length} Patch${report.patches.length !== 1 ? 'es' : ''}`);

      const vPass = stats.patches_validated_pass ?? 0;
      const vFail = stats.patches_validated_fail ?? 0;
      const vWarn = stats.patches_validated_warn ?? 0;
      const totalVal = report.patch_validations?.length ?? 0;
      if (vFail > 0) {
        setStepState(stepValidator, 'error', `${vPass} PASS / ${vFail} FAIL`);
      } else {
        setStepState(stepValidator, 'done',
          totalVal > 0 ? `${vPass} PASS${vWarn > 0 ? ' / ' + vWarn + ' WARN' : ''}` : 'No Patches');
      }

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
    [stepAst, stepHunter, stepAuditor, stepPatcher, stepValidator].forEach(step => {
      if (!step) return;
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

    // Build a quick lookup: candidate_id → validation result
    const validationMap = {};
    (report.patch_validations || []).forEach(v => { validationMap[v.candidate_id] = v; });

    let html = '';
    report.patches.forEach(patch => {
      const diffLines = patch.unified_diff.split('\n').map(line => {
        if (line.startsWith('+') && !line.startsWith('+++')) return `<div class="diff-line add">${escapeHtml(line)}</div>`;
        if (line.startsWith('-') && !line.startsWith('---')) return `<div class="diff-line del">${escapeHtml(line)}</div>`;
        if (line.startsWith('@@') || line.startsWith('---') || line.startsWith('+++')) return `<div class="diff-line info">${escapeHtml(line)}</div>`;
        return `<div class="diff-line">${escapeHtml(line)}</div>`;
      }).join('');

      const val = validationMap[patch.candidate_id];
      const verdictColor = !val ? '#64748b' : val.verdict === 'PASS' ? '#10b981' : val.verdict === 'WARN' ? '#f59e0b' : '#ef4444';
      const verdictIcon = !val ? '—' : val.verdict === 'PASS' ? '✓' : val.verdict === 'WARN' ? '⚠' : '✗';

      // Build 6-check grid if we have validation
      let checksHtml = '';
      if (val && val.checks) {
        const checkLabels = {
          syntax_valid: 'Syntax Valid',
          sink_neutralized: 'Sink Neutralized',
          safe_replacement_exists: 'Safe Replacement',
          signatures_intact: 'Signatures Intact',
          no_new_sinks: 'No New Sinks',
          regression_test_quality: 'Regression Test',
        };
        const checkItems = Object.entries(checkLabels).map(([key, label]) => {
          const chkVal = val.checks[key];
          const passed = chkVal === true || chkVal === 'PASS';
          const warn = chkVal === 'WARN';
          const color = passed ? '#10b981' : warn ? '#f59e0b' : '#ef4444';
          const icon = passed ? '✓' : warn ? '⚠' : '✗';
          return `<span style="display:inline-flex;align-items:center;gap:0.25rem;font-size:0.72rem;padding:0.2rem 0.5rem;border-radius:4px;background:rgba(255,255,255,0.05);border:1px solid ${color}33;color:${color};">${icon} ${label}</span>`;
        }).join('');
        checksHtml = `
          <div style="margin-top:0.75rem;">
            <div style="font-size:0.72rem;font-weight:700;color:var(--text-dim);margin-bottom:0.4rem;text-transform:uppercase;letter-spacing:0.05em;">Validation Checks</div>
            <div style="display:flex;flex-wrap:wrap;gap:0.4rem;">${checkItems}</div>
            ${val.validation_notes ? `<p style="margin-top:0.5rem;font-size:0.75rem;color:var(--text-muted);font-style:italic;">${escapeHtml(val.validation_notes)}</p>` : ''}
          </div>`;
      }

      // Original snippet context
      const origHtml = patch.original_snippet ? `
        <div style="margin-bottom:0.75rem;">
          <div style="font-size:0.72rem;font-weight:700;color:var(--text-dim);margin-bottom:0.3rem;text-transform:uppercase;letter-spacing:0.05em;">Original Vulnerable Code</div>
          <div class="diff-container" style="padding:0.5rem 1rem;">
            <div class="diff-line del">${escapeHtml(patch.original_snippet)}</div>
          </div>
        </div>` : '';

      html += `
        <div style="margin-bottom:2.5rem;border:1px solid var(--border-color);border-radius:var(--radius);padding:1.25rem;background:rgba(0,0,0,0.2);">
          <!-- Header row: summary + validator badge -->
          <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:0.75rem;flex-wrap:wrap;gap:0.75rem;">
            <div style="flex:1;min-width:0;">
              <div style="display:flex;align-items:center;gap:0.6rem;margin-bottom:0.3rem;">
                <span style="font-size:0.75rem;font-weight:800;padding:0.2rem 0.6rem;border-radius:4px;background:${verdictColor}22;border:1px solid ${verdictColor}55;color:${verdictColor};">${verdictIcon} ${val ? val.verdict : 'NOT VALIDATED'}</span>
                <span style="font-size:0.75rem;color:var(--text-dim);">${patch.cwe_id}</span>
                <code style="font-size:0.7rem;color:var(--accent-cyan);">${escapeHtml(patch.file_path)}${patch.vulnerable_lines ? ':' + patch.vulnerable_lines[0] : ''}</code>
              </div>
              <h3 style="font-size:0.95rem;font-weight:700;color:var(--text-main);">${escapeHtml(patch.patch_summary)}</h3>
              <p style="font-size:0.8rem;color:var(--text-muted);margin-top:0.2rem;">${escapeHtml(patch.security_rationale)}</p>
            </div>
            <button class="preset-btn" style="flex-shrink:0;" onclick="navigator.clipboard.writeText(${JSON.stringify(patch.unified_diff)}); this.textContent='Copied!'; setTimeout(()=>this.textContent='Copy Patch',1500);">
              Copy Patch
            </button>
          </div>

          <!-- Validation 6-check badges -->
          ${checksHtml}

          <!-- Original snippet (BEFORE) -->
          ${origHtml}

          <!-- Unified diff -->
          <div class="diff-container">
            <div class="diff-header">
              <span>Unified Diff — git apply compatible</span>
              <span style="font-size:0.75rem;color:var(--text-dim);">${escapeHtml(patch.file_path)}</span>
            </div>
            <div style="padding:0.5rem 0;">${diffLines}</div>
          </div>

          ${patch.regression_test_code ? `
            <div style="margin-top:1rem;">
              <h4 style="font-size:0.85rem;font-weight:700;color:var(--accent-cyan);margin-bottom:0.5rem;">Automated Pytest Regression Test</h4>
              <div class="diff-container" style="padding:1rem;color:#cbd5e1;">
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
      <!-- Row 1: Pipeline Summary -->
      <div style="margin-bottom:1.25rem;">
        <div style="font-size:0.72rem;font-weight:700;color:var(--text-dim);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:0.6rem;">Pipeline Summary</div>
        <div class="telemetry-grid">
          <div class="stat-box">
            <div class="stat-label">AST Sinks</div>
            <div class="stat-val" style="color:var(--accent-rose);">${stats.ast_sinks_detected ?? '—'}</div>
          </div>
          <div class="stat-box">
            <div class="stat-label">Candidates</div>
            <div class="stat-val" style="color:var(--accent-amber);">${stats.total_candidates_flagged ?? 0}</div>
          </div>
          <div class="stat-box">
            <div class="stat-label">Confirmed</div>
            <div class="stat-val" style="color:var(--accent-rose);">${stats.confirmed_vulnerabilities ?? 0}</div>
          </div>
          <div class="stat-box">
            <div class="stat-label">False Positives</div>
            <div class="stat-val" style="color:var(--accent-emerald);">${stats.false_positives_eliminated ?? 0}</div>
          </div>
          <div class="stat-box">
            <div class="stat-label">Patches</div>
            <div class="stat-val" style="color:var(--accent-cyan);">${stats.patches_synthesized ?? 0}</div>
          </div>
          <div class="stat-box">
            <div class="stat-label">Validated ✓</div>
            <div class="stat-val" style="color:#10b981;">${stats.patches_validated_pass ?? 0}</div>
          </div>
          <div class="stat-box">
            <div class="stat-label">Warn ⚠</div>
            <div class="stat-val" style="color:#f59e0b;">${stats.patches_validated_warn ?? 0}</div>
          </div>
          <div class="stat-box">
            <div class="stat-label">Failed ✗</div>
            <div class="stat-val" style="color:#ef4444;">${stats.patches_validated_fail ?? 0}</div>
          </div>
        </div>
      </div>

      <!-- Row 2: Cost & Performance -->
      <div style="margin-bottom:1.25rem;">
        <div style="font-size:0.72rem;font-weight:700;color:var(--text-dim);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:0.6rem;">Performance</div>
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
      </div>

      <h4 style="font-size:0.85rem;font-weight:700;color:var(--text-main);margin-bottom:0.75rem;">Stage Execution Breakdown</h4>
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
