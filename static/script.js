(() => {
  if (window.__scamEyeInitialized) return;
  window.__scamEyeInitialized = true;

  const $ = (id) => document.getElementById(id);
  const authView = $('authView'), appView = $('appView'), authNotice = $('authNotice');
  let supabase = null, currentSession = null, isBusy = false, isPasswordRecovery = window.location.pathname === '/reset-password';
  const authForms = ['signInForm','signUpForm','forgotForm','resetForm'];

  function notice(message, kind = 'info') {
    authNotice.textContent = message;
    authNotice.className = `notice ${kind}`;
    authNotice.hidden = !message;
  }
  function showAuthForm(name) {
    authForms.forEach(id => $(id).hidden = id !== name);
    $('showSignIn').classList.toggle('active', name === 'signInForm');
    $('showSignUp').classList.toggle('active', name === 'signUpForm');
    notice('');
  }
  function setFormBusy(form, busy, label) {
    const button = form.querySelector('button[type="submit"]');
    if (!button) return;
    if (busy) { button.dataset.originalText = button.textContent; button.disabled = true; button.textContent = label || 'Please wait…'; }
    else { button.disabled = false; if (button.dataset.originalText) button.textContent = button.dataset.originalText; }
  }
  async function getConfig() {
    const r = await fetch('/api/config');
    const data = await r.json();
    if (!r.ok) throw new Error(data.error || 'Could not load authentication configuration.');
    return data;
  }
  async function apiFetch(url, options = {}) {
    if (!currentSession?.access_token) throw new Error('Your session has expired. Please sign in again.');
    const headers = new Headers(options.headers || {});
    headers.set('Authorization', `Bearer ${currentSession.access_token}`);
    if (options.body && !(options.body instanceof FormData)) headers.set('Content-Type', 'application/json');
    const response = await fetch(url, { ...options, headers });
    const data = await response.json().catch(() => ({}));
    if (response.status === 401) { await supabase.auth.signOut(); throw new Error(data.error || 'Please sign in again.'); }
    if (!response.ok) throw new Error(data.error || 'Request failed.');
    return data;
  }
  async function setSignedIn(session) {
    currentSession = session;
    const isSignedIn = !!session;
    authView.hidden = isSignedIn;
    appView.hidden = !isSignedIn;
    $('logoutButton').hidden = !isSignedIn;
    if (isSignedIn) {
      history.replaceState({}, '', '/');
      await loadHistory();
    }
  }

  $('showSignIn').addEventListener('click', () => showAuthForm('signInForm'));
  $('showSignUp').addEventListener('click', () => showAuthForm('signUpForm'));
  $('forgotPasswordButton').addEventListener('click', () => showAuthForm('forgotForm'));
  $('backToSignIn').addEventListener('click', () => showAuthForm('signInForm'));

  $('signUpForm').addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = event.currentTarget, email = $('signUpEmail').value.trim(), password = $('signUpPassword').value;
    if (password !== $('signUpConfirm').value) return notice('Passwords do not match.', 'error');
    if (password.length < 8) return notice('Use a password with at least 8 characters.', 'error');
    setFormBusy(form, true, 'Creating account…');
    try {
      const { data, error } = await supabase.auth.signUp({
        email, password,
        options: { emailRedirectTo: `${window.location.origin}/` , data: { display_name: $('signUpName').value.trim() } }
      });
      if (error) throw error;
      if (data.session) {
        await setSignedIn(data.session);
      } else {
        notice('Account created. Check your inbox (and spam folder) for the verification link. You must verify your email before signing in.', 'success');
        form.reset();
      }
    } catch (e) { notice(e.message || 'Could not create account.', 'error'); }
    finally { setFormBusy(form, false); }
  });

  $('signInForm').addEventListener('submit', async (event) => {
    event.preventDefault(); const form = event.currentTarget;
    setFormBusy(form, true, 'Signing in…');
    try {
      const { data, error } = await supabase.auth.signInWithPassword({ email: $('signInEmail').value.trim(), password: $('signInPassword').value });
      if (error) throw error;
      if (!data.session) throw new Error('No active session was returned. Verify your email and try again.');
      await setSignedIn(data.session);
    } catch (e) { notice(e.message || 'Sign-in failed.', 'error'); }
    finally { setFormBusy(form, false); }
  });

  $('forgotForm').addEventListener('submit', async (event) => {
    event.preventDefault(); const form = event.currentTarget;
    setFormBusy(form, true, 'Sending email…');
    try {
      const { error } = await supabase.auth.resetPasswordForEmail($('forgotEmail').value.trim(), { redirectTo: `${window.location.origin}/reset-password` });
      if (error) throw error;
      notice('If an account exists for that email, a password reset link has been sent. Check your inbox and spam folder.', 'success');
    } catch (e) { notice(e.message || 'Could not send reset email.', 'error'); }
    finally { setFormBusy(form, false); }
  });

  $('resetForm').addEventListener('submit', async (event) => {
    event.preventDefault(); const form = event.currentTarget;
    if ($('newPassword').value !== $('confirmNewPassword').value) return notice('Passwords do not match.', 'error');
    if ($('newPassword').value.length < 8) return notice('Use a password with at least 8 characters.', 'error');
    setFormBusy(form, true, 'Updating password…');
    try {
      const { error } = await supabase.auth.updateUser({ password: $('newPassword').value });
      if (error) throw error;
      notice('Password updated. You can now continue to ScamEye.', 'success');
      form.reset();
      await setSignedIn((await supabase.auth.getSession()).data.session);
    } catch (e) { notice(e.message || 'Could not update password. Open the newest reset email link and try again.', 'error'); }
    finally { setFormBusy(form, false); }
  });

  $('logoutButton').addEventListener('click', async () => {
    try { const { error } = await supabase.auth.signOut(); if (error) throw error; await setSignedIn(null); showAuthForm('signInForm'); notice('You have signed out.', 'success'); }
    catch (e) { notice(e.message || 'Could not sign out.', 'error'); }
  });

  // Scanner UI
  const messageInput = $('messageInput'), imageInput = $('imageInput'), languageSelect = $('languageSelect');
  const resultSection = $('resultSection'), result = $('result'), loadingState = $('loadingState'), loadingTitle = $('loadingTitle'), charCount = $('charCount'), dropZone = $('dropZone');
  function escapeHTML(value) { return String(value ?? '').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;').replaceAll("'",'&#039;'); }
  function setLoading(active, title = 'Analyzing message…') { loadingState.hidden = !active; loadingTitle.textContent = title; $('checkButton').disabled = active; $('browseButton').disabled = active; $('clearButton').disabled = active; }
  function showResultSection() { resultSection.hidden = false; resultSection.scrollIntoView({ behavior: 'smooth', block: 'start' }); }
  function showError(message) { result.innerHTML = `<div class="error-card">${escapeHTML(message)}</div>`; showResultSection(); }
  function renderList(items) { if (!Array.isArray(items) || !items.length) return '<li>No strong warning signs were identified.</li>'; return items.map(item => `<li>${escapeHTML(item)}</li>`).join(''); }
  function renderTranslation(label, text) { return text ? `<div class="translation-block"><div class="translation-label">${escapeHTML(label)}</div><p>${escapeHTML(text)}</p></div>` : ''; }
  function renderAnalysis(data) {
    const level = ['High','Medium','Low','Unclear'].includes(data.danger_level) ? data.danger_level : 'Unclear';
    const lang = languageSelect.value;
    const translations = lang ? `${renderTranslation(`${lang} · Explanation`,data.explanation_translation)}${renderTranslation(`${lang} · Safer action`,data.action_translation)}` : '';
    result.innerHTML = `<div class="result-main"><article class="result-card risk-card risk-${level.toLowerCase()}"><div class="risk-label">OVERALL RISK</div><div class="risk-level">${escapeHTML(level)}</div><div class="risk-type">${escapeHTML(data.classification || data.scam_type || 'Inconclusive')}</div><div class="meta-row"><span class="meta-chip">AI confidence: <b>${escapeHTML(data.confidence || 'Low')}</b></span><span class="meta-chip">Signal score: <b>${escapeHTML(data.rule_score ?? '—')}/100</b></span></div></article><article class="result-card"><h3>Warning signs detected</h3><ul class="warning-list">${renderList(data.warning_signs)}</ul></article></div><article class="result-card"><h3>Why ScamEye flagged it</h3><p>${escapeHTML(data.explanation || 'No detailed explanation was provided.')}</p>${translations}</article><article class="result-card action-card"><h3>Safer next step</h3><p>${escapeHTML(data.action || 'Verify the message through an official channel.')}</p>${lang ? renderTranslation(`${lang} · Next step`,data.action_translation) : ''}</article>`;
    showResultSection();
  }
  $('checkButton').addEventListener('click', async () => {
    if (isBusy) return; const message = messageInput.value.trim();
    if (!message) { messageInput.focus(); return showError('Please paste a message first.'); }
    isBusy = true; setLoading(true); resultSection.hidden = true;
    try { const data = await apiFetch('/analyze', { method:'POST', body:JSON.stringify({ message, language:languageSelect.value }) }); renderAnalysis(data); await loadHistory(); }
    catch (e) { showError(e.message || 'The analysis service is temporarily unavailable.'); }
    finally { isBusy = false; setLoading(false); }
  });
  $('clearButton').addEventListener('click', () => { if (isBusy) return; messageInput.value=''; charCount.textContent='0 / 8000'; resultSection.hidden=true; result.innerHTML=''; messageInput.focus(); });
  $('newScanButton').addEventListener('click', () => { resultSection.hidden=true; result.innerHTML=''; messageInput.focus(); });
  $('browseButton').addEventListener('click', () => { if (!isBusy) imageInput.click(); });
  messageInput.addEventListener('input', () => charCount.textContent = `${messageInput.value.length} / 8000`);
  document.querySelectorAll('[data-example]').forEach(button => button.addEventListener('click', () => { messageInput.value=button.dataset.example || ''; messageInput.dispatchEvent(new Event('input')); messageInput.focus(); }));
  async function scanImage(image) {
    if (isBusy) return;
    if (!['image/jpeg','image/png','image/webp'].includes(image.type)) return showError('Please upload a JPG, PNG, or WebP image.');
    if (image.size > 6*1024*1024) return showError('Image is too large. Maximum image size is 6 MB.');
    isBusy=true; setLoading(true,'Reading screenshot…'); resultSection.hidden=true;
    const formData = new FormData(); formData.append('image',image);
    try { const data=await apiFetch('/scan-image',{method:'POST',body:formData}); messageInput.value=data.extracted_text || ''; messageInput.dispatchEvent(new Event('input')); messageInput.focus(); notice('Screenshot text extracted. Review it, then select Analyze message.','success'); }
    catch(e) { showError(e.message || 'Image scanning failed.'); }
    finally { isBusy=false; setLoading(false); imageInput.value=''; }
  }
  imageInput.addEventListener('change',e=>{ if(e.target.files?.[0]) scanImage(e.target.files[0]); });
  dropZone.addEventListener('click',e=>{ if (!e.target.closest('button') && !isBusy) imageInput.click(); });
  ['dragenter','dragover'].forEach(name=>dropZone.addEventListener(name,e=>{e.preventDefault();dropZone.classList.add('dragover');}));
  ['dragleave','drop'].forEach(name=>dropZone.addEventListener(name,e=>{e.preventDefault();dropZone.classList.remove('dragover');}));
  dropZone.addEventListener('drop',e=>{if(e.dataTransfer.files?.[0])scanImage(e.dataTransfer.files[0]);});
  messageInput.addEventListener('keydown',e=>{if((e.ctrlKey||e.metaKey)&&e.key==='Enter'){e.preventDefault();$('checkButton').click();}});

  async function loadHistory() {
    const list = $('historyList');
    try {
      const data = await apiFetch('/api/history');
      if (!data.scans?.length) { list.innerHTML='<p class="muted">No saved scans yet. Analyze a message to start your history.</p>'; return; }
      list.innerHTML = data.scans.map(scan => `<article class="history-item"><div class="history-copy"><div class="history-meta"><span class="risk-pill risk-${escapeHTML(String(scan.danger_level).toLowerCase())}">${escapeHTML(scan.danger_level)}</span><span>${escapeHTML(new Date(scan.created_at).toLocaleString())}</span></div><strong>${escapeHTML(scan.scam_type || scan.classification || 'Message scan')}</strong><p>${escapeHTML((scan.message_text || '').slice(0,180))}${(scan.message_text || '').length>180?'…':''}</p></div><button class="delete-scan" type="button" data-delete-id="${escapeHTML(scan.id)}" aria-label="Delete scan">Delete</button></article>`).join('');
      list.querySelectorAll('[data-delete-id]').forEach(button=>button.addEventListener('click',async()=>{
        if(!confirm('Delete this saved scan? This cannot be undone.'))return;
        button.disabled=true;
        try{await apiFetch(`/api/history/${encodeURIComponent(button.dataset.deleteId)}`,{method:'DELETE'});await loadHistory();}
        catch(e){alert(e.message || 'Could not delete scan.');button.disabled=false;}
      }));
    } catch(e) { list.innerHTML=`<p class="error-inline">${escapeHTML(e.message || 'Could not load scan history.')}</p>`; }
  }
  $('refreshHistoryButton').addEventListener('click',loadHistory);

  async function init() {
    try {
      const config = await getConfig();
      supabase = window.supabase.createClient(config.supabaseUrl, config.supabaseAnonKey, { auth: { persistSession: true, autoRefreshToken: true, detectSessionInUrl: true } });
      supabase.auth.onAuthStateChange((event, session) => {
        // Defer work outside Supabase's auth callback to avoid holding its internal lock.
        queueMicrotask(async () => {
          if (event === 'PASSWORD_RECOVERY') {
            isPasswordRecovery = true;
            authView.hidden = false; appView.hidden = true;
            showAuthForm('resetForm');
            notice('Choose a new password for your account.', 'success');
            return;
          }
          if (isPasswordRecovery) return;
          if (event === 'SIGNED_IN' || event === 'TOKEN_REFRESHED' || event === 'INITIAL_SESSION') {
            if (session && session.user?.email_confirmed_at) await setSignedIn(session);
            else if (session && !session.user?.email_confirmed_at) {
              await supabase.auth.signOut(); await setSignedIn(null);
              notice('Please verify your email before signing in.', 'error');
            } else await setSignedIn(null);
          }
        });
      });
      const { data, error } = await supabase.auth.getSession();
      if (error) throw error;
      if (isPasswordRecovery) {
        authView.hidden = false; appView.hidden = true;
        if (data.session) {
          showAuthForm('resetForm');
          notice('Choose a new password for your account.', 'success');
        } else {
          showAuthForm('signInForm');
          notice('Open the newest password-reset link from your email to choose a new password.', 'info');
        }
      } else if (data.session && data.session.user?.email_confirmed_at) await setSignedIn(data.session);
      else { if (data.session) await supabase.auth.signOut(); await setSignedIn(null); }
    } catch(e) {
      authView.hidden=false; appView.hidden=true;
      notice(e.message || 'Could not initialize authentication. Check your Supabase configuration.','error');
    }
  }
  init();
})();
