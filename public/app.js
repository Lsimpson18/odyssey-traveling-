(() => {
  const views = {
    signin: document.getElementById('view-signin'),
    signup: document.getElementById('view-signup'),
    forgot: document.getElementById('view-forgot'),
    home: document.getElementById('view-home'),
  };

  function show(name, { focus = true } = {}) {
    for (const [key, el] of Object.entries(views)) el.hidden = key !== name;
    views[name].querySelectorAll('.msg').forEach((m) => (m.hidden = true));
    if (focus) {
      const first = views[name].querySelector('input, button.primary');
      if (first) first.focus({ preventScroll: true });
    }
  }

  async function api(path, body) {
    const res = await fetch('/api/auth/' + path, {
      method: body ? 'POST' : 'GET',
      headers: { 'Content-Type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
      credentials: 'same-origin',
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || 'Something went wrong. Please try again.');
    return data;
  }

  function showHome(user) {
    document.getElementById('home-name').textContent = user.name.split(' ')[0];
    show('home', { focus: false });
  }

  // Switch between sign in / sign up / forgot password
  document.querySelectorAll('[data-go]').forEach((btn) =>
    btn.addEventListener('click', () => show(btn.dataset.go))
  );

  // Show / hide password
  document.querySelectorAll('.eye').forEach((btn) =>
    btn.addEventListener('click', () => {
      const input = btn.parentElement.querySelector('input');
      const reveal = input.type === 'password';
      input.type = reveal ? 'text' : 'password';
      btn.setAttribute('aria-pressed', String(reveal));
      btn.setAttribute('aria-label', reveal ? 'Hide password' : 'Show password');
      btn.querySelector('.eye-on').hidden = reveal;
      btn.querySelector('.eye-off').hidden = !reveal;
    })
  );

  // Forms
  document.querySelectorAll('form[data-action]').forEach((form) =>
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const msg = form.querySelector('.msg');
      const btn = form.querySelector('.primary');
      const label = btn.textContent;
      const body = Object.fromEntries(new FormData(form));
      msg.hidden = true;
      msg.classList.remove('ok');
      btn.disabled = true;
      btn.textContent = 'Please wait…';
      try {
        const action = form.dataset.action;
        const data = await api(action, body);
        if (action === 'forgot-password') {
          msg.textContent = data.message;
          msg.classList.add('ok');
          msg.hidden = false;
        } else {
          form.reset();
          showHome(data.user);
        }
      } catch (err) {
        msg.textContent = err.message;
        msg.hidden = false;
      } finally {
        btn.disabled = false;
        btn.textContent = label;
      }
    })
  );

  document.getElementById('logout').addEventListener('click', async () => {
    await api('logout', {}).catch(() => {});
    show('signin');
  });

  // Already signed in from an earlier visit?
  api('me').then((d) => showHome(d.user)).catch(() => {});
})();
