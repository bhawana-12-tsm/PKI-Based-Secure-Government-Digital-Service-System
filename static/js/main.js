// ── Nav toggle ───────────────────────────────────────────────────────────
const navToggle = document.getElementById('navToggle');
const navMenu = document.getElementById('navMenu');
if (navToggle && navMenu) {
  navToggle.addEventListener('click', () => {
    navMenu.classList.toggle('open');
  });
}

// ── User dropdown ─────────────────────────────────────────────────────────
const userMenuBtn = document.getElementById('userMenuBtn');
const userDropdown = document.getElementById('userDropdown');
if (userMenuBtn && userDropdown) {
  userMenuBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    userDropdown.classList.toggle('open');
  });
  document.addEventListener('click', () => userDropdown.classList.remove('open'));
}

// ── Password toggle ───────────────────────────────────────────────────────
function togglePw(inputId, btn) {
  const input = document.getElementById(inputId);
  if (!input) return;
  const isText = input.type === 'text';
  input.type = isText ? 'password' : 'text';
  btn.innerHTML = isText ? '<i class="fas fa-eye"></i>' : '<i class="fas fa-eye-slash"></i>';
}

// ── Auto-dismiss flash messages ───────────────────────────────────────────
document.querySelectorAll('.flash').forEach(el => {
  setTimeout(() => {
    el.style.transition = 'opacity 0.4s, transform 0.4s';
    el.style.opacity = '0';
    el.style.transform = 'translateX(20px)';
    setTimeout(() => el.remove(), 400);
  }, 6000);
});

// ── Province → District loader ────────────────────────────────────────────
const provinceSelect = document.getElementById('province');
const districtSelect = document.getElementById('district');
if (provinceSelect && districtSelect) {
  const savedDistrict = districtSelect.dataset.saved || '';
  provinceSelect.addEventListener('change', () => {
    const province = provinceSelect.value;
    districtSelect.innerHTML = '<option value="">Loading...</option>';
    districtSelect.disabled = true;
    if (!province) {
      districtSelect.innerHTML = '<option value="">Select District</option>';
      districtSelect.disabled = false;
      return;
    }
    fetch(`/api/districts/${encodeURIComponent(province)}`)
      .then(r => r.json())
      .then(districts => {
        districtSelect.innerHTML = '<option value="">Select District</option>';
        districts.forEach(d => {
          const opt = document.createElement('option');
          opt.value = d;
          opt.textContent = d;
          if (d === savedDistrict) opt.selected = true;
          districtSelect.appendChild(opt);
        });
        districtSelect.disabled = false;
      });
  });
  // Trigger if province already has a value (form reload)
  if (provinceSelect.value) {
    provinceSelect.dispatchEvent(new Event('change'));
  }
}
