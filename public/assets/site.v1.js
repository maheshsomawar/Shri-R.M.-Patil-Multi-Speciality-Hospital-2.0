(function () {
  'use strict';

  var VERIFIED_DOCTORS = [
    { username: 'dr_rohan', full_name: 'Dr. Rohan Patil', specialization: 'Consultant Orthopaedician', qualification: 'MBBS, MD, D.Ortho, DNB (Ortho)', reg_no: '2008/10/3539', consultation_fee_inr: 500, department: 'Orthopaedics — Dr. Rohan Patil' },
    { username: 'dr_rahul', full_name: 'Dr. Rahul Patil', specialization: 'Consultant Obgy Specialist', qualification: 'MBBS, DGO, DNB (Obs & Gyn)', reg_no: '2022/12/9582', consultation_fee_inr: 500, department: 'Obstetrics & Gynaecology — Dr. Rahul Patil' },
    { username: 'dr_manjusha', full_name: 'Dr. Manjusha Patil', specialization: 'Dental Surgeon', qualification: 'BDS', reg_no: 'A-29811', consultation_fee_inr: 400, department: 'Dental Surgery — Dr. Manjusha Patil' },
    { username: 'dr_snehal', full_name: 'Dr. Snehal Patil', specialization: 'General Physician', qualification: 'MBBS', reg_no: 'A-2018/03/0645', consultation_fee_inr: 300, department: 'General Medicine — Dr. Snehal Patil' }
  ];

  var DEPT_TO_USER = {
    'Orthopaedics — Dr. Rohan Patil': 'dr_rohan',
    'Obstetrics & Gynaecology — Dr. Rahul Patil': 'dr_rahul',
    'Dental Surgery — Dr. Manjusha Patil': 'dr_manjusha',
    'General Medicine — Dr. Snehal Patil': 'dr_snehal'
  };

  var DEPT_TO_FEE = {
    'Orthopaedics — Dr. Rohan Patil': 500,
    'Obstetrics & Gynaecology — Dr. Rahul Patil': 500,
    'Dental Surgery — Dr. Manjusha Patil': 400,
    'General Medicine — Dr. Snehal Patil': 300
  };

  function esc(str) {
    return String(str == null ? '' : str)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function normalizeMobile(raw) {
    return String(raw || '')
      .replace(/[\s\-()+]/g, '')
      .replace(/^91(?=[6-9]\d{9}$)/, '')
      .replace(/^0(?=[6-9]\d{9}$)/, '')
      .trim();
  }

  function todayISO() {
    var now = new Date();
    var local = new Date(now.getTime() + (330 + now.getTimezoneOffset()) * 60000);
    return local.toISOString().slice(0, 10);
  }

  var tabBookBtn = document.getElementById('tab-book-btn');
  var tabCheckBtn = document.getElementById('tab-check-btn');
  var panelBook = document.getElementById('panel-book');
  var panelCheck = document.getElementById('panel-check');
  var dateInput = document.getElementById('book-date');
  var deptSelect = document.getElementById('book-department');
  var slotsGrid = document.getElementById('slots-grid');
  var slotsStatus = document.getElementById('slots-status-label');
  var slotHidden = document.getElementById('book-slot');

  function switchTab(tabName, shouldScroll) {
    var isCheck = tabName === 'check';
    panelBook.classList.toggle('hidden', isCheck);
    panelCheck.classList.toggle('hidden', !isCheck);
    tabBookBtn.classList.toggle('active', !isCheck);
    tabCheckBtn.classList.toggle('active', isCheck);
    if (shouldScroll) {
      document.getElementById('appointment-hub').scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }

  tabBookBtn.addEventListener('click', function () { switchTab('book', false); });
  tabCheckBtn.addEventListener('click', function () { switchTab('check', false); });
  ['nav-book-btn', 'hero-book-btn', 'tile-book-btn', 'cta-book-pill', 'mob-sticky-book'].forEach(function (id) {
    var el = document.getElementById(id);
    if (el) el.addEventListener('click', function () { switchTab('book', true); });
  });
  ['nav-check-btn', 'tile-check-btn', 'cta-check-pill'].forEach(function (id) {
    var el = document.getElementById(id);
    if (el) el.addEventListener('click', function () { switchTab('check', true); });
  });

  var mobMenu = document.getElementById('mobile-menu');
  document.getElementById('mobile-menu-btn').addEventListener('click', function () {
    mobMenu.classList.toggle('hidden');
  });
  mobMenu.querySelectorAll('a').forEach(function (a) {
    a.addEventListener('click', function () { mobMenu.classList.add('hidden'); });
  });
  document.getElementById('mob-book-btn').addEventListener('click', function () {
    mobMenu.classList.add('hidden');
    switchTab('book', true);
  });
  document.getElementById('mob-check-btn').addEventListener('click', function () {
    mobMenu.classList.add('hidden');
    switchTab('check', true);
  });

  var privacyModal = document.getElementById('privacy-modal');
  var refundModal = document.getElementById('refund-modal');
  var termsModal = document.getElementById('terms-modal');
  if (refundModal) {
    document.getElementById('open-refund-btn').addEventListener('click', function () { refundModal.classList.remove('hidden'); });
    document.getElementById('close-refund-modal').addEventListener('click', function () { refundModal.classList.add('hidden'); });
    document.getElementById('ok-refund-modal').addEventListener('click', function () { refundModal.classList.add('hidden'); });
  }
  if (termsModal) {
    document.getElementById('open-terms-btn').addEventListener('click', function () { termsModal.classList.remove('hidden'); });
    document.getElementById('close-terms-modal').addEventListener('click', function () { termsModal.classList.add('hidden'); });
    document.getElementById('ok-terms-modal').addEventListener('click', function () { termsModal.classList.add('hidden'); });
  }

  function launchRazorpayCheckoutIfLive(pay, appt, patientName, mobile) {
    if (!pay || !pay.provider_order_id || String(pay.provider_order_id).indexOf('order_local_') === 0) return;
    fetch('/api/payments/config', { credentials: 'same-origin' })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (cfg) {
        if (!cfg || !cfg.razorpay_configured || !cfg.key_id) return;
        function openCheckout() {
          if (!window.Razorpay) return;
          var rzp = new window.Razorpay({
            key: cfg.key_id,
            amount: Number(pay.amount_inr || 500) * 100,
            currency: 'INR',
            name: 'Shri R.M. Patil Multi Speciality Hospital',
            description: 'OPD Consultation (' + (appt.appointment_number || '') + ')',
            order_id: pay.provider_order_id,
            prefill: { name: patientName, contact: mobile },
            theme: { color: '#00768A' },
            handler: function (resp) {
              fetch('/api/payments/online/verify', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'same-origin',
                body: JSON.stringify({
                  order_id: resp.razorpay_order_id || pay.provider_order_id,
                  payment_id: resp.razorpay_payment_id,
                  signature: resp.razorpay_signature
                })
              }).then(function (r) { return r.json().then(function (d) { return { ok: r.ok, data: d }; }); })
                .then(function (out) {
                  if (out.ok) {
                    var p = out.data.payment || {};
                    document.getElementById('conf-payment').textContent =
                      '\u20B9' + (p.amount_inr || pay.amount_inr || 500) + ' \u2014 Online UPI / Card (PAID' +
                      (p.receipt_number ? ' · ' + p.receipt_number : '') + ')';
                  }
                });
            }
          });
          rzp.open();
        }
        if (window.Razorpay) { openCheckout(); return; }
        var sc = document.createElement('script');
        sc.src = 'https://checkout.razorpay.com/v1/checkout.js';
        sc.async = true;
        sc.onload = openCheckout;
        document.body.appendChild(sc);
      })
      .catch(function () {});
  }

  document.getElementById('open-privacy-btn').addEventListener('click', function () { privacyModal.classList.remove('hidden'); });
  document.getElementById('close-privacy-modal').addEventListener('click', function () { privacyModal.classList.add('hidden'); });
  document.getElementById('ok-privacy-modal').addEventListener('click', function () { privacyModal.classList.add('hidden'); });

  function updateFeeBadge() {
    document.getElementById('live-fee-badge').textContent = '\u20B9' + (DEPT_TO_FEE[deptSelect.value] || 500);
  }

  function renderDoctors(doctorsList) {
    var grid = document.getElementById('doctors-grid');
    grid.innerHTML = doctorsList.map(function (doc) {
      var deptVal = doc.department || Object.keys(DEPT_TO_USER).find(function (k) { return DEPT_TO_USER[k] === doc.username; }) || '';
      var initials = (doc.full_name || 'DR').replace(/^Dr\.\s*/i, '').split(/\s+/).map(function (w) { return w[0]; }).join('').slice(0, 2).toUpperCase();
      return '<div class="doc-card"><div><div class="doc-top"><div class="doc-ava">' + esc(initials) + '</div><div><h3 class="doc-name">' + esc(doc.full_name) + '</h3><div class="doc-spec">' + esc(doc.specialization || doc.specialty || '') + '</div></div></div><p class="doc-qual">' + esc(doc.qualification) + '</p><div class="doc-meta"><span>Reg: ' + esc(doc.reg_no || doc.registration_no || '') + '</span><span class="doc-fee">&#8377;' + esc(doc.consultation_fee_inr || doc.consultation_fee || 0) + '</span></div></div><button type="button" data-book-dept="' + esc(deptVal) + '" class="doc-btn">Book with ' + esc(doc.full_name) + '</button></div>';
    }).join('');

    grid.querySelectorAll('.doc-btn').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var dept = btn.getAttribute('data-book-dept');
        if (dept) {
          deptSelect.value = dept;
          updateFeeBadge();
          document.getElementById('booking-confirm-card').classList.add('hidden');
          document.getElementById('booking-form-wrap').classList.remove('hidden');
          switchTab('book', true);
          loadSlots();
        }
      });
    });
  }

  function loadSlots() {
    var docUser = DEPT_TO_USER[deptSelect.value] || 'dr_rohan';
    var dt = dateInput.value || todayISO();
    slotHidden.value = '';
    slotsStatus.textContent = 'Checking live availability...';
    slotsGrid.innerHTML = '<div class="skel-slot"></div>'.repeat(6);

    fetch('/api/doctors/' + encodeURIComponent(docUser) + '/slots?date=' + encodeURIComponent(dt))
      .then(function (res) { return res.json().then(function (d) { return { ok: res.ok, data: d }; }); })
      .then(function (out) {
        if (!out.ok) {
          slotsStatus.textContent = out.data.error || 'Could not load slots.';
          slotsGrid.innerHTML = '';
          return;
        }
        if (out.data.closed_reason) {
          slotsStatus.textContent = out.data.closed_reason;
          slotsGrid.innerHTML = '<div style="grid-column:1/-1;font-size:12.5px;color:#92400e;background:#fffbeb;border:1px solid #fde68a;border-radius:10px;padding:10px 12px">' + esc(out.data.closed_reason) + '</div>';
          return;
        }
        var openSlots = out.data.available_slots || [];
        var bookedSet = new Set(out.data.booked_slots || []);
        var allSlots = Array.from(new Set(openSlots.concat(Array.from(bookedSet)))).sort();
        if (!allSlots.length) {
          slotsStatus.textContent = 'No open slots on this date.';
          slotsGrid.innerHTML = '<div style="grid-column:1/-1;font-size:12.5px;color:#64748b">No slots available for this date. Please choose another date.</div>';
          return;
        }
        slotsStatus.textContent = openSlots.length + ' open slot(s)';
        slotsGrid.innerHTML = allSlots.map(function (slot) {
          if (bookedSet.has(slot)) {
            return '<button type="button" disabled class="slot-btn">' + esc(slot) + '</button>';
          }
          return '<button type="button" data-slot="' + esc(slot) + '" class="slot-btn">' + esc(slot) + '</button>';
        }).join('');

        slotsGrid.querySelectorAll('button[data-slot]').forEach(function (b) {
          b.addEventListener('click', function () {
            slotsGrid.querySelectorAll('button[data-slot]').forEach(function (x) { x.classList.remove('active'); });
            b.classList.add('active');
            slotHidden.value = b.getAttribute('data-slot');
          });
        });
        var firstOpen = slotsGrid.querySelector('button[data-slot]');
        if (firstOpen) firstOpen.click();
      })
      .catch(function () {
        slotsStatus.textContent = 'Connection issue loading slots.';
        slotsGrid.innerHTML = '<div style="grid-column:1/-1;display:flex;align-items:center;justify-content:space-between;gap:8px;background:#fef2f2;border:1px solid #fecaca;color:#b91c1c;border-radius:10px;padding:10px 12px;font-size:12.5px"><span>Could not load slots. Check connection or call 02381-299133.</span><button type="button" id="retry-slots-btn" class="btn-pill-teal" style="padding:6px 12px;min-height:32px;font-size:12px">Retry</button></div>';
        var rb = document.getElementById('retry-slots-btn');
        if (rb) rb.addEventListener('click', loadSlots);
      });
  }

  deptSelect.addEventListener('change', function () { updateFeeBadge(); loadSlots(); });
  dateInput.addEventListener('change', loadSlots);

  var lastConfirmedApptNo = '';
  var lastConfirmedMobile = '';
  var currentIdempotencyKey = '';

  document.getElementById('booking-form').addEventListener('submit', function (e) {
    e.preventDefault();
    var errBox = document.getElementById('book-error');
    errBox.classList.add('hidden');

    var firstName = document.getElementById('book-first').value.trim();
    var lastName = document.getElementById('book-last').value.trim();
    var mobile = normalizeMobile(document.getElementById('book-mobile').value);
    var department = deptSelect.value;
    var appointmentDate = dateInput.value;
    var slotTime = slotHidden.value;
    var message = document.getElementById('book-message').value.trim();
    var consent = document.getElementById('book-consent').checked;

    if (!consent) {
      errBox.textContent = 'Please tick the consent box to confirm your appointment.';
      errBox.classList.remove('hidden');
      return;
    }
    if (!firstName || !lastName) {
      errBox.textContent = 'Please enter both first name and last name.';
      errBox.classList.remove('hidden');
      return;
    }
    if (!/^[6-9]\d{9}$/.test(mobile)) {
      errBox.textContent = 'Please enter a valid 10-digit Indian mobile number.';
      errBox.classList.remove('hidden');
      return;
    }

    var btn = document.getElementById('book-submit-btn');
    btn.disabled = true;
    btn.textContent = 'Confirming...';

    if (!currentIdempotencyKey) {
      currentIdempotencyKey = (window.crypto && crypto.randomUUID)
        ? crypto.randomUUID()
        : ('idem-' + Date.now() + '-' + Math.random().toString(36).slice(2, 10));
    }

    fetch('/api/appointments', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Idempotency-Key': currentIdempotencyKey },
      body: JSON.stringify({
        first_name: firstName,
        last_name: lastName,
        mobile: mobile,
        department: department,
        appointment_date: appointmentDate,
        slot_time: slotTime,
        payment_method: 'online_razorpay',
        message: message
      })
    })
      .then(function (res) { return res.json().then(function (d) { return { ok: res.ok, status: res.status, data: d }; }); })
      .then(function (out) {
        if (!out.ok) {
          errBox.textContent = out.data.error || 'Could not confirm appointment. Please try another slot.';
          errBox.classList.remove('hidden');
          if (out.status === 409) loadSlots();
          return;
        }
        var appt = out.data.appointment || {};
        var pay = out.data.payment || {};
        var sms = out.data.confirmation_sms || {};

        lastConfirmedApptNo = appt.appointment_number || '';
        lastConfirmedMobile = mobile;

        document.getElementById('conf-appt-no').textContent = lastConfirmedApptNo;
        document.getElementById('conf-appt-no-inline').textContent = lastConfirmedApptNo;
        document.getElementById('conf-status').textContent = (appt.status || 'confirmed').toUpperCase();
        document.getElementById('conf-patient').textContent = firstName + ' ' + lastName;
        document.getElementById('conf-department').textContent = appt.department || department;
        document.getElementById('conf-datetime').textContent = (appt.appointment_date || appointmentDate) + (appt.slot_time ? ' at ' + appt.slot_time : '');
        document.getElementById('conf-payment').textContent = '\u20B9' + (pay.amount_inr || DEPT_TO_FEE[department] || 500) + ' \u2014 Online UPI / Card (' + String(pay.payment_status || 'PENDING').toUpperCase() + ')';
        document.getElementById('conf-sms-text').textContent = sms.text || 'Appointment confirmation processed.';

        document.getElementById('booking-form-wrap').classList.add('hidden');
        document.getElementById('booking-confirm-card').classList.remove('hidden');
        launchRazorpayCheckoutIfLive(pay, appt, firstName + ' ' + lastName, mobile);
      })
      .catch(function () {
        errBox.textContent = 'Network error while booking. Please try again.';
        errBox.classList.remove('hidden');
      })
      .finally(function () {
        btn.disabled = false;
        btn.textContent = 'Proceed with Online Payment & Confirm \u2192';
      });
  });

  document.getElementById('conf-print-btn').addEventListener('click', function () { window.print(); });
  document.getElementById('res-print-btn').addEventListener('click', function () { window.print(); });
  document.getElementById('conf-new-btn').addEventListener('click', function () {
    currentIdempotencyKey = '';
    document.getElementById('booking-form').reset();
    dateInput.value = todayISO();
    updateFeeBadge();
    document.getElementById('booking-confirm-card').classList.add('hidden');
    document.getElementById('booking-form-wrap').classList.remove('hidden');
    loadSlots();
  });
  document.getElementById('conf-verify-btn').addEventListener('click', function () {
    document.getElementById('check-appt-no').value = lastConfirmedApptNo;
    document.getElementById('check-mobile').value = lastConfirmedMobile;
    switchTab('check', false);
    document.getElementById('check-form').dispatchEvent(new Event('submit', { cancelable: true }));
  });

  document.getElementById('check-form').addEventListener('submit', function (e) {
    e.preventDefault();
    var errBox = document.getElementById('check-error');
    var resCard = document.getElementById('check-result-card');
    errBox.classList.add('hidden');
    resCard.classList.add('hidden');

    var apptNo = document.getElementById('check-appt-no').value.trim().toUpperCase();
    var mobile = normalizeMobile(document.getElementById('check-mobile').value);
    if (!apptNo || !/^[6-9]\d{9}$/.test(mobile)) {
      errBox.textContent = 'Please enter both your Appointment Number (e.g. APT-20261128-001) and 10-digit registered mobile number.';
      errBox.classList.remove('hidden');
      return;
    }

    var btn = document.getElementById('check-submit-btn');
    btn.disabled = true;
    btn.textContent = 'Checking...';

    fetch('/api/appointments/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ appointment_number: apptNo, mobile: mobile })
    })
      .then(function (res) { return res.json().then(function (d) { return { ok: res.ok, data: d }; }); })
      .then(function (out) {
        if (!out.ok || !out.data.found) {
          errBox.textContent = out.data.error || 'No appointment found matching those details.';
          errBox.classList.remove('hidden');
          return;
        }
        var a = out.data.appointment;
        document.getElementById('res-appt-no').textContent = a.appointment_number;
        document.getElementById('res-patient').textContent = a.patient_name;
        document.getElementById('res-doctor').textContent = a.doctor_name;
        document.getElementById('res-qual').textContent = a.doctor_qualification || '';
        document.getElementById('res-datetime').textContent = a.appointment_date + (a.slot_time ? ' at ' + a.slot_time : '');
        document.getElementById('res-checkin').textContent = a.checked_in
          ? 'Checked In' + (a.queue_token ? ' (Token ' + a.queue_token + ')' : '')
          : 'Not Checked In Yet (Show Appointment No. at Reception)';
        document.getElementById('res-fee').textContent = '\u20B9' + a.consultation_fee + ' \u2014 Online (' + String(a.payment_status || 'PENDING').toUpperCase() + ')';
        document.getElementById('res-status-badge').textContent = String(a.status || 'confirmed').toUpperCase();
        resCard.classList.remove('hidden');
      })
      .catch(function () {
        errBox.textContent = 'Unable to verify right now. Please try again.';
        errBox.classList.remove('hidden');
      })
      .finally(function () {
        btn.disabled = false;
        btn.textContent = 'Check Status';
      });
  });


  window.addEventListener('offline', function () {
    if (!document.getElementById('offline-banner')) {
      var b = document.createElement('div');
      b.id = 'offline-banner';
      b.className = 'offline-bar no-print';
      b.textContent = 'You appear to be offline. For urgent care, call 02381-299133 or 94217 62599.';
      document.body.insertBefore(b, document.body.firstChild);
    }
  });
  window.addEventListener('online', function () {
    var b = document.getElementById('offline-banner');
    if (b) b.remove();
    loadSlots();
  });

  // Initialize immediately
  var today = todayISO();
  dateInput.min = today;
  dateInput.value = today;
  updateFeeBadge();
  renderDoctors(VERIFIED_DOCTORS);

  fetch('/api/public/info')
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(function (info) {
      if (!info) return;
      if (info.today_ist) { dateInput.min = info.today_ist; dateInput.value = info.today_ist; }
      if (Array.isArray(info.doctors) && info.doctors.length) renderDoctors(info.doctors);
    })
    .catch(function () {})
    .finally(loadSlots);
})();
