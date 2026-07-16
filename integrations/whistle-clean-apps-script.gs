/**
 * Whistle Clean — Inquiry & Booking handler (Google Apps Script Web App)
 * ----------------------------------------------------------------------
 * One script that, on every incoming request:
 *   1. Appends a row to a Google Sheet (the lead log)
 *   2. Emails whistleclean100@gmail.com a notification
 *   3. For contact-form INQUIRIES, creates a Google Calendar follow-up event
 *      (Calendly BOOKINGS already create their own calendar event natively,
 *       so this script only logs + emails those.)
 *
 * It accepts TWO payload shapes:
 *   • Contact-form inquiry (sent by the website server /api/quote)
 *   • Calendly v2 webhook  (invitee.created)
 *
 * SETUP: see growth-plan/06-integrations-setup.md. Quick version:
 *   1. Make a Google Sheet (signed in as whistleclean100@gmail.com).
 *   2. Extensions → Apps Script → paste this file → Save.
 *   3. Edit SECRET below to a long random string.
 *   4. Deploy → New deployment → Web app → Execute as: Me → Who has access: Anyone.
 *   5. Copy the Web app URL. Put it (with ?token=YOUR_SECRET appended for the
 *      Calendly webhook) where the guide says.
 */

// ===== CONFIG — EDIT THESE =====
var SECRET = 'Yt9sMOrazQSF18D2N5xiHKRoGgCTW3dE'; // must match the server's QUOTE_WEBHOOK_TOKEN
var NOTIFY_EMAIL = 'whistleclean100@gmail.com';
var SHEET_NAME = 'Leads';
var SHEET_ID = '';   // REQUIRED if this script is NOT bound to the Sheet: the long
                     // id from the spreadsheet URL, docs.google.com/spreadsheets/d/<THIS>/edit
var CALENDAR_ID = 'primary';            // 'primary' = the account's main calendar
var CREATE_EVENT_FOR_INQUIRIES = true;  // contact-form inquiries → calendar follow-up
var EMAIL_ON_BOOKING = true;            // also email on Calendly bookings (Calendly emails too)
// ================================

function doGet() {
  return jsonOut({ ok: true, service: 'whistle-clean-handler' });
}

function doPost(e) {
  try {
    var token = (e && e.parameter && e.parameter.token) || '';
    var data = {};
    if (e && e.postData && e.postData.contents) {
      data = JSON.parse(e.postData.contents);
    }
    if (!token && data.token) token = data.token;
    if (SECRET && token !== SECRET) {
      return jsonOut({ ok: false, error: 'unauthorized' });
    }

    var d = normalize(data);
    appendRow(d);

    if (d.type === 'booking') {
      if (EMAIL_ON_BOOKING) sendNotification(d);
    } else {
      sendNotification(d);
      if (CREATE_EVENT_FOR_INQUIRIES) createFollowupEvent(d);
    }

    return jsonOut({ ok: true, type: d.type });
  } catch (err) {
    return jsonOut({ ok: false, error: String(err) });
  }
}

/** Normalize either a Calendly webhook or a contact-form payload into one shape. */
function normalize(data) {
  // Calendly v2 webhook: { event: "invitee.created", payload: {...} }
  if (data && data.event && String(data.event).indexOf('invitee') === 0 && data.payload) {
    var p = data.payload;
    var ev = p.scheduled_event || {};
    var qa = (p.questions_and_answers || [])
      .map(function (q) { return q.question + ': ' + q.answer; })
      .join(' | ');
    return {
      type: 'booking',
      name: p.name || '',
      email: p.email || '',
      phone: findPhone(p),
      service: (ev.name || 'Booking'),
      date: ev.start_time || '',
      message: qa,
    };
  }
  // Contact-form inquiry (from the website server)
  return {
    type: data.type || 'inquiry',
    name: data.name || '',
    email: data.email || '',
    phone: data.phone || '',
    service: data.service || '',
    date: data.date || '',
    message: data.message || '',
  };
}

function findPhone(p) {
  if (p.text_reminder_number) return p.text_reminder_number;
  var qa = p.questions_and_answers || [];
  for (var i = 0; i < qa.length; i++) {
    if (/phone|tel|teléfono|telefono/i.test(qa[i].question)) return qa[i].answer;
  }
  return '';
}

function getSheet() {
  // openById works from both bound AND standalone script projects;
  // getActiveSpreadsheet() is null in standalone ones (a real footgun).
  var ss = SHEET_ID
    ? SpreadsheetApp.openById(SHEET_ID)
    : SpreadsheetApp.getActiveSpreadsheet();
  if (!ss) throw new Error('No spreadsheet: set SHEET_ID (script is not bound to a Sheet).');
  var sh = ss.getSheetByName(SHEET_NAME);
  if (!sh) {
    sh = ss.insertSheet(SHEET_NAME);
    sh.appendRow(['Timestamp', 'Type', 'Name', 'Email', 'Phone', 'Service', 'Requested Date', 'Message']);
    sh.getRange(1, 1, 1, 8).setFontWeight('bold');
  }
  return sh;
}

function appendRow(d) {
  getSheet().appendRow([new Date(), d.type, d.name, d.email, d.phone, d.service, d.date, d.message]);
}

function sendNotification(d) {
  var label = d.type === 'booking' ? 'New Booking' : 'New Inquiry';
  var subject = label + ' — ' + (d.name || 'Unknown') + (d.service ? ' (' + d.service + ')' : '');
  var body =
    label + ' from the Whistle Clean website\n\n' +
    'Name:           ' + d.name + '\n' +
    'Email:          ' + d.email + '\n' +
    'Phone:          ' + d.phone + '\n' +
    'Service:        ' + d.service + '\n' +
    'Requested date: ' + d.date + '\n' +
    'Message:        ' + d.message + '\n';
  var opts = {};
  if (d.email && /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(d.email)) opts.replyTo = d.email;
  MailApp.sendEmail(NOTIFY_EMAIL, subject, body, opts);
}

function createFollowupEvent(d) {
  var cal = CALENDAR_ID === 'primary'
    ? CalendarApp.getDefaultCalendar()
    : CalendarApp.getCalendarById(CALENDAR_ID);
  if (!cal) return;

  var desc = 'Website inquiry.\nPhone: ' + d.phone + '\nEmail: ' + d.email + '\nMessage: ' + d.message;
  var start = d.date ? new Date(d.date) : null;

  if (start && !isNaN(start.getTime())) {
    var title = 'Inquiry: ' + (d.service || 'Service') + ' — ' + (d.name || '');
    // A bare YYYY-MM-DD from the form → all-day event; otherwise a 1-hour slot.
    if (typeof d.date === 'string' && d.date.length <= 10) {
      cal.createAllDayEvent(title, start, { description: desc });
    } else {
      cal.createEvent(title, start, new Date(start.getTime() + 60 * 60 * 1000), { description: desc });
    }
  } else {
    // No date supplied → drop a same-day "follow up" reminder so it isn't missed.
    cal.createAllDayEvent('Follow up: ' + (d.name || 'website inquiry'), new Date(), { description: desc });
  }
}

function jsonOut(obj) {
  return ContentService
    .createTextOutput(JSON.stringify(obj))
    .setMimeType(ContentService.MimeType.JSON);
}
