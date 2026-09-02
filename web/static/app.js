// APB console: progressive enhancement only.
//
// Every page works with this file blocked. What it adds is the bulk selection
// bar on the blocklist table and a confirmation step before destructive
// actions. There are no third-party libraries, no network calls and no
// storage: the content security policy would refuse them anyway.

(function () {
  "use strict";

  // ---- bulk selection --------------------------------------------------

  document.querySelectorAll("form[data-bulk]").forEach(function (form) {
    var bar = form.querySelector("[data-bulkbar]");
    var count = form.querySelector("[data-bulkcount]");
    var all = form.querySelector("[data-selectall]");
    var rows = Array.prototype.slice.call(form.querySelectorAll("[data-row]"));
    var scope = form.querySelector('input[name="scope"]');
    if (!bar || !rows.length) return;

    function refresh() {
      var n = rows.filter(function (r) { return r.checked; }).length;
      var whole = scope && scope.checked;
      bar.hidden = n === 0 && !whole;
      if (count) {
        count.textContent = whole
          ? "every matching row"
          : n + (n === 1 ? " selected" : " selected");
      }
      if (all) {
        all.checked = n > 0 && n === rows.length;
        all.indeterminate = n > 0 && n < rows.length;
      }
    }

    rows.forEach(function (r) { r.addEventListener("change", refresh); });
    if (scope) scope.addEventListener("change", refresh);
    if (all) {
      all.addEventListener("change", function () {
        rows.forEach(function (r) { r.checked = all.checked; });
        refresh();
      });
    }

    // Shift-click selects a range, the way a file manager does.
    var last = null;
    rows.forEach(function (r, i) {
      r.addEventListener("click", function (ev) {
        if (ev.shiftKey && last !== null) {
          var lo = Math.min(last, i), hi = Math.max(last, i);
          for (var j = lo; j <= hi; j++) rows[j].checked = r.checked;
          refresh();
        }
        last = i;
      });
    });

    refresh();
  });

  // ---- confirmation before anything destructive ------------------------

  document.addEventListener("click", function (ev) {
    var el = ev.target.closest("[data-confirm]");
    if (!el) return;
    if (!window.confirm(el.getAttribute("data-confirm"))) {
      ev.preventDefault();
      ev.stopPropagation();
    }
  }, true);

  // ---- one-time-password fields ----------------------------------------

  document.querySelectorAll("input.code").forEach(function (input) {
    input.addEventListener("input", function () {
      var digits = input.value.replace(/\D/g, "").slice(0, 6);
      if (digits !== input.value) input.value = digits;
      // Submitting on the sixth digit saves a click on every sign in.
      if (digits.length === 6 && input.form) input.form.requestSubmit();
    });
  });
})();
